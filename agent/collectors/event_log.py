"""
ForensiTrace - Windows Event Log Telemetry Collector
Monitors Windows Event Logs (specifically Security and System channels) in a background
worker thread using pywin32 (win32evtlog) and normalizes records into the ForensiTrace schema.
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

import win32evtlog

logger = logging.getLogger(__name__)

# Mapping standard Windows EventLog event types to human-readable labels
EVENT_TYPE_NAMES: Dict[int, str] = {
    win32evtlog.EVENTLOG_SUCCESS: "Success",
    win32evtlog.EVENTLOG_ERROR_TYPE: "Error",
    win32evtlog.EVENTLOG_WARNING_TYPE: "Warning",
    win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
    win32evtlog.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
    win32evtlog.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
}


class EventLogCollector:
    """
    Asynchronous Windows Event Log telemetry collector.
    Polls configured Windows event log channels (e.g., Security, System) starting from
    the end of the log to capture exclusively new events generated during runtime.
    """

    def __init__(
        self,
        channels: Optional[Sequence[str]] = None,
        server: Optional[str] = None,
        poll_interval: float = 1.0,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """
        Initialize the EventLogCollector.

        :param channels: Sequence of event log channel names (defaults to ["Security", "System"]).
        :param server: Remote server name if monitoring remotely (defaults to None for local machine).
        :param poll_interval: Polling frequency in seconds.
        :param event_callback: Callback function receiving normalized event dictionaries.
        """
        self.channels: List[str] = list(channels) if channels else ["Security", "System"]
        self.server: Optional[str] = server
        self.poll_interval: float = poll_interval
        self.event_callback: Callable[[Dict[str, Any]], None] = (
            event_callback or self._default_event_handler
        )

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running: bool = False

    @staticmethod
    def _default_event_handler(event: Dict[str, Any]) -> None:
        """Default fallback handler that logs events."""
        logger.info("[EventLogCollector] Captured: %s", json.dumps(event))

    def _normalize_event(
        self, channel: str, record: Any
    ) -> Dict[str, Any]:
        """
        Translates a raw pywin32 PyEVENTLOGRECORD object into the standardized ForensiTrace schema.

        :param channel: Channel source name (e.g., 'System' or 'Security').
        :param record: Raw PyEVENTLOGRECORD instance returned by win32evtlog.ReadEventLog.
        :return: Standardized schema dictionary.
        """
        # Low 16 bits represent the user-visible Windows Event ID
        event_id = int(record.EventID) & 0xFFFF
        provider_name = str(record.SourceName or "UnknownProvider")
        entity = f"{provider_name}/{event_id}"

        # Standardize timestamp to ISO-8601 string
        if hasattr(record.TimeGenerated, "isoformat"):
            timestamp = record.TimeGenerated.isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        raw_data: Dict[str, Any] = {
            "channel": channel,
            "record_number": int(record.RecordNumber),
            "event_id": event_id,
            "event_id_raw": int(record.EventID),
            "provider_name": provider_name,
            "event_type": EVENT_TYPE_NAMES.get(
                record.EventType, f"Unknown ({record.EventType})"
            ),
            "event_type_id": int(record.EventType),
            "event_category": int(record.EventCategory),
            "computer_name": str(record.ComputerName or ""),
            "time_generated": str(record.TimeGenerated),
            "time_written": str(record.TimeWritten),
            "string_inserts": list(record.StringInserts) if record.StringInserts else [],
            "sid": str(record.Sid) if record.Sid else None,
        }

        return {
            "source": "event_log",
            "timestamp": timestamp,
            "entity": entity,
            "action": "logged",
            "raw_data": raw_data,
        }

    def _poll_channel(
        self, channel: str, h_log: Any, last_records: Dict[str, int]
    ) -> None:
        """
        Polls an open event log handle for records newer than last_records[channel].

        :param channel: Channel name.
        :param h_log: Open event log handle.
        :param last_records: Dictionary tracking latest seen record number per channel.
        """
        try:
            oldest = win32evtlog.GetOldestEventLogRecord(h_log)
            total = win32evtlog.GetNumberOfEventLogRecords(h_log)
        except Exception as exc:
            logger.error("Failed to query record status for '%s': %s", channel, exc)
            return

        if total == 0:
            return

        newest = oldest + total - 1
        last_seen = last_records.get(channel, newest)

        # No new records since previous poll
        if newest <= last_seen:
            return

        # Determine start record for sequential reading (handling log wrap or clear)
        seek_from = last_seen + 1
        if seek_from < oldest:
            logger.warning(
                "Log wrap or purge detected on '%s'. Advancing seek pointer from %s to %s",
                channel,
                seek_from,
                oldest,
            )
            seek_from = oldest

        flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ

        while seek_from <= newest and not self._stop_event.is_set():
            try:
                records = win32evtlog.ReadEventLog(h_log, flags, seek_from)
            except Exception as read_exc:
                logger.debug(
                    "ReadEventLog boundary error on '%s' at record %s: %s",
                    channel,
                    seek_from,
                    read_exc,
                )
                last_records[channel] = newest
                break

            if not records:
                break

            for record in records:
                if record.RecordNumber > last_records.get(channel, 0):
                    normalized = self._normalize_event(channel, record)
                    self.event_callback(normalized)
                    last_records[channel] = int(record.RecordNumber)

                if record.RecordNumber >= seek_from:
                    seek_from = int(record.RecordNumber) + 1

    def _monitor_loop(self) -> None:
        """
        Background monitoring thread worker.
        Safely opens event log handles in a try/finally block, positions at current end,
        and periodically polls for newly written records until signaled.
        """
        open_handles: Dict[str, Any] = {}
        last_records: Dict[str, int] = {}

        logger.info(
            "EventLogCollector worker thread initiated (TID: %s)",
            threading.get_ident(),
        )

        try:
            # 1. Initialize and open handles for each target channel
            for channel in self.channels:
                try:
                    h_log = win32evtlog.OpenEventLog(self.server, channel)
                    open_handles[channel] = h_log

                    # Position at the end of the log to capture only new incoming events
                    total = win32evtlog.GetNumberOfEventLogRecords(h_log)
                    oldest = win32evtlog.GetOldestEventLogRecord(h_log)
                    if total > 0:
                        last_records[channel] = oldest + total - 1
                    else:
                        last_records[channel] = 0

                    logger.info(
                        "Initialized '%s' log monitor at record #%s (Total historical: %s)",
                        channel,
                        last_records[channel],
                        total,
                    )
                except Exception as exc:
                    logger.warning(
                        "Could not open '%s' log: %s (Administrator privileges required to read Security log)",
                        channel,
                        exc,
                    )

            if not open_handles:
                logger.error("No event log channels could be opened for monitoring.")
                return

            logger.info("EventLogCollector entering active polling loop...")

            # 2. Continuous polling loop
            while not self._stop_event.is_set():
                for channel, h_log in list(open_handles.items()):
                    if self._stop_event.is_set():
                        break
                    try:
                        self._poll_channel(channel, h_log, last_records)
                    except Exception as poll_exc:
                        logger.error(
                            "Error while polling '%s': %s",
                            channel,
                            poll_exc,
                            exc_info=True,
                        )

                # Wait for poll interval or early exit on stop signal
                self._stop_event.wait(timeout=self.poll_interval)

        except Exception as exc:
            logger.critical(
                "Fatal unhandled exception in EventLogCollector: %s",
                exc,
                exc_info=True,
            )
        finally:
            # 3. Guaranteed handle cleanup
            logger.info("Cleaning up Windows Event Log handles...")
            for channel, h_log in open_handles.items():
                try:
                    win32evtlog.CloseEventLog(h_log)
                    logger.debug("Successfully closed handle for '%s'", channel)
                except Exception as close_exc:
                    logger.error(
                        "Failed to close event log handle for '%s': %s",
                        channel,
                        close_exc,
                    )
            open_handles.clear()
            logger.info("EventLogCollector worker thread terminated cleanly.")

    def start(self) -> None:
        """
        Starts the event log monitoring in a background thread.
        """
        if self._is_running:
            logger.warning("EventLogCollector is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="EventLogCollectorThread",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info("EventLogCollector background thread dispatched.")

    def stop(self, timeout: float = 3.0) -> None:
        """
        Signals the background polling thread to terminate and waits for it to join.

        :param timeout: Maximum seconds to wait for worker thread to exit.
        """
        if not self._is_running or self._thread is None:
            logger.debug("EventLogCollector is not currently running.")
            return

        logger.info("Signaling EventLogCollector to stop...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
        logger.info("EventLogCollector stopped successfully.")

    @property
    def is_running(self) -> bool:
        """Returns whether the collector background thread is currently active."""
        return (
            self._is_running
            and self._thread is not None
            and self._thread.is_alive()
        )


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="ForensiTrace Windows Event Log Collector (Test Runner)"
    )
    parser.add_argument(
        "--channels",
        nargs="+",
        default=["Security", "System"],
        help="Event log channels to monitor (default: Security System)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0)",
    )
    cli_args = parser.parse_args()

    print("=" * 80)
    print(" FORENSITRACE - WINDOWS EVENT LOG COLLECTOR [TEST MODE]")
    print(f" Target Channels : {', '.join(cli_args.channels)}")
    print(f" Poll Interval   : {cli_args.poll_interval}s")
    print(" NOTE            : Monitoring 'Security' log requires Administrator privileges.")
    print(" Status          : Active (Press Ctrl+C to terminate)")
    print("=" * 80)

    def print_captured_event(event_data: Dict[str, Any]) -> None:
        print("\n[+] Captured Windows Event Log:")
        print(json.dumps(event_data, indent=2))

    collector = EventLogCollector(
        channels=cli_args.channels,
        poll_interval=cli_args.poll_interval,
        event_callback=print_captured_event,
    )

    try:
        collector.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt detected. Shutting down Event Log collector...")
    finally:
        collector.stop()
        print("[*] Event Log Collector cleanly stopped.")
