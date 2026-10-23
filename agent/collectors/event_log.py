"""
ForensiTrace - Windows Event Log Telemetry Collector (DAKSH)
Monitors Windows Event Logs (specifically Security and System channels) in a background
worker thread using pywin32 (win32evtlog) and normalizes records into the ForensiTrace schema.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

logger = logging.getLogger("agent.eventlog")


class EventLogCollector:
    """
    Asynchronous Windows Event Log collector.
    Polls configured channels (Security, System) for key threat events:
    - 4688: Process Creation (action: PROCESS_STARTED)
    - 4624: Successful Logon (action: USER_LOGON)
    - 1102: Security Audit Log Cleared (action: LOG_CLEARED)
    - 104: System Audit Log Cleared (action: LOG_CLEARED)
    """

    def __init__(
        self,
        channels: Optional[Sequence[str]] = None,
        server: Optional[str] = None,
        poll_interval: float = 1.0,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        target_event_ids: Optional[List[int]] = None,
    ) -> None:
        self.channels: List[str] = list(channels) if channels else ["Security", "System"]
        self.server: Optional[str] = server
        self.poll_interval: float = poll_interval
        self.event_callback = event_callback or self._default_event_handler
        self.target_event_ids: List[int] = target_event_ids or [4688, 4624, 1102, 104]

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running: bool = False

    @staticmethod
    def _default_event_handler(event: Dict[str, Any]) -> None:
        logger.info("[EventLog] Event: %s", json.dumps(event))

    def _normalize_event(self, channel: str, record: Any) -> Dict[str, Any]:
        """Translates a pywin32 PyEVENTLOGRECORD into canonical schema."""
        event_id = int(record.EventID) & 0xFFFF
        provider_name = str(record.SourceName or "UnknownProvider")
        inserts = list(record.StringInserts) if record.StringInserts else []

        # Determine action and entity based on Event ID
        if event_id == 4688:
            canonical_action = "PROCESS_STARTED"
            entity_type = "process"
            # In Windows Security 4688, StringInserts[5] is usually the new process name
            proc_name = inserts[5] if len(inserts) > 5 else "ProcessCreation"
            entity = proc_name
        elif event_id == 4624:
            canonical_action = "USER_LOGON"
            entity_type = "system"
            target_user = inserts[5] if len(inserts) > 5 else "LogonUser"
            entity = f"Logon:{target_user}"
        elif event_id in (1102, 104):
            canonical_action = "LOG_CLEARED"
            entity_type = "system"
            entity = f"LogCleared:{channel}"
        else:
            canonical_action = "PROCESS_STARTED" if "process" in provider_name.lower() else "EVENT_LOGGED"
            entity_type = "system"
            entity = f"{provider_name}/{event_id}"

        # Standardize timestamp
        if hasattr(record.TimeGenerated, "isoformat"):
            timestamp = record.TimeGenerated.isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        raw_data = {
            "channel": channel,
            "record_number": int(record.RecordNumber),
            "event_id": event_id,
            "provider_name": provider_name,
            "computer_name": str(record.ComputerName or ""),
            "string_inserts": inserts,
            "time_generated": str(record.TimeGenerated),
            "action": "logged"  # legacy alias
        }

        details = {
            "channel": channel,
            "event_id": event_id,
            "provider": provider_name,
            "string_inserts": inserts[:10],
            "record_number": int(record.RecordNumber)
        }

        return {
            "source": "eventlog",
            "timestamp": timestamp,
            "entity": entity,
            "action": canonical_action,
            "entity_type": entity_type,
            "host": str(record.ComputerName or "WIN-ENDPOINT"),
            "user": "SYSTEM",
            "details": details,
            "raw_data": raw_data,
        }

    def _poll_channel(self, channel: str, h_log: Any, last_records: Dict[str, int]) -> None:
        try:
            oldest = win32evtlog.GetOldestEventLogRecord(h_log)
            total = win32evtlog.GetNumberOfEventLogRecords(h_log)
        except Exception as exc:
            logger.debug("Failed to query records on '%s': %s", channel, exc)
            return

        if total == 0:
            return

        newest = oldest + total - 1
        last_seen = last_records.get(channel, newest)

        if newest <= last_seen:
            return

        seek_from = last_seen + 1
        if seek_from < oldest:
            seek_from = oldest

        flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ

        while seek_from <= newest and not self._stop_event.is_set():
            try:
                records = win32evtlog.ReadEventLog(h_log, flags, seek_from)
            except Exception as read_exc:
                logger.debug("ReadEventLog boundary error on '%s': %s", channel, read_exc)
                last_records[channel] = newest
                break

            if not records:
                break

            for record in records:
                rec_num = int(record.RecordNumber)
                if rec_num > last_records.get(channel, 0):
                    ev_id = int(record.EventID) & 0xFFFF
                    # Filter for target forensic event IDs
                    if not self.target_event_ids or ev_id in self.target_event_ids:
                        normalized = self._normalize_event(channel, record)
                        logger.info("[COLLECTED EVENTLOG] %s (Event %d): %s", normalized["action"], ev_id, normalized["entity"])
                        self.event_callback(normalized)
                    last_records[channel] = rec_num

                if rec_num >= seek_from:
                    seek_from = rec_num + 1

    def _monitor_loop(self) -> None:
        if not WIN32_AVAILABLE:
            logger.warning("pywin32 not available in this environment. EventLogCollector running in idle mode.")
            while not self._stop_event.is_set():
                time.sleep(1)
            return

        open_handles: Dict[str, Any] = {}
        last_records: Dict[str, int] = {}

        try:
            for channel in self.channels:
                try:
                    h_log = win32evtlog.OpenEventLog(self.server, channel)
                    open_handles[channel] = h_log
                    total = win32evtlog.GetNumberOfEventLogRecords(h_log)
                    oldest = win32evtlog.GetOldestEventLogRecord(h_log)
                    last_records[channel] = (oldest + total - 1) if total > 0 else 0
                    logger.info("Monitoring '%s' channel from record #%d", channel, last_records[channel])
                except Exception as exc:
                    logger.warning("Could not open channel '%s': %s (Administrator privileges may be required)", channel, exc)

            while not self._stop_event.is_set():
                for channel, h_log in list(open_handles.items()):
                    self._poll_channel(channel, h_log, last_records)
                time.sleep(self.poll_interval)
        finally:
            for channel, h_log in open_handles.items():
                try:
                    win32evtlog.CloseEventLog(h_log)
                except Exception:
                    pass
            logger.info("EventLogCollector loop terminated.")

    def start(self) -> None:
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="EventLogCollectorThread",
            daemon=True
        )
        self._thread.start()
        self._is_running = True
        logger.info("EventLogCollector started.")

    def stop(self, timeout: float = 3.0) -> None:
        if not self._is_running or not self._thread:
            return
        logger.info("Stopping EventLogCollector...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
        logger.info("EventLogCollector stopped.")
