"""
ForensiTrace - USB / Removable Storage Device Telemetry Collector
Monitors hardware device arrival and removal events using Windows WMI event tracking
and normalizes them into the ForensiTrace preliminary forensic event schema.
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

import pythoncom
import wmi

logger = logging.getLogger(__name__)

# WMI EventType mapping for Win32_DeviceChangeEvent / Win32_VolumeChangeEvent
WMI_EVENT_TYPE_MAP = {
    1: "Configuration Changed",
    2: "Device Arrival",
    3: "Device Removal",
    4: "Docking",
}

# Windows GetDriveType return values mapping
DRIVE_TYPE_MAP = {
    0: "Unknown",
    1: "No Root Directory",
    2: "Removable (USB/Floppy)",
    3: "Fixed (Local Disk/SSD)",
    4: "Network (Remote)",
    5: "CD-ROM",
    6: "RAM Disk",
}


class USBDeviceCollector:
    """
    Asynchronous USB/Removable Device telemetry collector.
    Monitors Windows WMI volume and device change events in a dedicated background
    worker thread, ensuring thread-safe COM apartment initialization and cleanup.
    """

    def __init__(
        self,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        poll_interval_ms: int = 1000,
        event_class: str = "Win32_VolumeChangeEvent",
    ) -> None:
        """
        Initialize the USBDeviceCollector.

        :param event_callback: Callback function receiving normalized event dictionaries.
        :param poll_interval_ms: Polling timeout in milliseconds for WMI watcher loop.
        :param event_class: WMI event class to watch ("Win32_VolumeChangeEvent" or "Win32_DeviceChangeEvent").
        """
        self.event_callback = event_callback or self._default_event_handler
        self.poll_interval_ms = poll_interval_ms
        self.event_class = event_class
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running: bool = False

    @staticmethod
    def _default_event_handler(event: Dict[str, Any]) -> None:
        """Default fallback handler that logs events."""
        logger.info("[USBDeviceCollector] Captured: %s", json.dumps(event))

    def _gather_volume_metadata(
        self, wmi_conn: wmi.WMI, drive_letter: str
    ) -> Dict[str, Any]:
        """
        Queries Win32_LogicalDisk to enrich device arrival with volume metadata.

        :param wmi_conn: Active thread-bound WMI connection.
        :param drive_letter: Drive letter string (e.g., 'E:').
        :return: Dictionary containing filesystem, size, label, and device type information.
        """
        metadata: Dict[str, Any] = {
            "drive_letter": drive_letter,
            "volume_name": "",
            "file_system": "",
            "drive_type_id": None,
            "drive_type_desc": "Unknown",
            "is_removable": False,
            "size_bytes": None,
            "free_space_bytes": None,
        }

        if not drive_letter or drive_letter == "Unknown":
            return metadata

        try:
            # Query the specific logical disk
            disks = wmi_conn.Win32_LogicalDisk(DeviceID=drive_letter)
            if disks:
                disk = disks[0]
                drive_type = getattr(disk, "DriveType", 0) or 0
                metadata.update(
                    {
                        "volume_name": str(getattr(disk, "VolumeName", "") or ""),
                        "file_system": str(getattr(disk, "FileSystem", "") or ""),
                        "drive_type_id": drive_type,
                        "drive_type_desc": DRIVE_TYPE_MAP.get(
                            drive_type, f"Unknown ({drive_type})"
                        ),
                        "is_removable": (drive_type == 2),
                        "size_bytes": int(disk.Size) if getattr(disk, "Size", None) else None,
                        "free_space_bytes": int(disk.FreeSpace)
                        if getattr(disk, "FreeSpace", None)
                        else None,
                    }
                )
        except Exception as exc:
            logger.debug(
                "Unable to retrieve logical disk properties for %s: %s",
                drive_letter,
                exc,
            )

        return metadata

    def _process_wmi_event(self, wmi_conn: wmi.WMI, raw_event: Any) -> None:
        """
        Translates a raw WMI change event into the ForensiTrace standardized schema.

        :param wmi_conn: Active thread-bound WMI connection.
        :param raw_event: WMI event object returned by the watcher.
        """
        try:
            event_type_id = int(getattr(raw_event, "EventType", 0))

            # Action classification
            if event_type_id == 2:
                action = "connected"
            elif event_type_id == 3:
                action = "disconnected"
            else:
                logger.debug("Ignoring unmonitored event type: %s", event_type_id)
                return

            event_type_name = WMI_EVENT_TYPE_MAP.get(
                event_type_id, f"Unknown ({event_type_id})"
            )

            # Determine entity (Drive letter or general device identifier)
            drive_letter = str(getattr(raw_event, "DriveName", "") or "").strip()
            entity = drive_letter if drive_letter else "Unknown Device"

            raw_data: Dict[str, Any] = {
                "wmi_class": self.event_class,
                "event_type_id": event_type_id,
                "event_type_name": event_type_name,
                "entity_identifier": entity,
            }

            # If device arrival on a volume, enrich with storage properties
            if action == "connected" and drive_letter:
                volume_metadata = self._gather_volume_metadata(wmi_conn, drive_letter)
                raw_data["volume_info"] = volume_metadata

            # Construct standardized preliminary forensic schema
            normalized_event: Dict[str, Any] = {
                "source": "usb_device",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "entity": entity,
                "action": action,
                "raw_data": raw_data,
            }

            self.event_callback(normalized_event)
        except Exception as exc:
            logger.error(
                "Failed to normalize WMI event: %s", exc, exc_info=True
            )

    def _monitor_loop(self) -> None:
        """
        Dedicated background worker method.
        Initializes COM apartment, sets up WMI event subscription, and loops until signaled.
        """
        logger.info(
            "Initializing COM apartment for USBDeviceCollector worker thread (TID: %s)",
            threading.get_ident(),
        )
        pythoncom.CoInitialize()
        wmi_conn: Optional[wmi.WMI] = None
        watcher: Optional[Any] = None

        try:
            wmi_conn = wmi.WMI()
            # Construct notification query for device arrival (2) and removal (3)
            wql_query = (
                f"SELECT * FROM {self.event_class} WHERE EventType = 2 OR EventType = 3"
            )
            logger.info("Subscribing to WMI events with query: %s", wql_query)
            watcher = wmi_conn.watch_for(raw_wql=wql_query)

            logger.info("USBDeviceCollector background monitoring loop started.")
            while not self._stop_event.is_set():
                try:
                    event = watcher(timeout_ms=self.poll_interval_ms)
                    self._process_wmi_event(wmi_conn, event)
                except wmi.x_wmi_timed_out:
                    # Timeout elapsed without event; loop and check stop_event
                    continue
                except Exception as exc:
                    if not self._stop_event.is_set():
                        logger.error(
                            "Error while awaiting WMI event: %s", exc, exc_info=True
                        )
                        time.sleep(0.5)

        except Exception as exc:
            logger.critical(
                "Fatal error in USBDeviceCollector monitoring loop: %s",
                exc,
                exc_info=True,
            )
        finally:
            logger.info("Exiting USBDeviceCollector loop and cleaning up COM apartment...")
            del watcher
            del wmi_conn
            pythoncom.CoUninitialize()
            logger.info("USBDeviceCollector worker thread terminated cleanly.")

    def start(self) -> None:
        """
        Spawns the background monitoring thread.
        """
        if self._is_running:
            logger.warning("USBDeviceCollector is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="USBDeviceCollectorThread",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info("USBDeviceCollector background thread dispatched.")

    def stop(self, timeout: float = 3.0) -> None:
        """
        Signals the background thread to terminate and waits for it to join.

        :param timeout: Maximum seconds to wait for worker thread to exit.
        """
        if not self._is_running or self._thread is None:
            logger.debug("USBDeviceCollector is not currently running.")
            return

        logger.info("Signaling USBDeviceCollector background thread to stop...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
        logger.info("USBDeviceCollector stopped successfully.")

    @property
    def is_running(self) -> bool:
        """Returns whether the collector background thread is currently alive."""
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
        description="ForensiTrace USB Device Collector (Test Runner)"
    )
    parser.add_argument(
        "--event-class",
        type=str,
        default="Win32_VolumeChangeEvent",
        choices=["Win32_VolumeChangeEvent", "Win32_DeviceChangeEvent"],
        help="WMI event class to monitor (default: Win32_VolumeChangeEvent)",
    )
    parser.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help="Watcher polling interval in milliseconds (default: 1000)",
    )
    cli_args = parser.parse_args()

    print("=" * 80)
    print(" FORENSITRACE - USB DEVICE COLLECTOR [TEST MODE]")
    print(f" WMI Event Class  : {cli_args.event_class}")
    print(f" Polling Interval : {cli_args.poll_interval_ms} ms")
    print(" Status           : Active (Insert or remove a USB drive to test)")
    print(" Press Ctrl+C to terminate...")
    print("=" * 80)

    def print_captured_event(event_data: Dict[str, Any]) -> None:
        print("\n[+] Captured USB Device Event:")
        print(json.dumps(event_data, indent=2))

    collector = USBDeviceCollector(
        event_callback=print_captured_event,
        poll_interval_ms=cli_args.poll_interval_ms,
        event_class=cli_args.event_class,
    )

    try:
        collector.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt detected. Shutting down USB collector...")
    finally:
        collector.stop()
        print("[*] USB Device Collector cleanly stopped.")
