"""
ForensiTrace - USB / Removable Storage Device Telemetry Collector (CHETNA)
Monitors hardware device arrival and removal events using Windows WMI event tracking
and normalizes them into the canonical ForensiTrace event schema (docs/schema.md).
Features a dynamic drive hand-off callback to the FileSystemCollector.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

try:
    import pythoncom
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

logger = logging.getLogger("agent.usb")

WMI_EVENT_TYPE_MAP = {
    1: "Configuration Changed",
    2: "Device Arrival",
    3: "Device Removal",
    4: "Docking",
}

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
    Asynchronous USB/Removable Device collector with dynamic hand-off callback.
    """

    def __init__(
        self,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        drive_attached_callback: Optional[Callable[[str], None]] = None,
        drive_detached_callback: Optional[Callable[[str], None]] = None,
        poll_interval_ms: int = 1000,
        event_class: str = "Win32_VolumeChangeEvent",
    ) -> None:
        self.event_callback = event_callback or self._default_event_handler
        self.drive_attached_callback = drive_attached_callback
        self.drive_detached_callback = drive_detached_callback
        self.poll_interval_ms = poll_interval_ms
        self.event_class = event_class
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running: bool = False

    @staticmethod
    def _default_event_handler(event: Dict[str, Any]) -> None:
        logger.info("[USB] Event: %s", json.dumps(event))

    def _gather_volume_metadata(self, wmi_conn: Any, drive_letter: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            "drive_letter": drive_letter,
            "volume_name": "",
            "file_system": "",
            "drive_type_id": None,
            "drive_type_desc": "Unknown",
            "is_removable": True,
            "size_bytes": None,
            "free_space_bytes": None,
        }

        if not drive_letter or drive_letter == "Unknown":
            return metadata

        try:
            disks = wmi_conn.Win32_LogicalDisk(DeviceID=drive_letter)
            if disks:
                disk = disks[0]
                drive_type = getattr(disk, "DriveType", 0) or 0
                metadata.update({
                    "volume_name": str(getattr(disk, "VolumeName", "") or ""),
                    "file_system": str(getattr(disk, "FileSystem", "") or ""),
                    "drive_type_id": drive_type,
                    "drive_type_desc": DRIVE_TYPE_MAP.get(drive_type, f"Unknown ({drive_type})"),
                    "is_removable": (drive_type == 2),
                    "size_bytes": int(disk.Size) if getattr(disk, "Size", None) else None,
                    "free_space_bytes": int(disk.FreeSpace) if getattr(disk, "FreeSpace", None) else None,
                })
        except Exception as exc:
            logger.debug("Unable to retrieve volume metadata for %s: %s", drive_letter, exc)

        return metadata

    def _process_wmi_event(self, wmi_conn: Any, raw_event: Any) -> None:
        try:
            event_type_id = int(getattr(raw_event, "EventType", 0))

            if event_type_id == 2:
                canonical_action = "DEVICE_ARRIVED"
                legacy_action = "connected"
            elif event_type_id == 3:
                canonical_action = "DEVICE_REMOVED"
                legacy_action = "disconnected"
            else:
                return

            drive_letter = str(getattr(raw_event, "DriveName", "") or "").strip()
            volume_info = {}
            if canonical_action == "DEVICE_ARRIVED" and drive_letter and wmi_conn:
                volume_info = self._gather_volume_metadata(wmi_conn, drive_letter)

            volume_name = volume_info.get("volume_name", "")
            entity_str = f"{drive_letter} ({volume_name})" if volume_name else (drive_letter or "Unknown Removable Device")

            raw_data = {
                "wmi_class": self.event_class,
                "event_type_id": event_type_id,
                "drive_letter": drive_letter,
                "volume_info": volume_info,
                "action": legacy_action
            }

            normalized_event: Dict[str, Any] = {
                "source": "usb",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "entity": entity_str,
                "action": canonical_action,
                "entity_type": "device",
                "details": {
                    "drive_letter": drive_letter,
                    "volume_name": volume_name,
                    "is_removable": volume_info.get("is_removable", True),
                    "size_bytes": volume_info.get("size_bytes"),
                    "file_system": volume_info.get("file_system", "")
                },
                "raw_data": raw_data,
            }

            logger.info("[COLLECTED USB] %s: %s", canonical_action, entity_str)
            self.event_callback(normalized_event)

            # Runtime hand-off to FileSystemCollector
            if drive_letter:
                if canonical_action == "DEVICE_ARRIVED" and self.drive_attached_callback:
                    logger.info("[HANDOFF] Triggering FileSystemCollector to watch new drive: %s", drive_letter)
                    self.drive_attached_callback(drive_letter)
                elif canonical_action == "DEVICE_REMOVED" and self.drive_detached_callback:
                    logger.info("[HANDOFF] Triggering FileSystemCollector to stop watching: %s", drive_letter)
                    self.drive_detached_callback(drive_letter)

        except Exception as exc:
            logger.error("Failed to process WMI USB event: %s", exc, exc_info=True)

    def _monitor_loop(self) -> None:
        if not WMI_AVAILABLE:
            logger.warning("WMI or pythoncom not available in this environment. USB collector running in idle mode.")
            while not self._stop_event.is_set():
                time.sleep(1)
            return

        logger.info("Initializing COM apartment for USB collector thread (TID: %s)", threading.get_ident())
        pythoncom.CoInitialize()
        wmi_conn = None
        watcher = None

        try:
            wmi_conn = wmi.WMI()
            wql_query = f"SELECT * FROM {self.event_class} WHERE EventType = 2 OR EventType = 3"
            logger.info("Subscribed to WMI events: %s", wql_query)
            watcher = wmi_conn.watch_for(raw_wql=wql_query)

            while not self._stop_event.is_set():
                try:
                    wmi_event = watcher(timeout_ms=self.poll_interval_ms)
                    if wmi_event:
                        self._process_wmi_event(wmi_conn, wmi_event)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as loop_exc:
                    if not self._stop_event.is_set():
                        logger.error("Error in WMI polling loop: %s", loop_exc)
                        time.sleep(1.0)
        finally:
            logger.info("Uninitializing COM apartment for USB collector thread.")
            pythoncom.CoUninitialize()

    def start(self) -> None:
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="USBDeviceCollectorThread",
            daemon=True
        )
        self._thread.start()
        self._is_running = True
        logger.info("USBDeviceCollector background thread started.")

    def stop(self, timeout: float = 3.0) -> None:
        if not self._is_running or not self._thread:
            return
        logger.info("Stopping USBDeviceCollector...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
        logger.info("USBDeviceCollector stopped.")
