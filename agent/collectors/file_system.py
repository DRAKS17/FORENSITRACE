"""
ForensiTrace - File System Collector
Monitors endpoint file system events (created, modified, deleted) using watchdog
and normalizes them into the ForensiTrace preliminary forensic event schema.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class _ForensicFileSystemEventHandler(FileSystemEventHandler):
    """Internal Watchdog event handler that translates raw FS events into the ForensiTrace schema."""

    def __init__(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        super().__init__()
        self._callback = callback

    def _normalize_and_emit(self, action: str, event: FileSystemEvent) -> None:
        """Normalizes a watchdog file system event into ForensiTrace schema."""
        try:
            resolved_path = str(Path(event.src_path).resolve())
            is_dir = event.is_directory

            # Gather auxiliary file metadata if available
            size_bytes: Optional[int] = None
            if not is_dir and action != "deleted":
                try:
                    if os.path.exists(resolved_path):
                        size_bytes = os.path.getsize(resolved_path)
                except OSError:
                    size_bytes = None

            raw_data: Dict[str, Any] = {
                "event_type": event.event_type,
                "is_directory": is_dir,
                "src_path": resolved_path,
                "file_extension": Path(resolved_path).suffix if not is_dir else "",
            }
            if size_bytes is not None:
                raw_data["size_bytes"] = size_bytes

            normalized_event: Dict[str, Any] = {
                "source": "file_system",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "entity": resolved_path,
                "action": action,
                "raw_data": raw_data,
            }

            self._callback(normalized_event)
        except Exception as exc:
            logger.error(
                "Error processing file system event for %s: %s",
                event.src_path,
                exc,
                exc_info=True,
            )

    def on_created(self, event: FileSystemEvent) -> None:
        """Invoked when a file or directory is created."""
        self._normalize_and_emit(action="created", event=event)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Invoked when a file or directory is modified."""
        self._normalize_and_emit(action="modified", event=event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Invoked when a file or directory is deleted."""
        self._normalize_and_emit(action="deleted", event=event)


class FileSystemCollector:
    """
    Asynchronous File System telemetry collector.
    Monitors a target directory using a background Watchdog Observer thread
    and dispatches normalized events to a registered callback.
    """

    def __init__(
        self,
        target_path: str | Path,
        recursive: bool = True,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """
        Initialize the FileSystemCollector.

        :param target_path: Directory path to monitor.
        :param recursive: Whether to monitor subdirectories recursively.
        :param event_callback: Callback function receiving normalized event dictionaries.
        """
        self.target_path = Path(target_path).resolve()
        self.recursive = recursive
        self.event_callback = event_callback or self._default_event_handler
        self._observer: Optional[Observer] = None
        self._is_running: bool = False

    @staticmethod
    def _default_event_handler(event: Dict[str, Any]) -> None:
        """Default fallback handler that logs events."""
        logger.info("[FileSystemCollector] Captured: %s", json.dumps(event))

    def start(self) -> None:
        """
        Starts the watchdog observer in a dedicated background thread.
        """
        if self._is_running:
            logger.warning(
                "FileSystemCollector is already active on %s", self.target_path
            )
            return

        if not self.target_path.exists():
            raise FileNotFoundError(
                f"Target directory does not exist: {self.target_path}"
            )

        logger.info(
            "Initializing FileSystemCollector for target: %s (recursive=%s)",
            self.target_path,
            self.recursive,
        )

        event_handler = _ForensicFileSystemEventHandler(callback=self.event_callback)
        self._observer = Observer()
        self._observer.schedule(
            event_handler, str(self.target_path), recursive=self.recursive
        )
        self._observer.start()
        self._is_running = True
        logger.info("FileSystemCollector background observer started successfully.")

    def stop(self) -> None:
        """
        Cleanly stops and joins the observer background thread.
        """
        if not self._is_running or self._observer is None:
            logger.debug("FileSystemCollector is not currently running.")
            return

        logger.info("Stopping FileSystemCollector background observer...")
        self._observer.stop()
        self._observer.join()
        self._is_running = False
        logger.info("FileSystemCollector observer terminated cleanly.")

    @property
    def is_running(self) -> bool:
        """Returns whether the collector is currently monitoring."""
        return (
            self._is_running
            and self._observer is not None
            and self._observer.is_alive()
        )


if __name__ == "__main__":
    import argparse

    # Configure structured console logging for test run
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="ForensiTrace File System Collector (Test Runner)"
    )
    parser.add_argument(
        "--path",
        "-p",
        type=str,
        default=".",
        help="Directory path to monitor (default: current directory)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive monitoring of subdirectories",
    )
    cli_args = parser.parse_args()

    watch_directory = Path(cli_args.path).resolve()

    print("=" * 80)
    print(" FORENSITRACE - FILE SYSTEM COLLECTOR [TEST MODE]")
    print(f" Target Path : {watch_directory}")
    print(f" Recursive   : {not cli_args.no_recursive}")
    print(" Status      : Active (Press Ctrl+C to terminate)")
    print("=" * 80)

    def print_captured_event(event_data: Dict[str, Any]) -> None:
        print("\n[+] Captured File System Event:")
        print(json.dumps(event_data, indent=2))

    collector = FileSystemCollector(
        target_path=watch_directory,
        recursive=not cli_args.no_recursive,
        event_callback=print_captured_event,
    )

    try:
        collector.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt detected. Initiating graceful shutdown...")
    finally:
        collector.stop()
        print("[*] Collector successfully stopped.")
