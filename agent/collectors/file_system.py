"""
ForensiTrace - File System Telemetry Collector (CHETNA)
Monitors endpoint file operations (create, modify, delete, move) using watchdog.
Filters temporary noise, debounces rapid duplicate events, and supports dynamic
addition/removal of watched paths (e.g. dynamically watching removable USB drives).
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("agent.fs")

DEFAULT_IGNORE_EXTENSIONS = {".tmp", ".crdownload", ".part", ".log", ".swp", ".lock"}
DEFAULT_IGNORE_PREFIXES = {"~$", "Thumbs.db", "desktop.ini"}


class _ForensicEventHandler(FileSystemEventHandler):
    """
    Translates raw Watchdog events into normalized ForensiTrace schema.
    Includes debouncing and noise filtering.
    """

    def __init__(
        self,
        callback: Callable[[Dict[str, Any]], None],
        ignore_exts: Set[str],
        ignore_prefixes: Set[str],
        debounce_seconds: float = 0.5,
    ) -> None:
        super().__init__()
        self._callback = callback
        self._ignore_exts = ignore_exts
        self._ignore_prefixes = ignore_prefixes
        self._debounce_seconds = debounce_seconds
        self._recent_events: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _should_ignore(self, path_str: str) -> bool:
        base_name = os.path.basename(path_str)
        if any(base_name.startswith(p) for p in self._ignore_prefixes):
            return True
        ext = Path(path_str).suffix.lower()
        if ext in self._ignore_exts:
            return True
        return False

    def _is_debounced(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last_time = self._recent_events.get(key, 0.0)
            if (now - last_time) < self._debounce_seconds:
                return True
            self._recent_events[key] = now
            # Prune old cache entries
            if len(self._recent_events) > 500:
                cutoff = now - 5.0
                self._recent_events = {k: v for k, v in self._recent_events.items() if v > cutoff}
            return False

    def _normalize_and_emit(self, action: str, event: FileSystemEvent) -> None:
        try:
            resolved_path = str(Path(event.src_path).resolve())
            if self._should_ignore(resolved_path):
                return

            debounce_key = f"{action}:{resolved_path}"
            if self._is_debounced(debounce_key):
                return

            is_dir = event.is_directory
            size_bytes: Optional[int] = None
            mtime_iso: Optional[str] = None

            if not is_dir and action != "FILE_DELETED":
                try:
                    if os.path.exists(resolved_path):
                        stat = os.stat(resolved_path)
                        size_bytes = stat.st_size
                        mtime_iso = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                except OSError:
                    pass

            now_utc = datetime.now(timezone.utc).isoformat()
            raw_data = {
                "event_type": event.event_type,
                "is_directory": is_dir,
                "src_path": resolved_path,
                "action": action.lower().replace("file_", "")
            }
            if size_bytes is not None:
                raw_data["size_bytes"] = size_bytes
            if mtime_iso:
                raw_data["mtime"] = mtime_iso

            details = {
                "file_path": resolved_path,
                "file_name": os.path.basename(resolved_path),
                "file_extension": Path(resolved_path).suffix.lower() if not is_dir else "",
                "is_directory": is_dir,
                "size_bytes": size_bytes,
                "mtime": mtime_iso or now_utc
            }

            normalized_event: Dict[str, Any] = {
                "source": "fs",
                "timestamp": now_utc,
                "entity": resolved_path,
                "action": action,
                "entity_type": "file",
                "details": details,
                "raw_data": raw_data,
            }

            logger.info("[COLLECTED FS] %s: %s", action, resolved_path)
            self._callback(normalized_event)
        except Exception as exc:
            logger.error("Error processing file system event: %s", exc)

    def on_created(self, event: FileSystemEvent) -> None:
        self._normalize_and_emit("FILE_CREATED", event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._normalize_and_emit("FILE_MODIFIED", event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._normalize_and_emit("FILE_DELETED", event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._normalize_and_emit("FILE_MOVED", event)


class FileSystemCollector:
    """
    Multi-path Watchdog collector supporting dynamic addition/removal of drives.
    """

    def __init__(
        self,
        watch_paths: Optional[List[str]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        ignore_exts: Optional[Set[str]] = None,
        ignore_prefixes: Optional[Set[str]] = None,
        debounce_seconds: float = 0.5,
    ) -> None:
        self.watch_paths: List[str] = watch_paths or []
        self.event_callback = event_callback or self._default_event_handler
        self.ignore_exts = ignore_exts or DEFAULT_IGNORE_EXTENSIONS
        self.ignore_prefixes = ignore_prefixes or DEFAULT_IGNORE_PREFIXES
        self.debounce_seconds = debounce_seconds

        self._observer = Observer()
        self._handler = _ForensicEventHandler(
            callback=self.event_callback,
            ignore_exts=self.ignore_exts,
            ignore_prefixes=self.ignore_prefixes,
            debounce_seconds=self.debounce_seconds,
        )
        self._active_watches: Dict[str, Any] = {}
        self._is_running = False

    @staticmethod
    def _default_event_handler(event: Dict[str, Any]) -> None:
        logger.info("[FS] Event: %s", json.dumps(event))

    def add_watch(self, path: str) -> bool:
        """Dynamically starts monitoring a path (e.g. when USB drive arrives)."""
        target = str(Path(path).resolve())
        if target in self._active_watches:
            return True

        if not os.path.exists(target):
            logger.warning("Cannot watch non-existent path: %s", target)
            return False

        try:
            watch = self._observer.schedule(self._handler, target, recursive=True)
            self._active_watches[target] = watch
            logger.info("[WATCHDOG] Scheduled watch on target: %s", target)
            return True
        except Exception as e:
            logger.error("Failed to schedule watch on %s: %s", target, e)
            return False

    def remove_watch(self, path: str) -> None:
        """Stops monitoring a path (e.g. when USB drive unmounted)."""
        target = str(Path(path).resolve())
        watch = self._active_watches.pop(target, None)
        if watch:
            try:
                self._observer.unschedule(watch)
                logger.info("[WATCHDOG] Unscheduled watch on: %s", target)
            except Exception as e:
                logger.warning("Error unscheduling watch on %s: %s", target, e)

    def start(self) -> None:
        if self._is_running:
            return

        # Schedule initial paths
        for p in self.watch_paths:
            self.add_watch(p)

        self._observer.start()
        self._is_running = True
        logger.info("FileSystemCollector started.")

    def stop(self) -> None:
        if not self._is_running:
            return
        logger.info("Stopping FileSystemCollector...")
        self._observer.stop()
        self._observer.join(timeout=3.0)
        self._active_watches.clear()
        self._is_running = False
        logger.info("FileSystemCollector stopped.")
