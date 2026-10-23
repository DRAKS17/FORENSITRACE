"""
ForensiTrace - Agent Heartbeat Reporter
Periodically collects process-level CPU % and RSS RAM utilization to demonstrate
the minimal performance footprint of the ForensiTrace endpoint agent.
"""

from datetime import datetime, timezone
import logging
import platform
import threading
import time
from typing import Any, Callable, Dict, Optional
import psutil

logger = logging.getLogger("agent.heartbeat")


class HeartbeatReporter:
    """
    Periodic heartbeat monitor measuring CPU and RAM consumption.
    """

    def __init__(
        self,
        forward_callback: Callable[[Dict[str, Any]], None],
        interval_seconds: float = 10.0,
        host_id: str = "WIN-ENDPOINT",
    ):
        self.forward_callback = forward_callback
        self.interval_seconds = interval_seconds
        self.host_id = host_id
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._process = psutil.Process()

    def _monitor_loop(self) -> None:
        logger.info("HeartbeatReporter thread started (interval: %.1fs)", self.interval_seconds)

        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.interval_seconds):
                break

            try:
                cpu_percent = self._process.cpu_percent(interval=0.1)
                mem_info = self._process.memory_info()
                memory_mb = round(mem_info.rss / (1024 * 1024), 2)
                now_utc = datetime.now(timezone.utc).isoformat()

                event_data = {
                    "source": "heartbeat",
                    "timestamp": now_utc,
                    "host": self.host_id,
                    "user": "SYSTEM",
                    "entity": "agent_monitor",
                    "action": "HEARTBEAT",
                    "entity_type": "system",
                    "details": {
                        "cpu_percent": cpu_percent,
                        "memory_mb": memory_mb,
                        "threads": self._process.num_threads(),
                        "platform": platform.platform()
                    },
                    "raw_data": {
                        "cpu_percent": cpu_percent,
                        "memory_mb": memory_mb,
                        "pid": self._process.pid
                    }
                }
                self.forward_callback(event_data)
                logger.debug("[HEARTBEAT] CPU: %.1f%% | RAM: %.2f MB", cpu_percent, memory_mb)
            except Exception as e:
                logger.error("Error gathering heartbeat metrics: %s", e)

        logger.info("HeartbeatReporter thread stopped.")

    def start(self) -> None:
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="HeartbeatReporterThread",
            daemon=True
        )
        self._thread.start()
        self._is_running = True

    def stop(self, timeout: float = 3.0) -> None:
        if not self._is_running or not self._thread:
            return
        logger.info("Stopping HeartbeatReporter...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
