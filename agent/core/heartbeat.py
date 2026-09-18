import threading
import time
import psutil
import logging
from datetime import datetime, timezone
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)

class HeartbeatReporter:
    """
    Periodic heartbeat monitor to measure agent overhead (CPU and RAM)
    and forward it into the main event pipeline.
    """
    def __init__(self, forward_callback: Callable[[Dict[str, Any]], None], interval_seconds: float = 15.0):
        self.forward_callback = forward_callback
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread = None
        self._is_running = False
        self._process = psutil.Process()

    def _monitor_loop(self) -> None:
        logger.info(f"HeartbeatReporter thread started (Interval: {self.interval_seconds}s)")
        
        while not self._stop_event.is_set():
            # Wait for interval or stop signal
            if self._stop_event.wait(timeout=self.interval_seconds):
                break
                
            try:
                # Measure CPU over a short interval to get accurate percentage
                cpu_percent = self._process.cpu_percent(interval=0.1)
                
                # Get RSS memory in MB
                memory_info = self._process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                event_data = {
                    "source": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "entity": "agent_monitor",
                    "action": "pulse",
                    "raw_data": {
                        "cpu_percent": cpu_percent,
                        "memory_mb": round(memory_mb, 2)
                    }
                }
                self.forward_callback(event_data)
                logger.debug(f"Emitted heartbeat pulse (CPU: {cpu_percent}%, RAM: {memory_mb:.2f}MB)")
            except Exception as e:
                logger.error(f"Error gathering heartbeat telemetry: {e}")

        logger.info("HeartbeatReporter thread stopped.")

    def start(self) -> None:
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, name="HeartbeatReporterThread", daemon=True)
        self._thread.start()
        self._is_running = True

    def stop(self, timeout: float = 3.0) -> None:
        if not self._is_running or self._thread is None:
            return
        logger.info("Signaling HeartbeatReporter to stop...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
