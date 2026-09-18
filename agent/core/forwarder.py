import threading
import queue
import requests
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class EventForwarder:
    """
    Thread-safe event forwarder that consumes events from a queue and sends them
    to the backend via HTTP POST.
    """
    def __init__(self, backend_url: str):
        self.backend_url = backend_url
        self.queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = None
        self._is_running = False

    def submit_event(self, event_data: Dict[str, Any]) -> None:
        """
        Callback to be used by collectors to submit an event into the forwarder queue.
        """
        self.queue.put(event_data)

    def _worker_loop(self) -> None:
        logger.info(f"EventForwarder thread started. Target: {self.backend_url}")
        
        # We use requests.Session for HTTP keep-alive connection pooling
        session = requests.Session()
        
        while not self._stop_event.is_set():
            try:
                # Wait for an event with a timeout so we can check _stop_event periodically
                event_data = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # Process event
            try:
                response = session.post(self.backend_url, json=event_data, timeout=5.0)
                response.raise_for_status()
                logger.debug(f"Successfully forwarded event: {event_data.get('action')} from {event_data.get('source')}")
            except requests.RequestException as e:
                logger.warning(f"Failed to forward event to backend: {e}. Dropping event.")
            finally:
                self.queue.task_done()
        
        # Flush remaining queue items if possible during shutdown
        while not self.queue.empty():
            try:
                event_data = self.queue.get_nowait()
                try:
                    response = session.post(self.backend_url, json=event_data, timeout=2.0)
                    response.raise_for_status()
                except Exception as e:
                    logger.warning(f"Failed to forward final event during shutdown: {e}")
                finally:
                    self.queue.task_done()
            except queue.Empty:
                break
                
        session.close()
        logger.info("EventForwarder thread stopped.")

    def start(self) -> None:
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker_loop, name="EventForwarderThread", daemon=True)
        self._thread.start()
        self._is_running = True

    def stop(self, timeout: float = 5.0) -> None:
        if not self._is_running or self._thread is None:
            return
        logger.info("Signaling EventForwarder to stop...")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._is_running = False
