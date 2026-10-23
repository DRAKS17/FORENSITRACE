"""
ForensiTrace - Resilient Batched Event Forwarder (DAKSH)
Consumes events from collectors via a thread-safe queue and dispatches them
to the FastAPI backend using batched HTTP POST with exponential backoff.
Survives backend temporary outages without dropping events.
"""

from datetime import datetime
import json
import logging
import queue
import threading
import time
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger("agent.forwarder")


class EventForwarder:
    """
    Batched, thread-safe HTTP event forwarder with retry buffer.
    """

    def __init__(
        self,
        backend_url: str = "http://localhost:8000/api/v1/events",
        batch_size: int = 10,
        flush_interval: float = 2.0,
        max_buffer_size: int = 5000,
        retry_backoff: float = 1.5,
    ):
        self.backend_url = backend_url
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.retry_backoff = retry_backoff
        self.queue: queue.Queue = queue.Queue(maxsize=max_buffer_size)

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._is_running = False

    def submit_event(self, event_data: Dict[str, Any]) -> None:
        """
        Submits an event into the forwarding queue.
        Thread-safe callback registered with collectors.
        """
        try:
            self.queue.put_nowait(event_data)
            logger.debug(
                "[PRODUCED] Enqueued event: [%s] %s -> %s",
                event_data.get("source"),
                event_data.get("action"),
                event_data.get("entity")
            )
        except queue.Full:
            logger.warning("Event forwarder queue full! Dropping oldest event to preserve buffer.")
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(event_data)
            except Exception:
                pass

    def _flush_batch(self, session: requests.Session, batch: List[Dict[str, Any]]) -> bool:
        """
        Sends a batch to the backend with retry backoff. Returns True on success, False on failure.
        """
        if not batch:
            return True

        url = self.backend_url
        payload = batch if len(batch) > 1 else batch[0]

        max_retries = 3
        backoff = self.retry_backoff

        for attempt in range(1, max_retries + 1):
            if self._stop_event.is_set():
                break
            try:
                resp = session.post(url, json=payload, timeout=5.0)
                if resp.status_code in (200, 201):
                    logger.info("[DISPATCHED] Successfully forwarded batch of %d event(s) to %s", len(batch), url)
                    return True
                else:
                    logger.warning("[RETRY %d/%d] Backend returned HTTP %d: %s", attempt, max_retries, resp.status_code, resp.text[:100])
            except requests.RequestException as exc:
                logger.warning("[RETRY %d/%d] Backend connection failed: %s", attempt, max_retries, exc)

            time.sleep(backoff)
            backoff *= 1.5

        return False

    def _worker_loop(self) -> None:
        logger.info("EventForwarder worker started. Target: %s", self.backend_url)
        session = requests.Session()
        batch: List[Dict[str, Any]] = []
        last_flush_time = time.time()

        while not self._stop_event.is_set():
            try:
                event_data = self.queue.get(timeout=0.5)
                batch.append(event_data)
                self.queue.task_done()
            except queue.Empty:
                pass

            now = time.time()
            should_flush = len(batch) >= self.batch_size or (batch and (now - last_flush_time) >= self.flush_interval)

            if should_flush:
                success = self._flush_batch(session, batch)
                if success:
                    batch.clear()
                    last_flush_time = now
                else:
                    logger.error("Failed to forward batch of %d events after retries. Preserving in queue.", len(batch))
                    # Wait briefly before attempting again
                    time.sleep(2.0)

        # Final cleanup flush on shutdown
        if batch:
            self._flush_batch(session, batch)

        # Flush any remaining items in queue
        remaining = []
        while not self.queue.empty():
            try:
                remaining.append(self.queue.get_nowait())
                self.queue.task_done()
            except queue.Empty:
                break
        if remaining:
            logger.info("Flushing final %d events during shutdown...", len(remaining))
            self._flush_batch(session, remaining)

        session.close()
        logger.info("EventForwarder worker stopped.")

    def start(self) -> None:
        if self._is_running:
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="EventForwarderWorker",
            daemon=True
        )
        self._worker_thread.start()
        self._is_running = True

    def stop(self, timeout: float = 4.0) -> None:
        if not self._is_running or not self._worker_thread:
            return
        logger.info("Stopping EventForwarder...")
        self._stop_event.set()
        self._worker_thread.join(timeout=timeout)
        self._is_running = False
