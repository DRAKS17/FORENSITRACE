"""
ForensiTrace - Unified Windows Endpoint Agent (DAKSH & CHETNA)
Orchestrates parallel collectors (USB, File System, Event Log), runs the resource
heartbeat reporter, and forwards all telemetry through a resilient batched sender.
Implements the dynamic USB -> File System hand-off callback for runtime removable volume tracking.
"""

import argparse
import logging
import os
from pathlib import Path
import signal
import sys
import time
from typing import Any, Dict, List
import yaml

from agent.collectors.file_system import FileSystemCollector
from agent.collectors.usb_device import USBDeviceCollector
from agent.collectors.event_log import EventLogCollector
from agent.core.forwarder import EventForwarder
from agent.core.heartbeat import HeartbeatReporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("agent.main")


def load_config(config_path: str) -> Dict[str, Any]:
    """Loads YAML configuration with fallback defaults."""
    cfg_file = Path(config_path).resolve()
    if not cfg_file.exists():
        logger.warning("Config file not found at %s. Using internal agent defaults.", cfg_file)
        return {}
    try:
        with open(cfg_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error("Error loading %s: %s", cfg_file, e)
        return {}


def get_default_user_folders() -> List[str]:
    """Retrieves standard Windows user folders (Desktop, Downloads, Documents)."""
    user_home = Path.home()
    candidates = [
        user_home / "Desktop",
        user_home / "Downloads",
        user_home / "Documents",
        Path(os.environ.get("TEMP", "C:\\Windows\\Temp"))
    ]
    return [str(p) for p in candidates if p.exists()]


def main():
    parser = argparse.ArgumentParser(description="ForensiTrace Windows Endpoint Forensic Agent")
    parser.add_argument(
        "--config", type=str, default="agent/config.yaml",
        help="Path to agent configuration file (default: agent/config.yaml)"
    )
    parser.add_argument(
        "--backend-url", type=str, default=None,
        help="Override target backend ingestion URL"
    )
    parser.add_argument(
        "--watch-dir", type=str, default=None,
        help="Explicit directory path to watch for file system events"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    agent_cfg = config.get("agent", {})
    backend_cfg = config.get("backend", {})
    collectors_cfg = config.get("collectors", {})
    heartbeat_cfg = config.get("heartbeat", {})

    host_id = agent_cfg.get("host_id", "WIN-ENDPOINT-01")
    backend_url = args.backend_url or backend_cfg.get("url", "http://localhost:8000/api/v1/events")

    # Determine FS watch paths
    if args.watch_dir:
        watch_paths = [args.watch_dir]
    elif collectors_cfg.get("file_system", {}).get("watch_user_folders", True):
        watch_paths = get_default_user_folders()
    else:
        watch_paths = ["C:\\"]

    print("=" * 80)
    print(" FORENSITRACE - ENDPOINT AGENT SERVICE")
    print(f" Host ID         : {host_id}")
    print(f" Backend URL     : {backend_url}")
    print(f" FS Watch Targets: {', '.join(watch_paths)}")
    print("=" * 80)

    # 1. Initialize Event Forwarder
    forwarder = EventForwarder(
        backend_url=backend_url,
        batch_size=backend_cfg.get("batch_size", 10),
        flush_interval=backend_cfg.get("flush_interval_seconds", 2.0),
        retry_backoff=backend_cfg.get("retry_backoff_seconds", 1.5),
    )

    # 2. Initialize Heartbeat Reporter
    heartbeat = HeartbeatReporter(
        forward_callback=forwarder.submit_event,
        interval_seconds=heartbeat_cfg.get("interval_seconds", 10.0),
        host_id=host_id,
    )

    # 3. Initialize File System Collector
    fs_cfg = collectors_cfg.get("file_system", {})
    fs_collector = FileSystemCollector(
        watch_paths=watch_paths,
        event_callback=forwarder.submit_event,
        debounce_seconds=fs_cfg.get("debounce_seconds", 0.5),
    )

    # 4. Initialize USB Collector with Dynamic Hand-off to FS Collector!
    usb_collector = USBDeviceCollector(
        event_callback=forwarder.submit_event,
        drive_attached_callback=fs_collector.add_watch,
        drive_detached_callback=fs_collector.remove_watch,
        poll_interval_ms=collectors_cfg.get("usb", {}).get("poll_interval_ms", 1000),
    )

    # 5. Initialize Event Log Collector
    el_cfg = collectors_cfg.get("event_log", {})
    el_collector = EventLogCollector(
        channels=el_cfg.get("channels", ["Security", "System"]),
        poll_interval=el_cfg.get("poll_interval", 1.0),
        target_event_ids=el_cfg.get("target_event_ids", [4688, 4624, 1102, 104]),
        event_callback=forwarder.submit_event,
    )

    # Graceful shutdown handler
    def handle_exit(signum, frame):
        logger.info("Termination signal received. Initiating graceful shutdown...")
        fs_collector.stop()
        usb_collector.stop()
        el_collector.stop()
        heartbeat.stop()
        forwarder.stop()
        logger.info("ForensiTrace agent shut down cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        # Start pipeline
        forwarder.start()
        heartbeat.start()
        fs_collector.start()
        usb_collector.start()
        el_collector.start()

        logger.info("All agent subsystems active. Streaming telemetry to %s", backend_url)

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        handle_exit(None, None)
    except Exception as e:
        logger.critical("Fatal error in agent supervisor: %s", e, exc_info=True)
        handle_exit(None, None)


if __name__ == "__main__":
    main()
