import argparse
import logging
import time

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

def main():
    parser = argparse.ArgumentParser(description="ForensiTrace Endpoint Agent")
    parser.add_argument("--backend-url", type=str, default="http://localhost:8000/api/v1/events",
                        help="Target URL for event ingestion (default: http://localhost:8000/api/v1/events)")
    parser.add_argument("--watch-dir", type=str, default="C:\\", 
                        help="Directory to watch for file system events (default: C:\\)")
    args = parser.parse_args()

    print("=" * 80)
    print(" FORENSITRACE - ENDPOINT AGENT SERVICE")
    print(f" Backend URL     : {args.backend_url}")
    print(f" FS Watch Target : {args.watch_dir}")
    print("=" * 80)

    # Initialize Core Components
    forwarder = EventForwarder(backend_url=args.backend_url)
    heartbeat = HeartbeatReporter(forward_callback=forwarder.submit_event, interval_seconds=15.0)

    # Initialize Collectors, wiring them to the forwarder callback
    fs_collector = FileSystemCollector(watch_path=args.watch_dir, event_callback=forwarder.submit_event)
    usb_collector = USBDeviceCollector(event_callback=forwarder.submit_event)
    el_collector = EventLogCollector(channels=["Security", "System"], event_callback=forwarder.submit_event)

    try:
        # Start the pipeline (consumers before producers)
        forwarder.start()
        
        # Start monitors/producers
        heartbeat.start()
        fs_collector.start()
        usb_collector.start()
        el_collector.start()

        logger.info("All agent components started successfully. Press Ctrl+C to stop.")

        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Ctrl+C detected! Initiating graceful shutdown...")
    except Exception as e:
        logger.critical(f"Agent encountered a fatal error: {e}", exc_info=True)
    finally:
        # Gracefully stop components
        logger.info("Stopping collectors...")
        fs_collector.stop()
        usb_collector.stop()
        el_collector.stop()
        
        logger.info("Stopping heartbeat monitor...")
        heartbeat.stop()

        logger.info("Stopping event forwarder and flushing queue...")
        forwarder.stop()
        
        logger.info("Agent shutdown complete.")

if __name__ == "__main__":
    main()
