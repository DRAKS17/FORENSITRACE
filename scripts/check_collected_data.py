"""
ForensiTrace - Data Collection Status Inspector
Quickly summarizes the live data collected from the endpoint agent.
"""

import sqlite3
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.database import EvidenceStore


def main():
    store = EvidenceStore()
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]
    is_intact, tampered_id = store.verify_integrity()

    print("=" * 70)
    print(" FORENSITRACE - LIVE DATA COLLECTION STATUS")
    print("=" * 70)
    print(f"[*] Total Events Collected: {total_events}")
    print(f"[*] Hash Chain Integrity  : {'VERIFIED (Intact)' if is_intact else f'TAMPERED at Record #{tampered_id}'}")

    # Inspect breakdown by source
    events = store.get_events(limit=5000)
    if events:
        sources = {}
        for ev in events:
            sources[ev.source] = sources.get(ev.source, 0) + 1

        print("\n[*] Event Breakdown by Source Channel:")
        for src, cnt in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {src.upper():<12}: {cnt} events")

        oldest = events[0].timestamp
        newest = events[-1].timestamp
        print(f"\n[*] Collection Window:")
        print(f"    - Started : {oldest}")
        print(f"    - Latest  : {newest}")
    else:
        print("\n[!] No events collected yet. Agent is waiting for activity.")

    print("=" * 70)


if __name__ == "__main__":
    main()
