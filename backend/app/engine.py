"""
ForensiTrace - Rule-Based Correlation Engine
Analyzes sequences of raw events across telemetry sources, reconstructing unified
'Activities' and computing confidence scores based on timing and forensic artifacts.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

try:
    from backend.app.models import EventRecord, ActivityCreate
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from backend.app.models import EventRecord, ActivityCreate

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Analyzes streams of normalized EventRecords to detect multi-stage forensic activities.
    Uses deterministic rule-sets and sliding time windows to compute confidence scores.
    """

    def __init__(self):
        self.rules = [
            self._rule_usb_staging_execution
        ]

    def analyze(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        Runs all correlation rules against a sorted stream of event records.
        Returns a list of detected ActivityCreate models.
        """
        # Ensure events are sorted by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        activities = []
        for rule in self.rules:
            activities.extend(rule(sorted_events))
        return activities

    def _rule_usb_staging_execution(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        Phase 2 Demo Rule: "USB File Staging and Execution"
        Looks for:
        1. usb_device connection
        2. file_system creation/modification within 60s of USB
        3. event_log process launch within 60s of file event
        """
        activities = []
        n = len(events)
        
        for i in range(n):
            e1 = events[i]
            if e1.source != "usb_device" or e1.action not in ["connected", "arrival"]:
                continue
                
            # Stage 1 found: USB connected
            stage2_event: Optional[EventRecord] = None
            stage3_event: Optional[EventRecord] = None
            
            # Look for stage 2
            for j in range(i + 1, n):
                e2 = events[j]
                if (e2.timestamp - e1.timestamp).total_seconds() > 60:
                    break # Outside window
                if e2.source == "file_system" and e2.action in ["created", "modified"]:
                    stage2_event = e2
                    
                    # Look for stage 3
                    for k in range(j + 1, n):
                        e3 = events[k]
                        if (e3.timestamp - e2.timestamp).total_seconds() > 60:
                            break # Outside window
                        if e3.source == "event_log" and e3.action in ["logged", "process_created"]:
                            stage3_event = e3
                            break # Found best match
                    break # Best match for stage 2
            
            if stage2_event is None:
                continue
                
            # Evaluate chain and compute confidence
            confidence_score = 0.0
            narrative = ""
            evidence_ids = [e1.id, stage2_event.id]
            metadata = {}
            
            t1 = e1.timestamp
            t2 = stage2_event.timestamp
            t3 = stage3_event.timestamp if stage3_event else None
            
            delta_1_2 = (t2 - t1).total_seconds()
            delta_2_3 = (t3 - t2).total_seconds() if t3 else None
            
            if stage3_event:
                evidence_ids.append(stage3_event.id)
                # 3-stage chain
                if delta_1_2 <= 30 and delta_2_3 <= 30:
                    confidence_score = 0.90
                    narrative = f"High-confidence sequence: USB device connected ({e1.entity}), followed rapidly by file staging ({stage2_event.entity}) in {delta_1_2:.1f}s, and execution ({stage3_event.entity}) in {delta_2_3:.1f}s."
                else:
                    confidence_score = 0.75
                    narrative = f"Correlated sequence: USB connection ({e1.entity}), file staging ({stage2_event.entity}), and subsequent execution ({stage3_event.entity}). Timing is loose."
            else:
                # 2-stage partial match
                confidence_score = 0.50
                narrative = f"Partial sequence: USB connection ({e1.entity}) followed by file staging ({stage2_event.entity}) in {delta_1_2:.1f}s. No direct execution logged within window."
                
            # Timestamp consistency penalty
            # Check for irregular timing gaps
            if delta_1_2 < 0 or (delta_2_3 is not None and delta_2_3 < 0):
                confidence_score -= 0.15
                metadata["anomaly"] = "Negative timestamp delta detected, potential tampering."
                narrative += " [!] Anomaly: Chronological divergence detected."

            # Categorical level
            if confidence_score >= 0.75:
                confidence_level = "HIGH"
            elif confidence_score >= 0.45:
                confidence_level = "MEDIUM"
            else:
                confidence_level = "LOW"
                
            metadata["timing"] = {
                "usb_to_file_sec": delta_1_2,
                "file_to_exec_sec": delta_2_3
            }

            activity = ActivityCreate(
                rule_name="USB_STAGING_EXECUTION",
                title="Potential USB Staging and Execution",
                narrative=narrative,
                timestamp_start=t1,
                timestamp_end=t3 if t3 else t2,
                confidence_score=confidence_score,
                confidence_level=confidence_level,
                evidence_event_ids=evidence_ids,
                metadata=metadata
            )
            activities.append(activity)

        return activities


if __name__ == "__main__":
    import json
    
    logging.basicConfig(level=logging.INFO)
    print("=" * 80)
    print(" FORENSITRACE - CORRELATION ENGINE TEST")
    print("=" * 80)
    
    t0 = datetime.now(timezone.utc)
    
    e1 = EventRecord(
        id=101,
        source="usb_device",
        timestamp=t0,
        entity="E:",
        action="connected",
        raw_data={"volume": "MALICIOUS_DRIVE"},
        prev_hash="0"*64,
        record_hash="1"*64
    )
    
    e2 = EventRecord(
        id=102,
        source="file_system",
        timestamp=t0 + timedelta(seconds=5),
        entity="C:\\Users\\Admin\\Downloads\\payload.exe",
        action="created",
        raw_data={},
        prev_hash="1"*64,
        record_hash="2"*64
    )
    
    e3 = EventRecord(
        id=103,
        source="event_log",
        timestamp=t0 + timedelta(seconds=8),
        entity="Microsoft-Windows-Security-Auditing/4688",
        action="logged",
        raw_data={"process": "payload.exe"},
        prev_hash="2"*64,
        record_hash="3"*64
    )
    
    events = [e1, e2, e3]
    
    engine = CorrelationEngine()
    print("[*] Running synthetic mock sequence through engine...")
    activities = engine.analyze(events)
    
    assert len(activities) == 1, "Expected exactly 1 correlated activity."
    
    act = activities[0]
    print(f"\n[+] Detected Activity: {act.title} (Level: {act.confidence_level})")
    print(f"    Rule       : {act.rule_name}")
    print(f"    Confidence : {act.confidence_score}")
    print(f"    Narrative  : {act.narrative}")
    print(f"    Evidence IDs: {act.evidence_event_ids}")
    print(f"    Metadata   : {json.dumps(act.metadata)}")
    
    assert act.confidence_level == "HIGH", "Expected HIGH confidence for <30s chain"
    assert act.evidence_event_ids == [101, 102, 103], "Expected all 3 events to be linked"
    print("\n[+] SUCCESS: Correlation engine produced explainable activity provenance.")
