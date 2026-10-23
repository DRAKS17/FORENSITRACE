"""
ForensiTrace - Rule-Based Correlation Engine (AKASH)
Loads declarative correlation rules from rules.yaml (no machine learning).
Reconstructs multi-stage forensic 'Activities' across heterogeneous telemetry sources,
computes explainable confidence scores, identifies timestamp inconsistencies,
and generates plain-English narratives where every sentence cites event IDs.
"""

from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

try:
    from backend.app.models import EventRecord, ActivityCreate
except ModuleNotFoundError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from backend.app.models import EventRecord, ActivityCreate

logger = logging.getLogger(__name__)


def _extract_drive_letter(entity: str) -> Optional[str]:
    """Extracts a Windows drive letter (e.g. 'E:' or 'E:\\') from an entity string."""
    if not entity:
        return None
    cleaned = entity.strip()
    if len(cleaned) >= 2 and cleaned[1] == ":":
        return cleaned[:2].upper()
    return None


class CorrelationEngine:
    """
    Forensic correlation engine implementing rules R1 through R7 loaded from rules.yaml.
    Reconstructs attack paths, guarantees evidence provenance, and avoids binary pass/fail.
    """

    def __init__(self, rules_file: Optional[str] = None):
        if rules_file:
            self.rules_path = Path(rules_file).resolve()
        else:
            # Look in repository root or local directory
            default_path = Path(__file__).resolve().parent.parent.parent / "rules.yaml"
            self.rules_path = default_path if default_path.exists() else Path("rules.yaml").resolve()

        self.rules_config: Dict[str, Any] = self._load_rules_config()

    def _load_rules_config(self) -> Dict[str, Any]:
        """Loads and parses rules.yaml configuration."""
        if not self.rules_path.exists():
            logger.warning("Rules file not found at %s. Using internal rule defaults.", self.rules_path)
            return {}
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
                logger.info("Successfully loaded correlation rules from: %s", self.rules_path)
                return config
        except Exception as e:
            logger.error("Error reading rules.yaml: %s. Using internal rule defaults.", e)
            return {}

    def get_rule_cfg(self, rule_id: str) -> Dict[str, Any]:
        """Retrieves rule parameters from configuration with safe defaults."""
        rules = self.rules_config.get("rules", [])
        for r in rules:
            if r.get("id") == rule_id or r.get("name") == rule_id:
                return r
        return {}

    def analyze(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        Executes all correlation rules against the chronological stream of events.
        """
        if not events:
            return []

        # Sort strictly by timestamp ASC
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        activities: List[ActivityCreate] = []

        # Rule evaluation pipeline
        activities.extend(self._rule_r7_usb_staging_execution(sorted_events))
        activities.extend(self._rule_r1_device_file_staging(sorted_events))
        activities.extend(self._rule_r2_file_execution(sorted_events))
        activities.extend(self._rule_r3_direct_removable_execution(sorted_events))
        activities.extend(self._rule_r4_bulk_copy(sorted_events))
        activities.extend(self._rule_r5_log_cleared_coverup(sorted_events))
        activities.extend(self._rule_r6_timestamp_disagreement(sorted_events))

        logger.info("Correlation engine analysis completed. Generated %d activities.", len(activities))
        return activities

    # -------------------------------------------------------------------------
    # RULE R7: USB Staging and Execution Chain (R1 + R2)
    # -------------------------------------------------------------------------
    def _rule_r7_usb_staging_execution(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R7: USB arrival -> File write on that drive -> Process execution from that file.
        Window: 900s (15 min).
        """
        cfg = self.get_rule_cfg("R7")
        if cfg.get("enabled", True) is False:
            return []

        window_sec = cfg.get("window_seconds", 900)
        tight_sec = cfg.get("tight_threshold_seconds", 30)
        high_score = cfg.get("high_confidence_score", 0.90)
        med_score = cfg.get("medium_confidence_score", 0.75)
        part_score = cfg.get("partial_confidence_score", 0.50)
        penalty = cfg.get("divergence_penalty", 0.15)

        activities = []
        n = len(events)

        for i in range(n):
            e1 = events[i]
            if e1.get_canonical_source() != "usb" or e1.get_canonical_action() != "DEVICE_ARRIVED":
                continue

            usb_drive = _extract_drive_letter(e1.entity)
            stage2_event: Optional[EventRecord] = None
            stage3_event: Optional[EventRecord] = None

            for j in range(i + 1, n):
                e2 = events[j]
                delta_1_2 = (e2.timestamp - e1.timestamp).total_seconds()
                if delta_1_2 > window_sec:
                    break

                if e2.get_canonical_source() == "fs" and e2.get_canonical_action() in ("FILE_CREATED", "FILE_MODIFIED"):
                    fs_drive = _extract_drive_letter(e2.entity)
                    # If USB drive letter is known, match it; otherwise correlate if proximate
                    if usb_drive and fs_drive and usb_drive != fs_drive:
                        continue

                    stage2_event = e2
                    staged_path = e2.entity.lower()

                    for k in range(j + 1, n):
                        e3 = events[k]
                        delta_2_3 = (e3.timestamp - e2.timestamp).total_seconds()
                        if delta_2_3 > window_sec:
                            break

                        if e3.get_canonical_source() == "eventlog" and e3.get_canonical_action() == "PROCESS_STARTED":
                            exec_target = e3.entity.lower()
                            # Check if the process matches staged file name or full path
                            if os.path.basename(staged_path) in exec_target or staged_path in exec_target:
                                stage3_event = e3
                                break
                    break

            if not stage2_event:
                continue

            # Build narrative citing event IDs
            t1 = e1.timestamp
            t2 = stage2_event.timestamp
            t3 = stage3_event.timestamp if stage3_event else None
            d12 = (t2 - t1).total_seconds()
            d23 = (t3 - t2).total_seconds() if t3 else None

            links = [
                {
                    "event_id": e1.id,
                    "rule_id": "R7",
                    "reason": f"Initial removable hardware arrival ({e1.entity}) recorded at {t1.strftime('%H:%M:%S')}."
                },
                {
                    "event_id": stage2_event.id,
                    "rule_id": "R7",
                    "reason": f"File staging occurred on target drive ({stage2_event.entity}) within {d12:.1f}s of device arrival."
                }
            ]
            evidence_ids = [e1.id, stage2_event.id]

            if stage3_event:
                evidence_ids.append(stage3_event.id)
                links.append({
                    "event_id": stage3_event.id,
                    "rule_id": "R7",
                    "reason": f"Process execution spawned from staged binary ({stage3_event.entity}) within {d23:.1f}s of file write."
                })

                if d12 <= tight_sec and d23 <= tight_sec:
                    confidence = high_score
                    narrative = (
                        f"[Event #{e1.id}] USB device connected ({e1.entity}) at {t1.strftime('%H:%M:%S')}. "
                        f"[Event #{stage2_event.id}] High-speed file staging followed {d12:.1f}s later targeting {stage2_event.entity}. "
                        f"[Event #{stage3_event.id}] Subsequent process launch was executed from the staged path in {d23:.1f}s."
                    )
                else:
                    confidence = med_score
                    narrative = (
                        f"[Event #{e1.id}] Removable device connected ({e1.entity}). "
                        f"[Event #{stage2_event.id}] File {stage2_event.entity} was staged {d12:.1f}s later. "
                        f"[Event #{stage3_event.id}] Execution was confirmed {d23:.1f}s afterwards. "
                        f"Sequence shows elevated timing gap."
                    )
            else:
                confidence = part_score
                narrative = (
                    f"[Event #{e1.id}] Removable device connected ({e1.entity}). "
                    f"[Event #{stage2_event.id}] File {stage2_event.entity} was staged {d12:.1f}s later. "
                    f"No direct execution event was captured within the correlation window."
                )

            # Check timestamp anomalies
            anomalies = []
            if d12 < 0 or (d23 is not None and d23 < 0):
                confidence = max(0.1, confidence - penalty)
                anomalies.append("Negative time delta observed across telemetry sources.")
                narrative += f" [!] Anomaly: Chronological divergence detected ({anomalies[-1]})."

            level = "HIGH" if confidence >= 0.75 else ("MEDIUM" if confidence >= 0.45 else "LOW")

            activities.append(
                ActivityCreate(
                    rule_name="R7_USB_STAGING_EXECUTION",
                    title="USB Staging and Process Execution Chain",
                    narrative=narrative,
                    timestamp_start=t1,
                    timestamp_end=t3 or t2,
                    confidence_score=confidence,
                    confidence_level=level,
                    evidence_event_ids=evidence_ids,
                    metadata={
                        "rule_id": "R7",
                        "timing_seconds": {"usb_to_file": d12, "file_to_exec": d23},
                        "anomalies": anomalies
                    },
                    evidence_links=links
                )
            )

        return activities

    # -------------------------------------------------------------------------
    # RULE R1: Device Arrives -> File Staged / Modified
    # -------------------------------------------------------------------------
    def _rule_r1_device_file_staging(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R1: Device arrives, then a file is created or modified on that drive (window: 300s).
        """
        cfg = self.get_rule_cfg("R1")
        if cfg.get("enabled", True) is False:
            return []

        window_sec = cfg.get("window_seconds", 300)
        base_confidence = cfg.get("base_confidence", 0.70)
        activities = []
        n = len(events)

        for i in range(n):
            e1 = events[i]
            if e1.get_canonical_source() != "usb" or e1.get_canonical_action() != "DEVICE_ARRIVED":
                continue

            usb_drive = _extract_drive_letter(e1.entity)
            staged_events: List[EventRecord] = []

            for j in range(i + 1, n):
                e2 = events[j]
                delta = (e2.timestamp - e1.timestamp).total_seconds()
                if delta > window_sec:
                    break

                if e2.get_canonical_source() == "fs" and e2.get_canonical_action() in ("FILE_CREATED", "FILE_MODIFIED"):
                    fs_drive = _extract_drive_letter(e2.entity)
                    if usb_drive and fs_drive and usb_drive != fs_drive:
                        continue
                    staged_events.append(e2)

            if not staged_events:
                continue

            first_fs = staged_events[0]
            last_fs = staged_events[-1]
            d = (first_fs.timestamp - e1.timestamp).total_seconds()

            links = [
                {
                    "event_id": e1.id,
                    "rule_id": "R1",
                    "reason": f"Removable volume arrival on {e1.entity}."
                }
            ]
            for fs_ev in staged_events[:5]:  # limit links to first 5
                links.append({
                    "event_id": fs_ev.id,
                    "rule_id": "R1",
                    "reason": f"File write activity on removable media: {fs_ev.entity} ({fs_ev.action})."
                })

            narrative = (
                f"[Event #{e1.id}] Removable device {e1.entity} was connected at {e1.timestamp.strftime('%H:%M:%S')}. "
                f"[Event #{first_fs.id}] File write activity began {d:.1f}s later on target {first_fs.entity}."
            )
            if len(staged_events) > 1:
                narrative += f" A total of {len(staged_events)} file operations were recorded on this volume."

            activities.append(
                ActivityCreate(
                    rule_name="R1_DEVICE_FILE_STAGING",
                    title="Removable Storage File Staging",
                    narrative=narrative,
                    timestamp_start=e1.timestamp,
                    timestamp_end=last_fs.timestamp,
                    confidence_score=base_confidence,
                    confidence_level="MEDIUM" if base_confidence < 0.75 else "HIGH",
                    evidence_event_ids=[e1.id] + [ev.id for ev in staged_events],
                    metadata={"rule_id": "R1", "files_staged": len(staged_events)},
                    evidence_links=links
                )
            )

        return activities

    # -------------------------------------------------------------------------
    # RULE R2: File Created -> Process Execution
    # -------------------------------------------------------------------------
    def _rule_r2_file_execution(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R2: File created, then a process starts from that same path (window: 600s).
        """
        cfg = self.get_rule_cfg("R2")
        if cfg.get("enabled", True) is False:
            return []

        window_sec = cfg.get("window_seconds", 600)
        base_confidence = cfg.get("base_confidence", 0.75)
        activities = []
        n = len(events)

        for i in range(n):
            e1 = events[i]
            if e1.get_canonical_source() != "fs" or e1.get_canonical_action() not in ("FILE_CREATED", "FILE_MODIFIED"):
                continue

            target_path = e1.entity.lower()
            file_name = os.path.basename(target_path)
            # Only track executable extensions to minimize noise
            if not any(file_name.endswith(ext) for ext in (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll")):
                continue

            for j in range(i + 1, n):
                e2 = events[j]
                delta = (e2.timestamp - e1.timestamp).total_seconds()
                if delta > window_sec:
                    break

                if e2.get_canonical_source() == "eventlog" and e2.get_canonical_action() == "PROCESS_STARTED":
                    exec_cmd = e2.entity.lower()
                    if file_name in exec_cmd or target_path in exec_cmd:
                        narrative = (
                            f"[Event #{e1.id}] Binary file {e1.entity} was created at {e1.timestamp.strftime('%H:%M:%S')}. "
                            f"[Event #{e2.id}] Process execution was launched from that path {delta:.1f}s later ({e2.entity})."
                        )
                        links = [
                            {
                                "event_id": e1.id,
                                "rule_id": "R2",
                                "reason": f"Executable file written to disk: {e1.entity}."
                            },
                            {
                                "event_id": e2.id,
                                "rule_id": "R2",
                                "reason": f"Windows Event 4688 confirms execution of staged binary {e2.entity}."
                            }
                        ]
                        activities.append(
                            ActivityCreate(
                                rule_name="R2_FILE_CREATION_EXECUTION",
                                title="Staged File Execution",
                                narrative=narrative,
                                timestamp_start=e1.timestamp,
                                timestamp_end=e2.timestamp,
                                confidence_score=base_confidence,
                                confidence_level="HIGH" if base_confidence >= 0.75 else "MEDIUM",
                                evidence_event_ids=[e1.id, e2.id],
                                metadata={"rule_id": "R2", "file": e1.entity, "delta_seconds": delta},
                                evidence_links=links
                            )
                        )
                        break

        return activities

    # -------------------------------------------------------------------------
    # RULE R3: Direct Removable Execution (Without Prior Write)
    # -------------------------------------------------------------------------
    def _rule_r3_direct_removable_execution(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R3: A process starts from a removable drive with no earlier write seen (window: 600s).
        """
        cfg = self.get_rule_cfg("R3")
        if cfg.get("enabled", True) is False:
            return []

        window_sec = cfg.get("window_seconds", 600)
        base_confidence = cfg.get("base_confidence", 0.80)
        activities = []
        n = len(events)

        # Track active removable drive letters from USB events
        removable_drives = set()
        for e in events:
            if e.get_canonical_source() == "usb" and e.get_canonical_action() == "DEVICE_ARRIVED":
                dl = _extract_drive_letter(e.entity)
                if dl:
                    removable_drives.add(dl)

        for i in range(n):
            e = events[i]
            if e.get_canonical_source() == "eventlog" and e.get_canonical_action() == "PROCESS_STARTED":
                dl = _extract_drive_letter(e.entity)
                # Removable drive execution or explicit non-C: removable drive
                if dl and dl in removable_drives:
                    # Look back to see if a file write event occurred
                    prior_write = False
                    for j in range(max(0, i - 50), i):
                        past_ev = events[j]
                        if past_ev.get_canonical_source() == "fs" and past_ev.get_canonical_action() in ("FILE_CREATED", "FILE_MODIFIED"):
                            if _extract_drive_letter(past_ev.entity) == dl:
                                prior_write = True
                                break

                    if not prior_write:
                        narrative = (
                            f"[Event #{e.id}] Process {e.entity} was launched directly from removable storage ({dl}) "
                            f"without any preceding local file creation or write detected in the audit window."
                        )
                        links = [{
                            "event_id": e.id,
                            "rule_id": "R3",
                            "reason": f"Direct process spawn from removable volume {dl}."
                        }]
                        activities.append(
                            ActivityCreate(
                                rule_name="R3_DIRECT_REMOVABLE_EXECUTION",
                                title="Direct Execution from Removable Drive",
                                narrative=narrative,
                                timestamp_start=e.timestamp,
                                timestamp_end=e.timestamp,
                                confidence_score=base_confidence,
                                confidence_level="HIGH",
                                evidence_event_ids=[e.id],
                                metadata={"rule_id": "R3", "drive": dl},
                                evidence_links=links
                            )
                        )

        return activities

    # -------------------------------------------------------------------------
    # RULE R4: Bulk Copy to Removable Drive
    # -------------------------------------------------------------------------
    def _rule_r4_bulk_copy(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R4: Many files created on a removable drive in a short burst (window: 60s, threshold: >= 5).
        """
        cfg = self.get_rule_cfg("R4")
        if cfg.get("enabled", True) is False:
            return []

        window_sec = cfg.get("window_seconds", 60)
        threshold_count = cfg.get("count_threshold", 5)
        base_confidence = cfg.get("base_confidence", 0.85)
        activities = []
        n = len(events)

        processed_indices = set()

        for i in range(n):
            if i in processed_indices:
                continue

            e1 = events[i]
            if e1.get_canonical_source() != "fs" or e1.get_canonical_action() not in ("FILE_CREATED", "FILE_MODIFIED"):
                continue

            dl = _extract_drive_letter(e1.entity)
            if not dl or dl == "C:":
                continue

            cluster = [e1]
            cluster_indices = [i]

            for j in range(i + 1, n):
                e2 = events[j]
                if (e2.timestamp - e1.timestamp).total_seconds() > window_sec:
                    break
                if e2.get_canonical_source() == "fs" and e2.get_canonical_action() in ("FILE_CREATED", "FILE_MODIFIED"):
                    if _extract_drive_letter(e2.entity) == dl:
                        cluster.append(e2)
                        cluster_indices.append(j)

            if len(cluster) >= threshold_count:
                processed_indices.update(cluster_indices)
                first_ev = cluster[0]
                last_ev = cluster[-1]
                duration = (last_ev.timestamp - first_ev.timestamp).total_seconds()

                links = []
                for ev in cluster:
                    links.append({
                        "event_id": ev.id,
                        "rule_id": "R4",
                        "reason": f"Bulk file write on removable media: {ev.entity}."
                    })

                narrative = (
                    f"Rapid bulk copy detected on removable storage volume ({dl}): "
                    f"{len(cluster)} files were staged between {first_ev.timestamp.strftime('%H:%M:%S')} "
                    f"and {last_ev.timestamp.strftime('%H:%M:%S')} (within {duration:.1f}s). "
                    f"First file created: [Event #{first_ev.id}] {first_ev.entity}. "
                    f"Last file created: [Event #{last_ev.id}] {last_ev.entity}."
                )

                activities.append(
                    ActivityCreate(
                        rule_name="R4_BULK_REMOVABLE_COPY",
                        title="Rapid Bulk File Copy to Removable Drive",
                        narrative=narrative,
                        timestamp_start=first_ev.timestamp,
                        timestamp_end=last_ev.timestamp,
                        confidence_score=base_confidence,
                        confidence_level="HIGH",
                        evidence_event_ids=[ev.id for ev in cluster],
                        metadata={"rule_id": "R4", "file_count": len(cluster), "drive": dl, "duration_sec": duration},
                        evidence_links=links
                    )
                )

        return activities

    # -------------------------------------------------------------------------
    # RULE R5: Log Cleared Near Activity (Possible Cover-up)
    # -------------------------------------------------------------------------
    def _rule_r5_log_cleared_coverup(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R5: Event 1102 or 104 occurring within 10 min of file or USB activity.
        """
        cfg = self.get_rule_cfg("R5")
        if cfg.get("enabled", True) is False:
            return []

        window_sec = cfg.get("window_seconds", 600)
        base_confidence = cfg.get("base_confidence", 0.90)
        activities = []
        n = len(events)

        for i in range(n):
            e = events[i]
            if e.get_canonical_source() != "eventlog" or e.get_canonical_action() != "LOG_CLEARED":
                continue

            # Look backwards for proximate file or USB operations
            supporting_events = []
            for j in range(max(0, i - 100), i):
                past_ev = events[j]
                delta = (e.timestamp - past_ev.timestamp).total_seconds()
                if 0 <= delta <= window_sec:
                    if past_ev.get_canonical_source() in ("fs", "usb", "eventlog") and past_ev.id != e.id:
                        supporting_events.append(past_ev)

            links = [{
                "event_id": e.id,
                "rule_id": "R5",
                "reason": f"Audit log clear event observed: {e.entity}."
            }]
            for sup in supporting_events[-4:]:  # cite up to 4 recent operations
                links.append({
                    "event_id": sup.id,
                    "rule_id": "R5",
                    "reason": f"Prior endpoint activity prior to log clearing: [{sup.source.upper()}] {sup.entity}."
                })

            ev_ids = [e.id] + [s.id for s in supporting_events[-4:]]
            if supporting_events:
                last_sup = supporting_events[-1]
                delta_sec = (e.timestamp - last_sup.timestamp).total_seconds()
                narrative = (
                    f"[Event #{e.id}] Windows audit log was cleared ({e.entity}) at {e.timestamp.strftime('%H:%M:%S')}. "
                    f"This anti-forensic action occurred {delta_sec:.1f}s after prior host activity "
                    f"([Event #{last_sup.id}] {last_sup.entity}), indicating intentional evidence destruction."
                )
            else:
                narrative = (
                    f"[Event #{e.id}] Windows audit log was cleared ({e.entity}) at {e.timestamp.strftime('%H:%M:%S')}. "
                    f"Direct administrative erasure of forensic logs."
                )

            activities.append(
                ActivityCreate(
                    rule_name="R5_LOG_CLEARED_COVERUP",
                    title="Audit Log Cleared Following Suspicious Activity",
                    narrative=narrative,
                    timestamp_start=supporting_events[0].timestamp if supporting_events else e.timestamp,
                    timestamp_end=e.timestamp,
                    confidence_score=base_confidence,
                    confidence_level="HIGH",
                    evidence_event_ids=ev_ids,
                    metadata={"rule_id": "R5", "channel": e.entity},
                    evidence_links=links
                )
            )

        return activities

    # -------------------------------------------------------------------------
    # RULE R6: Timestamp Disagreement (Timestomping / Clock Skew)
    # -------------------------------------------------------------------------
    def _rule_r6_timestamp_disagreement(self, events: List[EventRecord]) -> List[ActivityCreate]:
        """
        R6: File's modified time differs from when the agent saw the event by > threshold (120s).
        """
        cfg = self.get_rule_cfg("R6")
        if cfg.get("enabled", True) is False:
            return []

        threshold_sec = cfg.get("threshold_seconds", 120)
        base_confidence = cfg.get("base_confidence", 0.80)
        activities = []

        for e in events:
            if e.get_canonical_source() != "fs":
                continue

            # Check details or raw_data for mtime
            mtime_str = (
                (e.details and e.details.get("mtime"))
                or (e.raw_data and e.raw_data.get("mtime"))
            )
            if not mtime_str:
                continue

            try:
                mtime_dt = datetime.fromisoformat(str(mtime_str).replace("Z", "+00:00"))
            except Exception:
                continue

            diff_sec = abs((e.timestamp - mtime_dt).total_seconds())
            if diff_sec > threshold_sec:
                narrative = (
                    f"[Event #{e.id}] Forensic timestamp anomaly on file {e.entity}: "
                    f"Agent observed event at {e.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}, "
                    f"but file metadata modified timestamp was recorded as {mtime_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                    f"(divergence of {diff_sec:.1f}s). Indicates potential timestomping or clock tampering."
                )
                links = [{
                    "event_id": e.id,
                    "rule_id": "R6",
                    "reason": f"Discrepancy of {diff_sec:.1f}s between filesystem mtime and agent collection timestamp."
                }]

                activities.append(
                    ActivityCreate(
                        rule_name="R6_TIMESTAMP_DISAGREEMENT",
                        title="File Timestamp Inconsistency (Timestomping / Clock Skew)",
                        narrative=narrative,
                        timestamp_start=min(e.timestamp, mtime_dt),
                        timestamp_end=max(e.timestamp, mtime_dt),
                        confidence_score=base_confidence,
                        confidence_level="HIGH",
                        evidence_event_ids=[e.id],
                        metadata={
                            "rule_id": "R6",
                            "divergence_seconds": diff_sec,
                            "observed_time": e.timestamp.isoformat(),
                            "mtime": mtime_dt.isoformat()
                        },
                        evidence_links=links
                    )
                )

        return activities
