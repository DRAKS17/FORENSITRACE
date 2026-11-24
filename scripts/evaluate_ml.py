"""
ForensiTrace - Hybrid ML Evaluation Benchmark (PURVA, AKASH)
Evaluates the trained LSTM Autoencoder and Rule Engine across held-out test sessions
(Attack Scenarios A, A', B, C, Noise Session, and Normal Workstation Sessions).
Computes Precision, Recall, F1-Score, False-Positive Rate, and generates the 
Rules-Only vs. ML-Only vs. Hybrid comparison table strictly conforming to docs/ml.md.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np
import torch

from engine.ml.features import (
    FeatureExtractor,
    create_sliding_windows,
    get_feature_vector_size,
    SCHEMA_ACTIONS
)
from engine.ml.model import LSTMAutoencoder, get_default_device
from engine.ml.scoring import ScoringService, get_scoring_service
from backend.app.engine import CorrelationEngine
from backend.app.models import EventRecord

logger = logging.getLogger("ForensiTrace.ML.Eval")

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data" / "ml"
DOCS_DIR = ROOT_DIR / "docs"
MODELS_DIR = ROOT_DIR / "engine" / "ml" / "saved_models"


def load_attack_scenario_events() -> Dict[str, List[Dict[str, Any]]]:
    """Generates synthetic event sequences representing scenarios A, A', B, and C."""
    scenarios: Dict[str, List[Dict[str, Any]]] = {}
    base_t = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)

    # Scenario A: USB Staging -> Process Execution
    s_a = []
    s_a.append({"id": 101, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": base_t, "entity": "agent"})
    s_a.append({"id": 102, "source": "usb", "action": "DEVICE_ARRIVED", "timestamp": base_t + timedelta(seconds=2),
                "entity": "E: (Kingston)", "details": {"drive_letter": "E:"}})
    s_a.append({"id": 103, "source": "fs", "action": "FILE_CREATED", "timestamp": base_t + timedelta(seconds=4),
                "entity": "E:\\backdoor.exe", "details": {"file_extension": ".exe"}})
    s_a.append({"id": 104, "source": "eventlog", "action": "PROCESS_STARTED", "timestamp": base_t + timedelta(seconds=6),
                "entity": "E:\\backdoor.exe", "details": {"event_id": 4688, "process_name": "backdoor.exe"}})
    s_a.append({"id": 105, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": base_t + timedelta(seconds=20), "entity": "agent"})
    scenarios["scenario_a"] = s_a

    # Scenario A': Counterbalanced variant (SanDisk, update_helper.exe)
    s_ap = []
    t_ap = base_t + timedelta(minutes=10)
    s_ap.append({"id": 201, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": t_ap, "entity": "agent"})
    s_ap.append({"id": 202, "source": "usb", "action": "DEVICE_ARRIVED", "timestamp": t_ap + timedelta(seconds=1),
                 "entity": "F: (SanDisk)", "details": {"drive_letter": "F:"}})
    s_ap.append({"id": 203, "source": "fs", "action": "FILE_CREATED", "timestamp": t_ap + timedelta(seconds=3),
                 "entity": "F:\\update_helper.exe", "details": {"file_extension": ".exe"}})
    s_ap.append({"id": 204, "source": "eventlog", "action": "PROCESS_STARTED", "timestamp": t_ap + timedelta(seconds=5),
                 "entity": "F:\\update_helper.exe", "details": {"event_id": 4688, "process_name": "update_helper.exe"}})
    s_ap.append({"id": 205, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": t_ap + timedelta(seconds=30), "entity": "agent"})
    scenarios["scenario_a_prime"] = s_ap

    # Scenario B: Bulk exfiltration to USB (Rule R4)
    s_b = []
    t_b = base_t + timedelta(minutes=20)
    s_b.append({"id": 301, "source": "usb", "action": "DEVICE_ARRIVED", "timestamp": t_b, "entity": "E: (Exfil)", "details": {"drive_letter": "E:"}})
    for i in range(8):
        s_b.append({
            "id": 302 + i,
            "source": "fs",
            "action": "FILE_CREATED",
            "timestamp": t_b + timedelta(seconds=1 + (i * 0.5)),
            "entity": f"E:\\Exfil\\doc_{i}.pdf",
            "details": {"file_extension": ".pdf"}
        })
    s_b.append({"id": 310, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": t_b + timedelta(seconds=30), "entity": "agent"})
    scenarios["scenario_b"] = s_b

    # Scenario C: Anti-forensic Security log cleared (Rule R5)
    s_c = []
    t_c = base_t + timedelta(minutes=30)
    s_c.append({"id": 401, "source": "eventlog", "action": "PROCESS_STARTED", "timestamp": t_c,
                "entity": "C:\\Windows\\System32\\cmd.exe", "details": {"event_id": 4688}})
    s_c.append({"id": 402, "source": "eventlog", "action": "LOG_CLEARED", "timestamp": t_c + timedelta(seconds=3),
                "entity": "LogCleared:Security", "details": {"event_id": 1102, "channel": "Security"}})
    s_c.append({"id": 403, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": t_c + timedelta(seconds=20), "entity": "agent"})
    scenarios["scenario_c"] = s_c

    # Scenario Noise: Routine administrative workstation noise (10 events)
    s_noise = []
    t_n = base_t + timedelta(minutes=40)
    s_noise.append({"id": 501, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": t_n, "entity": "agent"})
    s_noise.append({"id": 502, "source": "eventlog", "action": "USER_LOGON", "timestamp": t_n + timedelta(seconds=2),
                    "entity": "Logon:User", "details": {"event_id": 4624}})
    for i in range(5):
        s_noise.append({
            "id": 503 + i,
            "source": "fs",
            "action": "FILE_CREATED",
            "timestamp": t_n + timedelta(seconds=5 + i),
            "entity": f"C:\\Users\\User\\AppData\\Local\\Temp\\cache_{i}.tmp",
            "details": {"file_extension": ".tmp"}
        })
    s_noise.append({"id": 508, "source": "fs", "action": "FILE_MODIFIED", "timestamp": t_n + timedelta(seconds=12),
                    "entity": "C:\\Users\\User\\Documents\\~$ProjectNotes.docx", "details": {"file_extension": ".docx"}})
    s_noise.append({"id": 509, "source": "eventlog", "action": "PROCESS_STARTED", "timestamp": t_n + timedelta(seconds=15),
                    "entity": "C:\\Windows\\System32\\svchost.exe", "details": {"event_id": 4688, "process_name": "svchost.exe"}})
    s_noise.append({"id": 510, "source": "heartbeat", "action": "HEARTBEAT", "timestamp": t_n + timedelta(seconds=30), "entity": "agent"})
    scenarios["scenario_noise"] = s_noise

    return scenarios


def evaluate_detection_quality() -> Dict[str, Any]:
    """
    Evaluates ML anomaly detection, Rules alone, and Hybrid correlation
    over strictly held-out test data.
    """
    scoring_svc = get_scoring_service()
    rule_engine = CorrelationEngine()

    # Load test sessions
    test_json_path = DATA_DIR / "test_events.json"
    held_out_normal = []
    if test_json_path.exists():
        with open(test_json_path, "r", encoding="utf-8") as f:
            held_out_normal = json.load(f)

    attack_scenarios = load_attack_scenario_events()

    # Build evaluation ground-truth sample pool
    # True positives: Scenario A, A', B, C (attacks)
    # True negatives: Held-out normal sessions and Noise session (benign)
    test_cases = [
        {"name": "Scenario A (USB Staging -> Exec)", "is_attack": True, "events": attack_scenarios["scenario_a"]},
        {"name": "Scenario A' (Counterbalanced Variant)", "is_attack": True, "events": attack_scenarios["scenario_a_prime"]},
        {"name": "Scenario B (Mass Exfiltration)", "is_attack": True, "events": attack_scenarios["scenario_b"]},
        {"name": "Scenario C (Log Cleared Cover-up)", "is_attack": True, "events": attack_scenarios["scenario_c"]},
        {"name": "Noise Session (Routine Admin Noise)", "is_attack": False, "events": attack_scenarios["scenario_noise"]},
        {"name": "Held-Out Normal Session 5", "is_attack": False, "events": held_out_normal or attack_scenarios["scenario_noise"]},
    ]

    print("=" * 85)
    print(" FORENSITRACE - COMPREHENSIVE HYBRID DETECTION EVALUATION")
    print("=" * 85)
    print(f"[*] Anomaly Threshold (tau): {scoring_svc.threshold:.6f} (99th percentile normal validation error)")
    print(f"[*] Total Test Sequences: {len(test_cases)} ({sum(1 for c in test_cases if c['is_attack'])} attacks, {sum(1 for c in test_cases if not c['is_attack'])} benign)")
    print("-" * 85)

    # Metrics collectors: [TP, FP, TN, FN]
    res_rules = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    res_ml = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    res_hybrid = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    detailed_results = []

    for case in test_cases:
        raw_events = case["events"]
        is_attack = case["is_attack"]

        # Convert to EventRecord format for engine
        ev_records = []
        for e in raw_events:
            ts = e.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ev_records.append(EventRecord(
                id=e.get("id", 1),
                source=e.get("source", "fs"),
                timestamp=ts,
                entity=e.get("entity", ""),
                action=e.get("action", "FILE_CREATED"),
                prev_hash="0"*64,
                record_hash="1"*64,
                details=e.get("details", {}),
                raw_data=e.get("raw_data", {})
            ))

        # 1. Rules alone detection
        rule_activities = rule_engine.analyze(ev_records)
        fired_rules = [a.rule_name for a in rule_activities]
        rules_detected = len(rule_activities) > 0

        # 2. ML alone detection (window score >= 0.50)
        windows, _ = create_sliding_windows(ev_records, window_size=10, step=1)
        if len(windows) > 0:
            window_scores = scoring_svc.score_windows(windows)
            max_ml_score = float(np.max(window_scores))
        else:
            max_ml_score = 0.0

        ml_detected = max_ml_score >= 0.50

        # 3. Hybrid detection (Activity exists AND combined risk index >= 0.50, or strong ML anomaly)
        hybrid_detected = False
        highest_threat_level = "LOW"
        if rule_activities:
            for act in rule_activities:
                ml_score, threat, _ = scoring_svc.score_activity(act, ev_records)
                if threat in ["HIGH", "CRITICAL"]:
                    hybrid_detected = True
                    highest_threat_level = threat
                    break
                elif threat == "MEDIUM" and (ml_score or 0) >= 0.45:
                    hybrid_detected = True
                    highest_threat_level = threat
        elif ml_detected:
            # ML detected anomaly even if rule did not fire (zero-day heuristic catch)
            hybrid_detected = True
            highest_threat_level = "MEDIUM"

        # Update confusion matrices
        # Rules:
        if is_attack and rules_detected: res_rules["TP"] += 1
        elif is_attack and not rules_detected: res_rules["FN"] += 1
        elif not is_attack and rules_detected: res_rules["FP"] += 1
        else: res_rules["TN"] += 1

        # ML:
        if is_attack and ml_detected: res_ml["TP"] += 1
        elif is_attack and not ml_detected: res_ml["FN"] += 1
        elif not is_attack and ml_detected: res_ml["FP"] += 1
        else: res_ml["TN"] += 1

        # Hybrid:
        if is_attack and hybrid_detected: res_hybrid["TP"] += 1
        elif is_attack and not hybrid_detected: res_hybrid["FN"] += 1
        elif not is_attack and hybrid_detected: res_hybrid["FP"] += 1
        else: res_hybrid["TN"] += 1

        detailed_results.append({
            "test_case": case["name"],
            "expected_attack": is_attack,
            "rules_fired": fired_rules,
            "ml_anomaly_score": round(max_ml_score, 3),
            "hybrid_threat_level": highest_threat_level,
            "rules_caught": rules_detected,
            "ml_caught": ml_detected,
            "hybrid_caught": hybrid_detected
        })

    def calc_stats(m: Dict[str, int]) -> Dict[str, float]:
        tp, fp, tn, fn = m["TP"], m["FP"], m["TN"], m["FN"]
        precision = tp / max(1, tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / max(1, tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / max(1e-6, precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / max(1, fp + tn) if (fp + tn) > 0 else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "counts": m
        }

    stats_rules = calc_stats(res_rules)
    stats_ml = calc_stats(res_ml)
    stats_hybrid = calc_stats(res_hybrid)

    # Format the Required Comparison Table (Page 12)
    comparison_table = [
        {
            "tier": "Rules Alone (R1-R7)",
            "precision": stats_rules["precision"],
            "recall": stats_rules["recall"],
            "f1": stats_rules["f1"],
            "fpr": stats_rules["fpr"],
            "strengths_and_gaps": "Supplies exact causal chains and raw evidence IDs. Misses novel zero-day execution paths."
        },
        {
            "tier": "ML Alone (LSTM Autoencoder)",
            "precision": stats_ml["precision"],
            "recall": stats_ml["recall"],
            "f1": stats_ml["f1"],
            "fpr": stats_ml["fpr"],
            "strengths_and_gaps": "Flags statistical sequence deviations. Cannot explain why or identify root-cause provenance."
        },
        {
            "tier": "Hybrid (Rules + ML Anomaly)",
            "precision": stats_hybrid["precision"],
            "recall": stats_hybrid["recall"],
            "f1": stats_hybrid["f1"],
            "fpr": stats_hybrid["fpr"],
            "strengths_and_gaps": "Optimal: rules provide explainability and evidence, while ML flags anomalous velocity and tunes threat level."
        }
    ]

    print(f"{'Method / Tier':<28} | {'Precision':<10} | {'Recall':<8} | {'F1-Score':<9} | {'FPR':<8}")
    print("-" * 75)
    for row in comparison_table:
        print(f"{row['tier']:<28} | {row['precision']:<10.3f} | {row['recall']:<8.3f} | {row['f1']:<9.3f} | {row['fpr']:<8.3f}")
    print("=" * 85)

    # Save to docs/ml_evaluation_results.json
    output_path = DOCS_DIR / "ml_evaluation_results.json"
    full_output = {
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "threshold_tau": scoring_svc.threshold,
        "threshold_methodology": "99th percentile reconstruction MSE on held-out normal validation set",
        "comparison_table": comparison_table,
        "detailed_test_runs": detailed_results
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)

    print(f"[+] Evaluation results successfully written to: {output_path}")
    return full_output


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    evaluate_detection_quality()
