"""
ForensiTrace - Backend REST API Endpoints (FastAPI)
Implements all ingestion, correlation, timeline, verification, and export routes.
Exposes both root and /api/v1/ path prefixes to fulfill docs/api.md.
"""

from datetime import datetime
import logging
import os
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import FileResponse

from backend.app.models import (
    EventCreate,
    EventRecord,
    ActivityCreate,
    ActivityRecord,
    ActivityDetail,
    TimelineItem,
)
from backend.app.database import EvidenceStore
from backend.app.engine import CorrelationEngine
from backend.app.report_generator import generate_activity_pdf

logger = logging.getLogger(__name__)

router = APIRouter()
store = EvidenceStore()
engine = CorrelationEngine()


# -----------------------------------------------------------------------------
# EVENT INGESTION & QUERY
# -----------------------------------------------------------------------------
@router.post("/events", response_model=Union[EventRecord, List[EventRecord]])
@router.post("/api/v1/events", response_model=Union[EventRecord, List[EventRecord]])
def ingest_events(payload: Union[EventCreate, List[EventCreate]] = Body(...)):
    """
    Ingests a single event or a batch of events from the endpoint agent.
    Appends to SQLite using the cryptographic SHA-256 hash chain with deduplication.
    """
    try:
        if isinstance(payload, list):
            records = store.insert_events_batch(payload)
            logger.info("Ingested batch of %d events.", len(records))
            return records
        else:
            record = store.insert_event(payload)
            logger.debug("Ingested single event: [%s] %s", record.source, record.entity)
            return record
    except Exception as e:
        logger.error("Failed to insert event(s): %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database insertion failed: {str(e)}")


@router.get("/events", response_model=List[EventRecord])
@router.get("/api/v1/events", response_model=List[EventRecord])
def get_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query(None, description="Filter by source channel (usb, fs, eventlog, heartbeat)")
):
    """Retrieves stored records chronologically with pagination and optional source filtering."""
    try:
        return store.get_events(limit=limit, offset=offset, source=source)
    except Exception as e:
        logger.error("Failed to fetch events: %s", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")


# -----------------------------------------------------------------------------
# CORRELATION & FORENSIC ACTIVITIES
# -----------------------------------------------------------------------------
@router.post("/correlate", response_model=List[ActivityRecord])
@router.post("/api/v1/correlate", response_model=List[ActivityRecord])
def run_correlation(limit: int = Query(1000, description="Number of recent events to analyze")):
    """
    Executes the rule-based CorrelationEngine over stored events.
    Persists newly identified activities and establishes provenance links in activity_events.
    """
    try:
        events = store.get_events(limit=limit)
        activities = engine.analyze(events)

        saved_records = []
        for act in activities:
            record = store.insert_activity(act)
            saved_records.append(record)

        logger.info("Correlation triggered: %d activities identified and stored.", len(saved_records))
        return saved_records
    except Exception as e:
        logger.error("Failed to run correlation engine: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Correlation analysis failed")


@router.get("/activities", response_model=List[ActivityRecord])
@router.get("/api/v1/activities", response_model=List[ActivityRecord])
def get_activities(
    confidence_level: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, or HIGH"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Returns reconstructed activities sorted newest first."""
    try:
        return store.get_activities(limit=limit, offset=offset, confidence_level=confidence_level)
    except Exception as e:
        logger.error("Failed to fetch activities: %s", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/activities/{activity_id}", response_model=ActivityDetail)
@router.get("/api/v1/activities/{activity_id}", response_model=ActivityDetail)
def get_activity_detail(activity_id: int):
    """
    Fetches full activity metadata including its linked evidence provenance and one-line reasons.
    """
    detail = store.get_activity_by_id(activity_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Activity not found")
    return detail


@router.get("/activities/{activity_id}/evidence", response_model=List[EventRecord])
@router.get("/api/v1/activities/{activity_id}/evidence", response_model=List[EventRecord])
def get_activity_evidence(activity_id: int):
    """Retrieves raw EventRecord items linked to the specified activity."""
    evidence = store.get_activity_evidence(activity_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Activity not found or has no evidence")
    return evidence


@router.get("/timeline")
@router.get("/api/v1/timeline")
def get_timeline(limit: int = Query(200, ge=1, le=1000)):
    """Unified chronological timeline of activities and key forensic events for UI rendering."""
    try:
        return store.get_timeline(limit=limit)
    except Exception as e:
        logger.error("Failed to fetch timeline: %s", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")


# -----------------------------------------------------------------------------
# INTEGRITY, METRICS, & REPORTING
# -----------------------------------------------------------------------------
@router.get("/integrity")
@router.get("/api/v1/integrity")
def check_integrity():
    """
    Audits the entire SHA-256 cryptographic hash chain sequentially.
    Guarantees non-repudiation and detects data tampering.
    """
    try:
        is_intact, tampered_id = store.verify_integrity()
        events = store.get_events(limit=1)
        total_count = len(store.get_events(limit=10000))
        return {
            "intact": is_intact,
            "tampered_id": tampered_id,
            "total_records": total_count,
            "status": "VERIFIED" if is_intact else "COMPROMISED"
        }
    except Exception as e:
        logger.error("Failed to verify integrity: %s", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/metrics")
@router.get("/api/v1/metrics")
def get_metrics():
    """Calculates agent performance overhead (CPU % and RAM MB) from recent heartbeats."""
    try:
        events = store.get_events(limit=1000, source="heartbeat")
        if not events:
            # Check if any heartbeat was recorded with legacy name
            events = [e for e in store.get_events(limit=1000) if e.get_canonical_source() == "heartbeat"]

        if not events:
            return {"avg_cpu_percent": 0.0, "avg_memory_mb": 0.0, "samples": 0}

        total_cpu = 0.0
        total_mem = 0.0
        valid_samples = 0

        for hb in events:
            data = hb.details or hb.raw_data
            cpu = float(data.get("cpu_percent", 0.0))
            mem = float(data.get("memory_mb", 0.0))
            total_cpu += cpu
            total_mem += mem
            valid_samples += 1

        count = max(1, valid_samples)
        return {
            "avg_cpu_percent": round(total_cpu / count, 2),
            "avg_memory_mb": round(total_mem / count, 2),
            "samples": count
        }
    except Exception as e:
        logger.error("Failed to calculate metrics: %s", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/report/{activity_id}")
@router.get("/api/v1/activities/{activity_id}/export")
def export_activity_pdf(activity_id: int):
    """Generates and downloads a formal forensic PDF report with cryptographic assurance."""
    try:
        detail = store.get_activity_by_id(activity_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Activity not found")

        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, f"ForensiTrace_Report_{activity_id}.pdf")

        is_intact, _ = store.verify_integrity()
        generate_activity_pdf(
            activity=detail.activity,
            evidence=[item["event"] for item in detail.evidence],
            filepath=pdf_path,
            provenance_links=detail.evidence,
            chain_verified=is_intact
        )

        return FileResponse(
            path=pdf_path,
            filename=f"ForensiTrace_Report_{activity_id}.pdf",
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="ForensiTrace_Report_{activity_id}.pdf"'}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to generate PDF export: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/api/v1/reset")
def reset_database():
    """Resets database state for fresh demo execution."""
    try:
        store.clear_database()
        return {"status": "ok", "message": "Database reset successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
