from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.app.models import EventCreate, EventRecord, ActivityCreate, ActivityRecord
from backend.app.database import EvidenceStore
from backend.app.engine import CorrelationEngine
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
store = EvidenceStore()
engine = CorrelationEngine()

@router.post("/api/v1/events", response_model=EventRecord)
def create_event(event: EventCreate):
    try:
        record = store.insert_event(event)
        return record
    except Exception as e:
        logger.error(f"Failed to insert event: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/api/v1/events", response_model=List[EventRecord])
def get_events(limit: int = 100, offset: int = 0):
    try:
        records = store.get_events(limit=limit, offset=offset)
        return records
    except Exception as e:
        logger.error(f"Failed to fetch events: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/api/v1/integrity")
def check_integrity():
    try:
        is_intact, tampered_id = store.verify_integrity()
        return {"intact": is_intact, "tampered_id": tampered_id}
    except Exception as e:
        logger.error(f"Failed to verify integrity: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post("/api/v1/correlate", response_model=List[ActivityRecord])
def run_correlation():
    try:
        # In a production system, we would maintain a cursor or only fetch un-analyzed events.
        # For simplicity, we fetch recent events.
        events = store.get_events(limit=1000)
        activities = engine.analyze(events)
        
        saved_records = []
        for act in activities:
            record = store.insert_activity(act)
            saved_records.append(record)
            
        return saved_records
    except Exception as e:
        logger.error(f"Failed to run correlation engine: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/api/v1/activities", response_model=List[ActivityRecord])
def get_activities(confidence_level: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, or HIGH")):
    try:
        records = store.get_activities(limit=500)
        if confidence_level:
            records = [r for r in records if r.confidence_level.upper() == confidence_level.upper()]
        return records
    except Exception as e:
        logger.error(f"Failed to fetch activities: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/api/v1/activities/{activity_id}/evidence", response_model=List[EventRecord])
def get_activity_evidence(activity_id: int):
    try:
        evidence = store.get_activity_evidence(activity_id)
        if not evidence:
            raise HTTPException(status_code=404, detail="Activity not found or has no evidence")
        return evidence
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch activity evidence: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/api/v1/metrics")
def get_metrics():
    try:
        events = store.get_events(limit=1000)
        heartbeats = [e for e in events if e.source == "heartbeat"]
        if not heartbeats:
            return {"avg_cpu_percent": 0.0, "avg_memory_mb": 0.0, "samples": 0}
            
        total_cpu = sum(float(hb.raw_data.get("cpu_percent", 0.0)) for hb in heartbeats)
        total_mem = sum(float(hb.raw_data.get("memory_mb", 0.0)) for hb in heartbeats)
        
        count = len(heartbeats)
        return {
            "avg_cpu_percent": round(total_cpu / count, 2),
            "avg_memory_mb": round(total_mem / count, 2),
            "samples": count
        }
    except Exception as e:
        logger.error(f"Failed to calculate metrics: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

