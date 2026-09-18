from fastapi import APIRouter, HTTPException
from typing import List
from backend.app.models import EventCreate, EventRecord
from backend.app.database import EvidenceStore
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
store = EvidenceStore()

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
