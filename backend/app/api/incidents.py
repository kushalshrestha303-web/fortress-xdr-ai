"""Incident management endpoints"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.database import get_db
from app.core.security import get_current_user

router = APIRouter()

@router.get("/incidents")
async def list_incidents(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List security incidents"""
    return {
        "incidents": [
            {
                "id": "inc_001",
                "title": "Suspected Brute Force Attack",
                "status": "open",
                "severity": "critical",
                "created_at": datetime.utcnow().isoformat(),
                "alerts_count": 42
            }
        ]
    }

@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get incident details"""
    return {
        "id": incident_id,
        "title": "Suspected Brute Force Attack",
        "description": "Multiple failed login attempts detected",
        "status": "open",
        "severity": "critical",
        "created_at": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.100",
        "target_user": "admin",
        "failed_attempts": 50,
        "mitre_techniques": ["T1110", "T1078"],
        "recommendation": "Block source IP and enable MFA"
    }
