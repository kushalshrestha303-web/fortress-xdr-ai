"""Alert management endpoints"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from app.core.database import get_db
from app.core.security import get_current_user

router = APIRouter()

@router.get("/alerts")
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    source: Optional[str] = None,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List security alerts with filtering"""
    # In production, query alerts from OpenSearch
    return {
        "alerts": [
            {
                "id": "alert_001",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "critical",
                "source": "wazuh",
                "rule_id": "86601",
                "message": "GPL ATTACK_RESPONSE id check"
            }
        ],
        "total": 1,
        "skip": skip,
        "limit": limit
    }

@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get alert details"""
    return {
        "id": alert_id,
        "timestamp": datetime.utcnow().isoformat(),
        "severity": "critical",
        "source": "wazuh",
        "source_ip": "192.168.1.100",
        "destination_ip": "203.0.113.5",
        "rule_id": "86601",
        "message": "GPL ATTACK_RESPONSE id check",
        "mitre_technique": "T1190",
        "risk_score": 85
    }
