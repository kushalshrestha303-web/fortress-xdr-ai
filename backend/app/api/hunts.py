"""Threat hunting endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user

class HuntQuery(BaseModel):
    query_type: str  # kql, sigma, yara, natural_language
    query: str
    timeframe: str = "24h"
    limit: int = 100

router = APIRouter()

@router.post("/hunts/execute")
async def execute_hunt(
    hunt_query: HuntQuery,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Execute threat hunt"""
    if hunt_query.query_type not in ["kql", "sigma", "yara", "natural_language"]:
        raise HTTPException(status_code=400, detail="Invalid query type")
    
    return {
        "hunt_id": "hunt_001",
        "query": hunt_query.query,
        "query_type": hunt_query.query_type,
        "results": [
            {
                "event_id": "evt_001",
                "timestamp": datetime.utcnow().isoformat(),
                "process": "powershell.exe",
                "command_line": "powershell -Command Get-Process",
                "severity": "medium",
                "mitre_technique": "T1059"
            }
        ],
        "total_results": 1
    }
