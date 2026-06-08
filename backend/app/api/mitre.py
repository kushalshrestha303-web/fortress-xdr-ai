"""MITRE ATT&CK mapping endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.mitre_mapper import MitreMapper

class AlertAnalysis(BaseModel):
    """Alert data for MITRE mapping"""
    process_name: str = None
    command_line: str = None
    event_type: str = None
    network: dict = None

router = APIRouter()
mitre_mapper = MitreMapper()

@router.post("/mitre/map-alert")
async def map_alert_to_mitre(
    alert: AlertAnalysis,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Map security alert to MITRE ATT&CK techniques"""
    alert_dict = alert.dict(exclude_none=True)
    techniques = mitre_mapper.map_alert_to_techniques(alert_dict)
    
    return {
        "alert": alert_dict,
        "mapped_techniques": techniques,
        "timestamp": datetime.utcnow().isoformat(),
        "count": len(techniques)
    }

@router.get("/mitre/techniques")
async def get_mitre_techniques(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all available MITRE ATT&CK techniques"""
    return {
        "techniques": mitre_mapper.technique_map,
        "total": len(mitre_mapper.technique_map)
    }

@router.get("/mitre/techniques/{technique_id}")
async def get_technique_details(
    technique_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get details for specific MITRE technique"""
    if technique_id not in mitre_mapper.technique_map:
        raise HTTPException(status_code=404, detail="Technique not found")
    
    technique = mitre_mapper.technique_map[technique_id]
    return {
        "id": technique_id,
        "name": technique.get("name"),
        "tactic": technique.get("tactic"),
        "subtechniques": technique.get("subtechniques", {}),
        "patterns": mitre_mapper.signature_patterns.get(technique_id, {})
    }

@router.post("/mitre/attack-chain")
async def get_attack_chain(
    techniques: List[str],
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get MITRE ATT&CK chain for multiple techniques"""
    chain = mitre_mapper.get_attack_chain(techniques)
    
    return {
        "input_techniques": techniques,
        "attack_chain": chain,
        "tactics_involved": [item["tactic"] for item in chain]
    }

@router.get("/mitre/dashboard")
async def get_mitre_dashboard(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get MITRE ATT&CK dashboard data"""
    # In production, this would aggregate real detection data
    return {
        "tactics_covered": [
            "initial-access", "execution", "persistence", 
            "privilege-escalation", "defense-evasion"
        ],
        "top_techniques": [
            {"id": "T1110", "name": "Brute Force", "detections": 42},
            {"id": "T1059.001", "name": "PowerShell", "detections": 28},
            {"id": "T1021.006", "name": "WinRM", "detections": 15},
        ],
        "coverage_percentage": 45,
        "total_techniques": len(mitre_mapper.technique_map)
    }
