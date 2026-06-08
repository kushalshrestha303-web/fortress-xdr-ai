"""Threat hunting endpoints"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.threat_hunter import ThreatHunter, QueryType
from app.services.detection_engine import DetectionEngine

class HuntQuery(BaseModel):
    """Hunt query request"""
    query_type: str  # kql, sigma, yara, natural_language, opensearch, wazuh
    query: str
    timeframe: str = "24h"
    limit: int = 100

class HuntTemplate(BaseModel):
    """Hunt template selection"""
    template_name: str

router = APIRouter()
threat_hunter = ThreatHunter()
detection_engine = DetectionEngine()

@router.get("/hunts/templates")
async def list_hunt_templates(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List available hunt templates"""
    templates = threat_hunter.get_hunt_templates()
    
    return {
        "templates": [
            {
                "id": name,
                "name": template.get("name"),
                "description": template.get("description"),
                "tactics": template.get("tactics"),
                "mitre_techniques": template.get("mitre_techniques")
            }
            for name, template in templates.items()
        ],
        "total": len(templates)
    }

@router.get("/hunts/templates/{template_name}")
async def get_hunt_template(
    template_name: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific hunt template"""
    template = threat_hunter.get_hunt_template(template_name)
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    return template

@router.post("/hunts/execute")
async def execute_hunt(
    hunt_query: HuntQuery,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Execute threat hunt"""
    if hunt_query.query_type not in ["kql", "sigma", "yara", "natural_language", "opensearch", "wazuh"]:
        raise HTTPException(status_code=400, detail="Invalid query type")
    
    try:
        result = threat_hunter.execute_hunt(
            QueryType(hunt_query.query_type),
            hunt_query.query,
            hunt_query.timeframe
        )
        
        return {
            "hunt_id": "hunt_" + datetime.utcnow().strftime("%Y%m%d%H%M%S"),
            **result,
            "executed_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/hunts/template-execute")
async def execute_template_hunt(
    template_request: HuntTemplate,
    timeframe: str = Query("24h"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Execute pre-built hunt template"""
    template = threat_hunter.get_hunt_template(template_request.template_name)
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    # Execute KQL query from template
    result = threat_hunter.execute_hunt(
        QueryType.KQL,
        template["queries"]["kql"],
        timeframe
    )
    
    return {
        "hunt_id": "hunt_" + datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        "template_name": template_request.template_name,
        "template": template,
        **result,
        "executed_at": datetime.utcnow().isoformat()
    }

@router.get("/hunts/{hunt_id}/results")
async def get_hunt_results(
    hunt_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get hunt results"""
    # In production, fetch from database
    return {
        "hunt_id": hunt_id,
        "results": [],
        "status": "completed"
    }

@router.get("/detection-rules")
async def list_detection_rules(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all detection rules"""
    rules = detection_engine.get_all_rules()
    
    return {
        "rules": rules,
        "total": len(rules)
    }

@router.get("/detection-rules/{rule_id}")
async def get_detection_rule(
    rule_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific detection rule"""
    rule = detection_engine.get_rule(rule_id)
    
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return rule
