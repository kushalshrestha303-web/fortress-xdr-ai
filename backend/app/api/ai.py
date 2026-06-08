"""AI analysis endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.core.database import get_db
from app.core.security import get_current_user
import os

class AlertAnalysisRequest(BaseModel):
    alert_id: str
    include_mitre: bool = True
    include_recommendations: bool = True

class ChatMessage(BaseModel):
    message: str
    context: dict = {}

router = APIRouter()

@router.post("/ai/analyze-alert")
async def analyze_alert(
    request: AlertAnalysisRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze alert with AI"""
    return {
        "alert_id": request.alert_id,
        "analysis": {
            "classification": "Brute Force Attack",
            "explanation": "This alert indicates a brute force attack against RDP service with 50 failed login attempts in 5 minutes.",
            "severity": "Critical",
            "risk_score": 92,
            "mitre_techniques": ["T1110.001", "T1078.003"],
            "recommendations": [
                "Block source IP 192.168.1.100",
                "Enable account lockout policy",
                "Implement MFA for administrative accounts",
                "Review failed login attempts for credential harvesting"
            ]
        }
    }

@router.post("/ai/chat")
async def chat_with_ai(
    message: ChatMessage,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Chat with AI analyst"""
    return {
        "response": "Based on the alert data, this appears to be a brute force attack against your infrastructure. I recommend implementing rate limiting and MFA.",
        "suggestions": [
            "View similar alerts",
            "Generate incident report",
            "Create automated response"
        ]
    }
