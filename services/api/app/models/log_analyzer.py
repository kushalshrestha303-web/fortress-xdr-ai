from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class ParsedLogEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str = "UNKNOWN"
    info: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    raw: str


class DetectionFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    attack_type: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float
    source: str | None = None
    destination: str | None = None
    evidence: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)


class AttackDiagram(BaseModel):
    mermaid: str
    nodes: list[str]
    edges: list[dict[str, str]]


class AnalysisResult(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    upload_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    events: list[ParsedLogEvent]
    findings: list[DetectionFinding]
    summary: dict[str, Any]
    diagram: AttackDiagram
    charts: dict[str, Any]
    report: dict[str, Any]
