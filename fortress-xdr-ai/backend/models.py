from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class WazuhConfig(BaseModel):
    indexer_url: str
    alert_index: str
    verify_ssl: bool
    mode: str


class WazuhAlert(BaseModel):
    id: str
    alert_source: str = "Wazuh"
    timestamp: str | None = None
    agent_name: str | None = None
    agent_id: str | None = None
    manager_name: str | None = None
    rule_id: str | None = None
    rule_level: int = 0
    rule_description: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    decoder_name: str | None = None
    full_log: str | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    srcip: str | None = None
    dstip: str | None = None
    user_name: str | None = None
    suricata_signature: str | None = None
    suricata_category: str | None = None
    suricata_severity: str | None = None
    suricata_protocol: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class AlertListResponse(BaseModel):
    source: str
    total: int
    alerts: list[WazuhAlert]


class HuntRequest(BaseModel):
    query: str | None = None
    preset: str | None = None
    size: int = Field(default=50, ge=1, le=200)


class HuntResponse(BaseModel):
    query: str
    source: str
    total: int
    alerts: list[WazuhAlert]


class TimelineEvent(BaseModel):
    timestamp: str | None
    alert_id: str
    agent_name: str | None
    rule_id: str | None
    rule_level: int
    summary: str


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    priority: str
    factors: list[str]


class InvestigationResult(BaseModel):
    alert_id: str
    created_at: datetime
    verdict: str
    classification: str
    alert_type: str
    confidence_label: str
    confidence: int = Field(ge=0, le=100)
    reasoning: dict[str, list[str]]
    analyst_narrative: str
    triage: dict[str, Any]
    evidence: dict[str, Any]
    mitre_mapping: list[dict[str, Any]]
    mitre_intelligence: list[dict[str, Any]]
    attack_chain: list[dict[str, Any]]
    timeline: list[TimelineEvent]
    related_alerts: list[WazuhAlert]
    risk: RiskScore
    recommended_containment: list[str]
    playbook: dict[str, list[str]]
    active_response_recommendations: list[str]
    executive_report: dict[str, Any]
    analyst_report: str
    executive_summary: str
    workflow_steps: list[dict[str, Any]]
