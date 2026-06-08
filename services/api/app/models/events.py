from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


Sector = Literal["government", "bank", "hospital", "telecom", "enterprise", "critical-infrastructure"]


class TelemetryEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    sector: Sector
    source: str
    event_type: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    mitre_techniques: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class NgfwDpi(BaseModel):
    tls_sni: str | None = None
    http_host: str | None = None
    file_type: str | None = None
    payload_sha256: str | None = None
    user_agent: str | None = None


class NgfwIps(BaseModel):
    signature: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    cve: str | None = None
    blocked: bool = True


class NgfwLog(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    sector: Sector
    sensor_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str
    application: str
    action: Literal["allowed", "blocked", "alerted", "quarantined"]
    rule_id: str | None = None
    policy_name: str | None = None
    dpi: NgfwDpi = Field(default_factory=NgfwDpi)
    ips: NgfwIps = Field(default_factory=NgfwIps)
    bytes_in: int = 0
    bytes_out: int = 0
    geo: dict[str, str] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)


class PlaybookRunRequest(BaseModel):
    tenant_id: str
    incident_id: str
    severity: Literal["low", "medium", "high", "critical"]
    sector: Sector
    notify_email: str | None = "xitizsthax@gmail.com"
    context: dict[str, Any] = Field(default_factory=dict)


class PlaybookApprovalRequest(BaseModel):
    approver: str
    decision: Literal["approved", "rejected"]
    comment: str | None = None
