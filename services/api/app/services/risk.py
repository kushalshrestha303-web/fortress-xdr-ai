from app.models.events import NgfwLog, TelemetryEvent


SEVERITY_POINTS = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}
SECTOR_MULTIPLIER = {
    "government": 1.15,
    "bank": 1.2,
    "hospital": 1.15,
    "telecom": 1.1,
    "critical-infrastructure": 1.25,
    "enterprise": 1.0,
}


def score_event(event: TelemetryEvent) -> int:
    base = SEVERITY_POINTS[event.severity]
    mitre_bonus = min(len(event.mitre_techniques) * 5, 20)
    return min(100, round((base + mitre_bonus) * SECTOR_MULTIPLIER[event.sector]))


def score_ngfw_log(log: NgfwLog) -> int:
    base = SEVERITY_POINTS[log.ips.severity]
    if log.action in {"blocked", "quarantined"}:
        base += 8
    if log.dpi.payload_sha256:
        base += 10
    if log.ips.cve:
        base += 8
    if log.geo.get("dst_country") not in {None, "NP"}:
        base += 4
    return min(100, round(base * SECTOR_MULTIPLIER[log.sector]))

