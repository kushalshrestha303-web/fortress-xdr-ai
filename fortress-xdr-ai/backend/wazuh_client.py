from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from models import AlertListResponse, WazuhAlert, WazuhConfig

logger = logging.getLogger("fortress_xdr_ai.wazuh")

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env", override=True)
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class WazuhClient:
    def __init__(self) -> None:
        self.indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")
        self.indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        self.indexer_password = os.getenv("WAZUH_INDEXER_PASSWORD")
        self.alert_index = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*")
        self.verify_ssl = env_bool("VERIFY_SSL", False)
        self.timeout = float(os.getenv("WAZUH_TIMEOUT_SECONDS", "10"))
        self._last_source = "unknown"

    @property
    def config(self) -> WazuhConfig:
        return WazuhConfig(
            indexer_url=self.indexer_url,
            alert_index=self.alert_index,
            verify_ssl=self.verify_ssl,
            mode=self._last_source,
        )

    async def health(self) -> dict[str, Any]:
        try:
            response = await self._post({"size": 0}, size=0)
            return {
                "status": "ok",
                "mode": "indexer",
                "indexer_url": self.indexer_url,
                "alert_index": self.alert_index,
                "total_alerts_seen": response.get("hits", {}).get("total", {}),
            }
        except Exception as indexer_error:
            return {
                "status": "error",
                "mode": "indexer_unavailable",
                "indexer_url": self.indexer_url,
                "alert_index": self.alert_index,
                "warning": f"Indexer unavailable: {format_error(indexer_error)}",
            }

    async def recent_alerts(self, size: int = 500) -> AlertListResponse:
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"match_all": {}},
        }
        result = await self._search_indexer(body, size=size)
        self._log_alert_stats("/alerts/recent", result)
        return result

    async def suricata_alerts(self, size: int = 500) -> AlertListResponse:
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {
                "query_string": {
                    "query": '(rule.groups:suricata OR rule.description:*Suricata*)',
                    "fields": ["rule.groups", "rule.description", "decoder.name", "data.event_type"],
                    "default_operator": "OR",
                }
            },
        }
        result = await self._search_indexer(body, size=size)
        self._log_alert_stats("/alerts/suricata", result)
        return result

    async def high_alerts(self, size: int = 50, min_level: int = 10) -> AlertListResponse:
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"range": {"rule.level": {"gte": min_level}}},
        }
        return await self._search_indexer(body, size=size)

    async def search_alerts(self, query: str, size: int = 500) -> AlertListResponse:
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {
                "query_string": {
                    "query": query or "*",
                    "fields": [
                        "agent.name",
                        "manager.name",
                        "rule.id",
                        "rule.description",
                        "rule.groups",
                        "rule.mitre.tactic",
                        "rule.mitre.technique",
                        "decoder.name",
                        "full_log",
                        "data.*",
                    ],
                    "default_operator": "AND",
                }
            },
        }
        return await self._search_indexer(body, size=size)

    async def get_alert(self, alert_id: str) -> WazuhAlert | None:
        body = {"size": 1, "query": {"ids": {"values": [alert_id]}}}
        result = await self._search_indexer(body, size=1)
        return result.alerts[0] if result.alerts else None

    async def related_alerts(self, alert: WazuhAlert, size: int = 100) -> AlertListResponse:
        should: list[dict[str, Any]] = []
        if alert.agent_name:
            should.append({"term": {"agent.name.keyword": alert.agent_name}})
            should.append({"term": {"host.name.keyword": alert.agent_name}})
        for field, value in [("data.srcip", alert.srcip), ("data.dstip", alert.dstip), ("data.src_ip", alert.srcip), ("data.dest_ip", alert.dstip), ("data.user.name", alert.user_name), ("user.name", alert.user_name)]:
            if value:
                should.append({"term": {f"{field}.keyword": value}})
        for group in alert.rule_groups:
            should.append({"term": {"rule.groups.keyword": group}})
        for tactic in alert.mitre_tactics:
            should.append({"term": {"rule.mitre.tactic.keyword": tactic}})

        timestamp = _parse_time(alert.timestamp)
        filter_clause: list[dict[str, Any]] = []
        if timestamp:
            start = (timestamp - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
            end = (timestamp + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
            filter_clause.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
            "query": {
                "bool": {
                    "should": should or [{"match_all": {}}],
                    "minimum_should_match": 1 if should else 0,
                    "filter": filter_clause,
                }
            },
        }

        return await self._search_indexer(body, size=size)

    async def hunt(self, query: str, size: int = 50) -> AlertListResponse:
        preset = query.strip().lower()
        now = datetime.now(UTC)
        last_24h = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
        if "high severity" in preset:
            return await self.high_alerts(size=size, min_level=10)
        if "authentication" in preset or "fail" in preset or "brute" in preset:
            return await self.search_alerts('(rule.groups:authentication OR rule.description:*failed* OR rule.description:*brute*)', size)
        if "privilege escalation" in preset or "sudo" in preset:
            return await self.search_alerts('(rule.mitre.tactic:*Privilege* OR rule.description:*sudo* OR rule.description:*privilege* OR rule.description:*ROOT*)', size)
        if "powershell" in preset:
            return await self.search_alerts('(full_log:*powershell* OR rule.description:*PowerShell* OR data.win.eventdata.image:*powershell*)', size)
        if "malware" in preset:
            return await self.search_alerts('(rule.groups:malware OR rule.description:*malware*)', size)
        if "suricata" in preset:
            return await self.search_alerts('(decoder.name:suricata OR rule.groups:suricata)', size)
        if "rootcheck" in preset:
            return await self.search_alerts('(rule.groups:rootcheck OR decoder.name:rootcheck)', size)
        if "syscheck" in preset or "file integrity" in preset:
            return await self.search_alerts('(rule.groups:syscheck OR decoder.name:syscheck)', size)
        if "mitre" in preset or "att&ck" in preset or "attack tactic" in preset:
            tactic = query.split(":", 1)[1].strip() if ":" in query else "*"
            return await self.search_alerts(f'rule.mitre.tactic:*{tactic}*', size)
        if "last 24" in preset:
            body = {
                "size": size,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {"range": {"@timestamp": {"gte": last_24h}}},
            }
            return await self._search_indexer(body, size=size)
        return await self.search_alerts(query or "*", size)

    async def _search_indexer(self, body: dict[str, Any], size: int) -> AlertListResponse:
        try:
            data = await self._post(body, size=size)
            alerts = [self._from_hit(hit) for hit in data.get("hits", {}).get("hits", [])]
            self._last_source = "indexer"
            return AlertListResponse(source="indexer", total=len(alerts), alerts=alerts)
        except Exception:
            self._last_source = "indexer_unavailable"
            return AlertListResponse(source="indexer_unavailable", total=0, alerts=[])

    async def _post(self, body: dict[str, Any], size: int) -> dict[str, Any]:
        if not self.indexer_password:
            raise RuntimeError("WAZUH_INDEXER_PASSWORD is not set")
        url = f"{self.indexer_url}/{self.alert_index}/_search"
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            response = await client.post(url, auth=(self.indexer_user, self.indexer_password), json=body)
            response.raise_for_status()
            return response.json()

    def _from_hit(self, hit: dict[str, Any]) -> WazuhAlert:
        source = hit.get("_source", {})
        return self._from_source(source, generated_id=hit.get("_id", ""), document_id=hit.get("_id"))

    def _from_source(self, source: dict[str, Any], generated_id: str, document_id: str | None = None) -> WazuhAlert:
        rule = source.get("rule") or {}
        agent = source.get("agent") or {}
        manager = source.get("manager") or {}
        decoder = source.get("decoder") or {}
        data = source.get("data") or {}
        mitre = rule.get("mitre") or {}
        return WazuhAlert(
            id=document_id or source.get("id") or generated_id,
            alert_source=classify_alert_source(rule.get("groups"), decoder.get("name"), rule.get("description")),
            timestamp=source.get("@timestamp") or source.get("timestamp"),
            agent_name=agent.get("name"),
            agent_id=agent.get("id"),
            manager_name=manager.get("name"),
            rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
            rule_level=int(rule.get("level") or 0),
            rule_description=rule.get("description"),
            rule_groups=listify(rule.get("groups")),
            decoder_name=decoder.get("name"),
            full_log=source.get("full_log") or source.get("fullLog"),
            mitre_tactics=listify(mitre.get("tactic")),
            mitre_techniques=listify(mitre.get("technique")),
            srcip=pick(data, ["srcip", "src_ip", "srcaddr", "source.ip", "flow.src_ip"]) or source.get("srcip"),
            dstip=pick(data, ["dstip", "dst_ip", "dest_ip", "dstaddr", "destination.ip", "flow.dest_ip"]) or source.get("dstip"),
            user_name=pick(data, ["user.name", "srcuser", "dstuser", "win.eventdata.targetUserName"]) or (source.get("user") or {}).get("name"),
            suricata_signature=pick(data, ["alert.signature"]),
            suricata_category=pick(data, ["alert.category"]),
            suricata_severity=pick(data, ["alert.severity", "alert.metadata.signature_severity"]),
            suricata_protocol=pick(data, ["proto", "app_proto"]),
            data=data,
            raw=source,
        )

    @staticmethod
    def _is_suricata(alert: WazuhAlert) -> bool:
        groups = {group.lower() for group in alert.rule_groups}
        description = (alert.rule_description or "").lower()
        return "suricata" in groups or "suricata" in description

    def _log_alert_stats(self, endpoint: str, result: AlertListResponse) -> None:
        suricata_alerts = [alert for alert in result.alerts if self._is_suricata(alert)]
        first_rule = suricata_alerts[0].rule_id if suricata_alerts else None
        logger.debug(
            "%s returned %s alerts from %s; Suricata alerts found=%s; first Suricata rule id=%s",
            endpoint,
            result.total,
            result.source,
            len(suricata_alerts),
            first_rule,
        )


def listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def classify_alert_source(groups: Any, decoder_name: Any, description: Any) -> str:
    group_values = {item.lower() for item in listify(groups)}
    decoder = str(decoder_name or "").lower()
    desc = str(description or "").lower()
    if "suricata" in group_values or decoder == "suricata" or "suricata" in desc:
        return "Suricata"
    if "authentication" in group_values or "authentication" in desc or "pam" in group_values:
        return "Authentication"
    if "syscheck" in group_values or decoder == "syscheck":
        return "Syscheck"
    if "rootcheck" in group_values or decoder == "rootcheck":
        return "Rootcheck"
    return "Wazuh"


def format_error(error: Exception) -> str:
    message = str(error).strip()
    if message:
        return message
    return error.__class__.__name__


def pick(data: dict[str, Any], paths: list[str]) -> str | None:
    for path in paths:
        current: Any = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                current = None
                break
        if current:
            return str(current)
    return None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None
