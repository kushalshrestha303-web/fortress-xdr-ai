from collections import Counter, defaultdict

from app.models.log_analyzer import AttackDiagram, DetectionFinding, ParsedLogEvent

SUSPICIOUS_DOMAINS = {"greatyummyrecipes.org"}


def detect_attacks(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    findings.extend(_detect_syn_flood(events))
    findings.extend(_detect_port_scan(events))
    findings.extend(_detect_bruteforce(events))
    findings.extend(_detect_dns_tunneling(events))
    findings.extend(_detect_redirects(events))
    findings.extend(_detect_ddos(events))
    return findings


def build_attack_diagram(events: list[ParsedLogEvent], findings: list[DetectionFinding]) -> AttackDiagram:
    text = " ".join(event.info.lower() for event in events)
    if "greatyummyrecipes.org" in text or any("redirect" in finding.attack_type.lower() for finding in findings):
        nodes = ["User Browser", "GreatYummyRecipes.org", "Malware Redirect", "Malicious Payload", "Internal Server / C2 Callback"]
        edges = [
            {"from": nodes[0], "to": nodes[1], "label": "HTTP request"},
            {"from": nodes[1], "to": nodes[2], "label": "302 redirect"},
            {"from": nodes[2], "to": nodes[3], "label": "payload download"},
            {"from": nodes[3], "to": nodes[4], "label": "callback"},
        ]
    else:
        src = findings[0].source if findings and findings[0].source else "External Source"
        dst = findings[0].destination if findings and findings[0].destination else "Protected Asset"
        nodes = [src, "Network Edge", "Detection Engine", dst, "SOC Response"]
        edges = [
            {"from": nodes[0], "to": nodes[1], "label": "traffic"},
            {"from": nodes[1], "to": nodes[2], "label": "parsed logs"},
            {"from": nodes[2], "to": nodes[3], "label": "risk finding"},
            {"from": nodes[2], "to": nodes[4], "label": "incident report"},
        ]
    lines = ["flowchart LR"]
    for index, node in enumerate(nodes):
        lines.append(f'  N{index}["{node}"]')
    for edge in edges:
        lines.append(f'  N{nodes.index(edge["from"])} -->|{edge["label"]}| N{nodes.index(edge["to"])}')
    return AttackDiagram(mermaid="\n".join(lines), nodes=nodes, edges=edges)


def chart_data(events: list[ParsedLogEvent], findings: list[DetectionFinding]) -> dict[str, object]:
    protocol_counts = Counter(event.protocol for event in events)
    severity_counts = Counter(event.severity for event in events)
    source_counts = Counter(event.source_ip or "unknown" for event in events)
    buckets = Counter(event.timestamp[:16] for event in events)
    return {
        "packet_count_over_time": [{"time": key, "count": value} for key, value in sorted(buckets.items())],
        "top_source_ips": [{"ip": key, "count": value} for key, value in source_counts.most_common(8)],
        "protocol_distribution": [{"protocol": key, "count": value} for key, value in protocol_counts.items()],
        "severity_breakdown": [{"severity": key, "count": value} for key, value in severity_counts.items()],
        "attack_timeline": [{"attack_type": finding.attack_type, "severity": finding.severity, "confidence": finding.confidence} for finding in findings],
    }


def _detect_syn_flood(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    by_pair: dict[tuple[str | None, str | None], list[ParsedLogEvent]] = defaultdict(list)
    for event in events:
        info = event.info.upper()
        if "SYN" in info or "RST" in info or "504" in info:
            by_pair[_conversation_key(event.source_ip, event.destination_ip)].append(event)
    findings = []
    for (src, dst), grouped in by_pair.items():
        syn = sum("SYN" in event.info.upper() for event in grouped)
        rst = sum("RST" in event.info.upper() or "504" in event.info.upper() for event in grouped)
        if syn >= 5 and rst >= 1:
            findings.append(
                DetectionFinding(
                    attack_type="SYN flood / incomplete TCP handshake",
                    severity="critical",
                    confidence=0.91,
                    source=src,
                    destination=dst,
                    evidence=[event.raw for event in grouped[:6]],
                    mitre=["T1498"],
                )
            )
    return findings


def _conversation_key(source: str | None, destination: str | None) -> tuple[str | None, str | None]:
    if not source or not destination:
        return source, destination
    first, second = sorted([source, destination])
    return first, second


def _detect_ddos(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    destination_counts = Counter(event.destination_ip for event in events if event.destination_ip)
    source_counts = Counter(event.source_ip for event in events if event.source_ip)
    findings = []
    for destination, count in destination_counts.items():
        if count >= 20 and len(source_counts) >= 5:
            findings.append(
                DetectionFinding(
                    attack_type="Distributed denial of service",
                    severity="critical",
                    confidence=0.84,
                    destination=destination,
                    evidence=[event.raw for event in events if event.destination_ip == destination][:8],
                    mitre=["T1498"],
                )
            )
    return findings


def _detect_port_scan(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    ports_by_source: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.source_ip and ("PORT" in event.info.upper() or "SYN" in event.info.upper()):
            ports_by_source[event.source_ip].update(part for part in event.info.replace(",", " ").split() if part.isdigit())
    return [
        DetectionFinding(
            attack_type="Port scan",
            severity="high",
            confidence=0.78,
            source=source,
            evidence=[f"{source} touched {len(ports)} possible ports"],
            mitre=["T1046"],
        )
        for source, ports in ports_by_source.items()
        if len(ports) >= 8
    ]


def _detect_bruteforce(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    failures = [event for event in events if any(token in event.info.lower() for token in ("failed login", "auth failed", "invalid password", "401"))]
    by_source = Counter(event.source_ip for event in failures if event.source_ip)
    return [
        DetectionFinding(
            attack_type="Brute force authentication attempt",
            severity="high",
            confidence=0.82,
            source=source,
            evidence=[event.raw for event in failures if event.source_ip == source][:8],
            mitre=["T1110"],
        )
        for source, count in by_source.items()
        if count >= 5
    ]


def _detect_dns_tunneling(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    suspicious = [
        event for event in events
        if event.protocol == "DNS" and any(len(label) > 45 for label in event.info.split("."))
    ]
    if len(suspicious) >= 3:
        return [
            DetectionFinding(
                attack_type="DNS tunneling",
                severity="high",
                confidence=0.74,
                source=suspicious[0].source_ip,
                destination=suspicious[0].destination_ip,
                evidence=[event.raw for event in suspicious[:8]],
                mitre=["T1071.004"],
            )
        ]
    return []


def _detect_redirects(events: list[ParsedLogEvent]) -> list[DetectionFinding]:
    suspicious = [
        event for event in events
        if "redirect" in event.info.lower()
        or "302" in event.info
        or any(domain in event.info.lower() for domain in SUSPICIOUS_DOMAINS)
        or "payload" in event.info.lower()
        or "callback" in event.info.lower()
    ]
    if len(suspicious) >= 2:
        return [
            DetectionFinding(
                attack_type="Malware redirect / suspicious HTTP redirect",
                severity="critical",
                confidence=0.89,
                source=suspicious[0].source_ip,
                destination=suspicious[-1].destination_ip,
                evidence=[event.raw for event in suspicious[:8]],
                mitre=["T1189", "T1105", "T1071.001"],
            )
        ]
    return []
