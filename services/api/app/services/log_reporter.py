from datetime import datetime, timezone

from app.models.log_analyzer import AnalysisResult, AttackDiagram, DetectionFinding, ParsedLogEvent
from app.services.log_detector import build_attack_diagram, chart_data, detect_attacks


def analyze_events(upload_id: str, events: list[ParsedLogEvent]) -> AnalysisResult:
    findings = detect_attacks(events)
    diagram = build_attack_diagram(events, findings)
    report = build_report(events, findings)
    return AnalysisResult(
        upload_id=upload_id,
        events=events,
        findings=findings,
        summary=build_summary(events, findings),
        diagram=diagram,
        charts=chart_data(events, findings),
        report=report,
    )


def build_summary(events: list[ParsedLogEvent], findings: list[DetectionFinding]) -> dict[str, object]:
    primary = findings[0] if findings else None
    return {
        "attack_type": primary.attack_type if primary else "No confirmed attack detected",
        "source": primary.source if primary else None,
        "destination": primary.destination if primary else None,
        "timeline": [event.timestamp for event in events[:10]],
        "indicators_of_compromise": sorted({ioc for finding in findings for ioc in finding.evidence[:3]}),
        "business_impact": _business_impact(findings),
        "recommended_mitigation": _mitigations(findings),
        "ml_ready": {
            "feature_store": "events can be vectorized by source, destination, protocol, time bucket, and lexical indicators",
            "llm_adapter": "replace build_summary with OpenAI/local LLM adapter when configured",
            "anomaly_adapter": "plug statistical or PyTorch model behind detect_attacks interface",
        },
    }


def build_report(events: list[ParsedLogEvent], findings: list[DetectionFinding]) -> dict[str, object]:
    summary = build_summary(events, findings)
    return {
        "Executive Summary": f"{summary['attack_type']} detected across {len(events)} parsed log events." if findings else f"No confirmed attack detected across {len(events)} parsed log events.",
        "Incident Overview": f"Analyzer processed {len(events)} events and produced {len(findings)} findings.",
        "Attack Type": summary["attack_type"],
        "Timeline": [f"{event.timestamp} {event.source_ip or '-'} -> {event.destination_ip or '-'} {event.protocol} {event.info}" for event in events[:25]],
        "Evidence from Logs": [evidence for finding in findings for evidence in finding.evidence],
        "Indicators of Compromise": summary["indicators_of_compromise"],
        "Root Cause": "Initial hypothesis: exposed service, malicious redirect chain, weak authentication controls, or unfiltered network ingress. Confirm with endpoint and firewall evidence.",
        "Business Impact": summary["business_impact"],
        "Containment Actions": ["Block malicious IPs/domains", "Rate-limit suspicious sources", "Isolate affected endpoint", "Preserve logs and packet evidence"],
        "Eradication Actions": ["Remove payloads", "Reset credentials", "Patch exposed services", "Validate firewall and DNS controls"],
        "Recovery Plan": ["Restore normal traffic gradually", "Monitor recurrence", "Verify service health", "Close incident after evidence review"],
        "Recommendations": summary["recommended_mitigation"],
        "Appendix with parsed log evidence": [event.model_dump() for event in events[:100]],
    }


def report_to_markdown(result: AnalysisResult) -> str:
    lines = [f"# AI Log Attack Analyzer Report", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", ""]
    for section, value in result.report.items():
        lines.append(f"## {section}")
        if isinstance(value, list):
            for item in value:
                lines.append(f"- {item}")
        else:
            lines.append(str(value))
        lines.append("")
    lines.append("## Attack Diagram")
    lines.append("```mermaid")
    lines.append(result.diagram.mermaid)
    lines.append("```")
    return "\n".join(lines)


def report_to_html(result: AnalysisResult) -> str:
    severity_breakdown = result.charts.get("severity_breakdown", [])
    protocol_distribution = result.charts.get("protocol_distribution", [])
    top_source_ips = result.charts.get("top_source_ips", [])
    attack_timeline = result.charts.get("attack_timeline", [])
    severity_counts = {item["severity"]: item["count"] for item in severity_breakdown}
    protocol_counts = {item["protocol"]: item["count"] for item in protocol_distribution}
    max_protocol = max(protocol_counts.values(), default=1)
    max_source = max((item["count"] for item in top_source_ips), default=1)
    primary = result.findings[0] if result.findings else None
    diagram = _diagram_svg(result.diagram.nodes)
    timeline_items = "".join(
        f"<li><span>{_escape(event.timestamp)}</span><strong>{_escape(event.protocol)}</strong>{_escape(event.info[:160])}</li>"
        for event in result.events[:18]
    )
    evidence_rows = "".join(
        "<tr>"
        f"<td>{_escape(event.timestamp)}</td>"
        f"<td>{_escape(event.source_ip or '-')}</td>"
        f"<td>{_escape(event.destination_ip or '-')}</td>"
        f"<td>{_escape(event.protocol)}</td>"
        f"<td>{_escape(event.severity)}</td>"
        f"<td>{_escape(event.info[:180])}</td>"
        "</tr>"
        for event in result.events[:80]
    )
    protocol_bars = "".join(
        f"<div class='bar-row'><span>{_escape(protocol)}</span><div><i style='width:{round((count / max_protocol) * 100)}%'></i></div><b>{count}</b></div>"
        for protocol, count in protocol_counts.items()
    )
    source_bars = "".join(
        f"<div class='bar-row'><span>{_escape(item['ip'])}</span><div><i style='width:{round((item['count'] / max_source) * 100)}%'></i></div><b>{item['count']}</b></div>"
        for item in top_source_ips[:8]
    )
    findings = "".join(
        f"<article><h3>{_escape(finding.attack_type)}</h3><p>{_escape(finding.source or 'unknown')} to {_escape(finding.destination or 'unknown')}</p><b>{_escape(finding.severity)} - {round(finding.confidence * 100)}%</b></article>"
        for finding in result.findings
    ) or "<p class='muted'>No confirmed attack detected in this log set.</p>"

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Nepal Fortress ONE - AI Log Attack Analyzer Report</title>
  <style>
    body {{ margin: 0; background: #06080d; color: #e6edf6; font-family: Arial, Helvetica, sans-serif; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px; }}
    header {{ border: 1px solid #27313f; background: #10151d; padding: 28px; }}
    h1, h2, h3 {{ margin: 0; }}
    h1 {{ font-size: 30px; }}
    h2 {{ font-size: 18px; margin-bottom: 14px; }}
    .eyebrow {{ color: #36d7d7; text-transform: uppercase; font-size: 12px; letter-spacing: .08em; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 18px 0; }}
    .card {{ border: 1px solid #27313f; background: #10151d; padding: 18px; }}
    .card b {{ display: block; font-size: 26px; color: #fff; }}
    .muted, .card span {{ color: #9fb0c2; }}
    .two {{ display: grid; grid-template-columns: 1.15fr .85fr; gap: 16px; margin-top: 16px; }}
    .severity {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }}
    .sev {{ padding: 10px; border: 1px solid #27313f; text-align: center; }}
    .sev b {{ color: #f5b84b; }}
    .bar-row {{ display: grid; grid-template-columns: 130px 1fr 40px; gap: 10px; align-items: center; margin: 10px 0; }}
    .bar-row div {{ height: 10px; background: #0b1017; border: 1px solid #27313f; }}
    .bar-row i {{ display: block; height: 100%; background: #36d7d7; }}
    article {{ border: 1px solid #27313f; padding: 12px; margin-bottom: 10px; background: #0b1017; }}
    article b {{ color: #f5b84b; }}
    li {{ margin: 8px 0; color: #c7d4e2; }}
    li span {{ display: inline-block; min-width: 180px; color: #9fb0c2; }}
    li strong {{ display: inline-block; min-width: 70px; color: #36d7d7; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
    th, td {{ border-top: 1px solid #27313f; padding: 9px; text-align: left; vertical-align: top; }}
    th {{ color: #9fb0c2; background: #0b1017; }}
    .diagram {{ overflow-x: auto; }}
    @media print {{ body {{ background: white; color: #111; }} .card, header, article {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">Nepal Fortress ONE - AI Log Attack Analyzer</p>
    <h1>Cybersecurity Incident Visual Report</h1>
    <p class="muted">Generated {datetime.now(timezone.utc).isoformat()} for report {result.report_id}</p>
  </header>

  <section class="grid">
    <div class="card"><span>Primary Attack</span><b>{_escape(result.summary["attack_type"])}</b></div>
    <div class="card"><span>Parsed Events</span><b>{len(result.events)}</b></div>
    <div class="card"><span>Findings</span><b>{len(result.findings)}</b></div>
    <div class="card"><span>Highest Severity</span><b>{_escape(primary.severity if primary else "info")}</b></div>
  </section>

  <section class="two">
    <div class="card">
      <h2>Attack Flow</h2>
      <div class="diagram">{diagram}</div>
    </div>
    <div class="card">
      <h2>Detections</h2>
      {findings}
    </div>
  </section>

  <section class="two">
    <div class="card">
      <h2>Top Source IPs</h2>
      {source_bars}
    </div>
    <div class="card">
      <h2>Protocol Distribution</h2>
      {protocol_bars}
    </div>
  </section>

  <section class="card">
    <h2>Severity Breakdown</h2>
    <div class="severity">
      {''.join(f"<div class='sev'><span>{_escape(name)}</span><b>{severity_counts.get(name, 0)}</b></div>" for name in ["info", "low", "medium", "high", "critical"])}
    </div>
  </section>

  <section class="two">
    <div class="card">
      <h2>Business Impact</h2>
      <p>{_escape(str(result.summary["business_impact"]))}</p>
    </div>
    <div class="card">
      <h2>Recommended Mitigation</h2>
      <ul>{''.join(f"<li>{_escape(action)}</li>" for action in result.summary["recommended_mitigation"])}</ul>
    </div>
  </section>

  <section class="card">
    <h2>Attack Timeline</h2>
    <ol>{timeline_items}</ol>
  </section>

  <section class="card">
    <h2>Parsed Log Evidence</h2>
    <table>
      <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Severity</th><th>Info</th></tr></thead>
      <tbody>{evidence_rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>"""


def report_to_pdf_bytes(result: AnalysisResult) -> bytes:
    text = report_to_markdown(result).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    chunks = [text[index:index + 85] for index in range(0, min(len(text), 8000), 85)]
    y = 760
    body = ["BT", "/F1 10 Tf"]
    for chunk in chunks[:65]:
        body.append(f"50 {y} Td ({chunk}) Tj")
        body.append(f"-50 -12 Td")
        y -= 12
    body.append("ET")
    stream = "\n".join(body)
    pdf = (
        "%PDF-1.4\n"
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        f"5 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj\n"
        "xref\n0 6\n0000000000 65535 f \n"
        "trailer << /Root 1 0 R /Size 6 >>\nstartxref\n0\n%%EOF\n"
    )
    return pdf.encode("latin-1", errors="replace")


def _diagram_svg(labels: list[str]) -> str:
    width = max(900, len(labels) * 190)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="190" role="img">']
    parts.append('<defs><linearGradient id="g" x1="0" x2="1"><stop stop-color="#36d7d7"/><stop offset="1" stop-color="#f5b84b"/></linearGradient></defs>')
    parts.append('<rect width="100%" height="100%" fill="#080c12"/>')
    for index, label in enumerate(labels):
        x = 28 + index * 180
        parts.append(f'<rect x="{x}" y="62" width="145" height="58" rx="6" fill="#10151d" stroke="#36d7d7"/>')
        parts.append(f'<circle cx="{x + 16}" cy="91" r="5" fill="#f5b84b"/>')
        parts.append(f'<text x="{x + 30}" y="88" fill="#e6edf6" font-size="12">{_escape(label[:18])}</text>')
        parts.append(f'<text x="{x + 30}" y="104" fill="#9fb0c2" font-size="10">stage {index + 1}</text>')
        if index < len(labels) - 1:
            parts.append(f'<line x1="{x + 145}" y1="91" x2="{x + 178}" y2="91" stroke="url(#g)" stroke-width="3"/>')
            parts.append(f'<polygon points="{x + 178},91 {x + 168},86 {x + 168},96" fill="#f5b84b"/>')
    parts.append("</svg>")
    return "".join(parts)


def _escape(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _business_impact(findings: list[DetectionFinding]) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "High risk to service availability, confidentiality, and incident response workload. Critical business systems may require containment."
    if findings:
        return "Moderate risk requiring SOC review and targeted containment."
    return "No immediate business impact confirmed from provided logs."


def _mitigations(findings: list[DetectionFinding]) -> list[str]:
    actions = {"Preserve original logs and correlate with firewall, endpoint, DNS, and identity telemetry."}
    for finding in findings:
        if "SYN" in finding.attack_type or "denial" in finding.attack_type:
            actions.update({"Enable SYN cookies or upstream DDoS protection.", "Rate-limit sources and block abusive flows at NGFW."})
        if "redirect" in finding.attack_type:
            actions.update({"Block suspicious domains including GreatYummyRecipes.org.", "Hunt for payload download and C2 callback indicators."})
        if "Brute" in finding.attack_type:
            actions.update({"Enforce MFA and lockout policy.", "Block repeated authentication sources."})
        if "DNS" in finding.attack_type:
            actions.update({"Block long-label DNS exfiltration patterns.", "Route DNS through controlled resolvers with logging."})
    return sorted(actions)
