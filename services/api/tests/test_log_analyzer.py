from app.services.log_detector import detect_attacks
from app.services.log_parser import parse_log_bytes
from app.services.log_reporter import analyze_events


def test_detects_syn_flood() -> None:
    sample = "\n".join(
        [f"2026-05-17T10:00:0{i} TCP 198.51.100.9 -> 10.0.0.5 SYN port {80+i}" for i in range(6)]
        + ["2026-05-17T10:00:07 TCP 10.0.0.5 -> 198.51.100.9 RST ACK 504 Gateway Timeout"]
    )
    events = parse_log_bytes("syn.log", sample.encode())
    findings = detect_attacks(events)
    assert any("SYN flood" in finding.attack_type for finding in findings)


def test_detects_malware_redirect() -> None:
    sample = """
2026-05-17T11:00:00 HTTP 10.1.1.20 -> 203.0.113.20 GET http://GreatYummyRecipes.org/
2026-05-17T11:00:01 HTTP 203.0.113.20 -> 10.1.1.20 302 redirect malware payload
2026-05-17T11:00:02 HTTPS 10.1.1.20 -> 198.51.100.77 callback c2
"""
    events = parse_log_bytes("redirect.log", sample.encode())
    result = analyze_events("upload-1", events)
    assert any("redirect" in finding.attack_type.lower() for finding in result.findings)
    assert "GreatYummyRecipes.org" in result.diagram.nodes


def test_parses_xlsx_http_log() -> None:
    from io import BytesIO

    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Time", "Source", "Destination", "Protocol", "Info"])
    sheet.append(["2026-05-17T11:00:00", "10.1.1.20", "203.0.113.20", "HTTP", "GET http://GreatYummyRecipes.org/"])
    sheet.append(["2026-05-17T11:00:01", "203.0.113.20", "10.1.1.20", "HTTP", "302 redirect malware payload"])
    buffer = BytesIO()
    workbook.save(buffer)

    events = parse_log_bytes("http-log.xlsx", buffer.getvalue())
    result = analyze_events("xlsx-upload", events)

    assert len(events) == 2
    assert events[0].source_ip == "10.1.1.20"
    assert any("redirect" in finding.attack_type.lower() for finding in result.findings)
