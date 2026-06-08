import csv
import io
import time
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import Response

from app.models.log_analyzer import AnalysisResult, ParsedLogEvent
from app.core.config import settings
from app.core.notifications import send_email
from app.services.log_parser import parse_log_bytes
from app.services.log_reporter import analyze_events, report_to_html, report_to_markdown, report_to_pdf_bytes

router = APIRouter(prefix="/api/security", tags=["ai-log-analyzer"])

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".pcapng", ".xlsx"}
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
UPLOAD_ROOT = Path("storage/uploads").resolve()
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

UPLOADS: dict[str, dict[str, object]] = {}
REPORTS: dict[str, AnalysisResult] = {}
RATE_LIMIT: dict[str, list[float]] = {}
AUDIT_LOG: list[dict[str, object]] = []


@router.post("/logs/upload")
async def upload_log(request: Request, file: UploadFile = File(...)) -> dict[str, object]:
    _rate_limit(request)
    extension = Path(file.filename or "").suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Log file exceeds 8 MiB limit")

    upload_id = str(uuid4())
    safe_name = f"{upload_id}{extension}"
    destination = (UPLOAD_ROOT / safe_name).resolve()
    if not str(destination).startswith(str(UPLOAD_ROOT)):
        raise HTTPException(status_code=400, detail="Unsafe upload path")
    destination.write_bytes(content)
    events = parse_log_bytes(file.filename or safe_name, content)
    UPLOADS[upload_id] = {"filename": file.filename, "path": str(destination), "events": events}
    _audit(request, "upload", upload_id, {"filename": file.filename, "events": len(events)})
    return {"upload_id": upload_id, "filename": file.filename, "parsed_events": len(events), "events": events[:200]}


@router.post("/logs/analyze")
async def analyze_log(request: Request, payload: dict[str, str]) -> dict[str, object]:
    _rate_limit(request)
    upload_id = payload.get("upload_id")
    if not upload_id or upload_id not in UPLOADS:
        raise HTTPException(status_code=404, detail="Upload not found")
    events = UPLOADS[upload_id]["events"]
    result = analyze_events(upload_id, events)  # type: ignore[arg-type]
    REPORTS[result.report_id] = result
    notification = await _email_log_report(request, result)
    _audit(request, "analyze", upload_id, {"report_id": result.report_id, "findings": len(result.findings)})
    response = result.model_dump(mode="json")
    response["notification"] = notification
    response["download_links"] = _download_links(request, result.report_id)
    return response


@router.get("/reports/{report_id}")
async def get_report(report_id: str) -> dict[str, object]:
    result = REPORTS.get(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    return result.model_dump(mode="json")


@router.get("/reports/{report_id}/export/pdf")
async def export_pdf(report_id: str) -> Response:
    result = REPORTS.get(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(
        report_to_pdf_bytes(result),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident-report-{report_id}.pdf"'},
    )


@router.get("/reports/{report_id}/export/csv")
async def export_csv(report_id: str) -> Response:
    result = REPORTS.get(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp", "source_ip", "destination_ip", "protocol", "info", "severity"])
    writer.writeheader()
    for event in result.events:
        writer.writerow({key: getattr(event, key) for key in writer.fieldnames})
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="parsed-events-{report_id}.csv"'},
    )


@router.get("/reports/{report_id}/export/diagram.svg")
async def export_diagram_svg(report_id: str) -> Response:
    result = REPORTS.get(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    labels = result.diagram.nodes
    width = max(900, len(labels) * 190)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="220" role="img">']
    parts.append('<rect width="100%" height="100%" fill="#06080d"/>')
    for index, label in enumerate(labels):
        x = 30 + index * 180
        parts.append(f'<rect x="{x}" y="80" width="145" height="46" rx="6" fill="#10151d" stroke="#36d7d7"/>')
        parts.append(f'<text x="{x + 12}" y="108" fill="#e6edf6" font-size="12">{label}</text>')
        if index < len(labels) - 1:
            parts.append(f'<line x1="{x + 145}" y1="103" x2="{x + 180}" y2="103" stroke="#f5b84b" stroke-width="2"/>')
    parts.append("</svg>")
    return Response("".join(parts), media_type="image/svg+xml")


@router.get("/reports/{report_id}/export/markdown")
async def export_markdown(report_id: str) -> Response:
    result = REPORTS.get(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(report_to_markdown(result), media_type="text/markdown")


@router.get("/reports/{report_id}/export/html")
async def export_html(report_id: str) -> Response:
    result = REPORTS.get(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(
        report_to_html(result),
        media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="visual-incident-report-{report_id}.html"'},
    )


def _rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = [stamp for stamp in RATE_LIMIT.get(ip, []) if now - stamp < 60]
    if len(window) >= 30:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    window.append(now)
    RATE_LIMIT[ip] = window


def _audit(request: Request, action: str, object_id: str, detail: dict[str, object]) -> None:
    AUDIT_LOG.append(
        {
            "timestamp": time.time(),
            "client": request.client.host if request.client else "unknown",
            "action": action,
            "object_id": object_id,
            "detail": detail,
        }
    )


async def _email_log_report(request: Request, result: AnalysisResult) -> dict[str, str]:
    links = _download_links(request, result.report_id)
    body = "\n".join(
        [
            "NEPAL FORTRESS ONE - AI LOG ATTACK ANALYZER REPORT",
            "=" * 58,
            f"Report ID: {result.report_id}",
            f"Upload ID: {result.upload_id}",
            f"Attack Type: {result.summary.get('attack_type')}",
            f"Parsed Events: {len(result.events)}",
            f"Findings: {len(result.findings)}",
            f"Business Impact: {result.summary.get('business_impact')}",
            "",
            "Download Links",
            f"- Open Visual Report in Nepal Fortress ONE: {links['visual_page']}",
            f"- Direct Visual HTML Report: {links['html']}",
            f"- PDF Report: {links['pdf']}",
            f"- Attack Diagram SVG: {links['diagram_svg']}",
            f"- Parsed Evidence CSV: {links['csv']}",
            f"- Markdown Report: {links['markdown']}",
            "",
            "Report Preview",
            report_to_markdown(result)[:7000],
        ]
    )
    return await send_email(
        subject=f"[Nepal Fortress ONE] AI Log Analyzer Report {result.report_id}",
        body=body,
        to_email=str(settings.security_notification_to),
    )


def _download_links(request: Request, report_id: str) -> dict[str, str]:
    base = str(request.base_url).rstrip("/")
    frontend = settings.frontend_url.rstrip("/")
    return {
        "visual_page": f"{frontend}/security/log-analyzer/reports/{report_id}",
        "html": f"{base}/api/security/reports/{report_id}/export/html",
        "pdf": f"{base}/api/security/reports/{report_id}/export/pdf",
        "diagram_svg": f"{base}/api/security/reports/{report_id}/export/diagram.svg",
        "csv": f"{base}/api/security/reports/{report_id}/export/csv",
        "markdown": f"{base}/api/security/reports/{report_id}/export/markdown",
    }
