from fastapi import APIRouter

from app.core.bus import event_bus
from app.models.events import NgfwLog
from app.services.risk import score_ngfw_log

router = APIRouter(tags=["ngfw"])


@router.post("/ngfw/logs", status_code=202)
async def ingest_ngfw_log(log: NgfwLog) -> dict[str, object]:
    risk_score = score_ngfw_log(log)
    enriched = log.model_dump(mode="json") | {
        "risk_score": risk_score,
        "stream": "ngfw",
        "metrics": {
            "dpi_observed": any(log.dpi.model_dump().values()),
            "ips_triggered": bool(log.ips.signature),
            "application_filtered": log.action in {"blocked", "quarantined"},
        },
    }
    await event_bus.publish(enriched)
    return {"accepted": True, "event_id": log.event_id, "risk_score": risk_score}


@router.get("/ngfw/logs/recent")
async def recent_ngfw_logs() -> dict[str, object]:
    return {"logs": [event for event in event_bus.recent() if event.get("stream") == "ngfw"]}

