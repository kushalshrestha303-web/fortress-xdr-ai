from fastapi import APIRouter

from app.core.bus import event_bus
from app.models.events import TelemetryEvent
from app.services.risk import score_event

router = APIRouter(tags=["telemetry"])


@router.post("/telemetry/events", status_code=202)
async def ingest_event(event: TelemetryEvent) -> dict[str, object]:
    risk_score = score_event(event)
    enriched = event.model_dump(mode="json") | {"risk_score": risk_score, "stream": "telemetry"}
    await event_bus.publish(enriched)
    return {"accepted": True, "event_id": event.event_id, "risk_score": risk_score}


@router.get("/telemetry/recent")
async def recent_events() -> dict[str, object]:
    return {"events": [event for event in event_bus.recent() if event.get("stream") == "telemetry"]}

