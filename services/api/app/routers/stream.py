import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.bus import event_bus

router = APIRouter(tags=["stream"])


@router.websocket("/stream")
async def websocket_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = await event_bus.subscribe()
    try:
        await websocket.send_text(json.dumps({"stream": "system", "message": "connected"}))
        while True:
            event = await queue.get()
            await websocket.send_text(json.dumps(event))
    except WebSocketDisconnect:
        event_bus.unsubscribe(queue)

