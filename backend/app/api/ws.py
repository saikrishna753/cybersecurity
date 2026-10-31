"""WebSocket endpoint: /api/ws?token=<jwt>."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.security import decode_token
from app.ws.manager import ws_manager

logger = logging.getLogger("aiids.ws")
router = APIRouter()


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: str = Query(default="")):
    # authenticate before accepting
    if not token:
        await websocket.close(code=4401, reason="missing token")
        return
    try:
        payload = decode_token(token)
        user = payload.get("sub", "unknown")
    except Exception:
        await websocket.close(code=4401, reason="invalid token")
        return

    await ws_manager.connect(websocket, user)
    try:
        # initial hello with current status
        await websocket.send_json(
            {"type": "hello", "data": {"user": user, "connections": ws_manager.connection_count},
             "ts": None}
        )
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong", "data": {}, "ts": None})
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket)
