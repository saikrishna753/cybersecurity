"""WebSocket connection manager + event broadcast (async-safe)."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import WebSocket

logger = logging.getLogger("aiids.ws")


class WsManager:
    def __init__(self) -> None:
        self._conns: dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self) -> None:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

    async def connect(self, ws: WebSocket, user: str) -> None:
        await ws.accept()
        async with self._lock:
            self._conns[ws] = user
        logger.info("WS connected: %s (%d total)", user, len(self._conns))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._conns.pop(ws, None)

    async def broadcast(self, type_: str, data: dict) -> None:
        payload = {
            "type": type_,
            "data": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        async with self._lock:
            targets = list(self._conns.items())
        dead = []
        for ws, _user in targets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            async with self._lock:
                self._conns.pop(ws, None)

    def broadcast_threadsafe(self, type_: str, data: dict) -> None:
        """Called from worker threads (capture/detection) → schedule on event loop."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(type_, data), loop)
        except RuntimeError:
            logger.debug("WS loop unavailable; dropping %s event", type_)

    @property
    def connection_count(self) -> int:
        return len(self._conns)


ws_manager = WsManager()
