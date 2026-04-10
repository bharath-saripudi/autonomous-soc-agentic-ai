"""WebSocket Module — Real-time alert push to connected dashboards.

Provides:
  - Connection manager for multiple simultaneous dashboard clients
  - Broadcast to all connected clients on new alerts / state changes
  - Auto-cleanup of disconnected clients
"""

from typing import Any, Dict, List

import structlog
from fastapi import WebSocket, WebSocketDisconnect

logger = structlog.get_logger()


class WebSocketManager:
    """Manages active WebSocket connections for real-time alert streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("ws_client_connected", total=len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("ws_client_disconnected", total=len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]):
        """Push a message to all connected dashboard clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)

    async def send_alert_update(self, alert_id: str, event: str, data: Dict[str, Any]):
        """Send a structured alert update event."""
        await self.broadcast({
            "event": event,
            "alert_id": alert_id,
            **data,
        })

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


# Singleton instance
ws_manager = WebSocketManager()


async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint handler — keeps connection alive."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; client can send pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
