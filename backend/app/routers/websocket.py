"""
WebSocket Real-Time Event Stream Endpoint
"""
import uuid
import logging
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.realtime.connection_manager import manager
from app.core.security import decode_token

logger = logging.getLogger("websocket_router")
router = APIRouter(tags=["Real-Time Stream"])


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    Centralized Real-Time Event WebSocket Stream.
    Emits incident.created, incident.status_changed, ai.analysis.completed, playbook.completed, etc.
    """
    user_email = None
    if token:
        payload = decode_token(token)
        if payload and payload.get("sub"):
            user_email = payload.get("sub")

    # Reject unauthorized WebSocket connections
    if not user_email:
        logger.warning("Rejected unauthenticated WebSocket connection attempt")
        await websocket.close(code=1008, reason="Authentication token required")
        return

    client_id = f"cli_{uuid.uuid4().hex[:8]}"
    await manager.connect(websocket, client_id=client_id, user_email=user_email)

    try:
        while True:
            # Keep-alive heartbeat and message receipt
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(client_id=client_id, user_email=user_email)
    except Exception as e:
        logger.warning(f"WebSocket client error: {e}")
        await manager.disconnect(client_id=client_id, user_email=user_email)
