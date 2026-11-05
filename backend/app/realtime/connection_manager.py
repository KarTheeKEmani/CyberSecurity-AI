"""
Real-Time WebSocket Connection Manager
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
from app.core.security import decode_token

logger = logging.getLogger("realtime")


class ConnectionManager:
    """
    Manages active WebSocket client connections, heartbeat, and real-time event broadcasting.
    """

    def __init__(self):
        # Map of connection_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}
        # Map of user_email -> set of connection_ids
        self.user_connections: Dict[str, Set[str]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, client_id: str, user_email: Optional[str] = None):
        """Accept WebSocket connection and register client."""
        await websocket.accept()
        async with self.lock:
            self.active_connections[client_id] = websocket
            if user_email:
                if user_email not in self.user_connections:
                    self.user_connections[user_email] = set()
                self.user_connections[user_email].add(client_id)
        
        logger.info(f"WebSocket client connected: {client_id} (User: {user_email})")
        # Send connection ACK
        await self.send_personal_message({
            "type": "connection.ack",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "client_id": client_id,
                "status": "connected",
                "message": "AIAC Cyber Real-Time Stream Established",
            }
        }, websocket)

    async def disconnect(self, client_id: str, user_email: Optional[str] = None):
        """Remove WebSocket connection."""
        async with self.lock:
            if client_id in self.active_connections:
                del self.active_connections[client_id]
            if user_email and user_email in self.user_connections:
                self.user_connections[user_email].discard(client_id)
                if not self.user_connections[user_email]:
                    del self.user_connections[user_email]
        logger.info(f"WebSocket client disconnected: {client_id}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send JSON message to specific connection."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning(f"Error sending message to individual client: {e}")

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """
        Broadcast a real-time event to all connected clients.
        Must be called ONLY after the database transaction has committed.
        """
        payload = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        
        disconnected_clients = []
        async with self.lock:
            for client_id, ws in list(self.active_connections.items()):
                try:
                    await ws.send_json(payload)
                except Exception as e:
                    logger.warning(f"Failed to send to client {client_id}: {e}")
                    disconnected_clients.append(client_id)

        # Clean up any dead connections
        for client_id in disconnected_clients:
            await self.disconnect(client_id)


manager = ConnectionManager()
