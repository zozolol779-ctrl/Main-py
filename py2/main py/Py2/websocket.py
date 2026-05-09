"""
WebSocket support for real-time updates
"""
from fastapi import APIRouter, WebSocket, Depends, HTTPException, status
from sqlalchemy.orm import Session
import json
import logging
from typing import Set
from core.database import get_db
from core.security import get_current_user
from models.models import Investigation

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

# Store active connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}
    
    def add_connection(self, investigation_id: int, websocket: WebSocket):
        if investigation_id not in self.active_connections:
            self.active_connections[investigation_id] = []
        self.active_connections[investigation_id].append(websocket)
    
    async def remove_connection(self, investigation_id: int, websocket: WebSocket):
        if investigation_id in self.active_connections:
            self.active_connections[investigation_id].remove(websocket)
            if not self.active_connections[investigation_id]:
                del self.active_connections[investigation_id]
    
    async def broadcast(self, investigation_id: int, message: dict):
        """Broadcast message to all connected clients for investigation"""
        if investigation_id not in self.active_connections:
            return
        
        disconnected = []
        for websocket in self.active_connections[investigation_id]:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                disconnected.append(websocket)
        
        # Remove disconnected clients
        for websocket in disconnected:
            await self.remove_connection(investigation_id, websocket)

manager = ConnectionManager()

@router.websocket("/ws/investigations/{investigation_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    investigation_id: int,
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time investigation updates
    
    Connect with: ws://localhost:8000/ws/investigations/{investigation_id}
    Optional query param: ?token=JWT_TOKEN
    """
    
    # Verify investigation exists
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id
    ).first()
    
    if not investigation:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Investigation not found")
        return
    
    await websocket.accept()
    manager.add_connection(investigation_id, websocket)
    
    try:
        # Send connection confirmation
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "investigation_id": investigation_id,
            "message": "WebSocket connected successfully"
        })
        
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type")
                
                if message_type == "ping":
                    # Respond to ping
                    await websocket.send_json({"type": "pong"})
                
                elif message_type == "subscribe":
                    # Subscribe to specific entity updates
                    entity_id = message.get("entity_id")
                    await websocket.send_json({
                        "type": "subscribed",
                        "entity_id": entity_id,
                        "status": "subscribed"
                    })
                
                elif message_type == "unsubscribe":
                    # Unsubscribe from entity updates
                    entity_id = message.get("entity_id")
                    await websocket.send_json({
                        "type": "unsubscribed",
                        "entity_id": entity_id,
                        "status": "unsubscribed"
                    })
                
                else:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Unknown message type: {message_type}"
                    })
            
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    
    finally:
        await manager.remove_connection(investigation_id, websocket)

async def broadcast_entity_update(investigation_id: int, entity_id: int, update_data: dict):
    """Broadcast entity update to all connected clients"""
    message = {
        "type": "entity_update",
        "investigation_id": investigation_id,
        "entity_id": entity_id,
        "data": update_data
    }
    await manager.broadcast(investigation_id, message)

async def broadcast_relationship_created(investigation_id: int, relationship_data: dict):
    """Broadcast new relationship to all connected clients"""
    message = {
        "type": "relationship_created",
        "investigation_id": investigation_id,
        "data": relationship_data
    }
    await manager.broadcast(investigation_id, message)

async def broadcast_threat_detected(investigation_id: int, threat_data: dict):
    """Broadcast threat detection to all connected clients"""
    message = {
        "type": "threat_detected",
        "investigation_id": investigation_id,
        "severity": threat_data.get("severity"),
        "data": threat_data
    }
    await manager.broadcast(investigation_id, message)

async def broadcast_enrichment_complete(investigation_id: int, entity_id: int, enrichment_data: dict):
    """Broadcast enrichment completion to all connected clients"""
    message = {
        "type": "enrichment_complete",
        "investigation_id": investigation_id,
        "entity_id": entity_id,
        "source": enrichment_data.get("source"),
        "data": enrichment_data
    }
    await manager.broadcast(investigation_id, message)
