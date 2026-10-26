"""
AI Chatbot Router — Cybersecurity Threat Investigation Assistant
"""
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel, Field, field_validator, ConfigDict
from app.core.database import get_db
from app.core.config import settings
from app.models.chat import ChatConversation, ChatMessage
from app.models.user import User
from app.dependencies.auth import get_current_user
from app.services.chatbot_service import chat_with_ai
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/chatbot", tags=["AI Threat Assistant"])

# --- Schemas ---
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    conversation_id: Optional[int] = None
    incident_id: Optional[int] = None

    @field_validator("message")
    @classmethod
    def sanitize_message(cls, v):
        return v.strip()


class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: str
    content: str
    is_mock: bool
    created_at: datetime


class ConversationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    public_id: str
    title: str
    incident_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    message_count: int = 0


class ChatResponse(BaseModel):
    content: str
    is_mock: bool
    provider: str
    conversation_id: int
    conversation_public_id: str
    message_id: int


# --- Endpoints ---

@router.post("/chat", response_model=ChatResponse)
async def send_chat_message(
    req: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Send a message to the AI Threat Assistant.
    Retrieves incident context from the database and returns a grounded response.
    Mock mode is clearly labelled — never misrepresented as real AI.
    """
    result = await chat_with_ai(
        db=db,
        user=current_user,
        conversation_id=req.conversation_id,
        user_message=req.message,
        incident_id=req.incident_id,
    )

    if result.get("error"):
        raise HTTPException(status_code=403, detail=result["content"])

    return result


@router.get("/conversations", response_model=List[ConversationResponse])
def list_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all chat conversations for the current user."""
    convs = (
        db.query(ChatConversation)
        .filter(ChatConversation.user_id == current_user.id)
        .order_by(desc(ChatConversation.updated_at))
        .limit(50)
        .all()
    )
    result = []
    for c in convs:
        msg_count = db.query(ChatMessage).filter(ChatMessage.conversation_id == c.id).count()
        result.append({
            "id": c.id,
            "public_id": c.public_id,
            "title": c.title,
            "incident_id": c.incident_id,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
            "message_count": msg_count,
        })
    return result


@router.get("/conversations/{conv_id}/messages", response_model=List[MessageResponse])
def get_conversation_messages(
    conv_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get messages for a specific conversation. Enforces ownership check."""
    conv = db.query(ChatConversation).filter(
        ChatConversation.id == conv_id,
        ChatConversation.user_id == current_user.id,
    ).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found or access denied")

    messages = (
        db.query(ChatMessage)
        .filter(ChatMessage.conversation_id == conv_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )
    return messages


@router.delete("/conversations/{conv_id}")
def delete_conversation(
    conv_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a conversation and all its messages. Enforces ownership."""
    conv = db.query(ChatConversation).filter(
        ChatConversation.id == conv_id,
        ChatConversation.user_id == current_user.id,
    ).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found or access denied")

    db.delete(conv)
    db.commit()
    return {"status": "success", "message": "Conversation deleted"}
