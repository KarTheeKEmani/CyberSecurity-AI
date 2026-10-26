"""
API Key Management Model (Hashed Storage)
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(50), unique=True, index=True, nullable=False) # e.g. KEY-001
    name = Column(String(255), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by_name = Column(String(255), nullable=False, default="Security Admin")
    key_prefix = Column(String(50), nullable=False) # e.g. cs_live_k8j2n...9xQm
    key_hash = Column(String(255), nullable=False, unique=True, index=True)
    permissions = Column(JSON, nullable=False, default=list) # ["incidents:read", "incidents:write", "logs:ingest"]
    status = Column(String(50), nullable=False, default="active") # active, revoked, expired
    request_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", back_populates="api_keys")
