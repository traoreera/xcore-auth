from __future__ import annotations
from datetime import datetime
from uuid import UUID
from sqlalchemy import BigInteger, Integer, String, Boolean, Text, ForeignKey, DateTime, func, Index
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, INET, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(Text)
    geo_country: Mapped[str | None] = mapped_column(String(3))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User | None"] = relationship(back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_user_date", "user_id", "created_at"),
        Index("idx_audit_action_date", "action", "created_at"),
    )
