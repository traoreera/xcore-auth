from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import Field
from .common import BaseSchema, PaginatedResponse


class AuditLogOut(BaseSchema):
    id: int
    user_id: UUID | None = None
    action: str
    ip_address: str | None = None
    user_agent: str | None = None
    geo_country: str | None = None
    success: bool
    metadata: dict = {}
    created_at: datetime


class AuditFilter(BaseSchema):
    user_id: UUID | None = None
    action: str | None = None
    success: bool | None = None
    ip_address: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=200)


AuditLogPage = PaginatedResponse[AuditLogOut]
