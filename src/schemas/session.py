from __future__ import annotations
from datetime import datetime
from uuid import UUID
from .common import BaseSchema, UUIDMixin


class SessionOut(UUIDMixin):
    ip_address: str | None = None
    user_agent: str | None = None
    geo_country: str | None = None
    geo_city: str | None = None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    is_current: bool = False


class SessionOutAdmin(SessionOut):
    user_id: UUID
    is_active: bool
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    device_fingerprint: str | None = None


class RevokeSessionRequest(BaseSchema):
    reason: str | None = None


class RevokeAllSessionsResponse(BaseSchema):
    revoked_count: int
    message: str
