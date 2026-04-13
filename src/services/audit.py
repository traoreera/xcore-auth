from __future__ import annotations
from uuid import UUID
from fastapi import Request
from ..repositories.audit import AuditRepository
from ..schemas import AuditFilter


class AuditService:
    def __init__(self, db):
        self.db = db

    def _repo(self, session) -> AuditRepository:
        return AuditRepository(session)

    async def log(
        self,
        action: str,
        success: bool,
        request: Request | None = None,
        user_id: UUID | None = None,
        metadata: dict | None = None,
    ) -> None:
        ip_address = None
        user_agent = None
        geo_country = None

        if request:
            forwarded = request.headers.get("X-Forwarded-For")
            ip_address = forwarded.split(",")[0].strip() if forwarded else (
                request.client.host if request.client else None
            )
            user_agent = request.headers.get("User-Agent")

        async with self.db.session() as session:
            await self._repo(session).create(
                action=action,
                success=success,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                geo_country=geo_country,
                metadata=metadata or {},
            )

    async def list_paginated(self, filters: AuditFilter):
        async with self.db.session() as session:
            rows, total = await self._repo(session).list_paginated(filters)
            pages = (total + filters.per_page - 1) // filters.per_page
            return rows, total, pages
