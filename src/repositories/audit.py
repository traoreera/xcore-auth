from __future__ import annotations
from uuid import UUID
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..models import AuditLog
from ..schemas import AuditFilter


class AuditRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        action: str,
        success: bool,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        geo_country: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLog:
        log = AuditLog(
            action=action,
            success=success,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            geo_country=geo_country,
            metadata_=metadata or {},
        )  
        self.db.add(log)
        await self.db.commit()
        return log

    async def list_paginated(
        self, filters: AuditFilter
    ) -> tuple[list[AuditLog], int]:
        q = select(AuditLog)

        if filters.user_id:
            q = q.where(AuditLog.user_id == filters.user_id)
        if filters.action:
            q = q.where(AuditLog.action == filters.action)
        if filters.success is not None:
            q = q.where(AuditLog.success == filters.success)
        if filters.ip_address:
            q = q.where(AuditLog.ip_address == filters.ip_address)
        if filters.date_from:
            q = q.where(AuditLog.created_at >= filters.date_from)
        if filters.date_to:
            q = q.where(AuditLog.created_at <= filters.date_to)
        
        count_q = select(func.count()).select_from(q.subquery())
        total = (await self.db.execute(count_q)).scalar_one()

        q = q.order_by(AuditLog.created_at.desc())
        q = q.offset((filters.page - 1) * filters.per_page).limit(filters.per_page)
        rows = (await self.db.execute(q)).scalars().all()

        return list(rows), total
