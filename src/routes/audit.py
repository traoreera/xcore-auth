from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from ..schemas import AuditLogOut, AuditFilter, AuditLogPage, PaginatedResponse
from ..services import AuditService
from .deps import require_permission
from datetime import datetime
from uuid import UUID




def audit_router(db, cache, env) -> APIRouter:
    router = APIRouter()

    def _audit() -> AuditService:
        return AuditService(db)

    @router.get(
        "/",
        response_model=AuditLogPage,
        dependencies=[Depends(require_permission("audit:read"))],
    )
    async def list_audit_logs(
        user_id: UUID | None = Query(None),
        action: str | None = Query(None),
        success: bool | None = Query(None),
        ip_address: str | None = Query(None),
        date_from: datetime | None = Query(None),
        date_to: datetime | None = Query(None),
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=200),
    ):
        filters = AuditFilter(
            user_id=user_id,
            action=action,
            success=success,
            ip_address=ip_address,
            date_from=date_from,
            date_to=date_to,
            page=page,
            per_page=per_page,
        )
        rows, total, pages = await _audit().list_paginated(filters)
        return PaginatedResponse(
            items=[AuditLogOut.model_validate(r) for r in rows],
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
        )

    return router
