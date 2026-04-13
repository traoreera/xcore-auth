from __future__ import annotations
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request, status
from ..schemas import (
    SessionOut, SessionOutAdmin,
    RevokeSessionRequest, RevokeAllSessionsResponse,MessageResponse
)


from ..services import SessionService, AuditService
from .deps import get_current_user, get_session_id, require_permission


def sessions_router(db, cache, env) -> APIRouter:
    router = APIRouter()

    def _session_svc() -> SessionService:
        return SessionService(db, cache, env)

    def _audit() -> AuditService:
        return AuditService(db)

    # ── Sessions utilisateur courant ──────────────────────────

    @router.get("/", response_model=list[SessionOut])
    async def list_my_sessions(
        user=Depends(get_current_user),
        session_id: UUID = Depends(get_session_id),
    ):
        sessions = await _session_svc().list_user_sessions(user.id, session_id)
        return [SessionOut.model_validate(s) for s in sessions]

    @router.delete("/{session_id}", response_model=MessageResponse)
    async def revoke_session(
        session_id: UUID,
        body: RevokeSessionRequest,
        request: Request,
        user=Depends(get_current_user),
    ):
        from ..repositories.session import SessionRepository
        repo = SessionRepository(db)
        session = await repo.get_by_id(session_id)
        if not session:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable.")
        if str(session.user_id) != str(user.id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Session appartenant à un autre utilisateur.")
        await _session_svc().revoke_session(session_id, body.reason or "user_revoked")
        await _audit().log("session.revoke", True, request, user.id, {"session_id": str(session_id)})
        return MessageResponse(message="Session révoquée.")

    @router.delete("/", response_model=RevokeAllSessionsResponse)
    async def revoke_all_sessions(
        request: Request,
        user=Depends(get_current_user),
        current_session_id: UUID = Depends(get_session_id),
    ):
        count = await _session_svc().revoke_all_user_sessions(
            user.id, except_session_id=current_session_id
        )
        await _audit().log("session.revoke_all", True, request, user.id, {"count": count})
        return RevokeAllSessionsResponse(
            revoked_count=count,
            message=f"{count} session(s) révoquée(s).",
        )

    # ── Vue admin ─────────────────────────────────────────────

    @router.get(
        "/all",
        response_model=list[SessionOutAdmin],
        dependencies=[Depends(require_permission("sessions:read"))],
    )
    async def list_all_sessions(page: int = 1, per_page: int = 50):
        from ..repositories.session import SessionRepository
        sessions = await SessionRepository(db).list_all_sessions(page, per_page)
        return [SessionOutAdmin.model_validate(s) for s in sessions]

    return router
