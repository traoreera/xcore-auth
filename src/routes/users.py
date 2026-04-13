from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from ..repositories import UserRepository
from ..schemas import (
    AssignRoleRequest,
    PasswordChange,
    UserCreate,
    UserCreateAdmin,
    UserOut,
    UserOutAdmin,
    UserUpdate,
    UserUpdateAdmin,MessageResponse, PaginatedResponse
)
from ..services import AuditService, EmailService, PasswordService, RBACService
from .deps import get_current_user, require_permission


def users_router(db, cache, env, email_service=None) -> APIRouter:
    router = APIRouter()

    def _password_svc() -> PasswordService:
        return PasswordService(
            pwned_check_enabled=env.get("PWNED_CHECK_ENABLED", "true").lower() == "true"
        )

    def _email_svc() -> EmailService:
        return EmailService(env, email_service)

    # ── Profil courant ────────────────────────────────────────

    @router.get("/me", response_model=UserOut)
    async def get_me(user=Depends(get_current_user)):
        async with db.session() as session:
            repo = UserRepository(session)
            db_user = await repo.get_by_id(user.id)
            if not db_user:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")
            return UserOut.model_validate(db_user)

    @router.patch("/me", response_model=UserOut)
    async def update_me(
        body: UserUpdate,
        request: Request,
        user=Depends(get_current_user),
    ):
        async with db.session() as session:
            repo = UserRepository(session)
            db_user = await repo.get_by_id(user.id)
            if not db_user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)
            updates = body.model_dump(exclude_none=True)
            updated = await repo.update(db_user, **updates)
            await AuditService(db).log("user.update_self", True, request, user.id, updates)
            return UserOut.model_validate(updated)

    @router.patch("/me/password", response_model=MessageResponse)
    async def change_password(
        body: PasswordChange,
        request: Request,
        user=Depends(get_current_user),
    ):
        async with db.session() as session:
            repo = UserRepository(session)
            psvc = _password_svc()
            db_user = await repo.get_by_id(user.id)
            if not db_user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)
            if not psvc.verify(body.current_password, db_user.password_hash or ""):
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED, "Mot de passe actuel incorrect."
                )
            if await psvc.is_pwned(body.new_password):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY, "Mot de passe compromis."
                )
            new_hash = psvc.hash(body.new_password)
            await repo.update(db_user, password_hash=new_hash)
            await AuditService(db).log("user.password_changed", True, request, user.id)
            return MessageResponse(message="Mot de passe modifié avec succès.")

    @router.delete("/me", response_model=MessageResponse)
    async def delete_me(
        request: Request,
        user=Depends(get_current_user),
    ):
        async with db.session() as session:
            repo = UserRepository(session)
            db_user = await repo.get_by_id(user.id)
            if not db_user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)
            await repo.delete(db_user)
            await AuditService(db).log("user.delete_self", True, request, user.id)
            return MessageResponse(message="Compte supprimé.")

    # ── Administration ────────────────────────────────────────

    @router.get(
        "/",
        response_model=PaginatedResponse[UserOutAdmin],
        dependencies=[Depends(require_permission("users:list"))],
    )
    async def list_users(
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=200),
        search: str | None = Query(None),
    ):
        async with db.session() as session:
            repo = UserRepository(session)
            users, total = await repo.list_paginated(page, per_page, search)
            pages = (total + per_page - 1) // per_page
            items = [UserOutAdmin.model_validate(u) for u in users]
            return PaginatedResponse(
                items=items,
                total=total,
                page=page,
                per_page=per_page,
                pages=pages,
            )

    @router.post(
        "/",
        response_model=UserOutAdmin,
        status_code=201,
        dependencies=[Depends(require_permission("users:write"))],
    )
    async def create_user(body: UserCreateAdmin, request: Request):
        async with db.session() as session:
            repo = UserRepository(session)
            existing = await repo.get_by_email(body.email)
            if existing:
                raise HTTPException(status.HTTP_409_CONFLICT, "Email déjà utilisé.")

            psvc = _password_svc()
            if body.password:
                password_hash = psvc.hash(body.password)
            else:
                import secrets

                temp_pwd = secrets.token_urlsafe(12)
                password_hash = psvc.hash(temp_pwd)
                if body.send_welcome_email:
                    email_svc = _email_svc()
                    await email_svc.send_welcome_email(
                        body.email, body.first_name, temp_pwd
                    )

            user = await repo.create(
                email=body.email,
                password_hash=password_hash,
                first_name=body.first_name,
                last_name=body.last_name,
                is_active=body.is_active,
                is_verified=True,
            )

            # Assigner le rôle
            rbac_svc = RBACService(db, cache)
            _role_repo, _ = rbac_svc._repos(session)
            role = await _role_repo.get_by_name(body.role.value)
            if role:
                await _role_repo.assign_role_to_user(
                    UUID(user.id) if isinstance(user.id, str) else user.id,
                    UUID(role.id) if isinstance(role.id, str) else role.id
                )

            await AuditService(db).log("user.create_admin", True, request, user.id)
            return UserOutAdmin.model_validate(user)

    @router.get(
        "/{user_id}",
        response_model=UserOutAdmin,
        dependencies=[Depends(require_permission("users:read"))],
    )
    async def get_user(user_id: UUID):
        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get_by_id(user_id)
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")
            return UserOutAdmin.model_validate(user)

    @router.patch(
        "/{user_id}",
        response_model=UserOutAdmin,
        dependencies=[Depends(require_permission("users:write"))],
    )
    async def update_user(
        user_id: UUID,
        body: UserUpdateAdmin,
        request: Request,
        admin=Depends(get_current_user),
    ):
        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get_by_id(user_id)
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)
            updates = body.model_dump(exclude_none=True)
            updated = await repo.update(user, **updates)
            await AuditService(db).log(
                "user.update_admin",
                True,
                request,
                admin.id,
                {"target": str(user_id), **updates},
            )
            return UserOutAdmin.model_validate(updated)

    @router.delete(
        "/{user_id}",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("users:delete"))],
    )
    async def delete_user(
        user_id: UUID, request: Request, admin=Depends(get_current_user)
    ):
        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get_by_id(user_id)
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)
            await repo.delete(user)
            await AuditService(db).log(
                "user.delete_admin", True, request, admin.id, {"target": str(user_id)}
            )
            return MessageResponse(message="Utilisateur supprimé.")

    # ── Rôles utilisateur ─────────────────────────────────────

    @router.post(
        "/{user_id}/roles",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("users:write"))],
    )
    async def assign_role(
        user_id: UUID,
        body: AssignRoleRequest,
        request: Request,
        admin=Depends(get_current_user),
    ):
        from ..schemas.rbac import AssignRoleRequest

        body = AssignRoleRequest(**body.model_dump())
        rbac_svc = RBACService(db, cache)
        await rbac_svc.assign_role(user_id, body.role_id, admin.id)
        await AuditService(db).log(
            "rbac.role_assigned",
            True,
            request,
            admin.id,
            {"user": str(user_id), "role": str(body.role_id)},
        )
        return MessageResponse(message="Rôle assigné.")

    @router.delete(
        "/{user_id}/roles/{role_id}",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("users:write"))],
    )
    async def remove_role(
        user_id: UUID,
        role_id: UUID,
        request: Request,
        admin=Depends(get_current_user),
    ):
        rbac_svc = RBACService(db, cache)
        await rbac_svc.remove_role(user_id, role_id)
        await AuditService(db).log(
            "rbac.role_removed",
            True,
            request,
            admin.id,
            {"user": str(user_id), "role": str(role_id)},
        )
        return MessageResponse(message="Rôle retiré.")

    return router
