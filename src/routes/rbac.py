from __future__ import annotations
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request, status
from ..schemas import (
    RoleOut, RoleCreate, RoleUpdate,
    PermissionOut, PermissionCreate,
    AssignPermissionRequest,MessageResponse
)

from ..services import RBACService,AuditService
from .deps import require_permission, get_current_user


def rbac_router(db, cache, env) -> APIRouter:
    router = APIRouter()

    def _rbac() -> RBACService:
        return RBACService(db, cache)

    def _audit() -> AuditService:
        return AuditService(db)

    # ── Rôles ─────────────────────────────────────────────────

    @router.get(
        "/roles",
        response_model=list[RoleOut],
        dependencies=[Depends(require_permission("roles:read"))],
    )
    async def list_roles():
        roles = await _rbac().list_roles()
        return [RoleOut.model_validate(r) for r in roles]

    @router.post(
        "/roles",
        response_model=RoleOut,
        status_code=201,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def create_role(body: RoleCreate, request: Request, admin=Depends(get_current_user)):
        role = await _rbac().create_role(body.name, body.description, body.permission_ids)
        await _audit().log("rbac.role_created", True, request, admin.id, {"name": body.name})
        return RoleOut.model_validate(role)

    @router.get(
        "/roles/{role_id}",
        response_model=RoleOut,
        dependencies=[Depends(require_permission("roles:read"))],
    )
    async def get_role(role_id: UUID):
        from ..repositories.role import RoleRepository
        role = await RoleRepository(db).get_by_id(role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Rôle introuvable.")
        return RoleOut.model_validate(role)

    @router.patch(
        "/roles/{role_id}",
        response_model=RoleOut,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def update_role(
        role_id: UUID,
        body: RoleUpdate,
        request: Request,
        admin=Depends(get_current_user),
    ):
        from ..repositories.role import RoleRepository
        repo = RoleRepository(db)
        role = await repo.get_by_id(role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        if role.is_system:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Les rôles système ne peuvent pas être modifiés.")
        updated = await repo.update(role, **body.model_dump(exclude_none=True))
        await _audit().log("rbac.role_updated", True, request, admin.id, {"role_id": str(role_id)})
        return RoleOut.model_validate(updated)

    @router.delete(
        "/roles/{role_id}",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def delete_role(role_id: UUID, request: Request, admin=Depends(get_current_user)):
        from ..repositories.role import RoleRepository
        repo = RoleRepository(db)
        role = await repo.get_by_id(role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        if role.is_system:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Impossible de supprimer un rôle système.")
        await repo.delete(role)
        await _audit().log("rbac.role_deleted", True, request, admin.id, {"role_id": str(role_id)})
        return MessageResponse(message="Rôle supprimé.")

    @router.post(
        "/roles/{role_id}/permissions",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def add_permission_to_role(
        role_id: UUID,
        body: AssignPermissionRequest,
        request: Request,
        admin=Depends(get_current_user),
    ):
        from ..repositories.role import RoleRepository, PermissionRepository
        role = await RoleRepository(db).get_by_id(role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Rôle introuvable.")
        perm = await PermissionRepository(db).get_by_id(body.permission_id)
        if not perm:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Permission introuvable.")
        await RoleRepository(db).add_permission(role, perm)
        await _audit().log("rbac.permission_added_to_role", True, request, admin.id,
                           {"role": str(role_id), "perm": str(body.permission_id)})
        return MessageResponse(message="Permission ajoutée au rôle.")

    @router.delete(
        "/roles/{role_id}/permissions/{perm_id}",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def remove_permission_from_role(
        role_id: UUID,
        perm_id: UUID,
        request: Request,
        admin=Depends(get_current_user),
    ):
        from ..repositories.role import RoleRepository, PermissionRepository
        role = await RoleRepository(db).get_by_id(role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        perm = await PermissionRepository(db).get_by_id(perm_id)
        if not perm:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        await RoleRepository(db).remove_permission(role, perm)
        await _audit().log("rbac.permission_removed_from_role", True, request, admin.id,
                           {"role": str(role_id), "perm": str(perm_id)})
        return MessageResponse(message="Permission retirée du rôle.")

    # ── Permissions ───────────────────────────────────────────

    @router.get(
        "/permissions",
        response_model=list[PermissionOut],
        dependencies=[Depends(require_permission("roles:read"))],
    )
    async def list_permissions():
        perms = await _rbac().list_permissions()
        return [PermissionOut.model_validate(p) for p in perms]

    @router.post(
        "/permissions",
        response_model=PermissionOut,
        status_code=201,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def create_permission(
        body: PermissionCreate,
        request: Request,
        admin=Depends(get_current_user),
    ):
        perm = await _rbac().create_permission(
            body.name, body.resource, body.action, body.description
        )
        await _audit().log("rbac.permission_created", True, request, admin.id, {"name": body.name})
        return PermissionOut.model_validate(perm)

    @router.delete(
        "/permissions/{perm_id}",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("roles:write"))],
    )
    async def delete_permission(perm_id: UUID, request: Request, admin=Depends(get_current_user)):
        from ..repositories.role import PermissionRepository
        repo = PermissionRepository(db)
        perm = await repo.get_by_id(perm_id)
        if not perm:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        await repo.delete(perm)
        await _audit().log("rbac.permission_deleted", True, request, admin.id, {"perm_id": str(perm_id)})
        return MessageResponse(message="Permission supprimée.")

    return router
