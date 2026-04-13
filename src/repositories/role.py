from __future__ import annotations

from uuid import UUID

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from ..models import Role, Permission, UserRole


class RoleRepository:
    """
    Reçoit une AsyncSession déjà ouverte.
    La gestion du cycle de vie (commit / rollback / close)
    appartient à l'appelant (le service).
    """

    def __init__(self, session: AsyncSession) -> None:
        self.db = session

    # ------------------------------------------------------------------
    # Lecture
    # ------------------------------------------------------------------

    async def get_by_id(self, role_id: UUID) -> Role | None:
        result = await self.db.execute(
            select(Role)
            .where(Role.id == role_id)
            .options(selectinload(Role.permissions))
        )
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Role | None:
        result = await self.db.execute(
            select(Role)
            .where(Role.name == name)
            .options(selectinload(Role.permissions))
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Role]:
        result = await self.db.execute(
            select(Role).options(selectinload(Role.permissions))
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Écriture
    # ------------------------------------------------------------------

    async def create(
        self,
        name: str,
        description: str | None = None,
        is_system: bool = False,
    ) -> Role:
        role = Role(name=name, description=description, is_system=is_system)
        self.db.add(role)
        await self.db.flush()
        await self.db.refresh(role)
        await self.db.refresh(role, ["permissions"])
        return role

    async def update(self, role: Role, **kwargs) -> Role:
        for k, v in kwargs.items():
            setattr(role, k, v)
        role = await self.db.merge(role)
        await self.db.flush()
        await self.db.refresh(role)
        await self.db.refresh(role, ["permissions"])
        return role

    async def delete(self, role: Role) -> None:
        role = await self.db.merge(role)
        await self.db.delete(role)
        await self.db.flush()

    # ------------------------------------------------------------------
    # Permissions sur un rôle
    # ------------------------------------------------------------------

    async def add_permission(self, role: Role, permission: Permission) -> None:
        await self.db.refresh(role, ["permissions"])
        if permission not in role.permissions:
            role.permissions.append(permission)
            await self.db.flush()

    async def remove_permission(self, role: Role, permission: Permission) -> None:
        await self.db.refresh(role, ["permissions"])
        if permission in role.permissions:
            role.permissions.remove(permission)
            await self.db.flush()

    # ------------------------------------------------------------------
    # Rôles utilisateur
    # ------------------------------------------------------------------

    async def get_user_roles(self, user_id: UUID) -> list[Role]:
        result = await self.db.execute(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .options(selectinload(Role.permissions))
        )
        return list(result.scalars().all())

    async def assign_role_to_user(
        self,
        user_id: UUID,
        role_id: UUID,
        assigned_by: UUID | None = None,
    ) -> UserRole:
        existing = await self.db.execute(
            select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id,
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("Rôle déjà assigné à cet utilisateur.")

        ur = UserRole(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
        )
        self.db.add(ur)
        await self.db.flush()
        await self.db.refresh(ur)
        return ur

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> None:
        await self.db.execute(
            delete(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id,
            )
        )
        await self.db.flush()


# ======================================================================


class PermissionRepository:
    """
    Reçoit une AsyncSession déjà ouverte.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.db = session

    # ------------------------------------------------------------------
    # Lecture
    # ------------------------------------------------------------------

    async def get_by_id(self, perm_id: UUID) -> Permission | None:
        result = await self.db.execute(
            select(Permission).where(Permission.id == perm_id)
        )
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Permission | None:
        result = await self.db.execute(
            select(Permission).where(Permission.name == name)
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Permission]:
        result = await self.db.execute(select(Permission))
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Écriture
    # ------------------------------------------------------------------

    async def create(
        self,
        name: str,
        resource: str,
        action: str,
        description: str | None = None,
    ) -> Permission:
        perm = Permission(
            name=name,
            resource=resource,
            action=action,
            description=description,
        )
        self.db.add(perm)
        await self.db.flush()
        await self.db.refresh(perm)
        return perm

    async def delete(self, perm: Permission) -> None:
        perm = await self.db.merge(perm)
        await self.db.delete(perm)
        await self.db.flush()