from __future__ import annotations

import json
from uuid import UUID

from ..repositories import RoleRepository, PermissionRepository
from ..models import Role, Permission
from xcore.services.database import AsyncSQLAdapter

# Rôles système créés au démarrage
SYSTEM_ROLES = [
    {
        "name": "superadmin",
        "description": "Accès total au système",
        "permissions": [],  # toutes les permissions implicitement
    },
    {
        "name": "admin",
        "description": "Administration standard",
        "permissions": [
            ("users:list",    "users",    "list"),
            ("users:read",    "users",    "read"),
            ("users:write",   "users",    "write"),
            ("users:delete",  "users",    "delete"),
            ("roles:read",    "roles",    "read"),
            ("sessions:read", "sessions", "read"),
            ("audit:read",    "audit",    "read"),
        ],
    },
    {
        "name": "standard",
        "description": "Utilisateur standard",
        "permissions": [],
    },
]


class RBACService:
    def __init__(self, db: AsyncSQLAdapter, cache):
        self.db = db
        self.cache = cache

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _repos(self, session):
        """Crée les deux repos liés à une session déjà ouverte."""
        return RoleRepository(session), PermissionRepository(session)

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    async def seed_system_roles(self) -> None:
        """Crée les rôles et permissions système dans une seule transaction."""
        async with self.db.session() as session:
            role_repo, perm_repo = self._repos(session)

            for role_def in SYSTEM_ROLES:
                role = await role_repo.get_by_name(role_def["name"]) or await role_repo.create(
                                        name=role_def["name"],
                                        description=role_def["description"],
                                        is_system=True,
                                    )

                for perm_name, resource, action in role_def.get("permissions", []):
                    perm = await perm_repo.get_by_name(perm_name) or await perm_repo.create(
                                                name=perm_name,
                                                resource=resource,
                                                action=action,
                                            )
                    await role_repo.add_permission(role, perm)
            # Le commit est effectué automatiquement à la sortie du bloc
            # par l'AsyncSQLAdapter (@asynccontextmanager → await sess.commit())

    # ------------------------------------------------------------------
    # Permissions utilisateur
    # ------------------------------------------------------------------

    async def get_user_permissions(self, user_id: str) -> set[str]:
        cache_key = f"au:user:{user_id}:perms"
        cached = await self.cache.get(cache_key)
        if cached:
            return set(json.loads(cached))

        async with self.db.session() as session:
            role_repo, perm_repo = self._repos(session)
            roles = await role_repo.get_user_roles(UUID(user_id))
            perms: set[str] = set()
            for role in roles:
                if role.name == "superadmin":
                    all_perms = await perm_repo.list_all()
                    perms = {p.name for p in all_perms}
                    break
                for perm in role.permissions:
                    perms.add(perm.name)

        await self.cache.set(cache_key, json.dumps(list(perms)), ttl=300)
        return perms

    async def get_user_role_names(self, user_id: str) -> list[str]:
        cache_key = f"au:user:{user_id}:roles"
        cached = await self.cache.get(cache_key)
        if cached:
            return json.loads(cached)

        async with self.db.session() as session:
            role_repo, _ = self._repos(session)
            roles = await role_repo.get_user_roles(UUID(user_id))
            names = [r.name for r in roles]

        await self.cache.set(cache_key, json.dumps(names), ttl=300)
        return names

    async def has_permission(self, user_id: str, permission: str) -> bool:
        perms = await self.get_user_permissions(user_id)
        return permission in perms

    async def invalidate_user_cache(self, user_id: str) -> None:
        await self.cache.delete(f"au:user:{user_id}:perms")
        await self.cache.delete(f"au:user:{user_id}:roles")
        await self.cache.delete(f"au:user:{user_id}:profile")

    # ------------------------------------------------------------------
    # Gestion des rôles utilisateur
    # ------------------------------------------------------------------

    async def assign_role(
        self,
        user_id: UUID,
        role_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        async with self.db.session() as session:
            role_repo, _ = self._repos(session)
            await role_repo.assign_role_to_user(user_id, role_id, assigned_by)
        await self.invalidate_user_cache(str(user_id))

    async def remove_role(self, user_id: UUID, role_id: UUID) -> None:
        async with self.db.session() as session:
            role_repo, _ = self._repos(session)
            await role_repo.remove_role_from_user(user_id, role_id)
        await self.invalidate_user_cache(str(user_id))

    # ------------------------------------------------------------------
    # CRUD rôles / permissions
    # ------------------------------------------------------------------

    async def list_roles(self) -> list[Role]:
        async with self.db.session() as session:
            return await RoleRepository(session).list_all()

    async def list_permissions(self) -> list[Permission]:
        async with self.db.session() as session:
            return await PermissionRepository(session).list_all()

    async def create_role(
        self,
        name: str,
        description: str | None,
        permission_ids: list[UUID],
    ) -> Role:
        async with self.db.session() as session:
            role_repo, perm_repo = self._repos(session)
            role = await role_repo.create(name=name, description=description)
            for pid in permission_ids:
                perm = await perm_repo.get_by_id(pid)
                if perm:
                    await role_repo.add_permission(role, perm)
        return role

    async def create_permission(
        self,
        name: str,
        resource: str,
        action: str,
        description: str | None,
    ) -> Permission:
        async with self.db.session() as session:
            return await PermissionRepository(session).create(
                name, resource, action, description
            )