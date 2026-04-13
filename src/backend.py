from __future__ import annotations

from fastapi import Request

from xcore.kernel.api.auth import AuthBackend, AuthPayload

from .schemas.user import UserOutWithPermissions
from .services.token import TokenService


class XcoreAuthBackend(AuthBackend):
    """
    Backend d'authentification enregistré dans le kernel xcore.
    Active @require_permission sur toutes les routes des autres plugins.
    """

    def __init__(self, db, cache, env: dict):
        self.db = db
        self.cache = cache
        self.env = env
        self._token_svc = TokenService(cache, env)

    async def decode_token(self, token: str) -> AuthPayload | None:
        user = await self._token_svc.verify(token=token)
        if user:
            return AuthPayload(
                sub=str(user.id), roles=user.roles, permissions=user.permissions
            )
        return None

    async def has_permission(
        self, payload: AuthPayload | UserOutWithPermissions, permission: str
    ) -> bool:
        """
        Vérifie qu'un utilisateur possède une permission donnée.
        Utilisé par @require_permission dans les plugins tiers.
        """
        if isinstance(payload, dict):
            roles = payload.get("roles", [])
            permissions = payload.get("permissions", [])
        else:
            roles = payload.roles
            permissions = payload.permissions

        if "superadmin" in roles:
            return True
        return permission in permissions

    async def extract_token(self, request: Request) -> str | None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        # Fallback : cookie access_token (optionnel)
        return request.cookies.get("access_token")
