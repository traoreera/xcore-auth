from __future__ import annotations
from uuid import UUID
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ..services import TokenService
from ..schemas import UserOutWithPermissions

bearer_scheme = HTTPBearer(auto_error=False)
_runtime_env: dict | None = None
_runtime_cache = None


def configure_auth_runtime(*, env: dict, cache) -> None:
    global _runtime_env, _runtime_cache
    _runtime_env = env
    _runtime_cache = cache


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> UserOutWithPermissions:
    """Extrait et valide l'access token. Injecte le user courant."""
    token = None
    if credentials:
        token = credentials.credentials
    if not token:
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip() or None

    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token manquant.")

    env = getattr(request.app.state, "xcore_env", None) or _runtime_env
    cache = getattr(request.app.state, "xcore_cache", None) or _runtime_cache
    if env is None or cache is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Configuration auth indisponible.",
        )
    token_svc = TokenService(cache, env)
    user = await token_svc.verify(token)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token invalide ou expiré.")
    return user


def require_permission(permission: str):
    """Dépendance FastAPI qui vérifie qu'un utilisateur a une permission donnée."""
    async def _check(user: UserOutWithPermissions = Depends(get_current_user)):
        if permission not in user.permissions and "superadmin" not in user.roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Permission requise : {permission}",
            )
        return user
    return _check


def get_session_id(user: UserOutWithPermissions = Depends(get_current_user)) -> UUID:
    """Extrait session_id depuis le payload JWT."""
    return UUID(user.model_extra.get("session_id", str(UUID(int=0))))
