from fastapi import APIRouter

from .audit import audit_router
from .auth import auth_router
from .oauth import oauth_router
from .rbac import rbac_router
from .sessions import sessions_router
from .users import users_router
from .deps import configure_auth_runtime


def build_router(db, cache, env, email_service=None) -> APIRouter:
    """Assemble tous les sous-routers du plugin auth_user."""
    configure_auth_runtime(env=env, cache=cache)
    router = APIRouter()
    router.include_router(auth_router(db, cache, env, email_service), tags=["Auth"])
    router.include_router(users_router(db, cache, env, email_service), tags=["Users"])
    #router.include_router(users_router(db, cache, env), tags=["Users"])
    router.include_router(rbac_router(db, cache, env), prefix="", tags=["RBAC"])
    router.include_router(
        sessions_router(db, cache, env), prefix="/sessions", tags=["Sessions"]
    )
    router.include_router(
        oauth_router(db, cache, env), prefix="/oauth", tags=["OAuth"]
    )
    router.include_router(
        audit_router(db, cache, env), prefix="/audit-logs", tags=["Audit"]
    )
    return router
