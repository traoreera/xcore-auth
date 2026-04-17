from __future__ import annotations
from fastapi import APIRouter
from xcore.sdk import TrustedBase, ok, error
from xcore.kernel.api.auth import register_auth_backend, unregister_auth_backend

from .schemas import auth
from .schemas import user as UserSchemas
from .ipc import IpcHandler

class Plugin(IpcHandler, TrustedBase):

    def _xflow_integration_contract(self) -> dict:
        return {
            "plugin": "auth",
            "display_name": "Auth",
            "description": "Central IAM plugin for identity, permissions and user lookup.",
            "xflow_supported": True,
            "ipc_actions": [
                {"name": "verify_token", "qualified_name": "auth.verify_token", "input_schema": {"token": "string"}},
                {"name": "permission", "qualified_name": "auth.permission", "input_schema": {"user_id": "string(uuid)", "permission": "string"}},
                {"name": "get_user", "qualified_name": "auth.get_user", "input_schema": {"user_id": "string(uuid)"}},
                {"name": "register_user", "qualified_name": "auth.register_user", "input_schema": {"email": "email", "password": "string", "first_name": "string", "last_name": "string"}},
                {"name": "forgot_password", "qualified_name": "auth.forgot_password", "input_schema": {"email": "email"}},
                {"name": "reset_password", "qualified_name": "auth.reset_password", "input_schema": {"token": "string", "new_password": "string", "new_password_confirm": "string"}},
                {"name": "verify_email", "qualified_name": "auth.verify_email", "input_schema": {"token": "string"}},
                {"name": "list_user_sessions", "qualified_name": "auth.list_user_sessions", "input_schema": {"user_id": "string(uuid)", "current_session_id": "string(uuid)|optional"}},
                {"name": "revoke_session", "qualified_name": "auth.revoke_session", "input_schema": {"session_id": "string(uuid)", "reason": "string|optional"}},
                {"name": "revoke_all_sessions", "qualified_name": "auth.revoke_all_sessions", "input_schema": {"user_id": "string(uuid)", "except_session_id": "string(uuid)|optional"}},
                {"name": "cleanup_sessions", "qualified_name": "auth.cleanup_sessions", "input_schema": {}}
            ],
            "events": {
                "listens": ["auth.get.user.ids"],
                "emits": ["auth.sessions.expired", "auth_user.loaded"]
            },
            "http_routes": [
                {"path": "/xflow/integration", "methods": ["GET"]},
                {"path": "/oauth/*", "methods": ["GET", "POST"]},
                {"path": "/sessions/*", "methods": ["GET", "POST", "DELETE"]},
                {"path": "/audit-logs/*", "methods": ["GET"]},
                {"path": "/users/*", "methods": ["GET", "POST", "PATCH", "DELETE"]}
            ]
        }

    async def on_load(self):
        self.db    = self.get_service("db")
        self.cache = self.get_service("cache")
        self.sched = self.get_service("scheduler")
        try:
            self.email = self.get_service("ext.email")
        except:
            self.email = None 
        env = self.ctx.env
        event = self.ctx.events

        # 1. Migrations automatiques au démarrage #TODO: xcore a du mal avec les migrations auto, à revoir
        #from xcore.services.database.migrations import MigrationRunner
        #await MigrationRunner(env["DATABASE_URL"], "./data/migrations").upgrade()
        
        @event.on("auth.get.user.ids")
        async def users_ids(event):
            from .repositories.user import UserRepository
            async with self.db.session() as sess :
                repo = UserRepository(sess)
                rps = await repo.get_users_ids()
            return rps
        from .models.base import Base
        async with self.db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # 2. Seed des rôles et permissions système
        from .services.rbac import RBACService
        await RBACService(self.db, self.cache).seed_system_roles()

        # 3. Enregistrer le backend d'auth → active @require_permission globalement
        from .backend import XcoreAuthBackend
        register_auth_backend(XcoreAuthBackend(self.db, cache=self.cache, env=self.ctx.env))

        XcoreAuthBackend(self.db, self.cache, env)

        # 4. Job de nettoyage des sessions expirées (toutes les heures)
        @self.sched.cron("0 * * * *", 'auth.clean.oldsession')
        async def cleanup_sessions():
            from .repositories.session import SessionRepository
            async with self.db.session() as session:
                count = await SessionRepository(session).expire_old()
                await self.ctx.events.emit("auth.sessions.expired", {"count": count})

        # 5. Health checks
        self._register_health()

        # 6. Métriques Prometheus
        self._register_metrics()

        await self.ctx.events.emit("auth_user.loaded", {"plugin": "auth_user", "version": "0.1.0"})

    async def on_unload(self):
        unregister_auth_backend()


    def get_router(self) -> APIRouter:
        from .routes import build_router
        router = build_router(self.db, self.cache, self.ctx.env, self.email)

        @router.get("/xflow/integration", tags=["xflow", "auth"])
        async def xflow_integration():
            return self._xflow_integration_contract()

        return router



    async def _verify_token(self, payload: dict) -> dict:
        req = auth.TokenVerifyRequest(**payload)
        from .services.token import TokenService
        data = await TokenService(self.cache, self.ctx.env).verify(req.token)
        resp = auth.TokenVerifyResponse(valid=data is not None, user=data)
        return ok(**resp.model_dump())

    async def _has_permission(self, payload: dict) -> dict:
        req = auth.HasPermissionRequest(**payload)
        from .services.rbac import RBACService
        allowed = await RBACService(self.db, self.cache).has_permission(
            str(req.user_id), req.permission
        )
        return ok(**auth.HasPermissionResponse(allowed=allowed).model_dump())

    async def _get_user(self, payload: dict) -> dict:
        from .repositories.user import UserRepository
        from uuid import UUID
        async with self.db.session() as session:
            user = await UserRepository(session).get_by_id(UUID(payload["user_id"]))
            if not user:
                return error("Utilisateur introuvable", "not_found")
            return ok(**UserSchemas.UserOut.model_validate(user).model_dump())

    # ── Health checks ─────────────────────────────────────────

    def _register_health(self):
        @self.ctx.health.register("auth_user.db")
        async def check_db():
            try:
                async with self.db.session() as db : await db.execute("SELECT 1")
                return True, "ok"
            except Exception as e:
                return False, str(e)
        @self.ctx.health.register("auth_user.cache")
        async def check_cache():
            try:
                ok_ = await self.cache._backend.ping()
                return ok_, "ok" if ok_ else "unreachable"
            except Exception as e:
                return False, str(e)

    # ── Métriques ─────────────────────────────────────────────

    def _register_metrics(self):
        m = self.ctx.metrics
        self.m_logins   = m.counter("auth.logins_total",labels=["Nombre total de connexions réussies"])
        self.m_failures = m.counter("auth.login_failures_total",labels=["Nombre total d'échecs de connexion"])
        self.m_mfa      = m.counter("auth.mfa_verifications_total", labels=["Vérifications MFA effectuées"])
        self.m_tokens   = m.counter("auth.tokens_issued_total",labels=["Tokens JWT émis"])
        self.m_latency  = m.histogram("auth.request_duration_seconds")
        self.g_sessions = m.gauge("auth.active_sessions",labels=["Sessions actives courantes"])
