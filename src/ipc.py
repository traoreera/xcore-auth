from uuid import UUID

from xcore.sdk import AutoDispatchMixin, action, error, ok

from .schemas import auth
from .services.token import TokenService
from .schemas import  user as UserSchemas
from .schemas.session import SessionOutAdmin


class IpcHandler(AutoDispatchMixin):

    @action("verify.user.token")
    async def verify_token(self, payload: dict) -> dict:
        data = await TokenService(self.cache, self.ctx.env).verify(payload['token'])
        resp = auth.TokenVerifyResponse(valid=data is not None, user=data)
        return ok(data=resp.model_dump())
    
    @action("user.permission.verify")
    async def has_permission(self, payload: dict) -> dict:
        from .services.rbac import RBACService
        
        req = auth.HasPermissionRequest(**payload)
        allowed = await RBACService(self.db, self.cache).has_permission(
            str(req.user_id), req.permission
        )
        return ok(**auth.HasPermissionResponse(allowed=allowed).model_dump())
    
    @action("search.user")
    async def get_user(self, payload: dict) -> dict:
        from .repositories.user import UserRepository

        async with self.db.session() as session:
            user = await UserRepository(session).get_by_id(UUID(payload["user_id"]))
            if not user:
                return error(data={"error": "Utilisateur introuvable", "code": "not_found"}, msg="Utilisateur introuvable", code="not_found")
            return ok(data=UserSchemas.UserOut.model_validate(user).model_dump())

    @action("register_user")
    async def register_user(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.RegisterRequest(**payload)
        result = await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).register(req, None)
        return ok(data=result.model_dump())

    @action("user.forgot.password")
    async def forgot_password(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.ForgotPasswordRequest(**payload)
        await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).forgot_password(req, None)
        return ok(
            data={
                "msg": "Si cet email existe, un lien vous a été envoyé."
            }
        )


    @action("verify.user.email")
    async def verify_email(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.VerifyEmailRequest(**payload)
        await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).verify_email(req, None)
        return ok(
            data={
                "msg":"Email vérifié avec succès."
            }
        )

    @action("list.user.sessions")
    async def list_user_sessions(self, payload: dict) -> dict:
        from .services.session import SessionService

        user_id = UUID(payload["user_id"])
        current_session_id = UUID(payload["current_session_id"]) if payload.get("current_session_id") else None
        sessions = await SessionService(self.db, self.cache, self.ctx.env).list_user_sessions(
            user_id=user_id,
            current_session_id=current_session_id,
        )
        items = [SessionOutAdmin.model_validate(s).model_dump(mode="json") for s in sessions]
        return ok(data=items)

    @action("revoke.user.session")
    async def revoke_session(self, payload: dict) -> dict:
        from .services.session import SessionService

        session_id = UUID(payload["session_id"])
        reason = payload.get("reason")
        await SessionService(self.db, self.cache, self.ctx.env).revoke_session(
            session_id=session_id,
            reason=reason,
        )
        return ok(
            data={
                "msg":"Session révoquée."
            }
        )

    @action("revoke.all.user.sessions")
    async def revoke_all_sessions(self, payload: dict) -> dict:
        from .services.session import SessionService

        user_id = UUID(payload["user_id"])
        except_session_id = UUID(payload["except_session_id"]) if payload.get("except_session_id") else None
        count = await SessionService(self.db, self.cache, self.ctx.env).revoke_all_user_sessions(
            user_id=user_id,
            except_session_id=except_session_id,
        )
        return ok(revoked_count=count, message="Sessions révoquées.")

    @action("cleanup_sessions")
    async def cleanup_sessions(self, payload: dict) -> dict:
        from .repositories.session import SessionRepository

        async with self.db.session() as session:
            count = await SessionRepository(session).expire_old()
        return ok(
            data={
                "expired_count":count, 
                "msg":"Sessions expirées nettoyées."
            }
        )
