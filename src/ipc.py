from uuid import UUID

from xcore.sdk import AutoDispatchMixin, action, ok, validate_payload

from .schemas import auth
from .services.token import TokenService
from .schemas import  user as UserSchemas
from .schemas.session import SessionOutAdmin


class IpcHandler(AutoDispatchMixin):

    @action("verify_token")
    @validate_payload(auth.TokenVerifyRequest, 'dict')
    async def verify_token(self, payload: dict) -> dict:
        data = await TokenService(self.cache, self.ctx.env).verify(payload['token'])
        resp = auth.TokenVerifyResponse(valid=data is not None, user=data)
        return ok(**resp.model_dump())
    
    @action("permission")
    async def has_permission(self, payload: dict) -> dict:
        from .services.rbac import RBACService
        
        req = auth.HasPermissionRequest(**payload)
        allowed = await RBACService(self.db, self.cache).has_permission(
            str(req.user_id), req.permission
        )
        return ok(**auth.HasPermissionResponse(allowed=allowed).model_dump())
    
    @action("get_user")
    async def get_user(self, payload: dict) -> dict:
        from .repositories.user import UserRepository

        async with self.db.session() as session:
            user = await UserRepository(session).get_by_id(UUID(payload["user_id"]))
            if not user:
                return {"error": "Utilisateur introuvable", "code": "not_found"}
            return ok(**UserSchemas.UserOut.model_validate(user).model_dump())

    @action("register_user")
    @validate_payload(auth.RegisterRequest, "dict")
    async def register_user(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.RegisterRequest(**payload)
        result = await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).register(req, None)
        return ok(**result.model_dump())

    @action("forgot_password")
    @validate_payload(auth.ForgotPasswordRequest, "dict")
    async def forgot_password(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.ForgotPasswordRequest(**payload)
        await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).forgot_password(req, None)
        return ok(message="Si cet email existe, un lien vous a été envoyé.")

    @action("reset_password")
    @validate_payload(auth.ResetPasswordRequest, "dict")
    async def reset_password(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.ResetPasswordRequest(**payload)
        await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).reset_password(req, None)
        return ok(message="Mot de passe réinitialisé avec succès.")

    @action("verify_email")
    @validate_payload(auth.VerifyEmailRequest, "dict")
    async def verify_email(self, payload: dict) -> dict:
        from .services.auth import AuthService

        req = auth.VerifyEmailRequest(**payload)
        await AuthService(self.db, self.cache, self.ctx.env, getattr(self, "email", None)).verify_email(req, None)
        return ok(message="Email vérifié avec succès.")

    @action("list_user_sessions")
    async def list_user_sessions(self, payload: dict) -> dict:
        from .services.session import SessionService

        user_id = UUID(payload["user_id"])
        current_session_id = UUID(payload["current_session_id"]) if payload.get("current_session_id") else None
        sessions = await SessionService(self.db, self.cache, self.ctx.env).list_user_sessions(
            user_id=user_id,
            current_session_id=current_session_id,
        )
        items = [SessionOutAdmin.model_validate(s).model_dump(mode="json") for s in sessions]
        return ok(sessions=items)

    @action("revoke_session")
    async def revoke_session(self, payload: dict) -> dict:
        from .services.session import SessionService

        session_id = UUID(payload["session_id"])
        reason = payload.get("reason")
        await SessionService(self.db, self.cache, self.ctx.env).revoke_session(
            session_id=session_id,
            reason=reason,
        )
        return ok(message="Session révoquée.")

    @action("revoke_all_sessions")
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
        return ok(expired_count=count, message="Sessions expirées nettoyées.")
