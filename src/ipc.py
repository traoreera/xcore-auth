from xcore.sdk import AutoDispatchMixin, action, ok, validate_payload

from .schemas import auth
from .services.token import TokenService
from .schemas import  user as UserSchemas
from uuid import UUID


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