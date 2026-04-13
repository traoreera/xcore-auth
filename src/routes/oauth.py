from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..repositories.user import UserRepository
from ..schemas.auth import OAuthAuthorizeResponse, OAuthLinkRequest, LoginResponse
from ..schemas.common import MessageResponse
from ..services.audit import AuditService
from ..services.auth import AuthService
from ..services.oauth import OAuthService
from ..services.security import SecurityService
from .deps import get_current_user

SUPPORTED_PROVIDERS = {"google", "github", "microsoft"}


def oauth_router(db, cache, env) -> APIRouter:
    router = APIRouter()

    def _security() -> SecurityService:
        return SecurityService(env["ENCRYPTION_KEY"])

    def _oauth_svc() -> OAuthService:
        return OAuthService(cache, env, _security())

    def _auth_svc() -> AuthService:
        return AuthService(db, cache, env)

    def _audit() -> AuditService:
        return AuditService(db)

    def _base_url(request: Request) -> str:
        return str(request.base_url).rstrip("/")

    # ── Initier l'autorisation ────────────────────────────────

    @router.get("/{provider}", response_model=OAuthAuthorizeResponse)
    async def oauth_authorize(provider: str, request: Request):
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Provider inconnu : {provider}")
        result = await _oauth_svc().get_authorization_url(provider)
        return OAuthAuthorizeResponse(**result)

    # ── Callback après autorisation ───────────────────────────

    @router.get("/{provider}/callback", response_model=LoginResponse)
    async def oauth_callback(
        provider: str,
        code: str,
        state: str,
        request: Request,
        response: Response,
    ):
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        try:
            info = await _oauth_svc().exchange_code(provider, code, state)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

        async with db.session() as session:
            user_repo = UserRepository(session)

            # Chercher compte OAuth existant
            oauth_account = await user_repo.get_oauth_account(provider, info["provider_uid"])

            if oauth_account:
                user = await user_repo.get_by_id(oauth_account.user_id)
            else:
                # Chercher par email ou créer un nouvel utilisateur
                user = await user_repo.get_by_email(info["email"]) or await user_repo.create(
                                        email=info["email"],
                                        first_name=info["first_name"],
                                        last_name=info["last_name"],
                                        is_active=True,
                                        is_verified=True,
                                    )
                # Lier le compte OAuth
                await user_repo.add_oauth_account(
                    user,
                    provider=provider,
                    provider_uid=info["provider_uid"],
                    access_token=info.get("access_token"),
                    refresh_token=info.get("refresh_token"),
                )

        if not user or not user.is_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé.")

        login_resp = await _auth_svc()._issue_tokens(user, False, request, response)
        await _audit().log(f"user.oauth_login.{provider}", True, request, user.id)
        return login_resp

    # ── Lier un compte OAuth à un compte existant ─────────────

    @router.post("/{provider}/link", response_model=MessageResponse)
    async def oauth_link(
        provider: str,
        body: OAuthLinkRequest,
        request: Request,
        user=Depends(get_current_user),
    ):
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status.HTTP_404_NOT_FOUND)

        redirect_uri = f"{_base_url(request)}/auth/oauth/{provider}/callback"
        try:
            info = await _oauth_svc().exchange_code(provider, body.code, body.state)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

        async with db.session() as session:
            user_repo = UserRepository(session)
            existing = await user_repo.get_oauth_account(provider, info["provider_uid"])
            if existing:
                raise HTTPException(status.HTTP_409_CONFLICT, "Ce compte OAuth est déjà lié.")

            db_user = await user_repo.get_by_id(user.id)
            await user_repo.add_oauth_account(
                db_user,
                provider=provider,
                provider_uid=info["provider_uid"],
                access_token=info.get("access_token"),
                refresh_token=info.get("refresh_token"),
            )

        await _audit().log(f"user.oauth_linked.{provider}", True, request, user.id)
        return MessageResponse(message=f"Compte {provider} lié avec succès.")

    return router
