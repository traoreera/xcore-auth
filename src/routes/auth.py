from __future__ import annotations
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MagicLinkRequest,
    MFABackupCodesResponse,
    MFADisableRequest,
    MFAEnableResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,MessageResponse
)

from ..services import AuthService,SecurityService
from .deps import get_current_user, get_session_id


def auth_router(db, cache, env, email_service=None) -> APIRouter:
    router = APIRouter()

    def _auth_svc() -> AuthService:
        return AuthService(db, cache, env, email_service)

    # ── Inscription / Connexion ───────────────────────────────

    @router.post("/register", response_model=RegisterResponse, status_code=201)
    async def register(body: RegisterRequest, request: Request):
        return await _auth_svc().register(body, request)

    @router.post("/login", response_model=LoginResponse)
    async def login(body: LoginRequest, request: Request, response: Response):
        return await _auth_svc().login(body, request, response)

    @router.post("/logout", response_model=MessageResponse)
    async def logout(
        body: LogoutRequest,
        request: Request,
        response: Response,
        user=Depends(get_current_user),
        session_id: UUID = Depends(get_session_id),
    ):
        await _auth_svc().logout(
            logout_all=body.logout_all,
            user_id=user.id,
            session_id=session_id,
            request=request,
            response=response,
        )
        return MessageResponse(message="Déconnecté avec succès.")

    @router.post("/refresh", response_model=RefreshResponse)
    async def refresh(body: RefreshRequest, request: Request, response: Response):
        return await _auth_svc().refresh(body, request, response)

    # ── Mot de passe ──────────────────────────────────────────

    @router.post("/forgot-password", response_model=MessageResponse)
    async def forgot_password(body: ForgotPasswordRequest, request: Request):
        await _auth_svc().forgot_password(body, request)
        return MessageResponse(
            message="Si cet email existe, un lien vous a été envoyé."
        )

    @router.post("/reset-password", response_model=MessageResponse)
    async def reset_password(body: ResetPasswordRequest, request: Request):
        await _auth_svc().reset_password(body, request)
        return MessageResponse(message="Mot de passe réinitialisé avec succès.")

    # ── Vérification email ────────────────────────────────────

    @router.post("/verify-email", response_model=MessageResponse)
    async def verify_email(body: VerifyEmailRequest, request: Request):
        await _auth_svc().verify_email(body, request)
        return MessageResponse(message="Email vérifié avec succès.")

    @router.post("/resend-verification", response_model=MessageResponse)
    async def resend_verification(body: ResendVerificationRequest, request: Request):
        from datetime import UTC, datetime, timedelta

        from ..repositories.session import EmailTokenRepository
        from ..repositories.user import UserRepository
        from ..services.email import EmailService

        async with db.session() as session:
            user_repo = UserRepository(session)
            email_token_repo = EmailTokenRepository(session)
            email_svc = EmailService(env, email_service)
            security = SecurityService(env["ENCRYPTION_KEY"])

            user = await user_repo.get_by_email(body.email)
            if user and not user.is_verified:
                await email_token_repo.delete_user_tokens(user.id, "verify_email")
                token = security.generate_token()
                token_hash = security.hash_token(token)
                await email_token_repo.create(
                    user_id=user.id,
                    token_hash=token_hash,
                    type="verify_email",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
                await email_svc.send_verification_email(user.email, token, user.first_name)
        return MessageResponse(
            message="Si votre compte existe et n'est pas vérifié, un email vous a été envoyé."
        )

    # ── Magic link ────────────────────────────────────────────

    @router.post("/magic-link", response_model=MessageResponse)
    async def magic_link(body: MagicLinkRequest, request: Request):
        from datetime import UTC, datetime, timedelta

        from ..repositories.session import EmailTokenRepository
        from ..repositories.user import UserRepository
        from ..services.email import EmailService

        async with db.session() as session:
            user_repo = UserRepository(session)
            email_token_repo = EmailTokenRepository(session)
            email_svc = EmailService(env, email_service)
            security = SecurityService(env["ENCRYPTION_KEY"])

            user = await user_repo.get_by_email(body.email)
            if user and user.is_active:
                await email_token_repo.delete_user_tokens(user.id, "magic_link")
                token = security.generate_token()
                token_hash = security.hash_token(token)
                await email_token_repo.create(
                    user_id=user.id,
                    token_hash=token_hash,
                    type="magic_link",
                    expires_at=datetime.now(UTC) + timedelta(minutes=15),
                )
                redirect = str(body.redirect_url) if body.redirect_url else None
                await email_svc.send_magic_link_email(user.email, token, redirect)
        return MessageResponse(
            message="Si cet email existe, un lien de connexion vous a été envoyé."
        )

    @router.get("/magic-login", response_model=LoginResponse)
    async def magic_login(
        token: str,
        request: Request,
        response: Response,
        redirect: str | None = None,
    ):
        security = SecurityService(env["ENCRYPTION_KEY"])
        token_hash = security.hash_token(token)

        async with db.session() as session:
            from ..repositories.session import EmailTokenRepository
            from ..repositories.user import UserRepository

            email_token_repo = EmailTokenRepository(session)
            user_repo = UserRepository(session)

            email_token = await email_token_repo.get_valid(token_hash, "magic_link")
            if not email_token:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, "Lien invalide ou expiré."
                )

            user = await user_repo.get_by_id(UUID(email_token.user_id))
            if not user or not user.is_active:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            await email_token_repo.mark_used(email_token)
            return await _auth_svc()._issue_tokens(user, False, request, response)

    # ── MFA ───────────────────────────────────────────────────

    @router.post("/mfa/enable", response_model=MFAEnableResponse)
    async def mfa_enable(user=Depends(get_current_user)):
        return await _auth_svc().mfa_enable(user.id)

    @router.post("/mfa/verify", response_model=MFAVerifyResponse)
    async def mfa_verify(
        body: MFAVerifyRequest,
        request: Request,
        response: Response,
        user=Depends(get_current_user, use_cache=False),
    ):
        result = await _auth_svc().mfa_verify(body, user.id)
        if result.get("activated"):
            return MFAVerifyResponse(access_token="", refresh_token="", expires_in=0)
        # Flux login MFA complet → émettre tokens
        actual_user = result.get("user")
        if actual_user:
            login_resp = await _auth_svc()._issue_tokens(
                actual_user, False, request, response
            )
            return MFAVerifyResponse(
                access_token=login_resp.access_token or "",
                refresh_token=login_resp.refresh_token or "",
                expires_in=login_resp.expires_in or 0,
            )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Résultat MFA inattendu.")

    @router.post("/mfa/disable", response_model=MessageResponse)
    async def mfa_disable(
        body: MFADisableRequest,
        request: Request,
        user=Depends(get_current_user),
    ):
        await _auth_svc().mfa_disable(body, user.id, request)
        return MessageResponse(message="MFA désactivé avec succès.")

    @router.get("/mfa/backup-codes", response_model=MFABackupCodesResponse)
    async def backup_codes(user=Depends(get_current_user)):
        from ..repositories.user import UserRepository

        async with db.session() as session:
            user_repo = UserRepository(session)
            db_user = await user_repo.get_by_id(user.id)
            if not db_user or not db_user.mfa_backup_codes:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "MFA non activé.")
            from ..services.mfa import MFAService

            mfa_svc = MFAService(SecurityService(env["ENCRYPTION_KEY"]))
            remaining = mfa_svc.count_remaining_backup_codes(db_user.mfa_backup_codes)
            return MFABackupCodesResponse(
                backup_codes=["****"] * remaining,
                remaining_count=remaining,
            )

    return router
