from __future__ import annotations
from datetime import datetime, timedelta, UTC
from uuid import UUID
from fastapi import Request, Response, HTTPException, status

from ..repositories import UserRepository,  EmailTokenRepository

from ..schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    RefreshRequest, RefreshResponse,
    ForgotPasswordRequest, ResetPasswordRequest,
    VerifyEmailRequest,
    MFAVerifyRequest,
    MFAEnableResponse, MFADisableRequest,UserOutWithPermissions
)

# Seuils de verrouillage
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
RATE_LIMIT_LOGIN = 10  # tentatives par 10 min par IP


class AuthService:
    def __init__(self, db, cache, env: dict, email_service=None):
        self.db = db
        self.cache = cache
        self.env = env
        # Services sans dépendance à la DB session
        from . import MFAService, EmailService, RBACService, AuditService,  SecurityService,PasswordService, TokenService, SessionService
        self._password_svc = PasswordService(
            pwned_check_enabled=env.get("PWNED_CHECK_ENABLED", "true").lower() == "true"
        )
        self._security = SecurityService(env["ENCRYPTION_KEY"])
        self._token_svc = TokenService(cache, env)
        self._session_svc = SessionService(db, cache, env)
        self._mfa_svc = MFAService(self._security)
        self._email_svc = EmailService(env, email_service)
        self._rbac_svc = RBACService(db, cache)
        self._audit_svc = AuditService(db)

    # Helpers pour créer les repositories avec une session DB
    def _user_repo(self, session) -> UserRepository:
        return UserRepository(session)

    def _email_token_repo(self, session) -> EmailTokenRepository:
        return EmailTokenRepository(session)

    # ── Register ──────────────────────────────────────────────

    async def register(self, body: RegisterRequest, request: Request) -> RegisterResponse:
        async with self.db.session() as session:
            # Vérification unicité email
            existing = await self._user_repo(session).get_by_email(body.email)
            if existing:
                raise HTTPException(status.HTTP_409_CONFLICT, "Cet email est déjà utilisé.")

            # Vérification HaveIBeenPwned
            if await self._password_svc.is_pwned(body.password):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "Ce mot de passe a été compromis. Choisissez-en un autre.",
                )

            password_hash = self._password_svc.hash(body.password)
            user = await self._user_repo(session).create(
                email=body.email,
                password_hash=password_hash,
                first_name=body.first_name,
                last_name=body.last_name,
                is_active=True,
                is_verified=False,
            )

            # Assigner le rôle standard
            _role_repo, _ = self._rbac_svc._repos(session)
            std_role = await _role_repo.get_by_name("standard")
            if std_role:
                await _role_repo.assign_role_to_user(user.id, std_role.id)

            # Token de vérification email
            token = self._security.generate_token()
            token_hash = self._security.hash_token(token)
            expires = datetime.now(UTC) + timedelta(hours=1)
            await self._email_token_repo(session).create(
                user_id=user.id,
                token_hash=token_hash,
                type="verify_email",
                expires_at=expires,
            )
            await self._email_svc.send_verification_email(user.email, token, user.first_name)

            await self._audit_svc.log("user.register", True, request, user.id)
            return RegisterResponse(
                message="Compte créé. Vérifiez votre email.",
                user_id=user.id,
                email_verification_sent=True,
            )

    # ── Login ─────────────────────────────────────────────────

    async def login(
        self, body: LoginRequest, request: Request, response: Response
    ) -> LoginResponse:
        # Rate limiting IP
        ip = request.client.host if request.client else "unknown"
        rate_key = f"au:rate:login:ip:{ip}"
        attempts = await self.cache.get(rate_key)
        if attempts and int(attempts) >= RATE_LIMIT_LOGIN:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Trop de tentatives.")

        async with self.db.session() as session:
            user = await self._user_repo(session).get_by_email(body.email)

            # Vérification compte
            if not user or not user.password_hash:
                await self._increment_rate(rate_key)
                await self._audit_svc.log("user.login.failed", False, request, metadata={"reason": "not_found"})
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides.")

            # Verrouillage
            if user.locked_until and user.locked_until > datetime.now(UTC):
                raise HTTPException(status.HTTP_423_LOCKED, "Compte temporairement verrouillé.")

            if not user.is_active:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé.")

            # Vérification mot de passe
            if not self._password_svc.verify(body.password, user.password_hash):
                await self._user_repo(session).increment_failed_login(user)
                if user.failed_login_count + 1 >= MAX_FAILED_ATTEMPTS:
                    await self._user_repo(session).update(
                        user,
                        locked_until=datetime.now(UTC) + timedelta(minutes=LOCKOUT_MINUTES),
                    )
                await self._increment_rate(rate_key)
                await self._audit_svc.log("user.login.failed", False, request, user.id, {"reason": "bad_password"})
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides.")

            await self._user_repo(session).reset_failed_login(user)
            await self._user_repo(session).update(user, last_login_at=datetime.now(UTC))

            # Rehash si nécessaire
            if self._password_svc.needs_rehash(user.password_hash):
                new_hash = self._password_svc.hash(body.password)
                await self._user_repo(session).update(user, password_hash=new_hash)

            # MFA activé → retourner mfa_token
            if user.mfa_enabled:
                mfa_token = self._token_svc.create_mfa_token(str(user.id))
                await self._audit_svc.log("user.login.mfa_required", True, request, user.id)
                return LoginResponse(status="mfa_required", mfa_token=mfa_token)

            return await self._issue_tokens(user, body.remember_me, request, response)

    async def _issue_tokens(self, user, remember_me: bool, request: Request, response: Response) -> LoginResponse:
        roles = await self._rbac_svc.get_user_role_names(str(user.id))
        perms = await self._rbac_svc.get_user_permissions(str(user.id))

        user_with_perms = UserOutWithPermissions(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            mfa_enabled=user.mfa_enabled,
            last_login_at=user.last_login_at,
            roles=roles,
            permissions=list(perms),
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

        refresh_ttl = self._token_svc.get_refresh_ttl(remember_me)
        refresh_token = self._token_svc.create_refresh_token()
        session = await self._session_svc.create_session(
            user_id=user.id,
            refresh_token=refresh_token,
            expires_in=refresh_ttl,
            request=request,
        )
        access_token, expires_in = self._token_svc.create_access_token(
            user_with_perms, str(session.id)
        )

        # Cookie httpOnly pour le refresh token
        response.set_cookie(
            "refresh_token",
            refresh_token,
            max_age=refresh_ttl,
            httponly=True,
            secure=True,
            samesite="lax",
        )

        await self._audit_svc.log("user.login.success", True, request, user.id)
        return LoginResponse(
            status="ok",
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
        )

    # ── Refresh ───────────────────────────────────────────────

    async def refresh(
        self, body: RefreshRequest, request: Request, response: Response
    ) -> RefreshResponse:
        # Cookie prioritaire sur body
        refresh_token = request.cookies.get("refresh_token") or body.refresh_token
        if not refresh_token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token manquant.")

        session = await self._session_svc.get_by_refresh_token(refresh_token)
        if not session or not session.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalide ou expirée.")

        if session.expires_at < datetime.now(UTC):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expirée.")

        async with self.db.session() as session_db:
            user = await self._user_repo(session_db).get_by_id(UUID(session.user_id))
            if not user or not user.is_active:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utilisateur introuvable.")

            # Rotation du refresh token (token rotation)
            await self._session_svc.revoke_session(session.id, "rotation")
            roles = await self._rbac_svc.get_user_role_names(str(user.id))
            perms = await self._rbac_svc.get_user_permissions(str(user.id))

            user_with_perms = UserOutWithPermissions(
                id=user.id, email=user.email,
                first_name=user.first_name, last_name=user.last_name,
                is_active=user.is_active, is_verified=user.is_verified,
                mfa_enabled=user.mfa_enabled, last_login_at=user.last_login_at,
                roles=roles, permissions=list(perms),
                created_at=user.created_at, updated_at=user.updated_at,
            )

            refresh_ttl = self._token_svc.get_refresh_ttl()
            new_refresh = self._token_svc.create_refresh_token()
            new_session = await self._session_svc.create_session(
                user_id=user.id, refresh_token=new_refresh,
                expires_in=refresh_ttl, request=request,
            )
            access_token, expires_in = self._token_svc.create_access_token(
                user_with_perms, str(new_session.id)
            )
            response.set_cookie(
                "refresh_token", new_refresh, max_age=refresh_ttl,
                httponly=True, secure=True, samesite="lax",
            )
            return RefreshResponse(
                access_token=access_token,
                refresh_token=new_refresh,
                expires_in=expires_in,
            )

    # ── Logout ────────────────────────────────────────────────

    async def logout(
        self,
        logout_all: bool,
        user_id: UUID,
        session_id: UUID,
        request: Request,
        response: Response,
    ) -> None:
        if logout_all:
            await self._session_svc.revoke_all_user_sessions(user_id)
        else:
            await self._session_svc.revoke_session(session_id, "logout")
        response.delete_cookie("refresh_token")
        await self._audit_svc.log("user.logout", True, request, user_id)

    # ── Mot de passe oublié ───────────────────────────────────

    async def forgot_password(self, body: ForgotPasswordRequest, request: Request) -> None:
        # Rate limit
        email_hash = self._security.hash_token(body.email.lower())
        rate_key = f"au:rate:forgot:{email_hash}"
        attempts = await self.cache.get(rate_key)
        if attempts and int(attempts) >= 3:
            return  # Silencieux contre l'énumération

        async with self.db.session() as session:
            user = await self._user_repo(session).get_by_email(body.email)
            if user:
                await self._email_token_repo(session).delete_user_tokens(user.id, "reset_password")
                token = self._security.generate_token()
                token_hash = self._security.hash_token(token)
                await self._email_token_repo(session).create(
                    user_id=user.id,
                    token_hash=token_hash,
                    type="reset_password",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
                await self._email_svc.send_reset_password_email(user.email, token, user.first_name)
                await self._audit_svc.log("user.forgot_password", True, request, user.id)

        await self.cache.set(rate_key, str(int(attempts or 0) + 1), ttl=3600)

    async def reset_password(self, body: ResetPasswordRequest, request: Request) -> None:
        token_hash = self._security.hash_token(body.token)

        async with self.db.session() as session:
            email_token = await self._email_token_repo(session).get_valid(token_hash, "reset_password")
            if not email_token:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Token invalide ou expiré.")

            user = await self._user_repo(session).get_by_id(UUID(email_token.user_id))
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")

            if await self._password_svc.is_pwned(body.new_password):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Mot de passe compromis.")

            new_hash = self._password_svc.hash(body.new_password)
            await self._user_repo(session).update(user, password_hash=new_hash)
            await self._email_token_repo(session).mark_used(email_token)
            await self._session_svc.revoke_all_user_sessions(user.id)
            await self._audit_svc.log("user.reset_password", True, request, user.id)

    # ── Vérification email ────────────────────────────────────

    async def verify_email(self, body: VerifyEmailRequest, request: Request) -> None:
        token_hash = self._security.hash_token(body.token)

        async with self.db.session() as session:
            email_token = await self._email_token_repo(session).get_valid(token_hash, "verify_email")
            if not email_token:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Token invalide ou expiré.")

            user = await self._user_repo(session).get_by_id(UUID(email_token.user_id))
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")

            await self._user_repo(session).update(user, is_verified=True)
            await self._email_token_repo(session).mark_used(email_token)
            await self._audit_svc.log("user.email_verified", True, request, user.id)

    # ── MFA ───────────────────────────────────────────────────

    async def mfa_enable(self, user_id: UUID) -> MFAEnableResponse:
        async with self.db.session() as session:
            user = await self._user_repo(session).get_by_id(user_id)
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            setup = self._mfa_svc.generate_totp_setup(user.email)
            encrypted_secret = self._mfa_svc.encrypt_secret(setup["secret"])

            # Stocker secret + backup codes en attente de confirmation
            await self.cache.set(
                f"au:mfa:pending:{user_id}",
                f"{encrypted_secret}|{','.join(setup['backup_codes_hashed'])}",
                ttl=300,
            )
            return MFAEnableResponse(
                secret=setup["secret"],
                provisioning_uri=setup["provisioning_uri"],
                qr_code_base64=setup["qr_code_base64"],
                backup_codes=setup["backup_codes"],
            )

    async def mfa_verify(self, body: MFAVerifyRequest, user_id: UUID | None = None) -> dict:
        """Gère à la fois la confirmation d'activation et le login MFA."""
        actual_user_id = user_id

        # Flux login MFA
        if body.mfa_token:
            uid_str = self._token_svc.decode_mfa_token(body.mfa_token)
            if not uid_str:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token MFA invalide.")
            actual_user_id = UUID(uid_str)

        if not actual_user_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "user_id requis.")

        async with self.db.session() as session:
            user = await self._user_repo(session).get_by_id(actual_user_id)
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            code = body.code
            is_backup = len(code) == 8

            if is_backup and user.mfa_backup_codes:
                idx = self._mfa_svc.verify_backup_code(code, user.mfa_backup_codes)
                if idx is None:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code de secours invalide.")
                new_codes = self._mfa_svc.invalidate_backup_code(user.mfa_backup_codes, idx)
                await self._user_repo(session).update(user, mfa_backup_codes=new_codes)
            elif user.mfa_secret:
                if not self._mfa_svc.verify_totp(user.mfa_secret, code):
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code TOTP invalide.")
            else:
                # Confirmation d'activation : lire depuis le cache
                pending = await self.cache.get(f"au:mfa:pending:{actual_user_id}")
                if not pending:
                    raise HTTPException(status.HTTP_400_BAD_REQUEST, "Session d'activation expirée.")
                encrypted_secret, backup_hashes_str = pending.split("|", 1)
                if not self._mfa_svc.verify_totp(encrypted_secret, code):
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code TOTP invalide.")
                backup_hashes = backup_hashes_str.split(",")
                await self._user_repo(session).update(
                    user,
                    mfa_enabled=True,
                    mfa_secret=encrypted_secret,
                    mfa_backup_codes=backup_hashes,
                )
                await self.cache.delete(f"au:mfa:pending:{actual_user_id}")
                return {"activated": True}

            return {"verified": True, "user": user}

    async def mfa_disable(self, body: MFADisableRequest, user_id: UUID, request: Request) -> None:
        async with self.db.session() as session:
            user = await self._user_repo(session).get_by_id(user_id)
            if not user:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            if not self._password_svc.verify(body.password, user.password_hash or ""):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Mot de passe incorrect.")

            if not self._mfa_svc.verify_totp(user.mfa_secret or "", body.code):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code TOTP invalide.")

            await self._user_repo(session).update(
                user, mfa_enabled=False, mfa_secret=None, mfa_backup_codes=None
            )
            await self._audit_svc.log("user.mfa_disabled", True, request, user_id)

    # ── Helpers ───────────────────────────────────────────────

    async def _increment_rate(self, key: str) -> None:
        val = await self.cache.get(key)
        new_val = int(val or 0) + 1
        await self.cache.set(key, str(new_val), ttl=900)
