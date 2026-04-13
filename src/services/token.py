from __future__ import annotations
import uuid
from datetime import datetime, timedelta, UTC
from jose import jwt, JWTError
from ..schemas.auth import TokenPayload
from ..schemas.user import UserOutWithPermissions
from pathlib import Path

class TokenService:
    def __init__(self, cache, env: dict):
        self.cache = cache
        self._private_key = ""
        self._public_key = ""

        PRIVATE  = Path(env["JWT_PRIVATE_KEY"])
        PUBLIC  = Path(env["JWT_PUBLIC_KEY"])

        if not PRIVATE.exists() or not PUBLIC.exists(): raise FileNotFoundError(
            "le (ou) les fichier de pernision sont introuvable", PRIVATE, PUBLIC
        )
        self._private_key = PRIVATE.read_text('utf-8') 
        self._public_key = PUBLIC.read_text('utf-8')

        self._algorithm = env.get("JWT_ALGORITHM", "RS256")
        self._access_ttl = int(env.get("ACCESS_TOKEN_TTL", 900))
        self._refresh_ttl = int(env.get("REFRESH_TOKEN_TTL", 2592000))

    # ── Création ──────────────────────────────────────────────

    def create_access_token(
        self,
        user: UserOutWithPermissions,
        session_id: str,
    ) -> tuple[str, int]:
        """Retourne (token, expires_in_seconds)."""
        now = datetime.now(UTC)
        jti = str(uuid.uuid4())
        payload = {
            "sub": str(user.id),
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "roles": user.roles,
            "permissions": user.permissions,
            "session_id": session_id,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self._access_ttl)).timestamp()),
        }
        token = jwt.encode(payload, self._private_key, algorithm=self._algorithm)
        return token, self._access_ttl

    def create_refresh_token(self) -> str:
        """Token opaque aléatoire (haché avant stockage en DB)."""
        import secrets
        return secrets.token_urlsafe(64)

    def create_mfa_token(self, user_id: str) -> str:
        """JWT court-vécu (5 min) pour le flux MFA."""
        now = datetime.now(UTC)
        payload = {
            "sub": user_id,
            "type": "mfa",
            "jti": str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        return jwt.encode(payload, self._private_key, algorithm=self._algorithm)

    # ── Vérification ──────────────────────────────────────────

    async def verify(self, token: str) -> UserOutWithPermissions | None:
        try:
            payload = jwt.decode(token, self._public_key, algorithms=[self._algorithm])
        except JWTError:
            return None

        # Vérifier blacklist JTI
        jti = payload.get("jti")
        if jti and await self.cache.get(f"au:blacklist:jti:{jti}"):
            return None

        try:
            data = TokenPayload(**payload)
        except Exception:
            return None

        return UserOutWithPermissions(
            id=data.sub,
            email=data.email,
            roles=data.roles,
            permissions=data.permissions,
            first_name=getattr(data, "first_name", ""),
            last_name=getattr(data, "last_name", ""),
            is_active=True,
            is_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    def decode_mfa_token(self, token: str) -> str | None:
        """Retourne user_id ou None si invalide."""
        try:
            payload = jwt.decode(token, self._public_key, algorithms=[self._algorithm])
            if payload.get("type") != "mfa":
                return None
            return payload.get("sub")
        except JWTError:
            return None

    async def blacklist(self, jti: str, ttl: int) -> None:
        await self.cache.set(f"au:blacklist:jti:{jti}", "1", ttl=ttl)

    def get_refresh_ttl(self, remember_me: bool = False) -> int:
        return self._refresh_ttl * 3 if remember_me else self._refresh_ttl
