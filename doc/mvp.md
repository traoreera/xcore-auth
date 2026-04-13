# PLUGIN `auth_user` — SPÉCIFICATION TECHNIQUE v3
> Plugin xcore · Exécution : `trusted` · Auth + User fusionnés · Stack : FastAPI + PostgreSQL + Redis

---

## 1. Structure du projet

```
plugins/auth_user/
├── plugin.yaml
├── plugin.sig                    ← généré par xcore plugin sign
├── migrations/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       ├── 0001_initial_schema.py
│       ├── 0002_mfa_backup_codes.py
│       └── 0003_geo_sessions.py
└── src/
    ├── main.py                   ← Plugin entry point
    ├── backend.py                ← XcoreAuthBackend (protocole xcore)
    ├── routes/
    │   ├── __init__.py           ← build_router()
    │   ├── auth.py               ← /auth/*
    │   ├── users.py              ← /users/*  (fusionné ici)
    │   ├── rbac.py               ← /roles, /permissions
    │   ├── sessions.py           ← /sessions/*
    │   ├── oauth.py              ← /auth/oauth/*
    │   └── audit.py              ← /audit-logs
    ├── schemas/
    │   ├── __init__.py
    │   ├── auth.py               ← Register, Login, Token, MFA…
    │   ├── user.py               ← User, UserCreate, UserUpdate…
    │   ├── rbac.py               ← Role, Permission, Assignment…
    │   ├── session.py            ← Session, SessionRevoke…
    │   └── audit.py              ← AuditLog, AuditFilter…
    ├── models/
    │   ├── __init__.py
    │   ├── user.py               ← SQLAlchemy ORM
    │   ├── role.py
    │   ├── session.py
    │   └── audit.py
    ├── repositories/
    │   ├── user.py
    │   ├── role.py
    │   ├── session.py
    │   └── audit.py
    └── services/
        ├── auth.py
        ├── token.py
        ├── password.py
        ├── mfa.py
        ├── session.py
        ├── oauth.py
        ├── email.py
        ├── rbac.py
        ├── audit.py
        └── security.py
```

---

## 2. plugin.yaml

```yaml
name: auth_user
version: 1.0.0
author: team
description: "IAM centralisé — auth, users, RBAC, sessions, audit"
execution_mode: trusted
framework_version: ">=2.0"
entry_point: src/main.py

requires: []

permissions:
  - resource: "db.*"
    actions: ["read", "write"]
    effect: allow
  - resource: "cache.*"
    actions: ["read", "write"]
    effect: allow
  - resource: "scheduler.*"
    actions: ["read", "write"]
    effect: allow
  - resource: "os.*"
    actions: ["*"]
    effect: deny

resources:
  timeout_seconds: 15
  max_memory_mb: 256
  max_disk_mb: 100
  rate_limit:
    calls: 1000
    period_seconds: 60

runtime:
  health_check:
    enabled: true
    interval_seconds: 30
    timeout_seconds: 3
  retry:
    max_attempts: 1
    backoff_seconds: 0.0

env:
  DATABASE_URL: ${DATABASE_URL}
  JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY}     # PEM RS256
  JWT_PUBLIC_KEY: ${JWT_PUBLIC_KEY}
  JWT_ALGORITHM: ${JWT_ALGORITHM:-RS256}
  ACCESS_TOKEN_TTL: ${ACCESS_TOKEN_TTL:-900}
  REFRESH_TOKEN_TTL: ${REFRESH_TOKEN_TTL:-2592000}
  ENCRYPTION_KEY: ${ENCRYPTION_KEY}       # AES-256 (Fernet)
  GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
  GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET}
  GITHUB_CLIENT_ID: ${GITHUB_CLIENT_ID}
  GITHUB_CLIENT_SECRET: ${GITHUB_CLIENT_SECRET}
  MICROSOFT_CLIENT_ID: ${MICROSOFT_CLIENT_ID}
  MICROSOFT_CLIENT_SECRET: ${MICROSOFT_CLIENT_SECRET}
  SMTP_HOST: ${SMTP_HOST}
  SMTP_PORT: ${SMTP_PORT:-587}
  SMTP_USER: ${SMTP_USER}
  SMTP_PASSWORD: ${SMTP_PASSWORD}
  PWNED_CHECK_ENABLED: ${PWNED_CHECK_ENABLED:-true}
  APP_BASE_URL: ${APP_BASE_URL}

allowed_imports:
  - fastapi
  - pydantic
  - pydantic_settings
  - jose
  - passlib
  - argon2
  - pyotp
  - qrcode
  - httpx
  - email_validator
  - ua_parser
  - geoip2
  - cryptography
  - alembic
  - sqlalchemy
```

---

## 3. Schémas Pydantic v2 — `src/schemas/`

### 3.1 `schemas/common.py` — Primitives partagées

```python
# src/schemas/common.py
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """Racine commune : interdit les champs extra, convertit ORM → dict."""
    model_config = ConfigDict(
        from_attributes=True,    # SQLAlchemy ORM → Pydantic
        extra="forbid",          # Aucun champ inconnu accepté
        populate_by_name=True,
    )


class UUIDMixin(BaseSchema):
    id: UUID


class TimestampMixin(BaseSchema):
    created_at: datetime
    updated_at: datetime


class PaginatedResponse[T](BaseSchema):
    """Réponse paginée générique."""
    items: list[T]
    total: int
    page: int
    per_page: int
    pages: int


class MessageResponse(BaseSchema):
    message: str


class ErrorResponse(BaseSchema):
    detail: str
    code: str | None = None
```

---

### 3.2 `schemas/user.py`

```python
# src/schemas/user.py
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import (
    BaseModel, EmailStr, Field, field_validator,
    model_validator, ConfigDict
)
from .common import BaseSchema, UUIDMixin, TimestampMixin
import re


# ─── Validators réutilisables ─────────────────────────────────

PASSWORD_RE = re.compile(
    r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]).{12,}$"
)

def validate_password_strength(v: str) -> str:
    if not PASSWORD_RE.match(v):
        raise ValueError(
            "Le mot de passe doit contenir au moins 12 caractères, "
            "une majuscule, un chiffre et un caractère spécial."
        )
    return v


# ─── Enums ────────────────────────────────────────────────────

from enum import StrEnum

class UserRole(StrEnum):
    STANDARD  = "standard"
    ADMIN     = "admin"
    SUPERADMIN = "superadmin"


# ─── Schemas User ──────────────────────────────────────────────

class UserBase(BaseSchema):
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str  = Field(min_length=1, max_length=100)


class UserCreate(UserBase):
    """POST /auth/register"""
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class UserCreateAdmin(UserBase):
    """POST /users  (admin uniquement)"""
    password: str | None = Field(default=None, min_length=12, max_length=128)
    role: UserRole = UserRole.STANDARD
    is_active: bool = True
    send_welcome_email: bool = True

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str | None) -> str | None:
        if v is not None:
            return validate_password_strength(v)
        return v


class UserUpdate(BaseSchema):
    """PATCH /users/me  ou  PATCH /users/{id}"""
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name:  str | None = Field(default=None, min_length=1, max_length=100)
    # email non modifiable via ce schéma → processus de vérification dédié


class UserUpdateAdmin(UserUpdate):
    """PATCH /users/{id} — champs additionnels admin"""
    is_active: bool | None = None
    is_verified: bool | None = None


class PasswordChange(BaseSchema):
    """PATCH /users/me/password"""
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)
    new_password_confirm: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)

    @model_validator(mode="after")
    def passwords_match(self) -> "PasswordChange":
        if self.new_password != self.new_password_confirm:
            raise ValueError("Les mots de passe ne correspondent pas.")
        return self


class OAuthAccountOut(BaseSchema):
    provider: str
    provider_uid: str
    created_at: datetime


class UserOut(UUIDMixin, TimestampMixin):
    """Réponse publique — pas de données sensibles."""
    email: EmailStr
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login_at: datetime | None = None
    oauth_accounts: list[OAuthAccountOut] = []

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


class UserOutAdmin(UserOut):
    """Réponse admin — données supplémentaires."""
    failed_login_count: int
    locked_until: datetime | None = None
    roles: list["RoleOut"] = []


class UserOutWithPermissions(UserOut):
    """Réponse avec permissions dénormalisées (pour le JWT)."""
    roles: list[str] = []           # noms
    permissions: list[str] = []     # noms dénormalisés


# Import circulaire résolu en bas de fichier
from .rbac import RoleOut
UserOutAdmin.model_rebuild()
```

---

### 3.3 `schemas/auth.py`

```python
# src/schemas/auth.py
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator, HttpUrl
from .common import BaseSchema


# ─── Register / Login ─────────────────────────────────────────

class RegisterRequest(BaseSchema):
    """POST /auth/register"""
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    first_name: str = Field(min_length=1, max_length=100)
    last_name:  str = Field(min_length=1, max_length=100)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        from .user import validate_password_strength
        return validate_password_strength(v)


class RegisterResponse(BaseSchema):
    message: str
    user_id: UUID
    email_verification_sent: bool


class LoginRequest(BaseSchema):
    """POST /auth/login"""
    email: EmailStr
    password: str
    remember_me: bool = False    # TTL refresh token × 3 si True


class LoginResponse(BaseSchema):
    """
    Deux cas possibles :
      - MFA désactivé  → tokens directement
      - MFA activé     → status="mfa_required" + mfa_token
    """
    status: str                        # "ok" | "mfa_required"
    access_token:  str | None = None
    refresh_token: str | None = None   # aussi dans cookie httpOnly
    token_type:    str = "bearer"
    expires_in:    int | None = None   # secondes
    mfa_token:     str | None = None   # JWT 5 min, si mfa_required


class RefreshRequest(BaseSchema):
    """
    POST /auth/refresh
    Le refresh_token peut venir du cookie httpOnly (prioritaire)
    ou du body (clients mobiles / API).
    """
    refresh_token: str | None = None


class RefreshResponse(BaseSchema):
    access_token: str
    refresh_token: str
    expires_in: int


class LogoutRequest(BaseSchema):
    """POST /auth/logout — révoque la session courante."""
    logout_all: bool = False    # True → révoque toutes les sessions


# ─── Password ─────────────────────────────────────────────────

class ForgotPasswordRequest(BaseSchema):
    """POST /auth/forgot-password"""
    email: EmailStr


class ResetPasswordRequest(BaseSchema):
    """POST /auth/reset-password"""
    token: str
    new_password: str = Field(min_length=12, max_length=128)
    new_password_confirm: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        from .user import validate_password_strength
        return validate_password_strength(v)

    @field_validator("new_password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if info.data.get("new_password") and v != info.data["new_password"]:
            raise ValueError("Les mots de passe ne correspondent pas.")
        return v


# ─── Email verification ───────────────────────────────────────

class VerifyEmailRequest(BaseSchema):
    """POST /auth/verify-email"""
    token: str


class ResendVerificationRequest(BaseSchema):
    """POST /auth/resend-verification"""
    email: EmailStr


# ─── Magic link ───────────────────────────────────────────────

class MagicLinkRequest(BaseSchema):
    """POST /auth/magic-link"""
    email: EmailStr
    redirect_url: HttpUrl | None = None   # URL app après connexion


# ─── MFA ──────────────────────────────────────────────────────

class MFAEnableResponse(BaseSchema):
    """GET /auth/mfa/enable — initiation"""
    secret: str                    # base32 (affichage manuel)
    provisioning_uri: str          # otpauth://totp/...
    qr_code_base64: str            # image/png base64
    backup_codes: list[str]        # 10 codes en clair (une seule fois)


class MFAVerifyRequest(BaseSchema):
    """
    POST /auth/mfa/verify
    Utilisé pour :
      1. Confirmer l'activation (code TOTP du premier scan)
      2. Connexion avec MFA (mfa_token + code)
    """
    code: str = Field(min_length=6, max_length=8)   # 6 TOTP ou 8 backup
    mfa_token: str | None = None                     # présent lors du login


class MFAVerifyResponse(BaseSchema):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int


class MFADisableRequest(BaseSchema):
    """POST /auth/mfa/disable — nécessite code TOTP courant"""
    code: str = Field(min_length=6, max_length=6)
    password: str    # confirmation mdp obligatoire


class MFABackupCodesResponse(BaseSchema):
    backup_codes: list[str]   # codes en clair (masqués sinon en DB)
    remaining_count: int


class EmailOTPRequest(BaseSchema):
    """POST /auth/mfa/email-otp/verify"""
    code: str = Field(min_length=6, max_length=6)
    mfa_token: str


# ─── OAuth2 ───────────────────────────────────────────────────

class OAuthAuthorizeResponse(BaseSchema):
    """GET /auth/oauth/{provider}"""
    authorization_url: str
    state: str


class OAuthLinkRequest(BaseSchema):
    """POST /users/me/oauth/{provider}/link — liaison compte"""
    code: str
    state: str


# ─── Token (IPC inter-plugins) ────────────────────────────────

class TokenPayload(BaseSchema):
    """Payload décodé du JWT — utilisé en interne."""
    sub: str          # user_id (UUID str)
    email: str
    roles: list[str]
    permissions: list[str]
    session_id: str
    jti: str
    iat: int
    exp: int
    model_config = {"extra": "allow"}   # tolère champs futurs


class TokenVerifyRequest(BaseSchema):
    """IPC : action verify_token"""
    token: str


class TokenVerifyResponse(BaseSchema):
    valid: bool
    user: "UserOutWithPermissions | None" = None
    error: str | None = None


class HasPermissionRequest(BaseSchema):
    """IPC : action has_permission"""
    user_id: UUID
    permission: str


class HasPermissionResponse(BaseSchema):
    allowed: bool


# Import résolution différée
from .user import UserOutWithPermissions
TokenVerifyResponse.model_rebuild()
```

---

### 3.4 `schemas/rbac.py`

```python
# src/schemas/rbac.py
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import Field, field_validator
from .common import BaseSchema, UUIDMixin, TimestampMixin
import re


# ─── Permission ────────────────────────────────────────────────

PERMISSION_RE = re.compile(r"^[a-z_]+:[a-z_]+$")   # ex: users:read

class PermissionBase(BaseSchema):
    name: str = Field(min_length=3, max_length=100)
    resource: str = Field(min_length=1, max_length=100)
    action: str  = Field(min_length=1, max_length=50)
    description: str | None = None

    @field_validator("name")
    @classmethod
    def name_format(cls, v: str) -> str:
        if not PERMISSION_RE.match(v):
            raise ValueError("Format attendu : resource:action  (ex: users:read)")
        return v


class PermissionCreate(PermissionBase):
    """POST /permissions"""


class PermissionOut(UUIDMixin, PermissionBase):
    """GET /permissions · GET /permissions/{id}"""


# ─── Role ──────────────────────────────────────────────────────

class RoleBase(BaseSchema):
    name: str = Field(min_length=2, max_length=100)
    description: str | None = None

    @field_validator("name")
    @classmethod
    def name_slug(cls, v: str) -> str:
        if not re.match(r"^[a-z][a-z0-9_-]*$", v):
            raise ValueError("Le nom de rôle doit être en minuscules snake_case.")
        return v


class RoleCreate(RoleBase):
    """POST /roles"""
    permission_ids: list[UUID] = []


class RoleUpdate(BaseSchema):
    """PATCH /roles/{id}"""
    description: str | None = None


class RoleOut(UUIDMixin, TimestampMixin, RoleBase):
    """GET /roles · GET /roles/{id}"""
    is_system: bool
    permissions: list[PermissionOut] = []


class RoleOutSimple(UUIDMixin):
    """Utilisé dans UserOut pour éviter la récursion."""
    name: str
    description: str | None = None


# ─── Assignments ───────────────────────────────────────────────

class AssignRoleRequest(BaseSchema):
    """POST /users/{id}/roles"""
    role_id: UUID


class AssignPermissionRequest(BaseSchema):
    """POST /roles/{id}/permissions"""
    permission_id: UUID


class AssignmentOut(BaseSchema):
    """Réponse après assignation rôle ↔ user"""
    user_id: UUID
    role_id: UUID
    assigned_at: datetime
    assigned_by: UUID | None = None
```

---

### 3.5 `schemas/session.py`

```python
# src/schemas/session.py
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import IPvAnyAddress
from .common import BaseSchema, UUIDMixin


class SessionOut(UUIDMixin):
    """GET /sessions — session de l'utilisateur courant"""
    ip_address: str | None = None
    user_agent: str | None = None
    geo_country: str | None = None
    geo_city:    str | None = None
    created_at:  datetime
    last_used_at: datetime
    expires_at:  datetime
    is_current: bool = False     # True si c'est la session de la requête


class SessionOutAdmin(SessionOut):
    """GET /sessions/all — vue admin"""
    user_id:  UUID
    is_active: bool
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    device_fingerprint: str | None = None


class RevokeSessionRequest(BaseSchema):
    """DELETE /sessions/{id}"""
    reason: str | None = None   # facultatif, pour l'audit


class RevokeAllSessionsResponse(BaseSchema):
    revoked_count: int
    message: str
```

---

### 3.6 `schemas/audit.py`

```python
# src/schemas/audit.py
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import Field
from .common import BaseSchema, PaginatedResponse


class AuditLogOut(BaseSchema):
    """Un entrée du journal d'audit."""
    id: int
    user_id: UUID | None = None
    action: str
    ip_address: str | None = None
    user_agent: str | None = None
    geo_country: str | None = None
    success: bool
    metadata: dict = {}
    created_at: datetime


class AuditFilter(BaseSchema):
    """Query params GET /audit-logs — validation entrée."""
    user_id:    UUID | None = None
    action:     str | None = None
    success:    bool | None = None
    ip_address: str | None = None
    date_from:  datetime | None = None
    date_to:    datetime | None = None
    page:       int = Field(default=1, ge=1)
    per_page:   int = Field(default=50, ge=1, le=200)


AuditLogPage = PaginatedResponse[AuditLogOut]
```

---

## 4. Modèles SQLAlchemy — `src/models/`

### 4.1 `models/base.py`

```python
# src/models/base.py
from datetime import datetime, UTC
from uuid import uuid4
from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UUIDPKMixin:
    id: Mapped[str] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
```

---

### 4.2 `models/user.py`

```python
# src/models/user.py
from __future__ import annotations
from datetime import datetime
from sqlalchemy import (
    String, Boolean, Integer, DateTime, Text, ARRAY,
    ForeignKey, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, UUIDPKMixin, TimestampMixin


class User(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "users"

    email:               Mapped[str]           = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash:       Mapped[str | None]    = mapped_column(Text)
    first_name:          Mapped[str]           = mapped_column(String(100), nullable=False)
    last_name:           Mapped[str]           = mapped_column(String(100), nullable=False)
    is_active:           Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    is_verified:         Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled:         Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret:          Mapped[str | None]    = mapped_column(Text)              # chiffré AES-256
    mfa_backup_codes:    Mapped[list | None]   = mapped_column(ARRAY(Text))       # hashés argon2
    last_login_at:       Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
    failed_login_count:  Mapped[int]           = mapped_column(Integer, default=0, nullable=False)
    locked_until:        Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
    metadata_:           Mapped[dict]          = mapped_column("metadata", JSONB, default=dict, nullable=False)

    # Relations
    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    sessions:       Mapped[list["Session"]]      = relationship(back_populates="user", cascade="all, delete-orphan")
    user_roles:     Mapped[list["UserRole"]]     = relationship(back_populates="user", cascade="all, delete-orphan")
    audit_logs:     Mapped[list["AuditLog"]]     = relationship(back_populates="user")

    __table_args__ = (
        Index("idx_users_locked", "locked_until", postgresql_where="locked_until IS NOT NULL"),
    )


class OAuthAccount(Base, UUIDPKMixin):
    __tablename__ = "oauth_accounts"

    user_id:       Mapped[str]      = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider:      Mapped[str]      = mapped_column(String(50), nullable=False)
    provider_uid:  Mapped[str]      = mapped_column(String(255), nullable=False)
    access_token:  Mapped[str|None] = mapped_column(Text)   # chiffré
    refresh_token: Mapped[str|None] = mapped_column(Text)   # chiffré
    expires_at:    Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
    created_at:    Mapped[datetime]      = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(back_populates="oauth_accounts")

    __table_args__ = (UniqueConstraint("provider", "provider_uid"),)
```

---

### 4.3 `models/role.py`

```python
# src/models/role.py
from sqlalchemy import String, Boolean, Text, ForeignKey, Table, Column, DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, UUIDPKMixin, TimestampMixin

# Table d'association M2M Role ↔ Permission
role_permissions = Table(
    "role_permissions", Base.metadata,
    Column("role_id",       PG_UUID(as_uuid=True), ForeignKey("roles.id",       ondelete="CASCADE"), primary_key=True),
    Column("permission_id", PG_UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "roles"

    name:        Mapped[str]  = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str|None] = mapped_column(Text)
    is_system:   Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    permissions: Mapped[list["Permission"]] = relationship(secondary=role_permissions, back_populates="roles")
    user_roles:  Mapped[list["UserRole"]]   = relationship(back_populates="role")


class Permission(Base, UUIDPKMixin):
    __tablename__ = "permissions"

    name:        Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    resource:    Mapped[str] = mapped_column(String(100), nullable=False)
    action:      Mapped[str] = mapped_column(String(50),  nullable=False)
    description: Mapped[str|None] = mapped_column(Text)

    roles: Mapped[list["Role"]] = relationship(secondary=role_permissions, back_populates="permissions")

    from sqlalchemy import UniqueConstraint
    __table_args__ = (UniqueConstraint("resource", "action"),)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id:     Mapped[str]      = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id",  ondelete="CASCADE"), primary_key=True)
    role_id:     Mapped[str]      = mapped_column(PG_UUID(as_uuid=True), ForeignKey("roles.id",  ondelete="CASCADE"), primary_key=True)
    assigned_by: Mapped[str|None] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="user_roles", foreign_keys=[user_id])
    role: Mapped["Role"] = relationship(back_populates="user_roles")
```

---

### 4.4 `models/session.py`

```python
# src/models/session.py
from datetime import datetime
from sqlalchemy import String, Boolean, Text, ForeignKey, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, UUIDPKMixin


class Session(Base, UUIDPKMixin):
    __tablename__ = "sessions"

    user_id:            Mapped[str]      = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash: Mapped[str]      = mapped_column(Text, nullable=False, unique=True)
    ip_address:         Mapped[str|None] = mapped_column(INET)
    user_agent:         Mapped[str|None] = mapped_column(Text)
    device_fingerprint: Mapped[str|None] = mapped_column(String(64))
    geo_country:        Mapped[str|None] = mapped_column(String(3))
    geo_city:           Mapped[str|None] = mapped_column(String(100))
    is_active:          Mapped[bool]     = mapped_column(Boolean, default=True, nullable=False)
    created_at:         Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at:         Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at:       Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at:         Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
    revoked_reason:     Mapped[str|None]      = mapped_column(String(50))

    user: Mapped["User"] = relationship(back_populates="sessions")

    __table_args__ = (
        Index("idx_sessions_user_active", "user_id", postgresql_where="is_active = true"),
        Index("idx_sessions_token", "refresh_token_hash"),
    )


class EmailToken(Base, UUIDPKMixin):
    __tablename__ = "email_tokens"

    user_id:    Mapped[str]      = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str]      = mapped_column(Text, nullable=False, unique=True)
    type:       Mapped[str]      = mapped_column(String(30), nullable=False)  # verify_email | reset_password | magic_link
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at:    Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
```

---

### 4.5 `models/audit.py`

```python
# src/models/audit.py
from datetime import datetime
from sqlalchemy import BigInteger, String, Boolean, Text, ForeignKey, DateTime, func, Index
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    # Partitionnement recommandé : PARTITION BY RANGE (created_at)

    id:         Mapped[int]      = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id:    Mapped[str|None] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action:     Mapped[str]      = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str|None] = mapped_column(INET)
    user_agent: Mapped[str|None] = mapped_column(Text)
    geo_country:Mapped[str|None] = mapped_column(String(3))
    success:    Mapped[bool]     = mapped_column(Boolean, nullable=False)
    metadata_:  Mapped[dict]     = mapped_column("metadata", JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user: Mapped["User | None"] = relationship(back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_user_date", "user_id", "created_at"),
        Index("idx_audit_action_date", "action", "created_at"),
    )
```

---

## 5. Point d'entrée — `src/main.py`

```python
# src/main.py
from xcore.sdk import TrustedBase, ok, error
from xcore.kernel.api.auth import register_auth_backend, unregister_auth_backend
from fastapi import APIRouter
from .schemas.auth import (
    TokenVerifyRequest, TokenVerifyResponse,
    HasPermissionRequest, HasPermissionResponse,
)
from .schemas.user import UserOut


class Plugin(TrustedBase):

    async def on_load(self):
        self.db    = self.get_service("db")
        self.cache = self.get_service("cache")
        self.sched = self.get_service("scheduler")
        env = self.ctx.env

        # 1. Migrations
        from xcore.services.database.migrations import MigrationRunner
        MigrationRunner(env["DATABASE_URL"], "./migrations").upgrade()

        # 2. Seed rôles système
        from .services.rbac import RBACService
        await RBACService(self.db, self.cache).seed_system_roles()

        # 3. Backend auth → active @require_permission sur toutes routes xcore
        from .backend import XcoreAuthBackend
        register_auth_backend(XcoreAuthBackend(self.db, cache=self.cache, env=self.ctx.env))

        # 4. Job nettoyage sessions expirées (toutes les heures)
        @self.sched.cron("0 * * * *")
        async def cleanup_sessions():
            from .repositories.session import SessionRepository
            async with self.db.session() as session:
                count = await SessionRepository(session).expire_old()
                self.ctx.logger.info(f"[auth_user] {count} sessions expirées nettoyées.")

        # 5. Health checks
        self._register_health()

        # 6. Métriques
        self._register_metrics()

        await self.ctx.events.emit("auth_user.loaded", {"plugin": "auth_user"})

    async def on_unload(self):
        unregister_auth_backend()

    def get_router(self) -> APIRouter:
        from .routes import build_router
        return build_router(self.db, self.cache, self.ctx.env)

    # ── IPC inter-plugins ─────────────────────────────────────

    async def handle(self, action: str, payload: dict) -> dict:
        dispatch = {
            "verify_token":   self._verify_token,
            "has_permission": self._has_permission,
            "get_user":       self._get_user,
        }
        fn = dispatch.get(action)
        if not fn:
            return error(f"Action inconnue: {action}", "unknown_action")
        return await fn(payload)

    async def _verify_token(self, payload: dict) -> dict:
        req = TokenVerifyRequest(**payload)
        from .services.token import TokenService
        data = await TokenService(self.cache, self.ctx.env).verify(req.token)
        resp = TokenVerifyResponse(valid=data is not None, user=data)
        return ok(**resp.model_dump())

    async def _has_permission(self, payload: dict) -> dict:
        req = HasPermissionRequest(**payload)
        from .services.rbac import RBACService
        allowed = await RBACService(self.db, self.cache).has_permission(
            str(req.user_id), req.permission
        )
        return ok(**HasPermissionResponse(allowed=allowed).model_dump())

    async def _get_user(self, payload: dict) -> dict:
        from .repositories.user import UserRepository
        from uuid import UUID
        user = await UserRepository(self.db).get_by_id(UUID(payload["user_id"]))
        if not user:
            return error("Utilisateur introuvable", "not_found")
        return ok(**UserOut.model_validate(user).model_dump())

    # ── Health ────────────────────────────────────────────────

    def _register_health(self):
        @self.ctx.health.register("auth_user.db")
        async def check_db():
            await self.db.execute("SELECT 1")
            return True, "ok"

        @self.ctx.health.register("auth_user.cache")
        async def check_cache():
            ok_ = await self.cache._backend.ping()
            return ok_, "ok" if ok_ else "unreachable"

    # ── Métriques ─────────────────────────────────────────────

    def _register_metrics(self):
        m = self.ctx.metrics
        self.m_logins   = m.counter("auth.logins_total")
        self.m_failures = m.counter("auth.login_failures_total")
        self.m_mfa      = m.counter("auth.mfa_verifications_total")
        self.m_tokens   = m.counter("auth.tokens_issued_total")
        self.m_latency  = m.histogram("auth.request_duration_seconds")
        self.g_sessions = m.gauge("auth.active_sessions")
```

---

## 6. Routes — `src/routes/`

### 6.1 `routes/__init__.py`

```python
# src/routes/__init__.py
from fastapi import APIRouter
from .auth import router as auth_router
from .users import router as users_router
from .rbac import router as rbac_router
from .sessions import router as sessions_router
from .oauth import router as oauth_router
from .audit import router as audit_router


def build_router(db, cache, env) -> APIRouter:
    """Assemble tous les sous-routers du plugin auth_user."""
    router = APIRouter()
    router.include_router(auth_router(db, cache, env),     prefix="/auth",       tags=["Auth"])
    router.include_router(users_router(db, cache, env),    prefix="/users",      tags=["Users"])
    router.include_router(rbac_router(db, cache, env),     prefix="",            tags=["RBAC"])
    router.include_router(sessions_router(db, cache, env), prefix="/sessions",   tags=["Sessions"])
    router.include_router(oauth_router(db, cache, env),    prefix="/auth/oauth", tags=["OAuth"])
    router.include_router(audit_router(db, cache, env),    prefix="/audit-logs", tags=["Audit"])
    return router
```

### 6.2 `routes/auth.py` (extrait structurel)

```python
# src/routes/auth.py
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from ..schemas.auth import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    RefreshRequest, RefreshResponse,
    LogoutRequest,
    ForgotPasswordRequest, ResetPasswordRequest,
    VerifyEmailRequest, ResendVerificationRequest,
    MagicLinkRequest,
    MFAEnableResponse, MFAVerifyRequest, MFAVerifyResponse,
    MFADisableRequest, MFABackupCodesResponse,
    EmailOTPRequest,
)
from ..schemas.common import MessageResponse


def auth_router(db, cache, env) -> APIRouter:
    router = APIRouter()

    @router.post("/register", response_model=RegisterResponse, status_code=201)
    async def register(body: RegisterRequest, request: Request):
        from ..services.auth import AuthService
        return await AuthService(db, cache, env).register(body, request)

    @router.post("/login", response_model=LoginResponse)
    async def login(body: LoginRequest, request: Request, response: Response):
        from ..services.auth import AuthService
        return await AuthService(db, cache, env).login(body, request, response)

    @router.post("/logout", response_model=MessageResponse)
    async def logout(body: LogoutRequest, request: Request, response: Response):
        # current_user via Depends(get_current_user)
        ...

    @router.post("/refresh", response_model=RefreshResponse)
    async def refresh(body: RefreshRequest, request: Request, response: Response):
        ...

    @router.post("/forgot-password", response_model=MessageResponse)
    async def forgot_password(body: ForgotPasswordRequest):
        # Toujours retourner 200 même si email inconnu (anti-enumération)
        ...

    @router.post("/reset-password", response_model=MessageResponse)
    async def reset_password(body: ResetPasswordRequest):
        ...

    @router.post("/verify-email", response_model=MessageResponse)
    async def verify_email(body: VerifyEmailRequest):
        ...

    @router.post("/mfa/enable", response_model=MFAEnableResponse)
    async def mfa_enable(request: Request):
        ...

    @router.post("/mfa/verify", response_model=MFAVerifyResponse)
    async def mfa_verify(body: MFAVerifyRequest):
        ...

    @router.post("/mfa/disable", response_model=MessageResponse)
    async def mfa_disable(body: MFADisableRequest, request: Request):
        ...

    @router.get("/mfa/backup-codes", response_model=MFABackupCodesResponse)
    async def backup_codes(request: Request):
        ...

    return router
```

### 6.3 `routes/users.py` (extrait structurel)

```python
# src/routes/users.py
from fastapi import APIRouter, Depends, Query
from ..schemas.user import UserOut, UserOutAdmin, UserCreate, UserUpdate, UserUpdateAdmin, PasswordChange
from ..schemas.common import PaginatedResponse, MessageResponse
from xcore.sdk import require_permission


def users_router(db, cache, env) -> APIRouter:
    router = APIRouter()

    @router.get("/me", response_model=UserOut)
    async def get_me(request):
        ...

    @router.patch("/me", response_model=UserOut)
    async def update_me(body: UserUpdate, request):
        ...

    @router.patch("/me/password", response_model=MessageResponse)
    async def change_password(body: PasswordChange, request):
        ...

    @router.get(
        "/",
        response_model=PaginatedResponse[UserOutAdmin],
        dependencies=[Depends(require_permission("users:list"))],
    )
    async def list_users(
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=200),
        search: str | None = None,
    ):
        ...

    @router.get(
        "/{user_id}",
        response_model=UserOutAdmin,
        dependencies=[Depends(require_permission("users:read"))],
    )
    async def get_user(user_id: UUID):
        ...

    @router.patch(
        "/{user_id}",
        response_model=UserOutAdmin,
        dependencies=[Depends(require_permission("users:write"))],
    )
    async def update_user(user_id: UUID, body: UserUpdateAdmin):
        ...

    @router.delete(
        "/{user_id}",
        response_model=MessageResponse,
        dependencies=[Depends(require_permission("users:delete"))],
    )
    async def delete_user(user_id: UUID):
        ...

    return router
```

---

## 7. Cache Redis — Stratégie complète

| Clé Redis                           | TTL       | Contenu |
|-------------------------------------|-----------|---------|
| `au:user:{id}:perms`                | 5 min     | `set[str]` permissions dénormalisées |
| `au:user:{id}:roles`                | 5 min     | `list[str]` noms de rôles |
| `au:blacklist:jti:{jti}`            | TTL token | `"1"` |
| `au:email_token:{hash}`             | 1h        | `{user_id, type}` |
| `au:mfa_token:{token_hash}`         | 5 min     | `{user_id}` (pre-auth) |
| `au:email_otp:{user_id}`            | 10 min    | code haché |
| `au:oauth:state:{state}`            | 10 min    | `{code_verifier, provider}` |
| `au:rate:login:ip:{ip}`             | 15 min    | compteur sliding window |
| `au:rate:login:email:{email_hash}`  | 15 min    | failed attempts |
| `au:rate:forgot:{email_hash}`       | 1h        | compteur |
| `au:user:{id}:profile`              | 10 min    | `UserOut` sérialisé |

Invalidation : toute modification role/permission → `cache.keys("au:user:*:perms")` → delete bulk.

---

## 8. Dépendances Python

```txt
python-jose[cryptography]>=3.3
argon2-cffi>=21.3
pyotp>=2.9
qrcode[pil]>=7.4
httpx>=0.25
email-validator>=2.1
ua-parser>=0.18
geoip2>=4.7
cryptography>=42
alembic>=1.13
sqlalchemy[asyncio]>=2.0
pydantic[email]>=2.5
```
