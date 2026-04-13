from __future__ import annotations
from datetime import datetime
from pydantic import EmailStr, Field, field_validator, model_validator, ConfigDict
from .common import BaseSchema, UUIDMixin, TimestampMixin
from enum import StrEnum
import re

PASSWORD_RE = re.compile(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]).{8,}$")


def validate_password_strength(v: str) -> str:
    if not PASSWORD_RE.match(v):
        raise ValueError(
            "Le mot de passe doit contenir au moins 12 caractères, "
            "une majuscule, un chiffre et un caractère spécial."
        )
    return v


class UserRole(StrEnum):
    STANDARD = "standard"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class UserBase(BaseSchema):
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)


class UserCreate(UserBase):
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class UserCreateAdmin(UserBase):
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
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)


class UserUpdateAdmin(UserUpdate):
    is_active: bool | None = None
    is_verified: bool | None = None


class PasswordChange(BaseSchema):
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
    email: EmailStr
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login_at: datetime | None = None
    oauth_accounts: list[OAuthAccountOut] = []

    model_config = ConfigDict(from_attributes=True)

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


class UserOutAdmin(UserOut):
    failed_login_count: int
    locked_until: datetime | None = None
    roles: list["RoleOut"] = []


class UserOutWithPermissions(UserOut):
    roles: list[str] = []
    permissions: list[str] = []


from .rbac import RoleOut
UserOutAdmin.model_rebuild()
