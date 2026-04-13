from __future__ import annotations

from uuid import UUID

from pydantic import EmailStr, Field, HttpUrl, field_validator

from .common import BaseSchema


class RegisterRequest(BaseSchema):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)

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
    email: EmailStr
    password: str
    remember_me: bool = False


class LoginResponse(BaseSchema):
    status: str
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    mfa_token: str | None = None


class RefreshRequest(BaseSchema):
    refresh_token: str | None = None


class RefreshResponse(BaseSchema):
    access_token: str
    refresh_token: str
    expires_in: int


class LogoutRequest(BaseSchema):
    logout_all: bool = False


class ForgotPasswordRequest(BaseSchema):
    email: EmailStr


class ResetPasswordRequest(BaseSchema):
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


class VerifyEmailRequest(BaseSchema):
    token: str


class ResendVerificationRequest(BaseSchema):
    email: EmailStr


class MagicLinkRequest(BaseSchema):
    email: EmailStr
    redirect_url: HttpUrl | None = None


class MFAEnableResponse(BaseSchema):
    secret: str
    provisioning_uri: str
    qr_code_base64: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseSchema):
    code: str = Field(min_length=6, max_length=8)
    mfa_token: str | None = None


class MFAVerifyResponse(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MFADisableRequest(BaseSchema):
    code: str = Field(min_length=6, max_length=6)
    password: str


class MFABackupCodesResponse(BaseSchema):
    backup_codes: list[str]
    remaining_count: int


class EmailOTPRequest(BaseSchema):
    code: str = Field(min_length=6, max_length=6)
    mfa_token: str


class OAuthAuthorizeResponse(BaseSchema):
    authorization_url: str
    state: str


class OAuthLinkRequest(BaseSchema):
    code: str
    state: str


class TokenPayload(BaseSchema):
    sub: str
    email: str
    roles: list[str]
    permissions: list[str]
    session_id: str
    jti: str
    iat: int
    exp: int
    model_config = {"extra": "allow"}


class TokenVerifyRequest(BaseSchema):
    token: str


class TokenVerifyResponse(BaseSchema):
    valid: bool
    user: "UserOutWithPermissions | None" = None
    error: str | None = None


class HasPermissionRequest(BaseSchema):
    user_id: UUID
    permission: str


class HasPermissionResponse(BaseSchema):
    allowed: bool


from .user import UserOutWithPermissions

TokenVerifyResponse.model_rebuild()
