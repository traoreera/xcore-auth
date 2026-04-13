from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import Field, field_validator
from .common import BaseSchema, UUIDMixin, TimestampMixin
import re

PERMISSION_RE = re.compile(r"^[a-z_]+:[a-z_]+$")


class PermissionBase(BaseSchema):
    name: str = Field(min_length=3, max_length=100)
    resource: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=50)
    description: str | None = None

    @field_validator("name")
    @classmethod
    def name_format(cls, v: str) -> str:
        if not PERMISSION_RE.match(v):
            raise ValueError("Format attendu : resource:action  (ex: users:read)")
        return v


class PermissionCreate(PermissionBase):
    pass


class PermissionOut(UUIDMixin, PermissionBase):
    pass


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
    permission_ids: list[UUID] = []


class RoleUpdate(BaseSchema):
    description: str | None = None


class RoleOut(UUIDMixin, TimestampMixin, RoleBase):
    is_system: bool
    permissions: list[PermissionOut] = []


class RoleOutSimple(UUIDMixin):
    name: str
    description: str | None = None


class AssignRoleRequest(BaseSchema):
    role_id: UUID


class AssignPermissionRequest(BaseSchema):
    permission_id: UUID


class AssignmentOut(BaseSchema):
    user_id: UUID
    role_id: UUID
    assigned_at: datetime
    assigned_by: UUID | None = None
