from __future__ import annotations
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from typing import Generic, TypeVar

T = TypeVar("T")


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        populate_by_name=True,
    )


class UUIDMixin(BaseSchema):
    id: UUID


class TimestampMixin(BaseSchema):
    created_at: datetime
    updated_at: datetime


class PaginatedResponse(BaseSchema, Generic[T]):
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
