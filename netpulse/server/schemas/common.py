"""Базовые Pydantic-схемы ответов."""
from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class BaseResponse(BaseModel):
    ok: bool = True


class OkResponse(BaseResponse):
    pass


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T] = Field(default_factory=list)
    total: int = 0
    limit: int = 100
    offset: int = 0


class HealthResponse(BaseModel):
    overall: bool
    services: dict[str, Any] = Field(default_factory=dict)
