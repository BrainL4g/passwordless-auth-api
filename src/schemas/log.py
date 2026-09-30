"""Схемы роутера ``/logs``."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.utils.enums import AuthEventType, AuthLogStatus


class AuthLogResponse(BaseModel):
    """Одна запись аудита."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    event_type: AuthEventType
    status: AuthLogStatus
    timestamp: datetime
    ip_address: str | None
    user_agent: str | None
    details: str | None


class AuthLogListResponse(BaseModel):
    """Постраничный список записей аудита."""

    items: list[AuthLogResponse]
    total: int
    skip: int
    limit: int
