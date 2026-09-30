"""Схемы роутера ``/admin``."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.schemas.device import DeviceResponse


class AdminUserResponse(BaseModel):
    """Представление пользователя, видимое администраторам."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    updated_at: datetime


class UserListResponse(BaseModel):
    """Постраничное представление всех пользователей для администраторов."""

    items: list[AdminUserResponse]
    total: int
    skip: int
    limit: int


class AdminUserDevicesResponse(BaseModel):
    """Устройства произвольного пользователя (только для администраторов)."""

    user_id: int
    items: list[DeviceResponse]
