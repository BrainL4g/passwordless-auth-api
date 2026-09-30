"""Схемы роутера ``/devices``."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.models.device import Device
from src.schemas.common import CredentialPayload
from src.utils.enums import DeviceType


class DeviceResponse(BaseModel):
    """Устройство с единственным зарегистрированным passkey."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    device_name: str
    device_type: DeviceType
    created_at: datetime
    last_used: datetime | None = None
    credential_id: str | None = None


class DeviceListResponse(BaseModel):
    """Устройства текущего пользователя."""

    items: list[DeviceResponse]


class DeviceBeginResponse(BaseModel):
    """Ответ ``POST /devices/register/begin``."""

    challenge_id: str
    options: dict[str, Any] = Field(
        description="PublicKeyCredentialCreationOptions без сущности пользователя"
    )


class DeviceRegisterCompleteRequest(BaseModel):
    """Тело ``POST /devices/register/complete``."""

    challenge_id: str = Field(min_length=8, max_length=128)
    credential: CredentialPayload
    device_name: str = Field(min_length=1, max_length=128)
    device_type: DeviceType

    @field_validator("device_name")
    @classmethod
    def _strip_device_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("device_name must not be blank")
        return stripped


class DeviceAddedResponse(BaseModel):
    """Результат привязки дополнительного passkey."""

    device_id: int
    credential_id: str


def device_to_response(device: Device) -> DeviceResponse:
    """Преобразовать сущность устройства (с её passkey) в публичную схему."""
    return DeviceResponse(
        id=device.id,
        device_name=device.device_name,
        device_type=device.device_type,
        created_at=device.created_at,
        last_used=device.last_used,
        credential_id=device.credential.credential_id if device.credential else None,
    )
