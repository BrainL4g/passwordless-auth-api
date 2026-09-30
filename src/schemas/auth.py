"""Схемы роутера ``/auth``."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from src.schemas.common import USERNAME_PATTERN, CredentialPayload
from src.utils.enums import DeviceType


class RegistrationBeginRequest(BaseModel):
    """Тело ``POST /auth/register/begin``."""

    model_config = ConfigDict(
        json_schema_extra={"example": {"username": "alice", "email": "alice@example.com"}}
    )

    username: str = Field(
        min_length=3,
        max_length=64,
        pattern=USERNAME_PATTERN,
        description="3-64 символа: буквы и цифры, точка, дефис, подчёркивание; должен "
        "начинаться с буквы или цифры",
    )
    email: EmailStr

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        return value.strip()


class RegistrationBeginResponse(BaseModel):
    """Ответ ``POST /auth/register/begin``."""

    challenge_id: str = Field(description="Непрозрачный одноразовый id сохранённого challenge")
    options: dict[str, Any] = Field(
        description="PublicKeyCredentialCreationOptions в виде JSON-объекта"
    )


class RegistrationCompleteRequest(BaseModel):
    """Тело ``POST /auth/register/complete``."""

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


class LoginBeginRequest(BaseModel):
    """Тело ``POST /auth/login/begin``."""

    model_config = ConfigDict(json_schema_extra={"example": {"username": "alice"}})

    username: str = Field(min_length=1, max_length=64)

    @field_validator("username")
    @classmethod
    def _strip_username(cls, value: str) -> str:
        return value.strip()


class AuthenticationBeginResponse(BaseModel):
    """Ответ ``POST /auth/login/begin``."""

    challenge_id: str
    options: dict[str, Any] = Field(
        description="PublicKeyCredentialRequestOptions в виде JSON-объекта"
    )


class LoginCompleteRequest(BaseModel):
    """Тело ``POST /auth/login/complete``."""

    challenge_id: str = Field(min_length=8, max_length=128)
    credential: CredentialPayload


class TokenResponse(BaseModel):
    """Access token, выдаваемый после успешной церемонии WebAuthn."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Время жизни token в секундах")
