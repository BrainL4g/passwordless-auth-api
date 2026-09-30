"""Общие схемы: конверты, полезная нагрузка WebAuthn, healthcheck и ссылки на ресурсы."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")

USERNAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$"


class ErrorResponse(BaseModel):
    """Единое тело ошибки, используемое каждым неуспешным endpoint."""

    model_config = ConfigDict(
        json_schema_extra={"example": {"detail": "Not found", "code": "not_found"}}
    )

    detail: str = Field(description="Понятное человеку описание без секретов")
    code: str = Field(description="Стабильный машинно-читаемый код ошибки")


class PageResponse(BaseModel, Generic[T]):
    """Конверт постраничной выдачи на основе смещения."""

    items: list[T]
    total: int = Field(ge=0)
    skip: int = Field(ge=0)
    limit: int = Field(ge=1)


class CredentialPayload(BaseModel):
    """Учётные данные WebAuthn в их JSON-форме (браузер / Credential Manager).

    Ровно такую же структуру даёт ``JSON.stringify(credential)`` в браузере,
    а также ``PublicKeyCredential.toJson()`` /
    ``GetPublicKeyCredentialOption.requestJson`` на Android.
    """

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1, max_length=2048)
    raw_id: str | None = Field(default=None, max_length=4096)
    type: str = Field(default="public-key", max_length=64)
    response: dict[str, Any]
    authenticator_attachment: str | None = Field(default=None, max_length=64)
    client_extension_results: dict[str, Any] | None = None

    @field_validator("type")
    @classmethod
    def _validate_type(cls, value: str) -> str:
        if value != "public-key":
            raise ValueError("only 'public-key' credentials are supported")
        return value

    def to_library_input(self) -> dict[str, Any]:
        """Вернуть словарь, который вспомогательные функции ``webauthn`` разберут напрямую."""
        return self.model_dump(mode="json", exclude_none=True)


class HealthResponse(BaseModel):
    """Полезная нагрузка ``GET /health`` (используется Docker healthcheck)."""

    status: str = Field(examples=["ok"])
    service: str
    version: str
    database: str = Field(examples=["ok"])


class AssetLinkTarget(BaseModel):
    """Цель Digital Asset Links для Android-приложения."""

    namespace: str = "android_app"
    package_name: str
    sha256_cert_fingerprints: list[str] = Field(default_factory=list)


class AssetLinkStatement(BaseModel):
    """Одно утверждение Digital Asset Links."""

    relation: list[str] = Field(
        default_factory=lambda: ["delegate_permission/common.handle_all_urls"]
    )
    target: AssetLinkTarget
