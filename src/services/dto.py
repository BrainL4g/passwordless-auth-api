"""Объекты передачи данных, не зависящие от фреймворка и используемые между слоями."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class RequestContext:
    """Метаданные текущего вызова на уровне транспорта (никогда не содержат секретов)."""

    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class TokenPair:
    """Выданный access token."""

    access_token: str
    token_type: str
    expires_in: int


@dataclass(frozen=True)
class ChallengeBeginResult:
    """Результат церемонии ``*/begin``."""

    challenge_id: str
    options: dict[str, Any]


@dataclass(frozen=True)
class RegisteredCredential:
    """Результат привязки passkey к устройству."""

    device_id: int
    credential_id: str


@dataclass(frozen=True)
class Page(Generic[T]):
    """Страница доменных объектов на основе смещения."""

    items: Sequence[T]
    total: int
    skip: int
    limit: int
