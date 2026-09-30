"""Абстракция хранения challenge и её реализации.

Challenge WebAuthn служит якорем защиты от повторного использования для обеих
церемоний, поэтому он должен быть *одноразовым* и *ограниченным по времени*.
Сервисы зависят только от протокола :class:`ChallengeStore`, так что переход от
внутрипроцессного хранилища к общему хранилищу Redis — это изменение конфигурации
(принцип открытости/закрытости), не требующее правки сервисов.
"""

from __future__ import annotations

import json
import secrets
import threading
from abc import abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from src.utils.enums import ChallengeOperation
from src.utils.logging_setup import get_logger
from src.utils.time import utc_now

logger = get_logger(__name__)

CHALLENGE_ID_BYTES = 24


def new_challenge_id() -> str:
    """Возвращает случайный, URL-безопасный идентификатор challenge."""
    return secrets.token_urlsafe(CHALLENGE_ID_BYTES)


def new_challenge() -> bytes:
    """Возвращает случайный 32-байтовый challenge WebAuthn."""
    return secrets.token_bytes(32)


@dataclass(frozen=True)
class Challenge:
    """Сохранённый challenge WebAuthn вместе с контекстом церемонии."""

    challenge_id: str
    challenge: bytes
    operation: ChallengeOperation
    expires_at: datetime
    user_id: int | None = None
    username: str | None = None
    email: str | None = None
    user_handle: bytes | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        """Истёк ли TTL challenge."""
        return (now or utc_now()) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Сериализует в структуру, удобную для JSON (bytes становятся base64)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Challenge:
        """Восстанавливает challenge из результата :meth:`to_dict`."""
        return cls(
            challenge_id=str(payload["challenge_id"]),
            challenge=bytes(payload["challenge"]),
            operation=ChallengeOperation(payload["operation"]),
            expires_at=datetime.fromisoformat(str(payload["expires_at"])),
            user_id=payload.get("user_id"),
            username=payload.get("username"),
            email=payload.get("email"),
            user_handle=payload.get("user_handle"),
        )


@runtime_checkable
class ChallengeStore(Protocol):
    """Контракт хранения одноразовых challenge с ограничением по TTL."""

    @abstractmethod
    def save(self, challenge: Challenge) -> None:
        """Сохраняет challenge."""
        ...

    @abstractmethod
    def take(self, challenge_id: str) -> Challenge | None:
        """Атомарно получает **и удаляет** challenge.

        Возвращает ``None``, если идентификатор неизвестен, уже использован или
        истёк, что сохраняет одинаковое поведение для всех реализаций.
        """
        ...

    @abstractmethod
    def delete(self, challenge_id: str) -> bool:
        """Удаляет challenge, не расходуя его."""
        ...

    @abstractmethod
    def purge_expired(self) -> int:
        """Удаляет истёкшие записи и возвращает их количество."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Удаляет все записи (используется в тестах)."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Освобождает ресурсы, удерживаемые хранилищем."""
        ...


class InMemoryChallengeStore:
    """Локальное хранилище процесса с ленивой и фоновой очисткой по TTL.

    Примечание: при нескольких воркерах uvicorn каждый воркер держит собственное
    хранилище, поэтому ``register/begin`` и ``register/complete`` должны попасть
    в один и тот же воркер. Для многоворкерных/масштабируемых развёртываний
    используйте ``CHALLENGE_STORE=redis``.
    """

    def __init__(self, *, cleanup_interval_seconds: int = 60) -> None:
        if cleanup_interval_seconds < 1:
            raise ValueError("cleanup_interval_seconds must be positive")
        self._cleanup_interval = cleanup_interval_seconds
        self._challenges: dict[str, Challenge] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._janitor = threading.Thread(
            target=self._cleanup_loop,
            name="challenge-store-janitor",
            daemon=True,
        )
        self._janitor.start()

    def save(self, challenge: Challenge) -> None:
        with self._lock:
            self._purge_expired_locked()
            self._challenges[challenge.challenge_id] = challenge

    def take(self, challenge_id: str) -> Challenge | None:
        with self._lock:
            challenge = self._challenges.pop(challenge_id, None)
        if challenge is None:
            return None
        if challenge.is_expired():
            return None
        return challenge

    def delete(self, challenge_id: str) -> bool:
        with self._lock:
            return self._challenges.pop(challenge_id, None) is not None

    def purge_expired(self) -> int:
        with self._lock:
            return self._purge_expired_locked()

    def clear(self) -> None:
        with self._lock:
            self._challenges.clear()

    def close(self) -> None:
        """Останавливает фоновую уборку."""
        self._stop.set()

    def __len__(self) -> int:
        with self._lock:
            return len(self._challenges)

    def _purge_expired_locked(self) -> int:
        now = utc_now()
        expired = [key for key, value in self._challenges.items() if value.is_expired(now)]
        for key in expired:
            del self._challenges[key]
        if expired:
            logger.debug("purged_expired_challenges", extra={"count": len(expired)})
        return len(expired)

    def _cleanup_loop(self) -> None:
        while not self._stop.wait(self._cleanup_interval):
            try:
                self.purge_expired()
            except Exception:  # pragma: no cover - защита, уборщик не должен падать
                logger.exception("challenge_store_cleanup_failed")


class _RedisClient(Protocol):
    """Что хранилище требует от клиента Redis, как это предоставляет :class:`_RedisAdapter`.

    Всё передаётся обычным текстом: за декодирование ``bytes``, которые клиент
    возвращает при создании без ``decode_responses=True``, отвечает адаптер.
    """

    def set(self, name: str, value: str, ex: int, nx: bool) -> object: ...

    def getdel(self, name: str) -> str | None: ...

    def delete(self, *names: str) -> object: ...

    def keys(self, pattern: str) -> list[str]: ...

    def close(self) -> None: ...


class _RedisChallengeCodec:
    """Вспомогательные функции сериализации между :class:`Challenge` и строками Redis."""

    @staticmethod
    def encode(challenge: Challenge) -> str:
        return json.dumps(
            {
                "challenge_id": challenge.challenge_id,
                "challenge": challenge.challenge.hex(),
                "operation": str(challenge.operation),
                "expires_at": challenge.expires_at.isoformat(),
                "user_id": challenge.user_id,
                "username": challenge.username,
                "email": challenge.email,
                "user_handle": challenge.user_handle.hex() if challenge.user_handle else None,
            }
        )

    @staticmethod
    def decode(raw: str | bytes) -> Challenge:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        payload: dict[str, Any] = json.loads(text)
        user_handle_hex: str | None = payload.get("user_handle")
        return Challenge(
            challenge_id=str(payload["challenge_id"]),
            challenge=bytes.fromhex(str(payload["challenge"])),
            operation=ChallengeOperation(payload["operation"]),
            expires_at=datetime.fromisoformat(str(payload["expires_at"])),
            user_id=payload.get("user_id"),
            username=payload.get("username"),
            email=payload.get("email"),
            user_handle=bytes.fromhex(user_handle_hex) if user_handle_hex else None,
        )


class _RedisAdapter:
    """Сужает реальный клиент ``redis.Redis`` до протокола :class:`_RedisClient`.

    ``redis-py`` объявляет сильно перегруженные сигнатуры; хранилище использует
    лишь пять простых операций, поэтому адаптер фиксирует типы, на которые
    опирается, декодирует ``bytes``, которые клиент может вернуть, и избавляет
    остальной модуль от приведений к ``Any``.
    """

    __slots__ = ("_client",)

    def __init__(self, client: Any) -> None:
        self._client = client

    @staticmethod
    def _text(value: bytes | str) -> str:
        return value.decode("utf-8") if isinstance(value, bytes) else value

    def set(self, name: str, value: str, ex: int, nx: bool) -> bool:
        return bool(self._client.set(name, value, ex=ex, nx=nx))

    def getdel(self, name: str) -> str | None:
        value = self._client.getdel(name)
        return None if value is None else self._text(value)

    def delete(self, *names: str) -> int:
        return int(self._client.delete(*names))

    def keys(self, pattern: str) -> list[str]:
        return [self._text(key) for key in self._client.keys(pattern)]

    def close(self) -> None:
        self._client.close()


class RedisChallengeStore:
    """Общее хранилище challenge на базе Redis (одноразовость через ``GETDEL``)."""

    def __init__(self, client: _RedisClient, *, key_prefix: str = "webauthn:challenge:") -> None:
        self._client = client
        self._prefix = key_prefix

    @classmethod
    def from_url(cls, url: str, *, key_prefix: str = "webauthn:challenge:") -> RedisChallengeStore:
        """Создаёт хранилище поверх клиента redis, созданного из ``url``."""
        from redis import Redis  # импортируется лениво: зависимость не обязательна в рантайме

        return cls(_RedisAdapter(Redis.from_url(url, decode_responses=True)), key_prefix=key_prefix)

    def _key(self, challenge_id: str) -> str:
        return f"{self._prefix}{challenge_id}"

    def save(self, challenge: Challenge) -> None:
        ttl = max(1, int((challenge.expires_at - utc_now()).total_seconds()))
        self._client.set(
            self._key(challenge.challenge_id),
            _RedisChallengeCodec.encode(challenge),
            ex=ttl,
            nx=True,
        )

    def take(self, challenge_id: str) -> Challenge | None:
        raw = self._client.getdel(self._key(challenge_id))
        if raw is None:
            return None
        challenge = _RedisChallengeCodec.decode(raw)
        if challenge.is_expired():
            return None
        return challenge

    def delete(self, challenge_id: str) -> bool:
        return bool(self._client.delete(self._key(challenge_id)))

    def purge_expired(self) -> int:
        """Redis сам истекает ключи, поэтому ничего вычищать не нужно."""
        return 0

    def clear(self) -> None:
        keys = self._client.keys(self._prefix + "*")
        if keys:
            self._client.delete(*keys)

    def close(self) -> None:
        self._client.close()


def build_challenge(
    *,
    operation: ChallengeOperation,
    ttl_seconds: int,
    user_id: int | None = None,
    username: str | None = None,
    email: str | None = None,
    user_handle: bytes | None = None,
) -> tuple[Challenge, bytes]:
    """Создаёт новую запись challenge вместе с его случайными байтами."""
    challenge_bytes = new_challenge()
    record = Challenge(
        challenge_id=new_challenge_id(),
        challenge=challenge_bytes,
        operation=operation,
        expires_at=utc_now() + timedelta(seconds=ttl_seconds),
        user_id=user_id,
        username=username,
        email=email,
        user_handle=user_handle,
    )
    return record, challenge_bytes
