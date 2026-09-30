"""Абстракция ограничения частоты запросов (реализация в памяти, переключается настройками)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from src.utils.exceptions import RateLimitExceededError
from src.utils.logging_setup import get_logger

logger = get_logger(__name__)


@runtime_checkable
class RateLimiter(Protocol):
    """Контракт ограничителя частоты с фиксированным окном."""

    def check(self, key: str) -> None:
        """Расходует один слот для ``key``.

        Raises:
            RateLimitExceededError: когда квота текущего окна исчерпана.
        """
        ...


@dataclass(slots=True)
class _Window:
    started_at: float
    count: int


class InMemoryRateLimiter:
    """Потокобезопасный внутрипроцессный ограничитель частоты с фиксированным окном.

    Ограничение: счётчики хранятся в памяти рабочего процесса, поэтому при
    нескольких воркерах uvicorn фактическая квота равна
    ``workers * max_requests``.  Общую реализацию (Redis) можно подключить позже
    благодаря протоколу :class:`RateLimiter`.
    """

    def __init__(self, *, max_requests: int, window_seconds: int) -> None:
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("max_requests and window_seconds must be positive")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        """Расходует один слот для ``key`` либо выбрасывает :class:`RateLimitExceededError`."""
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            window = self._windows.get(key)
            if window is None:
                self._windows[key] = _Window(started_at=now, count=1)
                return
            if window.count >= self._max_requests:
                retry_after = max(1, int(self._window_seconds - (now - window.started_at)))
                logger.info("rate_limit_exceeded", extra={"key": key, "retry_after": retry_after})
                raise RateLimitExceededError(
                    f"Too many requests, retry after {retry_after} seconds"
                )
            window.count += 1

    def reset(self) -> None:
        """Сбрасывает все счётчики (используется в тестах и при административной перезагрузке)."""
        with self._lock:
            self._windows.clear()

    def _purge_expired(self, now: float) -> None:
        expired = [
            key
            for key, window in self._windows.items()
            if now - window.started_at >= self._window_seconds
        ]
        for key in expired:
            del self._windows[key]


class NoopRateLimiter:
    """Ограничитель, используемый, когда ограничение частоты отключено настройками."""

    def check(self, key: str) -> None:
        """Принимает любой запрос."""
        return None
