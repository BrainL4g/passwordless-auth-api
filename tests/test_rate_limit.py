"""Ограничитель частоты запросов в памяти."""

from __future__ import annotations

import time

import pytest

from src.utils.exceptions import RateLimitExceededError
from src.utils.rate_limit import InMemoryRateLimiter, NoopRateLimiter, RateLimiter


def test_allows_up_to_the_quota() -> None:
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        limiter.check("1.2.3.4:/auth/login/begin")
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check("1.2.3.4:/auth/login/begin")
    assert "retry after" in exc_info.value.message


def test_keys_are_independent() -> None:
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    limiter.check("a")
    limiter.check("b")
    with pytest.raises(RateLimitExceededError):
        limiter.check("a")


def test_window_slides() -> None:
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=1)
    limiter.check("a")
    with pytest.raises(RateLimitExceededError):
        limiter.check("a")
    time.sleep(1.05)
    limiter.check("a")


def test_reset_clears_counters() -> None:
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    limiter.check("a")
    limiter.reset()
    limiter.check("a")


@pytest.mark.parametrize(("max_requests", "window"), [(0, 60), (1, 0), (-1, -1)])
def test_invalid_configuration(max_requests: int, window: int) -> None:
    with pytest.raises(ValueError):
        InMemoryRateLimiter(max_requests=max_requests, window_seconds=window)


def test_noop_limiter_accepts_everything() -> None:
    limiter = NoopRateLimiter()
    for _ in range(100):
        limiter.check("a")
    assert isinstance(limiter, RateLimiter)
    assert isinstance(InMemoryRateLimiter(max_requests=1, window_seconds=1), RateLimiter)
