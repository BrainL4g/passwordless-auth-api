"""Хранилище challenge: TTL, однократное использование, очистка и реализация на Redis."""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

import pytest

from src.services.challenge_store import (
    Challenge,
    InMemoryChallengeStore,
    RedisChallengeStore,
    _RedisAdapter,
    build_challenge,
    new_challenge,
    new_challenge_id,
)
from src.utils.enums import ChallengeOperation
from src.utils.time import utc_now
from tests.fakes import FakeRedisClient


def make_challenge(ttl_seconds: int = 300, **overrides: Any) -> Challenge:
    record, _ = build_challenge(
        operation=ChallengeOperation.LOGIN, ttl_seconds=ttl_seconds, **overrides
    )
    return record


def test_build_challenge_generates_unique_values() -> None:
    first, first_bytes = build_challenge(operation=ChallengeOperation.REGISTER, ttl_seconds=60)
    second, second_bytes = build_challenge(operation=ChallengeOperation.REGISTER, ttl_seconds=60)
    assert first.challenge_id != second.challenge_id
    assert first_bytes != second_bytes
    assert len(first_bytes) == 32
    assert first.expires_at > utc_now()


def test_new_helpers_are_random_and_url_safe() -> None:
    assert new_challenge_id() != new_challenge_id()
    assert new_challenge() != new_challenge()
    assert new_challenge_id().replace("-", "").replace("_", "").isalnum()


def test_challenge_is_expired_flag() -> None:
    assert make_challenge(ttl_seconds=-1).is_expired() is True
    assert make_challenge(ttl_seconds=300).is_expired() is False


def test_challenge_dict_round_trip() -> None:
    original = make_challenge(user_id=7, username="alice", email="a@b.c", user_handle=b"handle")
    restored = Challenge.from_dict(original.to_dict())
    assert restored == original


def test_in_memory_single_use() -> None:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    record = make_challenge()
    store.save(record)
    assert store.take(record.challenge_id) == record
    assert store.take(record.challenge_id) is None
    store.close()


def test_in_memory_take_unknown_returns_none() -> None:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    assert store.take("nope") is None
    store.close()


def test_in_memory_expired_challenge_is_not_returned() -> None:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    record = make_challenge()
    store.save(record)
    object.__setattr__(record, "expires_at", utc_now() - timedelta(seconds=1))
    assert store.take(record.challenge_id) is None
    store.close()


def test_in_memory_purge_expired() -> None:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    store.save(make_challenge())
    expired = make_challenge()
    object.__setattr__(expired, "expires_at", utc_now() - timedelta(seconds=1))
    store.save(expired)
    assert len(store) == 2
    assert store.purge_expired() == 1
    assert len(store) == 1
    store.close()


def test_in_memory_delete_and_clear() -> None:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    record = make_challenge()
    store.save(record)
    assert store.delete(record.challenge_id) is True
    assert store.delete(record.challenge_id) is False
    store.save(record)
    store.clear()
    assert len(store) == 0
    store.close()


def test_in_memory_rejects_invalid_cleanup_interval() -> None:
    with pytest.raises(ValueError):
        InMemoryChallengeStore(cleanup_interval_seconds=0)


def test_in_memory_background_cleanup() -> None:
    store = InMemoryChallengeStore(cleanup_interval_seconds=1)
    expired = make_challenge()
    object.__setattr__(expired, "expires_at", utc_now() - timedelta(seconds=1))
    store.save(expired)
    time.sleep(1.2)
    assert len(store) == 0
    store.close()


def test_redis_store_round_trip() -> None:
    client = FakeRedisClient()
    store = RedisChallengeStore(client)
    record = make_challenge(user_id=3, username="bob", email="b@b.c", user_handle=b"h")
    store.save(record)
    assert client.ttl[store._key(record.challenge_id)] > 0
    assert store.take(record.challenge_id) == record
    assert store.take(record.challenge_id) is None
    store.close()
    assert client.closed is True


def test_redis_store_delete_and_clear() -> None:
    client = FakeRedisClient()
    store = RedisChallengeStore(client)
    record = make_challenge()
    store.save(record)
    assert store.delete(record.challenge_id) is True
    assert store.delete(record.challenge_id) is False
    store.save(record)
    store.clear()
    assert client.store == {}
    assert store.purge_expired() == 0
    store.close()


def test_redis_store_ignores_expired() -> None:
    client = FakeRedisClient()
    store = RedisChallengeStore(client)
    record = make_challenge()
    object.__setattr__(record, "expires_at", utc_now() - timedelta(seconds=1))
    store.save(record)
    assert store.take(record.challenge_id) is None
    store.close()


def test_redis_store_uses_set_nx() -> None:
    client = FakeRedisClient()
    store = RedisChallengeStore(client)
    record = make_challenge()
    store.save(record)
    store.save(record)  # не должен перезаписывать, ключ всё ещё существует
    assert client.store[store._key(record.challenge_id)] is not None
    store.close()


def test_challenge_store_implementations_are_interchangeable() -> None:
    from src.services.challenge_store import ChallengeStore

    stores = [
        InMemoryChallengeStore(cleanup_interval_seconds=3600),
        RedisChallengeStore(FakeRedisClient()),
        RedisChallengeStore(_RedisAdapter(FakeRedisClient())),
    ]
    for store in stores:
        assert isinstance(store, ChallengeStore)
        record = make_challenge()
        store.save(record)
        assert store.take(record.challenge_id) is not None
        assert store.take(record.challenge_id) is None
        store.clear()
        store.close()


def test_redis_adapter_normalises_the_real_client_answers() -> None:
    """Адаптер — это обёртка над настоящим ``redis.Redis``."""

    class BytesRedis:
        """Отвечает ``bytes`` и лишними именованными аргументами, как redis-py."""

        def __init__(self) -> None:
            self.store: dict[str, bytes] = {}
            self.closed = False

        def set(self, name: str, value: bytes, **kwargs: Any) -> bool:
            self.store[name] = value
            return True

        def getdel(self, name: str) -> bytes | None:
            return self.store.pop(name, None)

        def delete(self, *names: str) -> int:
            return sum(1 for name in names if self.store.pop(name, None) is not None)

        def keys(self, pattern: str = "*", **kwargs: Any) -> list[bytes]:
            prefix = pattern.rstrip("*")
            return [name.encode() for name in self.store if name.startswith(prefix)]

        def close(self) -> None:
            self.closed = True

    backend = BytesRedis()
    adapter = _RedisAdapter(backend)
    assert adapter.set("k", "v", ex=300, nx=True) is True
    assert adapter.getdel("k") == "v"
    assert adapter.getdel("k") is None
    adapter.set("webauthn:challenge:1", "1", ex=300, nx=False)
    adapter.set("webauthn:challenge:2", "2", ex=300, nx=False)
    assert sorted(adapter.keys("webauthn:challenge:*")) == [
        "webauthn:challenge:1",
        "webauthn:challenge:2",
    ]
    assert adapter.delete("webauthn:challenge:1", "webauthn:challenge:2", "missing") == 2
    adapter.close()
    assert backend.closed is True


def test_redis_store_from_url_wraps_the_redis_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """``from_url`` прячет конкретный ``redis.Redis`` за адаптером."""
    redis = pytest.importorskip("redis")
    captured: dict[str, Any] = {}

    class FakeRedisClass:
        @staticmethod
        def from_url(url: str, *, decode_responses: bool) -> FakeRedisClient:
            captured["url"] = url
            captured["decode_responses"] = decode_responses
            return FakeRedisClient()

    monkeypatch.setattr(redis, "Redis", FakeRedisClass)
    store = RedisChallengeStore.from_url("redis://localhost:6379/0")
    assert captured == {"url": "redis://localhost:6379/0", "decode_responses": True}
    record = make_challenge()
    store.save(record)
    assert store.take(record.challenge_id) is not None
    store.close()
