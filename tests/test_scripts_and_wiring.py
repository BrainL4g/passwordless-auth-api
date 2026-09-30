"""Административный CLI-скрипт, связывание зависимостей и ограничитель частоты."""

from __future__ import annotations

import sys
import time
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import src.utils.rate_limit as rate_limit_module
from src.main import app
from src.repositories.user import SqlAlchemyUserRepository
from src.scripts import promote_admin
from src.services.admin_service import AdminService
from src.services.audit import AuditLogger
from src.services.auth_service import AuthService
from src.services.challenge_store import InMemoryChallengeStore, RedisChallengeStore
from src.services.device_service import DeviceService
from src.services.log_service import LogService
from src.services.security_service import SecurityService
from src.services.webauthn_service import WebAuthnService
from src.utils import deps
from src.utils.exceptions import NotFoundError, RateLimitExceededError
from src.utils.rate_limit import InMemoryRateLimiter, NoopRateLimiter
from tests.conftest import REPO_ROOT, build_settings, test_settings
from tests.factories import create_user


# ---------------------------------------------------------- promote_admin
def test_set_admin_status_grants(session: Session) -> None:
    create_user(session, username="alice")
    assert promote_admin.set_admin_status(session, "alice", is_admin=True) == "granted"
    session.expire_all()
    refreshed = SqlAlchemyUserRepository(session).get_by_username("alice")
    assert refreshed is not None and refreshed.is_admin is True


def test_set_admin_status_revokes(session: Session) -> None:
    create_user(session, username="root", is_admin=True)
    assert promote_admin.set_admin_status(session, "root", is_admin=False) == "revoked"
    session.expire_all()
    refreshed = SqlAlchemyUserRepository(session).get_by_username("root")
    assert refreshed is not None and refreshed.is_admin is False


def test_set_admin_status_is_case_insensitive(session: Session) -> None:
    create_user(session, username="alice")
    assert promote_admin.set_admin_status(session, "ALICE", is_admin=True) == "granted"


def test_set_admin_status_unknown_user(session: Session) -> None:
    with pytest.raises(NotFoundError):
        promote_admin.set_admin_status(session, "ghost", is_admin=True)


class _Scope:
    """Замена :func:`src.database.session_scope`."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def __enter__(self) -> Session:
        return self._session

    def __exit__(self, *_: object) -> None:
        return None


def test_main_promotes_and_reports(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], session: Session
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(promote_admin, "session_scope", lambda: _Scope(session))
    monkeypatch.setattr(
        promote_admin,
        "set_admin_status",
        lambda _s, username, *, is_admin: seen.update(username=username, admin=is_admin)
        or ("granted" if is_admin else "revoked"),
    )
    assert promote_admin.main(["alice"]) == 0
    assert seen == {"username": "alice", "admin": True}
    assert "granted" in capsys.readouterr().out


def test_main_revoke_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], session: Session
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(promote_admin, "session_scope", lambda: _Scope(session))
    monkeypatch.setattr(
        promote_admin,
        "set_admin_status",
        lambda _s, _u, *, is_admin: seen.setdefault("admin", is_admin) and "granted" or "revoked",
    )
    assert promote_admin.main(["alice", "--revoke"]) == 0
    assert seen["admin"] is False
    assert "revoked" in capsys.readouterr().out


def test_main_reports_an_unknown_user(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], session: Session
) -> None:
    def boom(_: Session, __: str, *, is_admin: bool) -> str:
        raise NotFoundError("User 'ghost' does not exist")

    monkeypatch.setattr(promote_admin, "session_scope", lambda: _Scope(session))
    monkeypatch.setattr(promote_admin, "set_admin_status", boom)
    assert promote_admin.main(["ghost"]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_main_requires_a_username(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["promote_admin"])
    with pytest.raises(SystemExit) as exc_info:
        promote_admin.main()
    assert exc_info.value.code == 2


# ------------------------------------------------ ограничение частоты запросов
def test_rate_limiter_factory_respects_the_flag() -> None:
    assert isinstance(deps._build_rate_limiter(False, 1, 1), NoopRateLimiter)
    assert isinstance(deps._build_rate_limiter(True, 5, 60), InMemoryRateLimiter)
    # кэшируется по конфигурации
    assert deps._build_rate_limiter(True, 5, 60) is deps._build_rate_limiter(True, 5, 60)


def test_rate_limiter_blocks_after_the_quota() -> None:
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)
    limiter.check("1.2.3.4:/auth/login/begin")
    limiter.check("1.2.3.4:/auth/login/begin")
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check("1.2.3.4:/auth/login/begin")
    assert exc_info.value.status_code == 429
    assert "retry after" in exc_info.value.message
    # Другой ключ не затрагивается.
    limiter.check("5.6.7.8:/auth/login/begin")
    limiter.reset()
    limiter.check("1.2.3.4:/auth/login/begin")


def test_rate_limiter_purges_expired_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    limiter.check("key")
    # Ограничитель читает время через глобальную переменную модуля, поэтому ссылка
    # на модуль ``time`` внутри ``rate_limit`` заменяется сдвинутыми часами.
    real_monotonic = time.monotonic
    monkeypatch.setattr(
        rate_limit_module, "time", SimpleNamespace(monotonic=lambda: real_monotonic() + 120)
    )
    limiter.check("key")  # старое окно истекло, слот снова свободен


@pytest.mark.parametrize("max_requests,window", [(0, 60), (5, 0), (-1, -1)])
def test_rate_limiter_rejects_invalid_configuration(max_requests: int, window: int) -> None:
    with pytest.raises(ValueError):
        InMemoryRateLimiter(max_requests=max_requests, window_seconds=window)


def test_noop_limiter_never_blocks() -> None:
    limiter = NoopRateLimiter()
    for _ in range(1000):
        limiter.check("key")  # никогда не бросает исключений и не хранит состояния


def test_rate_limited_endpoints_answer_429(client: TestClient) -> None:
    limited = build_settings(
        database_url=test_settings.database_url,
        secret_key=test_settings.secret_key,
        rp_id=test_settings.rp_id,
        allowed_origins=test_settings.allowed_origins,
        rate_limit_enabled=True,
        rate_limit_max_requests=2,
        rate_limit_window_seconds=60,
    )
    original = app.dependency_overrides[deps.cached_settings]
    deps._build_rate_limiter.cache_clear()
    app.dependency_overrides[deps.cached_settings] = lambda: limited
    try:
        payload = {"username": "alice"}
        assert client.post("/auth/login/begin", json=payload).status_code == 200
        assert client.post("/auth/login/begin", json=payload).status_code == 200
        blocked = client.post("/auth/login/begin", json=payload)
        assert blocked.status_code == 429
        assert blocked.json()["code"] == "rate_limited"
        # У другого маршрута своя квота (и он отвечает по своим правилам).
        assert client.post("/auth/register/begin", json=payload).status_code == 400
    finally:
        app.dependency_overrides[deps.cached_settings] = original
        deps._build_rate_limiter.cache_clear()


# --------------------------------------- связывание хранилища challenge
def test_challenge_store_factory_builds_memory() -> None:
    deps._build_challenge_store.cache_clear()
    store = deps.get_challenge_store(test_settings)
    assert isinstance(store, InMemoryChallengeStore)
    store.close()
    deps._build_challenge_store.cache_clear()


def test_challenge_store_factory_builds_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, str] = {}

    def fake_from_url(url: str, *, key_prefix: str = "webauthn:challenge:") -> object:
        created["url"] = url
        created["prefix"] = key_prefix
        return RedisChallengeStore(_FakeRedis())

    monkeypatch.setattr(RedisChallengeStore, "from_url", staticmethod(fake_from_url))
    deps._build_challenge_store.cache_clear()
    settings = test_settings.model_copy(update={"challenge_store": "redis"})
    assert deps.get_challenge_store(settings) is not None
    assert created["url"] == test_settings.redis_url
    assert created["prefix"] == "webauthn:challenge:"
    deps._build_challenge_store.cache_clear()


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def set(self, name: str, value: str, ex: int, nx: bool) -> bool:
        if nx and name in self.store:
            return False
        self.store[name] = value
        return True

    def getdel(self, name: str) -> str | None:
        return self.store.pop(name, None)

    def delete(self, *names: str) -> int:
        return sum(1 for name in names if self.store.pop(name, None) is not None)

    def keys(self, pattern: str) -> list[str]:
        return [name for name in self.store if name.startswith(pattern.rstrip("*"))]

    def close(self) -> None:
        return None


def test_cached_settings_is_a_singleton() -> None:
    assert deps.cached_settings() is deps.cached_settings()


# ------------------------------------------------------- DI: репозитории
def test_repository_dependencies_build_concrete_repositories(session: Session) -> None:
    from src.repositories.auth_log import SqlAlchemyAuthLogRepository
    from src.repositories.credential import SqlAlchemyCredentialRepository
    from src.repositories.device import SqlAlchemyDeviceRepository
    from src.repositories.transaction import SqlAlchemyTransactionManager
    from src.repositories.user import SqlAlchemyUserRepository

    assert isinstance(deps.get_user_repository(session), SqlAlchemyUserRepository)
    assert isinstance(deps.get_device_repository(session), SqlAlchemyDeviceRepository)
    assert isinstance(deps.get_credential_repository(session), SqlAlchemyCredentialRepository)
    assert isinstance(deps.get_auth_log_repository(session), SqlAlchemyAuthLogRepository)
    assert isinstance(deps.get_transaction_manager(session), SqlAlchemyTransactionManager)


# --------------------------------------------------------- DI: сервисы
def test_service_dependencies_build_services(session: Session, webauthn: object) -> None:
    users = deps.get_user_repository(session)
    devices = deps.get_device_repository(session)
    credentials = deps.get_credential_repository(session)
    logs = deps.get_auth_log_repository(session)
    transaction = deps.get_transaction_manager(session)
    audit = deps.get_audit_logger(logs, transaction)
    security = deps.get_security_service(test_settings)
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    try:
        assert isinstance(audit, AuditLogger)
        assert isinstance(deps.get_webauthn_service(test_settings), WebAuthnService)
        assert isinstance(security, SecurityService)
        assert isinstance(deps.get_log_service(logs), LogService)
        assert isinstance(
            deps.get_admin_service(users, devices, logs, transaction, audit), AdminService
        )
        assert isinstance(
            deps.get_auth_service(
                users=users,
                devices=devices,
                credentials=credentials,
                logs=logs,
                transaction=transaction,
                audit=audit,
                challenges=store,
                settings=test_settings,
                webauthn=webauthn,  # type: ignore[arg-type]
                security=security,
            ),
            AuthService,
        )
        assert isinstance(
            deps.get_device_service(
                devices=devices,
                credentials=credentials,
                logs=logs,
                transaction=transaction,
                audit=audit,
                challenges=store,
                settings=test_settings,
                webauthn=webauthn,  # type: ignore[arg-type]
            ),
            DeviceService,
        )
    finally:
        store.close()


def test_request_metadata_reaches_the_audit_trail(client: TestClient, session: Session) -> None:
    from src.repositories.auth_log import SqlAlchemyAuthLogRepository

    response = client.post(
        "/auth/login/begin", json={"username": "ghost"}, headers={"User-Agent": "Pixel 8/34"}
    )
    assert response.status_code == 200
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.user_agent == "Pixel 8/34"
    assert entry.ip_address == "testclient"


# ------------------------------------------------- дисциплина слоёв
def test_routers_never_touch_the_data_layer() -> None:
    """Роутеры только валидируют, вызывают сервис и сериализуют результат."""
    for path in (REPO_ROOT / "src" / "routers").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("src.repositories", "src.models", "src.database", "._session"):
            assert forbidden not in text, f"{path.name} must not use {forbidden}"


def test_services_depend_on_protocols_not_on_sql() -> None:
    """Сервисы связаны с узкими протоколами репозиториев."""
    for path in (REPO_ROOT / "src" / "services").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "from src.repositories.protocols" in text or "repositories" not in text, path.name
        for forbidden in ("SqlAlchemy", "src.database", "src.routers", "._session"):
            assert forbidden not in text, f"{path.name} must not use {forbidden}"


@pytest.mark.parametrize("package", ["services", "routers", "repositories", "models", "schemas"])
def test_nothing_creates_the_schema_outside_alembic(package: str) -> None:
    """Схемой владеет Alembic, а не ``Base.metadata.create_all``."""
    for path in (REPO_ROOT / "src" / package).glob("*.py"):
        assert "create_all" not in path.read_text(encoding="utf-8"), path.name


def test_services_never_import_fastapi() -> None:
    """Слой сервисов не зависит от фреймворка: вместо этого он бросает доменные ошибки."""
    for path in (REPO_ROOT / "src" / "services").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "fastapi" not in text, f"{path.name} imports FastAPI"


def test_repositories_implement_the_declared_protocols() -> None:
    """Каждый SQL-репозиторий структурно удовлетворяет своему протоколу."""
    from src.repositories.auth_log import SqlAlchemyAuthLogRepository
    from src.repositories.credential import SqlAlchemyCredentialRepository
    from src.repositories.device import SqlAlchemyDeviceRepository
    from src.repositories.protocols import (
        AuthLogRepository,
        CredentialRepository,
        DeviceRepository,
        TransactionManager,
        UserRepository,
    )
    from src.repositories.transaction import SqlAlchemyTransactionManager
    from src.repositories.user import SqlAlchemyUserRepository

    # Протоколы с ``runtime_checkable`` проверяют лишь наличие методов, поэтому
    # структурная проверка не требует живой сессии.
    session = cast("Session", None)
    assert isinstance(SqlAlchemyUserRepository(session), UserRepository)
    assert isinstance(SqlAlchemyDeviceRepository(session), DeviceRepository)
    assert isinstance(SqlAlchemyCredentialRepository(session), CredentialRepository)
    assert isinstance(SqlAlchemyAuthLogRepository(session), AuthLogRepository)
    assert isinstance(SqlAlchemyTransactionManager(session), TransactionManager)
