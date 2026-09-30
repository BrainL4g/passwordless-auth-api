"""Фикстуры pytest.

Импорт этого модуля подготавливает окружение (``DATABASE_URL``, ``SECRET_KEY``
...) **до** импорта любого модуля приложения, потому что настройки
проверяются в момент импорта.

Стратегия работы с базой данных
-------------------------------
1. ``TEST_DATABASE_URL`` / ``TEST_DATABASE_ADMIN_URL``, если они заданы.
2. Доступный PostgreSQL на localhost -> выделенная база данных
   ``passwordless_auth_test`` создаётся один раз за сессию, и схема
   применяется настоящими миграциями Alembic.
3. Иначе используется временная файловая база данных SQLite (те же миграции),
   поэтому набор тестов остаётся запускаемым на машинах без PostgreSQL.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from alembic import command
from alembic.config import Config

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB_NAME = "passwordless_auth_test"
DEFAULT_PG_ADMIN_URL = "postgresql+psycopg://auth:auth@localhost:5432/auth"
TEST_SECRET_KEY = "test-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz"
TEST_ALLOWED_ORIGINS = "https://localhost:8443,android:apk-key-hash:TESTHASH"


def _can_connect(url: str) -> bool:
    try:
        engine = create_engine(url, poolclass=StaticPool)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        finally:
            engine.dispose()
    except Exception:
        return False
    return True


def _database_url_without_database(url: str) -> str:
    head, _, _ = url.rpartition("/")
    return f"{head}/postgres" if head else url


def _create_test_database(admin_url: str, db_name: str) -> str:
    """Создаёт базу ``db_name``, если её ещё нет, и возвращает её URL."""
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            exists = connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": db_name}
            ).scalar()
            if not exists:
                connection.execute(text(f'CREATE DATABASE "{db_name}"'))
    finally:
        engine.dispose()
    head, _, database = admin_url.rpartition("/")
    return f"{head}/{db_name}" if database else admin_url


def _resolve_test_database_url() -> tuple[str, str]:
    """Возвращает ``(url, kind)`` для базы данных, используемой в тестах."""
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        return explicit, "postgresql"
    admin_url = os.environ.get("TEST_DATABASE_ADMIN_URL", DEFAULT_PG_ADMIN_URL)
    if _can_connect(admin_url):
        return _create_test_database(admin_url, TEST_DB_NAME), "postgresql"
    tmp_dir = Path(tempfile.mkdtemp(prefix="passwordless-auth-tests-"))
    return f"sqlite:///{(tmp_dir / 'test.db').as_posix()}", "sqlite"


TEST_DATABASE_URL, TEST_DATABASE_KIND = _resolve_test_database_url()

os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["SECRET_KEY"] = TEST_SECRET_KEY
os.environ["RP_ID"] = "localhost"
os.environ["ALLOWED_ORIGINS"] = TEST_ALLOWED_ORIGINS
os.environ["CHALLENGE_STORE"] = "memory"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["ANDROID_PACKAGE_NAME"] = "com.example.passwordless"
os.environ["ANDROID_CERT_FINGERPRINTS"] = "TESTFINGERPRINT1,TESTFINGERPRINT2"
os.environ["CORS_ORIGINS"] = "https://localhost:8443"
os.environ["LOG_LEVEL"] = "WARNING"
for _key in ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "DB_PORT", "API_PORT"):
    os.environ.pop(_key, None)

# Приложение импортируется только после подготовки окружения.
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session as OrmSession  # noqa: E402

from src.database import create_db_engine  # noqa: E402
from src.main import app  # noqa: E402
from src.models import Base  # noqa: E402
from src.services.challenge_store import InMemoryChallengeStore  # noqa: E402
from src.utils.config import Settings  # noqa: E402
from src.utils.deps import (  # noqa: E402
    cached_settings,
    get_challenge_store,
    get_db,
    get_webauthn_service,
)
from tests.fakes import FakeWebAuthnService  # noqa: E402


def build_settings(**payload: Any) -> Settings:
    """Создаёт :class:`Settings` только из явно переданных kwargs.

    ``_env_file=None`` вместе с очищенным окружением (см.
    ``tests/test_config.py``) гарантирует, что тест действительно проверяет
    переданное значение, а не то, что разработчик имеет в своём ``.env``.
    """
    settings_class: Any = Settings
    return cast("Settings", settings_class(**payload, _env_file=None))


def _build_test_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "database_url": TEST_DATABASE_URL,
        "secret_key": TEST_SECRET_KEY,
        "rp_id": "localhost",
        "rp_name": "Test RP",
        "allowed_origins": [
            "https://localhost:8443",
            "android:apk-key-hash:TESTHASH",
        ],
        "cors_origins": ["https://localhost:8443"],
        "challenge_store": "memory",
        "rate_limit_enabled": False,
        "android_package_name": "com.example.passwordless",
        "android_cert_fingerprints": ["TESTFINGERPRINT1", "TESTFINGERPRINT2"],
        "access_token_expire_minutes": 30,
        "log_level": "WARNING",
    }
    base.update(overrides)
    return build_settings(**base)


test_settings = _build_test_settings()


def _apply_migrations(url: str) -> None:
    """Создаёт схему через Alembic (никогда не ``create_all``)."""
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    try:
        command.downgrade(config, "base")
        command.upgrade(config, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


@pytest.fixture(scope="session")
def engine() -> Generator[Engine, None, None]:
    """Движок на всю сессию, привязанный к мигрированной тестовой базе данных."""
    _apply_migrations(TEST_DATABASE_URL)
    db_engine = create_db_engine(test_settings)
    try:
        yield db_engine
    finally:
        db_engine.dispose()


@pytest.fixture(autouse=True)
def clean_database(engine: Engine) -> Generator[None, None, None]:
    """Очищает все таблицы перед каждым тестом."""
    tables = list(reversed(Base.metadata.sorted_tables))
    with engine.begin() as connection:
        for table in tables:
            connection.execute(table.delete())
    yield


@pytest.fixture
def session(engine: Engine) -> Generator[Session, None, None]:
    """Сессия, привязанная к тестовой базе данных."""
    db_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        yield db_session
    finally:
        db_session.rollback()
        db_session.close()


@pytest.fixture
def webauthn() -> FakeWebAuthnService:
    """Поддельный сервис протокола WebAuthn (заменяет границу py_webauthn)."""
    return FakeWebAuthnService()


@pytest.fixture
def challenge_store() -> Generator[InMemoryChallengeStore, None, None]:
    """Свежее хранилище challenge в памяти на каждый тест."""
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    try:
        yield store
    finally:
        store.clear()
        store.close()


@pytest.fixture
def client(
    engine: Engine,
    webauthn: FakeWebAuthnService,
    challenge_store: InMemoryChallengeStore,
) -> Generator[TestClient, None, None]:
    """HTTP-клиент, связанный с тестовой базой данных, настройками и подделками."""
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def _override_db() -> Generator[OrmSession, None, None]:
        db_session = testing_session()
        try:
            yield db_session
        finally:
            db_session.close()

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[cached_settings] = lambda: test_settings
    app.dependency_overrides[get_webauthn_service] = lambda: webauthn
    app.dependency_overrides[get_challenge_store] = lambda: challenge_store
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
