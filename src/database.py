"""Движок SQLAlchemy / фабрика сессий.

Сама схема **никогда** не создаётся из моделей: она берётся исключительно из
миграций Alembic (``alembic upgrade head``).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.utils.config import Settings, get_settings

_settings: Settings = get_settings()


def create_db_engine(settings: Settings) -> Engine:
    """Создать движок SQLAlchemy для настроенного URL базы данных.

    Также поддерживается SQLite (используется тестовым набором, когда PostgreSQL
    недоступен); для него создаётся статический пул и ``check_same_thread=False``,
    чтобы одну базу данных в процессе могли совместно использовать приложение и
    тестовый клиент.
    """
    url = settings.database_url
    common: dict[str, object] = {
        "echo": settings.database_echo,
        "future": True,
        "pool_pre_ping": True,
    }
    if url.startswith("sqlite"):
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            **common,
        )
    return create_engine(
        url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        **common,
    )


engine: Engine = create_db_engine(_settings)

SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Контекстный менеджер, задающий транзакционную область для серии операций."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
