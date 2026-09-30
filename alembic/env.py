"""Окружение Alembic.

URL базы данных берётся из переменной окружения ``DATABASE_URL``
(файл ``.env`` загружается pydantic-settings внутри приложения), а при её
отсутствии используется значение из ``alembic.ini``.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from src.models import Base

config = context.config

if config.config_file_name is not None:
    # ``disable_existing_loggers`` должен оставаться выключенным: миграции
    # запускаются и изнутри приложения (CMD в Docker, тестовый набор), и такой
    # запуск не должен глушить уже настроенные логгеры.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def get_url() -> str:
    """Определить URL базы данных для запуска миграций."""
    return os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url", "")


def run_migrations_offline() -> None:
    """Выполнить миграции без подключения к БД (SQL печатается в stdout)."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Выполнить миграции по живому подключению к базе данных."""
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
