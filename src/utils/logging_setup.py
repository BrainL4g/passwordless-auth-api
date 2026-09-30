"""Настройка логирования.

Секреты (пароли, токены, челленджи) никогда не попадают в записи логов:
логируется только информация уровня домена (идентификаторы пользователей, типы
событий, адреса клиентов).
"""

from __future__ import annotations

import logging
from typing import Any

_CONFIGURED = False
_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s %(message)s"


class SecretRedactingFilter(logging.Filter):
    """Фильтр, скрывающий очевидно чувствительные атрибуты записей (в разумных пределах)."""

    SENSITIVE_KEYS = frozenset(
        {
            "password",
            "secret",
            "secret_key",
            "token",
            "access_token",
            "refresh_token",
            "authorization",
            "challenge",
            "credential",
        }
    )

    def filter(self, record: logging.LogRecord) -> bool:
        extra: dict[str, Any] = getattr(record, "__dict__", {}).copy()
        for key in self.SENSITIVE_KEYS:
            if key in extra:
                setattr(record, key, "***")
        return True


def configure_logging(level: str = "INFO") -> None:
    """Настраивает корневой логгер один раз на процесс."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(
        level=level.upper(),
        format=_LOG_FORMAT,
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        force=True,
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if level.upper() == "DEBUG" else logging.WARNING
    )
    logging.getLogger().addFilter(SecretRedactingFilter())
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Возвращает логгер модуля."""
    return logging.getLogger(name)
