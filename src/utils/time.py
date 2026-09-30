"""Вспомогательные функции для работы со временем, общие для слоёв данных и сервисов."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Возвращает текущее время как datetime с учётом часового пояса (UTC)."""
    return datetime.now(timezone.utc)
