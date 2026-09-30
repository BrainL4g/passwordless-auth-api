"""Декларативная база и общие миксины столбцов."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from src.utils.time import utc_now


class Base(DeclarativeBase):
    """Базовый класс всех ORM-моделей."""


class TimestampMixin:
    """Добавляет метки времени создания/обновления, хранящиеся с учётом часового пояса."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
