"""Корень агрегата User."""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base, TimestampMixin
from src.utils.time import utc_now

if TYPE_CHECKING:  # pragma: no cover - только для типизации
    from src.models.auth_log import AuthLog
    from src.models.credential import Credential
    from src.models.device import Device

USER_HANDLE_LENGTH = 32


def generate_user_handle() -> bytes:
    """Вернуть случайный непрозрачный WebAuthn user handle.

    Именно этот handle аутентификатор сохраняет как ``user.id``; он не должен
    выводиться из имени пользователя или адреса электронной почты и не должен их
    раскрывать.
    """
    return secrets.token_bytes(USER_HANDLE_LENGTH)


class User(TimestampMixin, Base):
    """Учётная запись человека. Столбец с паролем отсутствует намеренно."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user_handle: Mapped[bytes] = mapped_column(
        LargeBinary(USER_HANDLE_LENGTH),
        default=generate_user_handle,
        unique=True,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    devices: Mapped[list[Device]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    credentials: Mapped[list[Credential]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    auth_logs: Mapped[list[AuthLog]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} active={self.is_active}>"
