"""Неизменяемый журнал аудита всех событий, значимых для аутентификации."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime
from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base
from src.utils.enums import AuthEventType, AuthLogStatus
from src.utils.time import utc_now

if TYPE_CHECKING:  # pragma: no cover - только для типизации
    from src.models.user import User


class AuthLog(Base):
    """Запись аудита. ``user_id`` устанавливается в NULL при удалении пользователя."""

    __tablename__ = "auth_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    event_type: Mapped[AuthEventType] = mapped_column(
        SAEnum(
            AuthEventType,
            name="auth_event_type",
            native_enum=False,
            length=64,
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    status: Mapped[AuthLogStatus] = mapped_column(
        SAEnum(
            AuthLogStatus,
            name="auth_log_status",
            native_enum=False,
            length=16,
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), default=None, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)
    details: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)

    user: Mapped[User | None] = relationship(back_populates="auth_logs")

    def __repr__(self) -> str:
        return (
            f"<AuthLog id={self.id} event={self.event_type} status={self.status} "
            f"user_id={self.user_id}>"
        )
