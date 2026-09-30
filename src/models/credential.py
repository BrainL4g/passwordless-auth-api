"""Учётные данные открытого ключа (WebAuthn), связанные с устройством 1:1."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - только для типизации
    from src.models.device import Device
    from src.models.user import User

CREDENTIAL_ID_MAX_LENGTH = 512


class Credential(TimestampMixin, Base):
    """Открытый ключ в формате COSE, зарегистрированный аутентификатором."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    credential_id: Mapped[str] = mapped_column(
        String(CREDENTIAL_ID_MAX_LENGTH),
        unique=True,
        index=True,
        nullable=False,
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    last_used: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        default=None,
        nullable=True,
    )

    user: Mapped[User] = relationship(back_populates="credentials")
    device: Mapped[Device] = relationship(back_populates="credential")

    def __repr__(self) -> str:
        return f"<Credential id={self.id} user_id={self.user_id} sign_count={self.sign_count}>"
