"""Зарегистрированное устройство (одна привязка аутентификатора на пользователя)."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base, TimestampMixin
from src.utils.enums import DeviceType

if TYPE_CHECKING:  # pragma: no cover - только для типизации
    from src.models.credential import Credential
    from src.models.user import User


class Device(TimestampMixin, Base):
    """Устройство (Android-смартфон, ПК на Windows, ...), хранящее ровно один passkey."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    device_type: Mapped[DeviceType] = mapped_column(
        SAEnum(
            DeviceType,
            name="device_type",
            native_enum=False,
            length=32,
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    user: Mapped[User] = relationship(back_populates="devices")
    credential: Mapped[Credential | None] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )

    @property
    def last_used(self) -> datetime | None:
        """Метка времени последней успешной аутентификации с этим устройством."""
        if self.credential is None:
            return None
        return self.credential.last_used

    def __repr__(self) -> str:
        return f"<Device id={self.id} name={self.device_name!r} type={self.device_type}>"
