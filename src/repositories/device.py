"""Реализация :class:`~src.repositories.protocols.DeviceRepository` на SQLAlchemy."""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from src.models.device import Device
from src.utils.enums import DeviceType


class SqlAlchemyDeviceRepository:
    """CRUD-доступ к таблице ``devices``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, *, user_id: int, device_name: str, device_type: DeviceType) -> Device:
        device = Device(user_id=user_id, device_name=device_name, device_type=device_type)
        self._session.add(device)
        self._session.flush()
        return device

    def get_by_id(self, device_id: int) -> Device | None:
        statement = (
            select(Device).options(selectinload(Device.credential)).where(Device.id == device_id)
        )
        return self._session.execute(statement).scalar_one_or_none()

    def list_by_user(self, user_id: int) -> Sequence[Device]:
        statement = (
            select(Device)
            .options(selectinload(Device.credential))
            .where(Device.user_id == user_id)
            .order_by(Device.id)
        )
        return self._session.execute(statement).scalars().all()

    def delete(self, device: Device) -> None:
        self._session.execute(delete(Device).where(Device.id == device.id))
        self._session.flush()
