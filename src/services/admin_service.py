"""Административные операции (только для администраторов, что обеспечивает роутер)."""

from __future__ import annotations

from collections.abc import Sequence

from src.models.device import Device
from src.models.user import User
from src.repositories.protocols import (
    AuthLogRepository,
    DeviceRepository,
    TransactionManager,
    UserRepository,
)
from src.services.audit import AuditLogger
from src.services.dto import Page, RequestContext
from src.utils.enums import AuthEventType, AuthLogStatus
from src.utils.exceptions import NotFoundError
from src.utils.logging_setup import get_logger

logger = get_logger(__name__)


class AdminService:
    """Сквозное управление учётными записями и аудит этих действий."""

    def __init__(
        self,
        *,
        users: UserRepository,
        devices: DeviceRepository,
        logs: AuthLogRepository,
        transaction: TransactionManager,
        audit: AuditLogger,
    ) -> None:
        self._users = users
        self._devices = devices
        self._logs = logs
        self._transaction = transaction
        self._audit = audit

    def list_users(
        self, *, skip: int, limit: int, admin: User, context: RequestContext
    ) -> Page[User]:
        """Возвращает страницу со всеми учётными записями."""
        self._audit.record(
            event_type=AuthEventType.ADMIN_LIST_USERS,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=admin.id,
            details={"skip": skip, "limit": limit},
        )
        return Page(
            items=self._users.list(skip=skip, limit=limit),
            total=self._users.count(),
            skip=skip,
            limit=limit,
        )

    def list_user_devices(
        self, *, user_id: int, admin: User, context: RequestContext
    ) -> Sequence[Device]:
        """Возвращает все устройства произвольной учётной записи."""
        self._require_user(user_id)
        self._audit.record(
            event_type=AuthEventType.ADMIN_LIST_USER_DEVICES,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=admin.id,
            details={"target_user_id": user_id},
        )
        return self._devices.list_by_user(user_id)

    def delete_user_device(
        self, *, user_id: int, device_id: int, admin: User, context: RequestContext
    ) -> None:
        """Удаляет устройство произвольной учётной записи."""
        self._require_user(user_id)
        device = self._devices.get_by_id(device_id)
        if device is None or device.user_id != user_id:
            self._audit.record(
                event_type=AuthEventType.ADMIN_DELETE_USER_DEVICE,
                status=AuthLogStatus.FAILURE,
                context=context,
                user_id=admin.id,
                details={"target_user_id": user_id, "device_id": device_id, "reason": "not_found"},
            )
            raise NotFoundError("Device not found")
        with self._transaction.transaction():
            self._devices.delete(device)
        self._audit.record(
            event_type=AuthEventType.ADMIN_DELETE_USER_DEVICE,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=admin.id,
            details={"target_user_id": user_id, "device_id": device_id},
        )

    def set_user_active(
        self, *, user_id: int, is_active: bool, admin: User, context: RequestContext
    ) -> User:
        """Активирует или блокирует учётную запись."""
        user = self._require_user(user_id)
        with self._transaction.transaction():
            updated = self._users.set_active(user, is_active=is_active)
        self._audit.record(
            event_type=(
                AuthEventType.ADMIN_ENABLE_USER if is_active else AuthEventType.ADMIN_DISABLE_USER
            ),
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=admin.id,
            details={"target_user_id": user_id, "is_active": is_active},
        )
        return updated

    def _require_user(self, user_id: int) -> User:
        user = self._users.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User not found")
        return user
