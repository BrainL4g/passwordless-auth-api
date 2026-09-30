"""Доступ только для чтения к журналу аудита."""

from __future__ import annotations

from src.models.auth_log import AuthLog
from src.models.user import User
from src.repositories.protocols import AuthLogRepository
from src.services.dto import Page


class LogService:
    """Обслуживает эндпоинты ``/logs``."""

    def __init__(self, *, logs: AuthLogRepository) -> None:
        self._logs = logs

    def list_my_logs(self, *, user: User, skip: int, limit: int) -> Page[AuthLog]:
        """Записи аудита только текущего пользователя."""
        return Page(
            items=self._logs.list_by_user(user_id=user.id, skip=skip, limit=limit),
            total=self._logs.count_by_user(user.id),
            skip=skip,
            limit=limit,
        )

    def list_all_logs(self, *, skip: int, limit: int) -> Page[AuthLog]:
        """Записи аудита всех пользователей (только для администраторов)."""
        return Page(
            items=self._logs.list_all(skip=skip, limit=limit),
            total=self._logs.count_all(),
            skip=skip,
            limit=limit,
        )
