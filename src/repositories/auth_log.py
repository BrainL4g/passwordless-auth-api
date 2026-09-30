"""Реализация :class:`~src.repositories.protocols.AuthLogRepository` на SQLAlchemy."""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.models.auth_log import AuthLog
from src.utils.enums import AuthEventType, AuthLogStatus


class SqlAlchemyAuthLogRepository:
    """Доступ только на добавление к таблице ``auth_logs``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        event_type: AuthEventType,
        status: AuthLogStatus,
        user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: str | None = None,
    ) -> AuthLog:
        entry = AuthLog(
            event_type=event_type,
            status=status,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )
        self._session.add(entry)
        self._session.flush()
        return entry

    def list_all(self, *, skip: int, limit: int) -> Sequence[AuthLog]:
        statement = (
            select(AuthLog)
            .order_by(AuthLog.timestamp.desc(), AuthLog.id.desc())
            .offset(skip)
            .limit(limit)
        )
        return self._session.execute(statement).scalars().all()

    def count_all(self) -> int:
        statement = select(func.count()).select_from(AuthLog)
        return int(self._session.execute(statement).scalar_one())

    def list_by_user(self, *, user_id: int, skip: int, limit: int) -> Sequence[AuthLog]:
        statement = (
            select(AuthLog)
            .where(AuthLog.user_id == user_id)
            .order_by(AuthLog.timestamp.desc(), AuthLog.id.desc())
            .offset(skip)
            .limit(limit)
        )
        return self._session.execute(statement).scalars().all()

    def count_by_user(self, user_id: int) -> int:
        statement = select(func.count()).select_from(AuthLog).where(AuthLog.user_id == user_id)
        return int(self._session.execute(statement).scalar_one())
