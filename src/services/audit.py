"""Запись журнала аудита, общая для всех сервисов.

Ошибки записи аудита никогда не должны прерывать бизнес-операцию, поэтому
исключения подавляются (и логируются), а не пробрасываются наружу.
"""

from __future__ import annotations

import json
from typing import Any

from src.repositories.protocols import AuthLogRepository, TransactionManager
from src.services.dto import RequestContext
from src.utils.enums import AuthEventType, AuthLogStatus
from src.utils.logging_setup import get_logger

logger = get_logger(__name__)


class AuditLogger:
    """Писатель в таблицу ``auth_logs``, работающий только на добавление."""

    def __init__(self, logs: AuthLogRepository, transaction: TransactionManager) -> None:
        self._logs = logs
        self._transaction = transaction

    def record(
        self,
        *,
        event_type: AuthEventType,
        status: AuthLogStatus,
        context: RequestContext,
        user_id: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Сохраняет одну запись аудита в собственной транзакции."""
        try:
            with self._transaction.transaction():
                self._logs.create(
                    event_type=event_type,
                    status=status,
                    user_id=user_id,
                    ip_address=context.ip_address,
                    user_agent=context.user_agent,
                    details=self._dump(details),
                )
        except Exception:  # pragma: no cover - аудит не должен ломать запросы
            logger.exception("audit_log_write_failed", extra={"event": str(event_type)})

    @staticmethod
    def _dump(details: dict[str, Any] | None) -> str | None:
        """Сериализует детали в JSON; секреты сюда передаваться не должны."""
        if not details:
            return None
        return json.dumps(details, ensure_ascii=False, default=str, sort_keys=True)
