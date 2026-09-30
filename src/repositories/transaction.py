"""Реализация границы транзакций."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session


class SqlAlchemyTransactionManager:
    """Единица работы поверх одной сессии SQLAlchemy.

    Используется сервисами, которые должны атомарно сохранить несколько агрегатов
    (регистрация создаёт сразу user + device + credential).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Фиксировать сессию при успехе, откатывать при любом исключении."""
        try:
            yield
        except Exception:
            self._session.rollback()
            raise
        else:
            self._session.commit()
