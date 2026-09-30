"""Реализация :class:`~src.repositories.protocols.UserRepository` на SQLAlchemy."""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.models.user import User


class SqlAlchemyUserRepository:
    """CRUD-доступ к таблице ``users``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        username: str,
        email: str,
        user_handle: bytes,
        is_admin: bool = False,
        is_active: bool = True,
    ) -> User:
        user = User(
            username=username,
            email=email,
            user_handle=user_handle,
            is_admin=is_admin,
            is_active=is_active,
        )
        self._session.add(user)
        self._session.flush()
        return user

    def get_by_id(self, user_id: int) -> User | None:
        return self._session.get(User, user_id)

    def get_by_username(self, username: str) -> User | None:
        statement = select(User).where(func.lower(User.username) == username.strip().lower())
        return self._session.execute(statement).scalar_one_or_none()

    def get_by_email(self, email: str) -> User | None:
        statement = select(User).where(func.lower(User.email) == email.strip().lower())
        return self._session.execute(statement).scalar_one_or_none()

    def list(self, *, skip: int, limit: int) -> Sequence[User]:
        statement = select(User).order_by(User.id).offset(skip).limit(limit)
        return self._session.execute(statement).scalars().all()

    def count(self) -> int:
        statement = select(func.count()).select_from(User)
        return int(self._session.execute(statement).scalar_one())

    def set_active(self, user: User, *, is_active: bool) -> User:
        user.is_active = is_active
        self._session.add(user)
        self._session.flush()
        return user
