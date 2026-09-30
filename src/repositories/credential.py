"""Реализация :class:`~src.repositories.protocols.CredentialRepository` на SQLAlchemy."""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.credential import Credential


class SqlAlchemyCredentialRepository:
    """CRUD-доступ к таблице ``credentials``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        user_id: int,
        device_id: int,
        credential_id: str,
        public_key: bytes,
        sign_count: int = 0,
    ) -> Credential:
        credential = Credential(
            user_id=user_id,
            device_id=device_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
        )
        self._session.add(credential)
        self._session.flush()
        return credential

    def get_by_credential_id(self, credential_id: str) -> Credential | None:
        statement = select(Credential).where(Credential.credential_id == credential_id)
        return self._session.execute(statement).scalar_one_or_none()

    def list_by_user(self, user_id: int) -> Sequence[Credential]:
        statement = select(Credential).where(Credential.user_id == user_id).order_by(Credential.id)
        return self._session.execute(statement).scalars().all()

    def update_usage(
        self, credential: Credential, *, sign_count: int, last_used: datetime
    ) -> Credential:
        credential.sign_count = sign_count
        credential.last_used = last_used
        self._session.add(credential)
        self._session.flush()
        return credential
