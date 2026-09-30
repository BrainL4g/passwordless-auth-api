"""Слой доступа к данным: протоколы репозиториев и их реализации на SQLAlchemy."""

from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.protocols import (
    AuthLogRepository,
    CredentialRepository,
    DeviceRepository,
    TransactionManager,
    UserRepository,
)
from src.repositories.transaction import SqlAlchemyTransactionManager
from src.repositories.user import SqlAlchemyUserRepository

__all__ = [
    "AuthLogRepository",
    "CredentialRepository",
    "DeviceRepository",
    "SqlAlchemyAuthLogRepository",
    "SqlAlchemyCredentialRepository",
    "SqlAlchemyDeviceRepository",
    "SqlAlchemyTransactionManager",
    "SqlAlchemyUserRepository",
    "TransactionManager",
    "UserRepository",
]
