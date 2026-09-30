"""Контракты репозиториев (инверсия зависимостей для сервисного слоя).

Сервисы зависят только от этих узких интерфейсов ``Protocol``, поэтому их можно
юнит-тестировать с помощью заглушек, а любую другую технологию хранения можно
подключить без изменения бизнес-логики (разделение интерфейсов: один протокол
на агрегат вместо одного бог-репозитория).
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol, Sequence, runtime_checkable

from src.models.auth_log import AuthLog
from src.models.credential import Credential
from src.models.device import Device
from src.models.user import User
from src.utils.enums import AuthEventType, AuthLogStatus, DeviceType


@runtime_checkable
class UserRepository(Protocol):
    """Операции хранения для учётных записей."""

    def create(
        self,
        *,
        username: str,
        email: str,
        user_handle: bytes,
        is_admin: bool = False,
        is_active: bool = True,
    ) -> User:
        """Вставить новую учётную запись и вернуть её."""
        ...

    def get_by_id(self, user_id: int) -> User | None:
        """Вернуть учётную запись или ``None``."""
        ...

    def get_by_username(self, username: str) -> User | None:
        """Регистронезависимый поиск по имени пользователя."""
        ...

    def get_by_email(self, email: str) -> User | None:
        """Регистронезависимый поиск по адресу электронной почты."""
        ...

    def list(self, *, skip: int, limit: int) -> Sequence[User]:
        """Вернуть страницу учётных записей, упорядоченных по id."""
        ...

    def count(self) -> int:
        """Общее количество учётных записей."""
        ...

    def set_active(self, user: User, *, is_active: bool) -> User:
        """Активировать/деактивировать учётную запись."""
        ...


@runtime_checkable
class DeviceRepository(Protocol):
    """Операции хранения для устройств."""

    def create(self, *, user_id: int, device_name: str, device_type: DeviceType) -> Device:
        """Вставить новое устройство и вернуть его."""
        ...

    def get_by_id(self, device_id: int) -> Device | None:
        """Вернуть устройство (passkey загружен заранее) или ``None``."""
        ...

    def list_by_user(self, user_id: int) -> Sequence[Device]:
        """Вернуть все устройства пользователя (passkey загружены заранее)."""
        ...

    def delete(self, device: Device) -> None:
        """Удалить устройство вместе с его passkey."""
        ...


@runtime_checkable
class CredentialRepository(Protocol):
    """Операции хранения для учётных данных WebAuthn."""

    def create(
        self,
        *,
        user_id: int,
        device_id: int,
        credential_id: str,
        public_key: bytes,
        sign_count: int = 0,
    ) -> Credential:
        """Вставить новые учётные данные и вернуть их."""
        ...

    def get_by_credential_id(self, credential_id: str) -> Credential | None:
        """Вернуть учётные данные по их base64url-идентификатору."""
        ...

    def list_by_user(self, user_id: int) -> Sequence[Credential]:
        """Вернуть все учётные данные пользователя."""
        ...

    def update_usage(
        self, credential: Credential, *, sign_count: int, last_used: datetime
    ) -> Credential:
        """Сохранить новый счётчик подписей и метку времени последнего использования."""
        ...


@runtime_checkable
class AuthLogRepository(Protocol):
    """Операции хранения для журнала аудита."""

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
        """Добавить запись аудита."""
        ...

    def list_all(self, *, skip: int, limit: int) -> Sequence[AuthLog]:
        """Вернуть страницу записей аудита, сначала самые новые."""
        ...

    def count_all(self) -> int:
        """Общее количество записей аудита."""
        ...

    def list_by_user(self, *, user_id: int, skip: int, limit: int) -> Sequence[AuthLog]:
        """Вернуть страницу записей аудита одного пользователя, сначала самые новые."""
        ...

    def count_by_user(self, user_id: int) -> int:
        """Общее количество записей аудита одного пользователя."""
        ...


@runtime_checkable
class TransactionManager(Protocol):
    """Граница единицы работы для сценариев записи, затрагивающих несколько агрегатов."""

    def transaction(self) -> AbstractContextManager[None]:
        """Фиксировать при успехе, откатывать при ошибке."""
        ...
