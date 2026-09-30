"""Фабрики объектов для тестов."""

from __future__ import annotations

import secrets
from collections.abc import Callable

from sqlalchemy.orm import Session

from src.models.auth_log import AuthLog
from src.models.credential import Credential
from src.models.device import Device
from src.models.user import User
from src.utils.enums import AuthEventType, AuthLogStatus, DeviceType
from src.utils.time import utc_now

DEFAULT_PUBLIC_KEY = b"cose-public-key-bytes"


def create_user(
    session: Session,
    *,
    username: str = "alice",
    email: str | None = None,
    is_active: bool = True,
    is_admin: bool = False,
    user_handle: bytes | None = None,
) -> User:
    """Вставляет пользователя напрямую (в обход процедуры регистрации WebAuthn)."""
    user = User(
        username=username,
        email=email or f"{username}@example.com",
        is_active=is_active,
        is_admin=is_admin,
        user_handle=user_handle or secrets.token_bytes(32),
    )
    session.add(user)
    session.commit()
    return user


def create_device(
    session: Session,
    user: User,
    *,
    device_name: str = "Pixel 8",
    device_type: DeviceType = DeviceType.ANDROID,
) -> Device:
    """Вставляет устройство для ``user``."""
    device = Device(user_id=user.id, device_name=device_name, device_type=device_type)
    session.add(device)
    session.commit()
    return device


def create_credential(
    session: Session,
    user: User,
    device: Device,
    *,
    credential_id: str = "Y3JlZC1hYmM",
    public_key: bytes = DEFAULT_PUBLIC_KEY,
    sign_count: int = 0,
) -> Credential:
    """Вставляет passkey устройства."""
    credential = Credential(
        user_id=user.id,
        device_id=device.id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
    )
    session.add(credential)
    session.commit()
    return credential


def create_user_with_credential(
    session: Session,
    *,
    username: str = "alice",
    is_admin: bool = False,
    is_active: bool = True,
    device_name: str = "Pixel 8",
    device_type: DeviceType = DeviceType.ANDROID,
    credential_id: str = "Y3JlZC1hYmM",
    sign_count: int = 0,
) -> tuple[User, Device, Credential]:
    """Создаёт полный набор: пользователь + устройство + credential."""
    user = create_user(session, username=username, is_active=is_active, is_admin=is_admin)
    device = create_device(session, user, device_name=device_name, device_type=device_type)
    credential = create_credential(
        session, user, device, credential_id=credential_id, sign_count=sign_count
    )
    return user, device, credential


def create_auth_log(
    session: Session,
    *,
    user: User | None = None,
    event_type: AuthEventType = AuthEventType.LOGIN_COMPLETE,
    status: AuthLogStatus = AuthLogStatus.SUCCESS,
    ip_address: str | None = "203.0.113.10",
    user_agent: str | None = "pytest",
    details: str | None = None,
) -> AuthLog:
    """Вставляет запись аудита."""
    entry = AuthLog(
        user_id=user.id if user else None,
        event_type=event_type,
        status=status,
        timestamp=utc_now(),
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
    )
    session.add(entry)
    session.commit()
    return entry


#: Псевдонимы-вызываемые объекты, удобные для параметризованных тестов.
user_factory: Callable[..., User] = create_user
device_factory: Callable[..., Device] = create_device
credential_factory: Callable[..., Credential] = create_credential
auth_log_factory: Callable[..., AuthLog] = create_auth_log
