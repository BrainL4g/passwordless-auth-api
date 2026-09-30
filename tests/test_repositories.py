"""CRUD репозиториев, связи, cascade и поведение SET NULL."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.models.auth_log import AuthLog
from src.models.base import Base
from src.models.credential import Credential
from src.models.device import Device
from src.models.user import User, generate_user_handle
from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.user import SqlAlchemyUserRepository
from src.utils.enums import AuthEventType, AuthLogStatus, DeviceType
from src.utils.time import utc_now
from tests.factories import (
    create_auth_log,
    create_credential,
    create_device,
    create_user,
    create_user_with_credential,
)


@pytest.fixture
def users(session: Session) -> SqlAlchemyUserRepository:
    return SqlAlchemyUserRepository(session)


@pytest.fixture
def devices(session: Session) -> SqlAlchemyDeviceRepository:
    return SqlAlchemyDeviceRepository(session)


@pytest.fixture
def credentials(session: Session) -> SqlAlchemyCredentialRepository:
    return SqlAlchemyCredentialRepository(session)


@pytest.fixture
def logs(session: Session) -> SqlAlchemyAuthLogRepository:
    return SqlAlchemyAuthLogRepository(session)


# ------------------------------------------------------------ пользователи
def test_user_defaults(users: SqlAlchemyUserRepository) -> None:
    user = users.create(username="alice", email="alice@example.com", user_handle=b"h" * 32)
    assert user.id is not None
    assert user.is_active is True
    assert user.is_admin is False
    assert user.created_at is not None and user.updated_at is not None
    assert repr(user).startswith("<User")


def test_user_lookups_are_case_insensitive(users: SqlAlchemyUserRepository) -> None:
    users.create(username="Alice", email="Alice@Example.com", user_handle=b"h" * 32)
    assert users.get_by_username("alice") is not None
    assert users.get_by_username("  ALICE ") is not None
    assert users.get_by_email("alice@example.com") is not None
    assert users.get_by_username("bob") is None
    assert users.get_by_email("bob@example.com") is None
    assert users.get_by_id(4242) is None


def test_user_unique_constraints(session: Session, users: SqlAlchemyUserRepository) -> None:
    users.create(username="alice", email="alice@example.com", user_handle=b"a" * 32)
    session.commit()
    with pytest.raises(IntegrityError):
        users.create(username="alice", email="other@example.com", user_handle=b"b" * 32)
        session.commit()
    session.rollback()
    with pytest.raises(IntegrityError):
        users.create(username="bob", email="alice@example.com", user_handle=b"c" * 32)
        session.commit()
    session.rollback()


def test_user_handle_is_unique_and_random() -> None:
    assert generate_user_handle() != generate_user_handle()
    assert len(generate_user_handle()) == 32
    session_users = generate_user_handle()
    assert isinstance(session_users, bytes)


def test_user_pagination_and_count(users: SqlAlchemyUserRepository) -> None:
    for index in range(5):
        users.create(
            username=f"user{index}", email=f"u{index}@example.com", user_handle=bytes([index]) * 32
        )
    assert users.count() == 5
    page = users.list(skip=0, limit=2)
    assert [user.username for user in page] == ["user0", "user1"]
    assert [user.username for user in users.list(skip=4, limit=2)] == ["user4"]


def test_set_active_updates_timestamp(session: Session, users: SqlAlchemyUserRepository) -> None:
    user = users.create(username="alice", email="alice@example.com", user_handle=b"h" * 32)
    session.commit()
    previous = user.updated_at
    users.set_active(user, is_active=False)
    session.commit()
    session.expire_all()
    refreshed = users.get_by_id(user.id)
    assert refreshed is not None
    assert refreshed.is_active is False
    assert refreshed.updated_at >= previous


# ------------------------------------------------------------- устройства
def test_device_crud(session: Session, devices: SqlAlchemyDeviceRepository) -> None:
    user = create_user(session, username="alice")
    device = devices.create(user_id=user.id, device_name="Pixel", device_type=DeviceType.ANDROID)
    assert device.id is not None
    assert devices.get_by_id(device.id) is not None
    assert devices.get_by_id(999) is None
    assert [item.id for item in devices.list_by_user(user.id)] == [device.id]
    assert devices.list_by_user(999) == []
    assert repr(device).startswith("<Device")
    devices.delete(device)
    assert devices.get_by_id(device.id) is None


def test_device_credential_is_one_to_one(
    session: Session,
    devices: SqlAlchemyDeviceRepository,
    credentials: SqlAlchemyCredentialRepository,
) -> None:
    user = create_user(session, username="alice")
    device = create_device(session, user)
    create_credential(session, user, device, credential_id="Zmlyc3Q=")
    with pytest.raises(IntegrityError):
        create_credential(session, user, device, credential_id="c2Vjb25k")
        session.commit()
    session.rollback()
    assert len(credentials.list_by_user(user.id)) == 1


def test_device_last_used_property(session: Session, devices: SqlAlchemyDeviceRepository) -> None:
    user, device, credential = create_user_with_credential(session, username="alice")
    fetched = devices.get_by_id(device.id)
    assert fetched is not None and fetched.last_used is None
    credentials = SqlAlchemyCredentialRepository(session)
    credentials.update_usage(credential, sign_count=3, last_used=utc_now())
    session.commit()
    session.expire_all()
    refreshed = devices.get_by_id(device.id)
    assert refreshed is not None and refreshed.last_used is not None


# ------------------------------------------------------------- credential'ы
def test_credential_operations(
    session: Session, credentials: SqlAlchemyCredentialRepository
) -> None:
    user, device, credential = create_user_with_credential(session, username="alice")
    assert credentials.get_by_credential_id("Y3JlZC1hYmM") is not None
    assert credentials.get_by_credential_id("unknown") is None
    assert len(credentials.list_by_user(user.id)) == 1
    updated = credentials.update_usage(credential, sign_count=12, last_used=utc_now())
    session.commit()
    assert updated.sign_count == 12
    assert updated.last_used is not None
    assert repr(credential).startswith("<Credential")
    assert device.id == credential.device_id


def test_credential_id_is_unique(
    session: Session, credentials: SqlAlchemyCredentialRepository
) -> None:
    user, device, _ = create_user_with_credential(
        session, username="alice", credential_id="YWxpY2U"
    )
    _, other_device, _ = create_user_with_credential(session, username="bob", credential_id="Ym9i")
    with pytest.raises(IntegrityError):
        credentials.create(
            user_id=user.id,
            device_id=other_device.id,
            credential_id="YWxpY2U",
            public_key=b"k",
        )
        session.commit()
    session.rollback()
    assert device.user_id == user.id


# ----------------------------------------------------------- логи входа
def test_auth_log_operations(session: Session, logs: SqlAlchemyAuthLogRepository) -> None:
    user = create_user(session, username="alice")
    entry = logs.create(
        event_type=AuthEventType.LOGIN_COMPLETE,
        status=AuthLogStatus.SUCCESS,
        user_id=user.id,
        ip_address="203.0.113.1",
        user_agent="agent",
        details='{"a": 1}',
    )
    session.commit()
    assert entry.timestamp is not None
    assert entry.user_id == user.id
    assert logs.count_all() == 1
    assert logs.count_by_user(user.id) == 1
    assert len(logs.list_all(skip=0, limit=10)) == 1
    assert len(logs.list_by_user(user_id=user.id, skip=0, limit=10)) == 1
    assert logs.list_by_user(user_id=999, skip=0, limit=10) == []
    assert logs.count_by_user(999) == 0
    assert repr(entry).startswith("<AuthLog")


def test_auth_logs_are_ordered_newest_first(
    session: Session, logs: SqlAlchemyAuthLogRepository
) -> None:
    user = create_user(session, username="alice")
    first = create_auth_log(session, user=user)
    second = create_auth_log(session, user=user)
    entries = logs.list_all(skip=0, limit=10)
    assert [entry.id for entry in entries] == [second.id, first.id]
    assert logs.list_all(skip=1, limit=10)[0].id == first.id


# ---------------------------------------------------------------- связи
def test_deleting_a_user_cascades(session: Session) -> None:
    user, device, credential = create_user_with_credential(session, username="alice")
    create_auth_log(session, user=user)
    user_id, device_id, credential_id = user.id, device.id, credential.id
    session.delete(user)
    session.commit()
    session.expire_all()  # забываем карту идентичности, строк уже нет
    assert session.get(User, user_id) is None
    assert session.get(Device, device_id) is None
    assert session.get(Credential, credential_id) is None
    assert session.query(AuthLog).count() == 1
    remaining = session.query(AuthLog).one()
    assert remaining.user_id is None  # ON DELETE SET NULL


def test_relationship_navigation(session: Session) -> None:
    user, device, credential = create_user_with_credential(session, username="alice")
    assert [item.id for item in user.devices] == [device.id]
    assert [item.id for item in user.credentials] == [credential.id]
    assert device.user.id == user.id
    assert credential.device.id == device.id
    assert user.auth_logs == []


def test_expected_indexes_exist(engine: Engine) -> None:
    inspector = inspect(engine)
    assert {index["name"] for index in inspector.get_indexes("users")} >= {
        "ix_users_username",
        "ix_users_email",
    }
    assert {index["name"] for index in inspector.get_indexes("credentials")} >= {
        "ix_credentials_credential_id",
        "ix_credentials_user_id",
        "ix_credentials_device_id",
    }
    assert {index["name"] for index in inspector.get_indexes("devices")} >= {"ix_devices_user_id"}
    assert {index["name"] for index in inspector.get_indexes("auth_logs")} >= {
        "ix_auth_logs_user_id",
        "ix_auth_logs_timestamp",
    }


def test_tables_match_the_models(engine: Engine) -> None:
    assert set(Base.metadata.tables) == {"users", "devices", "credentials", "auth_logs"}
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        ).scalars()
        existing = set(rows)
    assert set(Base.metadata.tables).issubset(existing)
