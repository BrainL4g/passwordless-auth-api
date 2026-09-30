"""AdminService и LogService."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from src.models.user import User
from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.transaction import SqlAlchemyTransactionManager
from src.repositories.user import SqlAlchemyUserRepository
from src.services.admin_service import AdminService
from src.services.audit import AuditLogger
from src.services.dto import RequestContext
from src.services.log_service import LogService
from src.utils.enums import AuthEventType, AuthLogStatus
from src.utils.exceptions import NotFoundError
from tests.factories import create_auth_log, create_user, create_user_with_credential

CONTEXT = RequestContext(ip_address="203.0.113.9", user_agent="pytest-agent")


@pytest.fixture
def admin(session: Session) -> User:
    return create_user(session, username="root", is_admin=True)


@pytest.fixture
def service(session: Session) -> AdminService:
    transaction = SqlAlchemyTransactionManager(session)
    logs = SqlAlchemyAuthLogRepository(session)
    return AdminService(
        users=SqlAlchemyUserRepository(session),
        devices=SqlAlchemyDeviceRepository(session),
        logs=logs,
        transaction=transaction,
        audit=AuditLogger(logs, transaction),
    )


def test_list_users_paginates(session: Session, service: AdminService, admin: User) -> None:
    create_user(session, username="alice")
    create_user(session, username="bob")
    page = service.list_users(skip=0, limit=1, admin=admin, context=CONTEXT)
    assert page.total == 3
    assert page.limit == 1
    assert len(page.items) == 1
    rest = service.list_users(skip=1, limit=10, admin=admin, context=CONTEXT)
    assert [user.username for user in rest.items] == ["alice", "bob"]


def test_list_user_devices(session: Session, service: AdminService, admin: User) -> None:
    user, device, _ = create_user_with_credential(session, username="alice")
    devices = service.list_user_devices(user_id=user.id, admin=admin, context=CONTEXT)
    assert [item.id for item in devices] == [device.id]


def test_list_user_devices_unknown_user(
    session: Session, service: AdminService, admin: User
) -> None:
    with pytest.raises(NotFoundError):
        service.list_user_devices(user_id=4242, admin=admin, context=CONTEXT)


def test_delete_user_device(session: Session, service: AdminService, admin: User) -> None:
    user, device, _ = create_user_with_credential(session, username="alice")
    service.delete_user_device(user_id=user.id, device_id=device.id, admin=admin, context=CONTEXT)
    assert SqlAlchemyDeviceRepository(session).get_by_id(device.id) is None
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)[0]
    assert entry.event_type == AuthEventType.ADMIN_DELETE_USER_DEVICE
    assert entry.status == AuthLogStatus.SUCCESS


def test_delete_user_device_wrong_owner(
    session: Session, service: AdminService, admin: User
) -> None:
    alice, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    _, bob_device, _ = create_user_with_credential(session, username="bob", credential_id="Ym9i")
    with pytest.raises(NotFoundError):
        service.delete_user_device(
            user_id=alice.id, device_id=bob_device.id, admin=admin, context=CONTEXT
        )


def test_delete_user_device_unknown_user(
    session: Session, service: AdminService, admin: User
) -> None:
    with pytest.raises(NotFoundError):
        service.delete_user_device(user_id=999, device_id=1, admin=admin, context=CONTEXT)


def test_disable_and_enable_user(session: Session, service: AdminService, admin: User) -> None:
    user = create_user(session, username="alice")
    disabled = service.set_user_active(
        user_id=user.id, is_active=False, admin=admin, context=CONTEXT
    )
    assert disabled.is_active is False
    assert disabled.updated_at >= user.created_at
    enabled = service.set_user_active(user_id=user.id, is_active=True, admin=admin, context=CONTEXT)
    assert enabled.is_active is True
    events = [
        entry.event_type
        for entry in SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)
    ]
    assert AuthEventType.ADMIN_DISABLE_USER in events
    assert AuthEventType.ADMIN_ENABLE_USER in events


def test_set_active_unknown_user(session: Session, service: AdminService, admin: User) -> None:
    with pytest.raises(NotFoundError):
        service.set_user_active(user_id=1234, is_active=False, admin=admin, context=CONTEXT)


def test_log_service_scopes_to_the_user(session: Session) -> None:
    logs = SqlAlchemyAuthLogRepository(session)
    service = LogService(logs=logs)
    alice, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    bob, _, _ = create_user_with_credential(session, username="bob", credential_id="Ym9i")
    create_auth_log(session, user=alice)
    create_auth_log(session, user=alice)
    create_auth_log(session, user=bob)

    mine = service.list_my_logs(user=alice, skip=0, limit=1)
    assert mine.total == 2
    assert len(mine.items) == 1
    every = service.list_all_logs(skip=0, limit=10)
    assert every.total == 3
