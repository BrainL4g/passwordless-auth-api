"""HTTP-контракт роутеров ``/admin`` и ``/logs``."""

from __future__ import annotations

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.credential import Credential
from src.models.device import Device
from src.models.user import User
from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.services.security_service import SecurityService
from src.utils.enums import AuthEventType, AuthLogStatus
from tests.conftest import test_settings
from tests.factories import create_auth_log, create_user, create_user_with_credential

CREDENTIAL_ALICE = "YWxpY2U"
CREDENTIAL_BOB = "Ym9i"


def auth(user_id: int) -> dict[str, str]:
    token = SecurityService(test_settings).create_access_token(user_id).access_token
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin(session: Session) -> User:
    return create_user(session, username="root", email="root@example.com", is_admin=True)


@pytest.fixture
def alice(session: Session) -> tuple[User, Device, Credential]:
    return create_user_with_credential(session, username="alice", credential_id=CREDENTIAL_ALICE)


# --------------------------------------------------------- проверки доступа
@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/admin/users"),
        ("get", "/admin/users/1/devices"),
        ("delete", "/admin/users/1/devices/1"),
        ("post", "/admin/users/1/disable"),
        ("post", "/admin/users/1/enable"),
        ("get", "/logs/admin"),
        ("get", "/logs/my"),
    ],
)
def test_endpoints_require_a_token(client: TestClient, method: str, path: str) -> None:
    response = getattr(client, method)(path)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/admin/users"),
        ("get", "/admin/users/1/devices"),
        ("delete", "/admin/users/1/devices/1"),
        ("post", "/admin/users/1/disable"),
        ("post", "/admin/users/1/enable"),
        ("get", "/logs/admin"),
    ],
)
def test_endpoints_require_an_administrator(
    client: TestClient, session: Session, method: str, path: str
) -> None:
    user = create_user(session, username="alice", is_admin=False)
    response = getattr(client, method)(path, headers=auth(user.id))
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/admin/users"),
        ("get", "/admin/users/1/devices"),
        ("delete", "/admin/users/1/devices/1"),
        ("post", "/admin/users/1/disable"),
        ("post", "/admin/users/1/enable"),
        ("get", "/logs/admin"),
    ],
)
def test_disabled_administrator_is_rejected(
    client: TestClient, session: Session, method: str, path: str
) -> None:
    admin_user = create_user(session, username="root", is_admin=True, is_active=False)
    response = getattr(client, method)(path, headers=auth(admin_user.id))
    assert response.status_code == 403
    assert response.json()["code"] == "account_disabled"


def test_non_admin_may_read_own_logs(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice", is_admin=False)
    assert client.get("/logs/my", headers=auth(user.id)).status_code == 200


# --------------------------------------------------- admin: пользователи
def test_list_users_paginates(client: TestClient, session: Session, admin: User) -> None:
    create_user(session, username="alice", email="alice@example.com")
    create_user(session, username="bob", email="bob@example.com")
    headers = auth(admin.id)
    response = client.get("/admin/users?skip=0&limit=2", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["skip"] == 0
    assert body["limit"] == 2
    assert [item["username"] for item in body["items"]] == ["root", "alice"]
    second = client.get("/admin/users?skip=2&limit=2", headers=headers).json()
    assert [item["username"] for item in second["items"]] == ["bob"]


def test_list_users_defaults_and_bounds(client: TestClient, session: Session, admin: User) -> None:
    headers = auth(admin.id)
    default = client.get("/admin/users", headers=headers).json()
    assert default["skip"] == 0
    assert default["limit"] == 50
    assert client.get("/admin/users?skip=-1", headers=headers).status_code == 400
    assert client.get("/admin/users?limit=0", headers=headers).status_code == 400
    assert client.get("/admin/users?limit=201", headers=headers).status_code == 400


def test_list_users_never_exposes_the_user_handle(
    client: TestClient, session: Session, admin: User
) -> None:
    create_user(session, username="alice")
    item = client.get("/admin/users", headers=auth(admin.id)).json()["items"][1]
    assert set(item) == {
        "id",
        "username",
        "email",
        "is_active",
        "is_admin",
        "created_at",
        "updated_at",
    }
    assert "user_handle" not in item


# -------------------------------------------------- admin: устройства
def test_admin_lists_devices_of_any_user(
    client: TestClient, session: Session, admin: User, alice: tuple[User, Device, Credential]
) -> None:
    user, device, credential = alice
    response = client.get(f"/admin/users/{user.id}/devices", headers=auth(admin.id))
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == user.id
    assert [item["id"] for item in body["items"]] == [device.id]
    assert body["items"][0]["credential_id"] == credential.credential_id


def test_admin_devices_of_unknown_user_is_404(
    client: TestClient, session: Session, admin: User
) -> None:
    response = client.get("/admin/users/4242/devices", headers=auth(admin.id))
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_admin_deletes_a_device_of_any_user(
    client: TestClient, session: Session, admin: User, alice: tuple[User, Device, Credential]
) -> None:
    user, device, _ = alice
    response = client.delete(f"/admin/users/{user.id}/devices/{device.id}", headers=auth(admin.id))
    assert response.status_code == 204
    assert response.content == b""
    assert SqlAlchemyDeviceRepository(session).get_by_id(device.id) is None


def test_admin_cannot_delete_a_device_of_a_third_user(
    client: TestClient, session: Session, admin: User
) -> None:
    alice_user, _, _ = create_user_with_credential(
        session, username="alice", credential_id=CREDENTIAL_ALICE
    )
    _, bob_device, _ = create_user_with_credential(
        session, username="bob", credential_id=CREDENTIAL_BOB
    )
    response = client.delete(
        f"/admin/users/{alice_user.id}/devices/{bob_device.id}",
        headers=auth(admin.id),
    )
    assert response.status_code == 404
    assert SqlAlchemyDeviceRepository(session).get_by_id(bob_device.id) is not None


def test_admin_deleting_a_device_of_an_unknown_user_is_404(
    client: TestClient, session: Session, admin: User
) -> None:
    response = client.delete("/admin/users/4242/devices/1", headers=auth(admin.id))
    assert response.status_code == 404


# --------------------------------------------- admin: блокировка/разблокировка
def test_admin_disables_and_enables_an_account(
    client: TestClient, session: Session, admin: User
) -> None:
    user = create_user(session, username="alice")
    headers = auth(admin.id)
    disabled = client.post(f"/admin/users/{user.id}/disable", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False
    enabled = client.post(f"/admin/users/{user.id}/enable", headers=headers)
    assert enabled.status_code == 200
    assert enabled.json()["is_active"] is True
    events = [
        entry.event_type
        for entry in SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)
    ]  # noqa: E501
    assert AuthEventType.ADMIN_DISABLE_USER in events
    assert AuthEventType.ADMIN_ENABLE_USER in events


def test_disabled_user_cannot_use_the_api(
    client: TestClient, session: Session, admin: User
) -> None:
    user = create_user(session, username="alice")
    headers = auth(user.id)
    assert client.get("/devices/", headers=headers).status_code == 200
    client.post(f"/admin/users/{user.id}/disable", headers=auth(admin.id))
    blocked = client.get("/devices/", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "account_disabled"


def test_disabled_user_cannot_log_in(client: TestClient, session: Session, admin: User) -> None:
    user, _, _ = create_user_with_credential(
        session, username="alice", credential_id=CREDENTIAL_ALICE
    )
    client.post(f"/admin/users/{user.id}/disable", headers=auth(admin.id))
    response = client.post("/auth/login/begin", json={"username": "alice"})
    assert response.status_code == 403
    assert response.json()["code"] == "account_disabled"


def test_admin_acting_on_an_unknown_user_is_404(
    client: TestClient, session: Session, admin: User
) -> None:
    response = client.post("/admin/users/4242/disable", headers=auth(admin.id))
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_admin_can_disable_itself(client: TestClient, session: Session, admin: User) -> None:
    headers = auth(admin.id)
    assert client.post(f"/admin/users/{admin.id}/disable", headers=headers).status_code == 200
    # Аутентификация по-прежнему действительна, но учётная запись теперь заблокирована.
    assert client.get("/admin/users", headers=headers).status_code == 403


# ---------------------------------------------------------------- логи
def test_logs_my_only_returns_own_events(client: TestClient, session: Session) -> None:
    alice_user, _, _ = create_user_with_credential(
        session, username="alice", credential_id=CREDENTIAL_ALICE
    )
    bob, _, _ = create_user_with_credential(session, username="bob", credential_id=CREDENTIAL_BOB)
    create_auth_log(session, user=alice_user, event_type=AuthEventType.LOGIN_BEGIN)
    create_auth_log(session, user=alice_user, event_type=AuthEventType.LOGIN_COMPLETE)
    create_auth_log(session, user=bob, event_type=AuthEventType.LOGIN_BEGIN)

    body = client.get("/logs/my", headers=auth(alice_user.id)).json()
    assert body["total"] == 2
    assert {item["event_type"] for item in body["items"]} == {
        AuthEventType.LOGIN_BEGIN.value,
        AuthEventType.LOGIN_COMPLETE.value,
    }
    assert all(item["user_id"] == alice_user.id for item in body["items"])


def test_logs_my_is_empty_for_a_fresh_account(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice")
    body = client.get("/logs/my", headers=auth(user.id)).json()
    assert body == {"items": [], "total": 0, "skip": 0, "limit": 50}


def test_logs_my_paginates(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice")
    for _ in range(3):
        create_auth_log(session, user=user)
    body = client.get("/logs/my?skip=1&limit=1", headers=auth(user.id)).json()
    assert body["total"] == 3
    assert body["skip"] == 1
    assert body["limit"] == 1
    assert len(body["items"]) == 1


def test_logs_admin_returns_everything_newest_first(
    client: TestClient, session: Session, admin: User
) -> None:
    alice_user = create_user(session, username="alice")
    first = create_auth_log(session, user=alice_user, event_type=AuthEventType.LOGIN_BEGIN)
    second = create_auth_log(session, user=alice_user, event_type=AuthEventType.LOGIN_COMPLETE)
    body = client.get("/logs/admin", headers=auth(admin.id)).json()
    assert body["total"] == 2
    assert [item["id"] for item in body["items"]] == [second.id, first.id]


def test_logs_expose_the_request_metadata(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice")
    create_auth_log(
        session, user=user, ip_address="203.0.113.42", user_agent="Pixel/8", details='{"a":1}'
    )
    item = client.get("/logs/my", headers=auth(user.id)).json()["items"][0]
    assert item["ip_address"] == "203.0.113.42"
    assert item["user_agent"] == "Pixel/8"
    assert item["details"] == '{"a":1}'
    assert item["status"] == AuthLogStatus.SUCCESS.value
    assert item["timestamp"]


@pytest.mark.parametrize("query", ["skip=-1", "limit=0", "limit=201"])
def test_logs_validate_pagination(client: TestClient, session: Session, query: str) -> None:
    user = create_user(session, username="alice")
    response = client.get(f"/logs/my?{query}", headers=auth(user.id))
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


# ---------------------------------------------------------------- token'ы
def test_expired_token_is_rejected(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice")
    expired = jwt.encode(
        {"sub": str(user.id), "exp": 1, "iat": 0}, test_settings.secret_key, algorithm="HS256"
    )
    response = client.get("/devices/", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401
    assert response.json()["code"] == "token_expired"


def test_token_of_a_deleted_account_is_rejected(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice")
    headers = auth(user.id)
    session.delete(user)
    session.commit()
    response = client.get("/devices/", headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "bearer "},
    ],
)
def test_malformed_authorization_headers(client: TestClient, header: dict[str, str]) -> None:
    response = client.get("/devices/", headers=header)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_admin_routes_are_documented(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "/admin/users" in paths
    assert "/admin/users/{user_id}/devices" in paths
    assert "/admin/users/{user_id}/devices/{device_id}" in paths
    assert "/admin/users/{user_id}/disable" in paths
    assert "/admin/users/{user_id}/enable" in paths
    assert "/logs/my" in paths
    assert "/logs/admin" in paths
