"""HTTP-контракт роутера ``/devices``."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.utils.enums import AuthEventType, AuthLogStatus, DeviceType
from tests.conftest import test_settings
from tests.factories import create_user, create_user_with_credential
from tests.fakes import (
    REGISTRATION_CREDENTIAL_ID,
    FakeWebAuthnService,
    registration_payload,
)


def token_for(user_id: int) -> str:
    """Выпускает access token для ``user_id`` тестовым ключом подписи."""
    from src.services.security_service import SecurityService

    return SecurityService(test_settings).create_access_token(user_id).access_token


def auth(user_id: int) -> dict[str, str]:
    return {"Authorization": f"Bearer {token_for(user_id)}"}


# ------------------------------------------------------------------ список
def test_list_devices_requires_a_token(client: TestClient) -> None:
    response = client.get("/devices/")
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_list_devices_is_empty_for_a_fresh_account(client: TestClient, session: Session) -> None:
    user = create_user(session, username="alice")
    response = client.get("/devices/", headers=auth(user.id))
    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_list_devices_returns_own_devices_only(client: TestClient, session: Session) -> None:
    alice, alice_device, credential = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    create_user_with_credential(session, username="bob", credential_id="Ym9i")
    response = client.get("/devices/", headers=auth(alice.id))
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0] == {
        "id": alice_device.id,
        "device_name": "Pixel 8",
        "device_type": "android",
        "created_at": alice_device.created_at.isoformat().replace("+00:00", "Z"),
        "last_used": None,
        "credential_id": credential.credential_id,
    }


def test_list_devices_reports_the_last_authentication(client: TestClient, session: Session) -> None:
    user, device, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    credentials = SqlAlchemyCredentialRepository(session)
    stored = credentials.get_by_credential_id(REGISTRATION_CREDENTIAL_ID)
    assert stored is not None
    from src.utils.time import utc_now

    credentials.update_usage(stored, sign_count=1, last_used=utc_now())
    session.commit()
    items = client.get("/devices/", headers=auth(user.id)).json()["items"]
    assert items[0]["id"] == device.id
    assert items[0]["last_used"] is not None


# ------------------------------------------------------------ добавление passkey
def test_device_register_begin_excludes_existing_passkeys(
    client: TestClient, session: Session
) -> None:
    user, _, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    response = client.post("/devices/register/begin", headers=auth(user.id))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"challenge_id", "options"}
    assert [item["id"] for item in body["options"]["excludeCredentials"]] == [
        REGISTRATION_CREDENTIAL_ID
    ]
    assert body["options"]["user"]["id"]


def test_device_register_begin_requires_authentication(client: TestClient) -> None:
    assert client.post("/devices/register/begin").status_code == 401


def test_device_register_complete_adds_a_device(
    client: TestClient, session: Session, webauthn: FakeWebAuthnService
) -> None:
    user, _, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    webauthn.registration_result = type(webauthn.registration_result)(
        credential_id="bmV3",
        public_key=b"new-key",
        sign_count=0,
        aaguid="aaguid",
        device_type="singleDevice",
        backed_up=False,
    )
    begin = client.post("/devices/register/begin", headers=auth(user.id)).json()
    response = client.post(
        "/devices/register/complete",
        headers=auth(user.id),
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload("bmV3"),
            "device_name": "ThinkPad X1",
            "device_type": "windows",
        },
    )
    assert response.status_code == 201
    assert response.json()["credential_id"] == "bmV3"
    items = client.get("/devices/", headers=auth(user.id)).json()["items"]
    assert [item["device_type"] for item in items] == ["android", "windows"]
    assert items[1]["device_name"] == "ThinkPad X1"
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.DEVICE_ADD
    assert entry.status == AuthLogStatus.SUCCESS


def test_device_register_complete_rejects_another_users_challenge(
    client: TestClient, session: Session
) -> None:
    alice, _, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    bob, _, _ = create_user_with_credential(session, username="bob", credential_id="Ym9i")
    begin = client.post("/devices/register/begin", headers=auth(bob.id)).json()
    response = client.post(
        "/devices/register/complete",
        headers=auth(alice.id),
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload("bmV3"),
            "device_name": "Stolen",
            "device_type": "windows",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "challenge_operation_mismatch"


def test_device_register_complete_rejects_duplicate_credential(
    client: TestClient, session: Session
) -> None:
    user, _, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    begin = client.post("/devices/register/begin", headers=auth(user.id)).json()
    response = client.post(
        "/devices/register/complete",
        headers=auth(user.id),
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload(),
            "device_name": "Clone",
            "device_type": "windows",
        },
    )
    assert response.status_code == 409
    assert response.json()["code"] == "conflict"
    assert len(client.get("/devices/", headers=auth(user.id)).json()["items"]) == 1


def test_device_register_complete_rejects_unknown_challenge(
    client: TestClient, session: Session
) -> None:
    user = create_user(session, username="alice")
    response = client.post(
        "/devices/register/complete",
        headers=auth(user.id),
        json={
            "challenge_id": "missing-challenge",
            "credential": registration_payload(),
            "device_name": "Pixel",
            "device_type": "android",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "challenge_not_found"


def test_device_register_complete_rejects_invalid_device_type(
    client: TestClient, session: Session
) -> None:
    user = create_user(session, username="alice")
    begin = client.post("/devices/register/begin", headers=auth(user.id)).json()
    response = client.post(
        "/devices/register/complete",
        headers=auth(user.id),
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload(),
            "device_name": "Toaster",
            "device_type": "smart-fridge",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


# ---------------------------------------------------------------- удаление
def test_delete_own_device(client: TestClient, session: Session) -> None:
    user, device, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    response = client.delete(f"/devices/{device.id}", headers=auth(user.id))
    assert response.status_code == 204
    assert response.content == b""
    assert client.get("/devices/", headers=auth(user.id)).json()["items"] == []
    assert (
        SqlAlchemyCredentialRepository(session).get_by_credential_id(REGISTRATION_CREDENTIAL_ID)
        is None
    )
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.DEVICE_DELETE
    assert entry.status == AuthLogStatus.SUCCESS


def test_delete_foreign_device_is_404(client: TestClient, session: Session) -> None:
    alice, _, _ = create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID
    )
    _, bob_device, _ = create_user_with_credential(session, username="bob", credential_id="Ym9i")
    response = client.delete(f"/devices/{bob_device.id}", headers=auth(alice.id))
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    assert SqlAlchemyDeviceRepository(session).get_by_id(bob_device.id) is not None


@pytest.mark.parametrize("device_id", [0, -1])
def test_delete_rejects_non_positive_ids(
    client: TestClient, session: Session, device_id: int
) -> None:
    user = create_user(session, username="alice")
    response = client.delete(f"/devices/{device_id}", headers=auth(user.id))
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


def test_devices_are_documented(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "/devices/" in paths
    assert "/devices/register/begin" in paths
    assert "/devices/register/complete" in paths
    assert "/devices/{device_id}" in paths
    assert set(paths["/devices/{device_id}"]) == {"delete"}


def test_device_type_enum_is_exposed_in_the_schema(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    device_type = schema["components"]["schemas"]["DeviceType"]
    assert device_type["enum"] == [member.value for member in DeviceType]
