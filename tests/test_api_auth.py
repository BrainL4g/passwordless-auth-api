"""HTTP-контракт роутера ``/auth``."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.user import SqlAlchemyUserRepository
from src.utils.enums import AuthEventType, AuthLogStatus, DeviceType
from src.utils.exceptions import WebAuthnVerificationError
from tests.factories import create_user, create_user_with_credential
from tests.fakes import (
    REGISTRATION_CREDENTIAL_ID,
    FakeWebAuthnService,
    authentication_payload,
    registration_payload,
)

CHALLENGE_ID = "challenge-id-1234"


def register(
    client: TestClient,
    *,
    username: str = "alice",
    email: str = "alice@example.com",
    device_name: str = "Pixel 8",
    device_type: str = "android",
) -> dict[str, object]:
    """Выполняет полную двухэтапную регистрацию и возвращает тело с токеном."""
    begin = client.post("/auth/register/begin", json={"username": username, "email": email})
    assert begin.status_code == 200, begin.text
    body = begin.json()
    complete = client.post(
        "/auth/register/complete",
        json={
            "challenge_id": body["challenge_id"],
            "credential": registration_payload(),
            "device_name": device_name,
            "device_type": device_type,
        },
    )
    assert complete.status_code == 200, complete.text
    return dict(complete.json())


# ----------------------------------------------------- register/begin
def test_register_begin_returns_creation_options(client: TestClient) -> None:
    response = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "alice@example.com"}
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"challenge_id", "options"}
    assert len(body["challenge_id"]) >= 8
    assert body["options"]["attestation"] == "none"
    assert body["options"]["user"]["name"] == "alice"
    assert body["options"]["user"]["displayName"] == "alice@example.com"
    assert body["options"]["authenticatorSelection"]["authenticatorAttachment"] == "platform"
    assert body["options"]["authenticatorSelection"]["residentKey"] == "preferred"
    assert body["options"]["authenticatorSelection"]["userVerification"] == "required"
    assert body["options"]["excludeCredentials"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "ab", "email": "a@example.com"},
        {"username": "-nope", "email": "a@example.com"},
        {"username": "alice", "email": "not-an-email"},
        {"username": "alice"},
        {"email": "a@example.com"},
        {},
    ],
)
def test_register_begin_validation_errors(client: TestClient, payload: dict[str, str]) -> None:
    response = client.post("/auth/register/begin", json=payload)
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "validation_error"
    assert body["detail"]


def test_register_begin_conflicts_with_existing_username(
    client: TestClient, session: Session
) -> None:
    create_user(session, username="alice", email="taken@example.com")
    response = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "fresh@example.com"}
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == "user_already_exists"
    assert "username" in body["detail"].lower()
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.REGISTER_BEGIN
    assert entry.status == AuthLogStatus.FAILURE
    assert entry.ip_address == "testclient"


def test_register_begin_conflicts_with_existing_email(client: TestClient, session: Session) -> None:
    create_user(session, username="other", email="alice@example.com")
    response = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "alice@example.com"}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "user_already_exists"


# -------------------------------------------------- register/complete
def test_register_complete_issues_a_token(client: TestClient, session: Session) -> None:
    body = register(client)
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 30 * 60
    assert isinstance(body["access_token"], str) and body["access_token"]

    user = SqlAlchemyUserRepository(session).get_by_username("alice")
    assert user is not None
    devices = SqlAlchemyDeviceRepository(session).list_by_user(user.id)
    assert [device.device_type for device in devices] == [DeviceType.ANDROID]
    assert [device.device_name for device in devices] == ["Pixel 8"]


def test_registered_token_authenticates_subsequent_requests(client: TestClient) -> None:
    token = register(client)["access_token"]
    response = client.get("/devices/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1


def test_register_complete_rejects_unknown_challenge(client: TestClient) -> None:
    response = client.post(
        "/auth/register/complete",
        json={
            "challenge_id": CHALLENGE_ID,
            "credential": registration_payload(),
            "device_name": "Pixel",
            "device_type": "android",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "challenge_not_found"


def test_register_complete_rejects_reused_challenge(client: TestClient) -> None:
    begin = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "alice@example.com"}
    ).json()
    payload = {
        "challenge_id": begin["challenge_id"],
        "credential": registration_payload(),
        "device_name": "Pixel",
        "device_type": "android",
    }
    assert client.post("/auth/register/complete", json=payload).status_code == 200
    replay = client.post("/auth/register/complete", json=payload)
    assert replay.status_code == 400
    assert replay.json()["code"] == "challenge_not_found"


def test_register_complete_surfaces_verification_failure(
    client: TestClient, webauthn: FakeWebAuthnService, session: Session
) -> None:
    begin = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "alice@example.com"}
    ).json()
    webauthn.registration_error = WebAuthnVerificationError()
    response = client.post(
        "/auth/register/complete",
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload(),
            "device_name": "Pixel",
            "device_type": "android",
        },
    )
    assert response.status_code == 401
    assert response.json()["code"] == "webauthn_verification_failed"
    assert SqlAlchemyUserRepository(session).get_by_username("alice") is None
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.REGISTER_COMPLETE
    assert entry.status == AuthLogStatus.FAILURE


def test_register_complete_rejects_blank_device_name(client: TestClient) -> None:
    begin = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "alice@example.com"}
    ).json()
    response = client.post(
        "/auth/register/complete",
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload(),
            "device_name": "   ",
            "device_type": "android",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


def test_register_complete_rejects_unknown_device_type(client: TestClient) -> None:
    begin = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "alice@example.com"}
    ).json()
    response = client.post(
        "/auth/register/complete",
        json={
            "challenge_id": begin["challenge_id"],
            "credential": registration_payload(),
            "device_name": "Toaster",
            "device_type": "smart-fridge",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


# -------------------------------------------------------- login/begin
def test_login_begin_returns_allow_credentials(client: TestClient, session: Session) -> None:
    create_user_with_credential(session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID)
    response = client.post("/auth/login/begin", json={"username": " ALICE "})
    assert response.status_code == 200
    body = response.json()
    assert body["options"]["rpId"] == "localhost"
    assert body["options"]["userVerification"] == "required"
    assert [item["id"] for item in body["options"]["allowCredentials"]] == [
        REGISTRATION_CREDENTIAL_ID
    ]


def test_login_begin_unknown_user_looks_identical(client: TestClient) -> None:
    response = client.post("/auth/login/begin", json={"username": "ghost"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"challenge_id", "options"}
    assert body["options"]["allowCredentials"] == []
    assert body["options"]["challenge"]
    assert body["options"]["rpId"] == "localhost"


def test_login_begin_user_without_passkeys_looks_identical(
    client: TestClient, session: Session
) -> None:
    create_user(session, username="alice")
    response = client.post("/auth/login/begin", json={"username": "alice"})
    assert response.status_code == 200
    assert response.json()["options"]["allowCredentials"] == []


def test_login_begin_disabled_user_is_explicit(client: TestClient, session: Session) -> None:
    create_user_with_credential(session, username="alice", is_active=False)
    response = client.post("/auth/login/begin", json={"username": "alice"})
    assert response.status_code == 403
    assert response.json()["code"] == "account_disabled"


def test_login_begin_requires_username(client: TestClient) -> None:
    response = client.post("/auth/login/begin", json={})
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


# ------------------------------------------------------ login/complete
def test_login_complete_issues_a_token(client: TestClient, session: Session) -> None:
    create_user_with_credential(session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID)
    begin = client.post("/auth/login/begin", json={"username": "alice"}).json()
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": authentication_payload()},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 30 * 60
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.LOGIN_COMPLETE
    assert entry.status == AuthLogStatus.SUCCESS
    assert entry.user_agent == "testclient"


def test_login_complete_with_decoy_challenge_fails(client: TestClient) -> None:
    begin = client.post("/auth/login/begin", json={"username": "ghost"}).json()
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": authentication_payload()},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "authentication_failed"


def test_login_complete_rejects_challenge_of_another_ceremony(client: TestClient) -> None:
    begin = client.post(
        "/auth/register/begin", json={"username": "alice", "email": "a@b.co"}
    ).json()
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": authentication_payload()},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "challenge_operation_mismatch"


def test_login_complete_rejects_expired_challenge(
    client: TestClient, session: Session, challenge_store: object
) -> None:
    from datetime import timedelta

    from src.utils.time import utc_now

    create_user_with_credential(session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID)
    begin = client.post("/auth/login/begin", json={"username": "alice"}).json()
    store = challenge_store
    assert store is not None
    record = store.take(begin["challenge_id"])  # type: ignore[attr-defined]
    assert record is not None
    object.__setattr__(record, "expires_at", utc_now() - timedelta(seconds=1))
    store.save(record)  # type: ignore[attr-defined]
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": authentication_payload()},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "challenge_not_found"


def test_login_complete_rejects_sign_count_regression(
    client: TestClient, session: Session, webauthn: FakeWebAuthnService
) -> None:
    create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID, sign_count=9
    )
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id=REGISTRATION_CREDENTIAL_ID,
        new_sign_count=4,
        user_handle=None,
        device_type="singleDevice",
        backed_up=False,
    )
    begin = client.post("/auth/login/begin", json={"username": "alice"}).json()
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": authentication_payload()},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "sign_count_mismatch"
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.status == AuthLogStatus.FAILURE


def test_login_complete_accepts_zero_sign_count(client: TestClient, session: Session) -> None:
    create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID, sign_count=0
    )
    begin = client.post("/auth/login/begin", json={"username": "alice"}).json()
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": authentication_payload()},
    )
    assert response.status_code == 200


def test_login_complete_rejects_malformed_credential(client: TestClient) -> None:
    begin = client.post("/auth/login/begin", json={"username": "ghost"}).json()
    response = client.post(
        "/auth/login/complete",
        json={"challenge_id": begin["challenge_id"], "credential": {"id": "x"}},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


# ------------------------------------------------------------------ logout
def test_logout_returns_no_content(client: TestClient) -> None:
    response = client.post("/auth/logout")
    assert response.status_code == 204
    assert response.content == b""


# ------------------------------------------------------------------- OpenAPI
def test_auth_routes_are_documented(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "/auth/register/begin" in paths
    assert "/auth/register/complete" in paths
    assert "/auth/login/begin" in paths
    assert "/auth/login/complete" in paths
    assert "/auth/logout" in paths
