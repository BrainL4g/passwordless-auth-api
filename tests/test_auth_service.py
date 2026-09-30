"""AuthService: церемонии регистрации и входа."""

from __future__ import annotations

from collections.abc import Generator
from datetime import timedelta
from typing import Any, cast

import pytest
from sqlalchemy.orm import Session

from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.transaction import SqlAlchemyTransactionManager
from src.repositories.user import SqlAlchemyUserRepository
from src.services.audit import AuditLogger
from src.services.auth_service import AuthService
from src.services.challenge_store import InMemoryChallengeStore, build_challenge
from src.services.dto import RequestContext
from src.services.security_service import SecurityService
from src.utils.enums import AuthEventType, AuthLogStatus, ChallengeOperation, DeviceType
from src.utils.exceptions import (
    AccountDisabledError,
    AuthenticationFailedError,
    ChallengeNotFoundError,
    ChallengeOperationMismatchError,
    ConflictError,
    SignCounterMismatchError,
    UserAlreadyExistsError,
    WebAuthnVerificationError,
)
from src.utils.time import utc_now
from tests.conftest import test_settings
from tests.factories import create_user, create_user_with_credential
from tests.fakes import (
    REGISTRATION_CREDENTIAL_ID,
    FakeWebAuthnService,
    authentication_payload,
    registration_payload,
)

CONTEXT = RequestContext(ip_address="203.0.113.5", user_agent="pytest-agent")


@pytest.fixture
def store() -> Generator[InMemoryChallengeStore, None, None]:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def service(
    session: Session, webauthn: FakeWebAuthnService, store: InMemoryChallengeStore
) -> AuthService:
    transaction = SqlAlchemyTransactionManager(session)
    audit = AuditLogger(SqlAlchemyAuthLogRepository(session), transaction)
    return AuthService(
        users=SqlAlchemyUserRepository(session),
        devices=SqlAlchemyDeviceRepository(session),
        credentials=SqlAlchemyCredentialRepository(session),
        logs=SqlAlchemyAuthLogRepository(session),
        webauthn=webauthn,
        security=SecurityService(test_settings),
        challenges=store,
        transaction=transaction,
        audit=audit,
        challenge_ttl_seconds=test_settings.challenge_ttl_seconds,
        user_handle_length=test_settings.user_handle_length,
    )


def _events(session: Session, event_type: AuthEventType | None = None) -> list[Any]:
    entries = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=100)
    if event_type is None:
        return list(entries)
    return [entry for entry in entries if entry.event_type == event_type]


# ----------------------------------------------------------- регистрация
def test_begin_registration_returns_options_and_stores_challenge(
    service: AuthService, webauthn: FakeWebAuthnService, store: InMemoryChallengeStore
) -> None:
    result = service.begin_registration(
        username="alice", email="alice@example.com", context=CONTEXT
    )
    assert result.challenge_id
    assert result.options["user"]["name"] == "alice"
    assert result.options["attestation"] == "none"
    stored = store.take(result.challenge_id)
    assert stored is not None
    assert stored.operation == ChallengeOperation.REGISTER
    assert stored.username == "alice"
    assert stored.email == "alice@example.com"
    assert stored.user_handle is not None and len(stored.user_handle) == 32
    assert webauthn.registration_calls[0]["user_id"] == stored.user_handle


@pytest.mark.parametrize(
    ("existing_username", "existing_email", "new_username", "new_email"),
    [
        ("alice", "other@example.com", "alice", "new@example.com"),
        ("other", "alice@example.com", "alice", "alice@example.com"),
        ("alice", "alice@example.com", "Alice", "fresh@example.com"),
    ],
)
def test_begin_registration_conflicts(
    service: AuthService,
    session: Session,
    existing_username: str,
    existing_email: str,
    new_username: str,
    new_email: str,
) -> None:
    create_user(session, username=existing_username, email=existing_email)
    with pytest.raises(UserAlreadyExistsError) as exc_info:
        service.begin_registration(username=new_username, email=new_email, context=CONTEXT)
    assert exc_info.value.status_code == 409
    assert _events(session, AuthEventType.REGISTER_BEGIN)[0].status == AuthLogStatus.FAILURE


def test_complete_registration_creates_everything_atomically(
    service: AuthService, session: Session
) -> None:
    begin = service.begin_registration(username="alice", email="alice@example.com", context=CONTEXT)
    tokens = service.complete_registration(
        challenge_id=begin.challenge_id,
        credential=registration_payload(),
        device_name="Pixel 8",
        device_type=DeviceType.ANDROID,
        context=CONTEXT,
    )
    assert tokens.token_type == "bearer"
    user = SqlAlchemyUserRepository(session).get_by_username("alice")
    assert user is not None and user.is_active is True and user.is_admin is False
    devices = SqlAlchemyDeviceRepository(session).list_by_user(user.id)
    assert len(devices) == 1
    credentials = SqlAlchemyCredentialRepository(session).list_by_user(user.id)
    assert [item.credential_id for item in credentials] == [REGISTRATION_CREDENTIAL_ID]
    assert _events(session, AuthEventType.REGISTER_COMPLETE)[0].status == AuthLogStatus.SUCCESS


def test_complete_registration_rejects_wrong_operation(
    service: AuthService, webauthn: FakeWebAuthnService
) -> None:
    record, _ = build_challenge(operation=ChallengeOperation.LOGIN, ttl_seconds=300, user_id=1)
    challenges = cast("InMemoryChallengeStore", service._challenges)
    challenges.save(record)
    with pytest.raises(ChallengeOperationMismatchError):
        service.complete_registration(
            challenge_id=record.challenge_id,
            credential=registration_payload(),
            device_name="x",
            device_type=DeviceType.WINDOWS,
            context=CONTEXT,
        )


def test_complete_registration_unknown_challenge(service: AuthService) -> None:
    with pytest.raises(ChallengeNotFoundError) as exc_info:
        service.complete_registration(
            challenge_id="unknown-challenge-id",
            credential=registration_payload(),
            device_name="x",
            device_type=DeviceType.WINDOWS,
            context=CONTEXT,
        )
    assert exc_info.value.status_code == 400


def test_challenge_is_single_use_even_after_failure(
    service: AuthService, webauthn: FakeWebAuthnService
) -> None:
    begin = service.begin_registration(username="alice", email="alice@example.com", context=CONTEXT)
    webauthn.registration_error = WebAuthnVerificationError()
    with pytest.raises(WebAuthnVerificationError):
        service.complete_registration(
            challenge_id=begin.challenge_id,
            credential=registration_payload(),
            device_name="Pixel",
            device_type=DeviceType.ANDROID,
            context=CONTEXT,
        )
    webauthn.registration_error = None
    with pytest.raises(ChallengeNotFoundError):
        service.complete_registration(
            challenge_id=begin.challenge_id,
            credential=registration_payload(),
            device_name="Pixel",
            device_type=DeviceType.ANDROID,
            context=CONTEXT,
        )


def test_complete_registration_expired_challenge(
    service: AuthService, session: Session, store: InMemoryChallengeStore
) -> None:
    begin = service.begin_registration(username="alice", email="alice@example.com", context=CONTEXT)
    record = store.take(begin.challenge_id)
    assert record is not None
    object.__setattr__(record, "expires_at", utc_now() - timedelta(seconds=1))
    store.save(record)
    with pytest.raises(ChallengeNotFoundError):
        service.complete_registration(
            challenge_id=begin.challenge_id,
            credential=registration_payload(),
            device_name="Pixel",
            device_type=DeviceType.ANDROID,
            context=CONTEXT,
        )


def test_complete_registration_rejects_credential_of_another_account(
    service: AuthService, session: Session
) -> None:
    create_user_with_credential(session, username="bob", credential_id=REGISTRATION_CREDENTIAL_ID)
    begin = service.begin_registration(username="alice", email="alice@example.com", context=CONTEXT)
    with pytest.raises(ConflictError):
        service.complete_registration(
            challenge_id=begin.challenge_id,
            credential=registration_payload(),
            device_name="Pixel",
            device_type=DeviceType.ANDROID,
            context=CONTEXT,
        )
    assert SqlAlchemyUserRepository(session).get_by_username("alice") is None


def test_complete_registration_detects_username_taken_in_between(
    service: AuthService, session: Session
) -> None:
    begin = service.begin_registration(username="alice", email="alice@example.com", context=CONTEXT)
    create_user(session, username="alice", email="someone-else@example.com")
    with pytest.raises(UserAlreadyExistsError):
        service.complete_registration(
            challenge_id=begin.challenge_id,
            credential=registration_payload(),
            device_name="Pixel",
            device_type=DeviceType.ANDROID,
            context=CONTEXT,
        )


# ------------------------------------------------------------------- login
def test_begin_login_returns_allow_credentials(service: AuthService, session: Session) -> None:
    create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    result = service.begin_login(username="ALICE", context=CONTEXT)
    assert result.options["rpId"] == test_settings.rp_id
    assert result.options["userVerification"] == "required"
    assert [item["id"] for item in result.options["allowCredentials"]] == ["YWxpY2U"]
    assert _events(session, AuthEventType.LOGIN_BEGIN)[0].status == AuthLogStatus.SUCCESS


def test_begin_login_for_unknown_user_is_a_decoy(
    service: AuthService, session: Session, webauthn: FakeWebAuthnService
) -> None:
    result = service.begin_login(username="ghost", context=CONTEXT)
    assert result.challenge_id
    assert result.options["allowCredentials"] == []
    assert result.options["challenge"]
    entry = _events(session, AuthEventType.LOGIN_BEGIN)[0]
    assert entry.user_id is None
    assert entry.status == AuthLogStatus.FAILURE
    # Приманка-challenge не должна вести никуда.
    with pytest.raises(AuthenticationFailedError):
        service.complete_login(
            challenge_id=result.challenge_id,
            credential=authentication_payload(),
            context=CONTEXT,
        )


def test_begin_login_for_user_without_passkeys_is_a_decoy(
    service: AuthService, session: Session
) -> None:
    create_user(session, username="alice")
    result = service.begin_login(username="alice", context=CONTEXT)
    assert result.options["allowCredentials"] == []


def test_begin_login_for_disabled_user(service: AuthService, session: Session) -> None:
    create_user_with_credential(session, username="alice", is_active=False)
    with pytest.raises(AccountDisabledError) as exc_info:
        service.begin_login(username="alice", context=CONTEXT)
    assert exc_info.value.status_code == 403


def test_complete_login_updates_sign_count_and_last_used(
    service: AuthService, session: Session, webauthn: FakeWebAuthnService
) -> None:
    user, _, credential = create_user_with_credential(
        session, username="alice", credential_id="YWxpY2U", sign_count=4
    )
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id="YWxpY2U",
        new_sign_count=9,
        user_handle=None,
        device_type="singleDevice",
        backed_up=False,
    )
    begin = service.begin_login(username="alice", context=CONTEXT)
    tokens = service.complete_login(
        challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
    )
    assert tokens.token_type == "bearer"
    session.expire_all()
    refreshed = SqlAlchemyCredentialRepository(session).get_by_credential_id("YWxpY2U")
    assert refreshed is not None
    assert refreshed.sign_count == 9
    assert refreshed.last_used is not None
    assert _events(session, AuthEventType.LOGIN_COMPLETE)[0].status == AuthLogStatus.SUCCESS
    assert user.id is not None


def test_complete_login_accepts_zero_sign_count(
    service: AuthService, session: Session, webauthn: FakeWebAuthnService
) -> None:
    create_user_with_credential(
        session, username="alice", credential_id=REGISTRATION_CREDENTIAL_ID, sign_count=0
    )
    begin = service.begin_login(username="alice", context=CONTEXT)
    service.complete_login(
        challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
    )
    refreshed = SqlAlchemyCredentialRepository(session).get_by_credential_id(
        REGISTRATION_CREDENTIAL_ID
    )
    assert refreshed is not None and refreshed.sign_count == 0


@pytest.mark.parametrize(("stored", "received"), [(5, 5), (5, 3), (7, 1)])
def test_complete_login_rejects_sign_count_regression(
    service: AuthService,
    session: Session,
    webauthn: FakeWebAuthnService,
    stored: int,
    received: int,
) -> None:
    create_user_with_credential(
        session, username="alice", credential_id="YWxpY2U", sign_count=stored
    )
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id="YWxpY2U",
        new_sign_count=received,
        user_handle=None,
        device_type="singleDevice",
        backed_up=False,
    )
    begin = service.begin_login(username="alice", context=CONTEXT)
    with pytest.raises(SignCounterMismatchError) as exc_info:
        service.complete_login(
            challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
        )
    assert exc_info.value.status_code == 401
    entry = _events(session, AuthEventType.LOGIN_COMPLETE)[0]
    assert entry.status == AuthLogStatus.FAILURE
    assert "sign_count_mismatch" in str(entry.details)


def test_complete_login_rejects_foreign_credential(
    service: AuthService, session: Session, webauthn: FakeWebAuthnService
) -> None:
    create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    create_user_with_credential(session, username="bob", credential_id="Ym9i")
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id="Ym9i",
        new_sign_count=1,
        user_handle=None,
        device_type="singleDevice",
        backed_up=False,
    )
    begin = service.begin_login(username="alice", context=CONTEXT)
    with pytest.raises(AuthenticationFailedError):
        service.complete_login(
            challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
        )


def test_complete_login_rejects_mismatching_user_handle(
    service: AuthService, session: Session, webauthn: FakeWebAuthnService
) -> None:
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id="YWxpY2U",
        new_sign_count=1,
        user_handle=b"somebody-elses-handle",
        device_type="singleDevice",
        backed_up=False,
    )
    begin = service.begin_login(username="alice", context=CONTEXT)
    with pytest.raises(AuthenticationFailedError):
        service.complete_login(
            challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
        )
    assert bytes(user.user_handle) != b"somebody-elses-handle"


def test_complete_login_rejects_invalid_credential_payload(
    service: AuthService, session: Session, webauthn: FakeWebAuthnService
) -> None:
    from src.utils.exceptions import InvalidCredentialError

    create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    webauthn.parse_error = InvalidCredentialError()
    begin = service.begin_login(username="alice", context=CONTEXT)
    with pytest.raises(InvalidCredentialError):
        service.complete_login(
            challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
        )


def test_complete_login_rejects_challenge_of_registration(
    service: AuthService, session: Session
) -> None:
    record, _ = build_challenge(operation=ChallengeOperation.REGISTER, ttl_seconds=300, user_id=1)
    cast("InMemoryChallengeStore", service._challenges).save(record)
    with pytest.raises(ChallengeOperationMismatchError):
        service.complete_login(
            challenge_id=record.challenge_id,
            credential=authentication_payload(),
            context=CONTEXT,
        )


def test_complete_login_for_deleted_user(service: AuthService, session: Session) -> None:
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    begin = service.begin_login(username="alice", context=CONTEXT)
    session.delete(user)
    session.commit()
    with pytest.raises(AuthenticationFailedError):
        service.complete_login(
            challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
        )


def test_complete_login_for_user_disabled_in_between(
    service: AuthService, session: Session
) -> None:
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    begin = service.begin_login(username="alice", context=CONTEXT)
    user.is_active = False
    session.commit()
    with pytest.raises(AccountDisabledError):
        service.complete_login(
            challenge_id=begin.challenge_id,
            credential=authentication_payload(),
            context=CONTEXT,
        )
