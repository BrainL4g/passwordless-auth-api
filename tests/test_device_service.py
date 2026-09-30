"""DeviceService: дополнительные passkey и удаление устройств."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.transaction import SqlAlchemyTransactionManager
from src.services.audit import AuditLogger
from src.services.challenge_store import InMemoryChallengeStore, build_challenge
from src.services.device_service import DeviceService
from src.services.dto import RequestContext
from src.utils.enums import AuthEventType, AuthLogStatus, ChallengeOperation, DeviceType
from src.utils.exceptions import (
    ChallengeNotFoundError,
    ChallengeOperationMismatchError,
    ConflictError,
    NotFoundError,
    WebAuthnVerificationError,
)
from tests.conftest import test_settings
from tests.factories import create_user, create_user_with_credential
from tests.fakes import FakeWebAuthnService, registration_payload

CONTEXT = RequestContext(ip_address="198.51.100.7", user_agent="pytest-agent")


@pytest.fixture
def service(
    session: Session, webauthn: FakeWebAuthnService
) -> tuple[DeviceService, InMemoryChallengeStore]:
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    transaction = SqlAlchemyTransactionManager(session)
    device_service = DeviceService(
        devices=SqlAlchemyDeviceRepository(session),
        credentials=SqlAlchemyCredentialRepository(session),
        logs=SqlAlchemyAuthLogRepository(session),
        webauthn=webauthn,
        challenges=store,
        transaction=transaction,
        audit=AuditLogger(SqlAlchemyAuthLogRepository(session), transaction),
        challenge_ttl_seconds=test_settings.challenge_ttl_seconds,
    )
    return device_service, store


def test_list_devices(
    session: Session, service: tuple[DeviceService, InMemoryChallengeStore]
) -> None:
    device_service, _ = service
    user, device, _ = create_user_with_credential(session, username="alice")
    create_user_with_credential(session, username="bob", credential_id="Ym9i")
    devices = device_service.list_devices(user)
    assert [item.id for item in devices] == [device.id]
    assert devices[0].credential is not None
    assert devices[0].last_used is None


def test_begin_registration_excludes_existing_credentials(
    session: Session,
    service: tuple[DeviceService, InMemoryChallengeStore],
    webauthn: FakeWebAuthnService,
) -> None:
    device_service, store = service
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    result = device_service.begin_registration(user, CONTEXT)
    assert [item["id"] for item in result.options["excludeCredentials"]] == ["YWxpY2U"]
    assert result.options["user"]["name"] == "alice"
    record = store.take(result.challenge_id)
    assert record is not None and record.user_id == user.id
    assert record.operation == ChallengeOperation.REGISTER
    assert webauthn.registration_calls[0]["user_id"] == bytes(user.user_handle)


def test_complete_registration_adds_device(
    session: Session,
    service: tuple[DeviceService, InMemoryChallengeStore],
    webauthn: FakeWebAuthnService,
) -> None:
    device_service, _ = service
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    webauthn.registration_result = type(webauthn.registration_result)(
        credential_id="bmV3",
        public_key=b"new-key",
        sign_count=0,
        aaguid="aaguid",
        device_type="singleDevice",
        backed_up=False,
    )
    begin = device_service.begin_registration(user, CONTEXT)
    added = device_service.complete_registration(
        user=user,
        challenge_id=begin.challenge_id,
        credential=registration_payload("bmV3"),
        device_name="ThinkPad",
        device_type=DeviceType.WINDOWS,
        context=CONTEXT,
    )
    assert added.credential_id == "bmV3"
    assert added.device_id > 0
    assert len(device_service.list_devices(user)) == 2
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)[0]
    assert entry.event_type == AuthEventType.DEVICE_ADD
    assert entry.status == AuthLogStatus.SUCCESS


def test_complete_registration_rejects_foreign_challenge(
    session: Session, service: tuple[DeviceService, InMemoryChallengeStore]
) -> None:
    device_service, store = service
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    other = create_user(session, username="bob")
    record, _ = build_challenge(
        operation=ChallengeOperation.REGISTER, ttl_seconds=300, user_id=other.id
    )
    store.save(record)
    with pytest.raises(ChallengeOperationMismatchError):
        device_service.complete_registration(
            user=user,
            challenge_id=record.challenge_id,
            credential=registration_payload("bmV3"),
            device_name="x",
            device_type=DeviceType.WINDOWS,
            context=CONTEXT,
        )


def test_complete_registration_unknown_challenge(
    session: Session, service: tuple[DeviceService, InMemoryChallengeStore]
) -> None:
    device_service, _ = service
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    with pytest.raises(ChallengeNotFoundError):
        device_service.complete_registration(
            user=user,
            challenge_id="missing-challenge",
            credential=registration_payload(),
            device_name="x",
            device_type=DeviceType.WINDOWS,
            context=CONTEXT,
        )


def test_complete_registration_duplicate_credential(
    session: Session,
    service: tuple[DeviceService, InMemoryChallengeStore],
    webauthn: FakeWebAuthnService,
) -> None:
    device_service, _ = service
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    webauthn.registration_result = type(webauthn.registration_result)(
        credential_id="YWxpY2U",
        public_key=b"other-key",
        sign_count=0,
        aaguid="aaguid",
        device_type="singleDevice",
        backed_up=False,
    )
    begin = device_service.begin_registration(user, CONTEXT)
    with pytest.raises(ConflictError):
        device_service.complete_registration(
            user=user,
            challenge_id=begin.challenge_id,
            credential=registration_payload("YWxpY2U"),
            device_name="x",
            device_type=DeviceType.WINDOWS,
            context=CONTEXT,
        )
    assert len(device_service.list_devices(user)) == 1


def test_complete_registration_verification_failure_is_audited(
    session: Session,
    service: tuple[DeviceService, InMemoryChallengeStore],
    webauthn: FakeWebAuthnService,
) -> None:
    device_service, _ = service
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    begin = device_service.begin_registration(user, CONTEXT)
    webauthn.registration_error = WebAuthnVerificationError()
    with pytest.raises(WebAuthnVerificationError):
        device_service.complete_registration(
            user=user,
            challenge_id=begin.challenge_id,
            credential=registration_payload("bmV3"),
            device_name="x",
            device_type=DeviceType.WINDOWS,
            context=CONTEXT,
        )
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)[0]
    assert entry.event_type == AuthEventType.DEVICE_ADD
    assert entry.status == AuthLogStatus.FAILURE


def test_delete_own_device(
    session: Session, service: tuple[DeviceService, InMemoryChallengeStore]
) -> None:
    device_service, _ = service
    user, device, credential = create_user_with_credential(session, username="alice")
    device_service.delete_device(user, device.id, CONTEXT)
    assert device_service.list_devices(user) == []
    assert SqlAlchemyCredentialRepository(session).get_by_credential_id("Y3JlZC1hYmM") is None
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)[0]
    assert entry.event_type == AuthEventType.DEVICE_DELETE
    assert credential.device_id == device.id


def test_delete_foreign_device_is_not_found(
    session: Session, service: tuple[DeviceService, InMemoryChallengeStore]
) -> None:
    device_service, _ = service
    alice, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    _, bob_device, _ = create_user_with_credential(session, username="bob", credential_id="Ym9i")
    with pytest.raises(NotFoundError) as exc_info:
        device_service.delete_device(alice, bob_device.id, CONTEXT)
    assert exc_info.value.status_code == 404
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=10)[0]
    assert entry.status == AuthLogStatus.FAILURE


def test_delete_unknown_device(
    session: Session, service: tuple[DeviceService, InMemoryChallengeStore]
) -> None:
    device_service, _ = service
    user, _, _ = create_user_with_credential(session, username="alice")
    with pytest.raises(NotFoundError):
        device_service.delete_device(user, 9999, CONTEXT)


def test_device_entity_maps_to_response(session: Session) -> None:
    from src.schemas.device import device_to_response

    _, device, credential = create_user_with_credential(session, username="alice")
    response = device_to_response(device)
    assert response.id == device.id
    assert response.credential_id == credential.credential_id
    assert response.device_type == DeviceType.ANDROID
    assert response.last_used is None
