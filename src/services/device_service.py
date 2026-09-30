"""Управление устройствами: просмотр, привязка дополнительных passkey и удаление."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from src.models.device import Device
from src.models.user import User
from src.repositories.protocols import (
    AuthLogRepository,
    CredentialRepository,
    DeviceRepository,
    TransactionManager,
)
from src.services.audit import AuditLogger
from src.services.challenge_store import Challenge, ChallengeStore, build_challenge
from src.services.dto import ChallengeBeginResult, RegisteredCredential, RequestContext
from src.services.webauthn_service import WebAuthnGateway
from src.utils.enums import AuthEventType, AuthLogStatus, ChallengeOperation, DeviceType
from src.utils.exceptions import (
    ChallengeNotFoundError,
    ChallengeOperationMismatchError,
    ConflictError,
    DomainError,
    NotFoundError,
)
from src.utils.logging_setup import get_logger

logger = get_logger(__name__)


class DeviceService:
    """Управляет passkey аутентифицированного пользователя."""

    def __init__(
        self,
        *,
        devices: DeviceRepository,
        credentials: CredentialRepository,
        logs: AuthLogRepository,
        webauthn: WebAuthnGateway,
        challenges: ChallengeStore,
        transaction: TransactionManager,
        audit: AuditLogger,
        challenge_ttl_seconds: int,
    ) -> None:
        self._devices = devices
        self._credentials = credentials
        self._logs = logs
        self._webauthn = webauthn
        self._challenges = challenges
        self._transaction = transaction
        self._audit = audit
        self._challenge_ttl = challenge_ttl_seconds

    def list_devices(self, user: User) -> Sequence[Device]:
        """Все устройства ``user`` вместе с загруженными passkey."""
        return self._devices.list_by_user(user.id)

    def begin_registration(self, user: User, context: RequestContext) -> ChallengeBeginResult:
        """Начинает привязку дополнительного passkey к ``user``."""
        credentials = self._credentials.list_by_user(user.id)
        record, challenge_bytes = build_challenge(
            operation=ChallengeOperation.REGISTER,
            ttl_seconds=self._challenge_ttl,
            user_id=user.id,
            username=user.username,
        )
        self._challenges.save(record)
        options = self._webauthn.build_registration_options(
            challenge=challenge_bytes,
            user_id=bytes(user.user_handle),
            username=user.username,
            email=user.email,
            exclude_credential_ids=self._webauthn.decode_credential_ids(
                [credential.credential_id for credential in credentials]
            ),
        )
        return ChallengeBeginResult(challenge_id=record.challenge_id, options=options.options)

    def complete_registration(
        self,
        *,
        user: User,
        challenge_id: str,
        credential: dict[str, Any],
        device_name: str,
        device_type: DeviceType,
        context: RequestContext,
    ) -> RegisteredCredential:
        """Завершает привязку дополнительного passkey."""
        try:
            record = self._consume_challenge(challenge_id, user)
            verified = self._webauthn.verify_registration(
                credential=credential, expected_challenge=record.challenge
            )
            if self._credentials.get_by_credential_id(verified.credential_id) is not None:
                raise ConflictError("Credential is already registered")
            with self._transaction.transaction():
                device = self._devices.create(
                    user_id=user.id, device_name=device_name, device_type=device_type
                )
                self._credentials.create(
                    user_id=user.id,
                    device_id=device.id,
                    credential_id=verified.credential_id,
                    public_key=verified.public_key,
                    sign_count=verified.sign_count,
                )
        except DomainError as exc:
            self._audit.record(
                event_type=AuthEventType.DEVICE_ADD,
                status=AuthLogStatus.FAILURE,
                context=context,
                user_id=user.id,
                details={"reason": exc.code, "device_name": device_name},
            )
            raise
        self._audit.record(
            event_type=AuthEventType.DEVICE_ADD,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=user.id,
            details={"device_id": device.id, "device_name": device_name},
        )
        return RegisteredCredential(device_id=device.id, credential_id=verified.credential_id)

    def delete_device(self, user: User, device_id: int, context: RequestContext) -> None:
        """Удаляет одно из собственных устройств (вместе с его passkey)."""
        device = self._devices.get_by_id(device_id)
        if device is None or device.user_id != user.id:
            # Чужие устройства сообщаются как «не найдены», чтобы не утекали идентификаторы.
            self._audit.record(
                event_type=AuthEventType.DEVICE_DELETE,
                status=AuthLogStatus.FAILURE,
                context=context,
                user_id=user.id,
                details={"reason": "not_found", "device_id": device_id},
            )
            raise NotFoundError("Device not found")
        try:
            with self._transaction.transaction():
                self._devices.delete(device)
        except DomainError as exc:
            self._audit.record(
                event_type=AuthEventType.DEVICE_DELETE,
                status=AuthLogStatus.FAILURE,
                context=context,
                user_id=user.id,
                details={"reason": exc.code, "device_id": device_id},
            )
            raise
        self._audit.record(
            event_type=AuthEventType.DEVICE_DELETE,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=user.id,
            details={"device_id": device_id, "device_name": device.device_name},
        )

    def _consume_challenge(self, challenge_id: str, user: User) -> Challenge:
        """Забирает challenge и убеждается, что он принадлежит ``user``."""
        record = self._challenges.take(challenge_id)
        if record is None:
            raise ChallengeNotFoundError()
        if record.operation != ChallengeOperation.REGISTER or record.user_id != user.id:
            raise ChallengeOperationMismatchError()
        return record
