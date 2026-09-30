"""Церемонии регистрации и входа (ядро бизнес-логики).

Заметки по безопасности
-----------------------
* Challenge одноразовые: они удаляются из хранилища при первом вызове
  ``*/complete``, независимо от того, завершился он успехом или нет.
* ``login/begin`` отвечает *подставным* challenge, когда имя пользователя
  неизвестно или у него нет passkey, чтобы форма ответа не раскрывала,
  существует ли учётная запись.  Заблокированные учётные записи получают явный
  ``403``: пользователь должен иметь возможность узнать, что его учётная запись
  заблокирована, поэтому именно этот случай допускает перечисление аккаунтов
  (описано в README).
* Счётчики подписей: переход ``0 -> 0`` — норма для платформенных аутентификаторов
  и синхронизируемых passkey, и он принимается; счётчик, который не увеличивается
  при ненулевом значении, считается возможным клоном аутентификатора.
"""

from __future__ import annotations

import secrets
from typing import Any

from src.models.credential import Credential
from src.models.user import User
from src.repositories.protocols import (
    AuthLogRepository,
    CredentialRepository,
    DeviceRepository,
    TransactionManager,
    UserRepository,
)
from src.services.audit import AuditLogger
from src.services.challenge_store import Challenge, ChallengeStore, build_challenge
from src.services.dto import ChallengeBeginResult, RequestContext, TokenPair
from src.services.security_service import SecurityService
from src.services.webauthn_service import WebAuthnGateway
from src.utils.enums import AuthEventType, AuthLogStatus, ChallengeOperation, DeviceType
from src.utils.exceptions import (
    AccountDisabledError,
    AuthenticationFailedError,
    ChallengeNotFoundError,
    ChallengeOperationMismatchError,
    ConflictError,
    DomainError,
    SignCounterMismatchError,
    UserAlreadyExistsError,
)
from src.utils.logging_setup import get_logger
from src.utils.time import utc_now

logger = get_logger(__name__)


class AuthService:
    """Реализует церемонии регистрации и аутентификации WebAuthn."""

    def __init__(
        self,
        *,
        users: UserRepository,
        devices: DeviceRepository,
        credentials: CredentialRepository,
        logs: AuthLogRepository,
        webauthn: WebAuthnGateway,
        security: SecurityService,
        challenges: ChallengeStore,
        transaction: TransactionManager,
        audit: AuditLogger,
        challenge_ttl_seconds: int,
        user_handle_length: int = 32,
    ) -> None:
        self._users = users
        self._devices = devices
        self._credentials = credentials
        self._logs = logs
        self._webauthn = webauthn
        self._security = security
        self._challenges = challenges
        self._transaction = transaction
        self._audit = audit
        self._challenge_ttl = challenge_ttl_seconds
        self._user_handle_length = user_handle_length

    # --------------------------------------------------------- вспомогательное
    def _issue_challenge(
        self,
        *,
        operation: ChallengeOperation,
        user_id: int | None = None,
        username: str | None = None,
        email: str | None = None,
        user_handle: bytes | None = None,
    ) -> tuple[Challenge, bytes]:
        record, challenge_bytes = build_challenge(
            operation=operation,
            ttl_seconds=self._challenge_ttl,
            user_id=user_id,
            username=username,
            email=email,
            user_handle=user_handle,
        )
        self._challenges.save(record)
        return record, challenge_bytes

    def _consume_challenge(self, challenge_id: str, expected: ChallengeOperation) -> Challenge:
        """Забирает challenge из хранилища; использовать его второй раз нельзя."""
        record = self._challenges.take(challenge_id)
        if record is None:
            raise ChallengeNotFoundError()
        if record.operation != expected:
            raise ChallengeOperationMismatchError()
        return record

    def _record_failure(
        self, event_type: AuthEventType, context: RequestContext, exc: DomainError, **details: Any
    ) -> None:
        self._audit.record(
            event_type=event_type,
            status=AuthLogStatus.FAILURE,
            context=context,
            details={"reason": exc.code, **details},
        )

    # ------------------------------------------------------ регистрация
    def begin_registration(
        self, *, username: str, email: str, context: RequestContext
    ) -> ChallengeBeginResult:
        """Шаг 1/2 регистрации: проверка уникальности и возврат опций."""
        normalized_username = username.strip()
        normalized_email = email.strip()
        if self._users.get_by_username(normalized_username) is not None:
            self._audit.record(
                event_type=AuthEventType.REGISTER_BEGIN,
                status=AuthLogStatus.FAILURE,
                context=context,
                details={"reason": "username_taken", "username": normalized_username},
            )
            raise UserAlreadyExistsError("Username is already registered")
        if self._users.get_by_email(normalized_email) is not None:
            self._audit.record(
                event_type=AuthEventType.REGISTER_BEGIN,
                status=AuthLogStatus.FAILURE,
                context=context,
                details={"reason": "email_taken", "username": normalized_username},
            )
            raise UserAlreadyExistsError("Email is already registered")

        user_handle = secrets.token_bytes(self._user_handle_length)
        record, challenge_bytes = self._issue_challenge(
            operation=ChallengeOperation.REGISTER,
            username=normalized_username,
            email=normalized_email,
            user_handle=user_handle,
        )
        options = self._webauthn.build_registration_options(
            challenge=challenge_bytes,
            user_id=user_handle,
            username=normalized_username,
            email=normalized_email,
            exclude_credential_ids=(),
        )
        self._audit.record(
            event_type=AuthEventType.REGISTER_BEGIN,
            status=AuthLogStatus.SUCCESS,
            context=context,
            details={"username": normalized_username},
        )
        return ChallengeBeginResult(challenge_id=record.challenge_id, options=options.options)

    def complete_registration(
        self,
        *,
        challenge_id: str,
        credential: dict[str, Any],
        device_name: str,
        device_type: DeviceType,
        context: RequestContext,
    ) -> TokenPair:
        """Шаг 2/2 регистрации: проверка attestation и единовременное сохранение."""
        username = ""
        try:
            record = self._consume_challenge(challenge_id, ChallengeOperation.REGISTER)
            username = record.username or ""
            verified = self._webauthn.verify_registration(
                credential=credential, expected_challenge=record.challenge
            )
            email = record.email or ""
            user_handle = record.user_handle or secrets.token_bytes(self._user_handle_length)
            if self._credentials.get_by_credential_id(verified.credential_id) is not None:
                raise ConflictError("Credential is already registered")
            if self._users.get_by_username(username) is not None:
                raise UserAlreadyExistsError("Username is already registered")
            if self._users.get_by_email(email) is not None:
                raise UserAlreadyExistsError("Email is already registered")
            with self._transaction.transaction():
                user = self._users.create(username=username, email=email, user_handle=user_handle)
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
            self._record_failure(AuthEventType.REGISTER_COMPLETE, context, exc, username=username)
            raise
        self._audit.record(
            event_type=AuthEventType.REGISTER_COMPLETE,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=user.id,
            details={"username": user.username, "device_name": device_name},
        )
        return self._security.create_access_token(user.id)

    # ----------------------------------------------------------- вход
    def begin_login(self, *, username: str, context: RequestContext) -> ChallengeBeginResult:
        """Шаг 1/2 входа: возврат ``allowCredentials`` известной учётной записи."""
        normalized = username.strip()
        user = self._users.get_by_username(normalized)
        if user is None:
            return self._decoy_login_begin(username=normalized, context=context)
        if not user.is_active:
            self._audit.record(
                event_type=AuthEventType.LOGIN_BEGIN,
                status=AuthLogStatus.FAILURE,
                context=context,
                user_id=user.id,
                details={"reason": "account_disabled", "username": normalized},
            )
            raise AccountDisabledError()
        credentials = self._credentials.list_by_user(user.id)
        if not credentials:
            return self._decoy_login_begin(username=normalized, context=context)
        record, challenge_bytes = self._issue_challenge(
            operation=ChallengeOperation.LOGIN, user_id=user.id, username=user.username
        )
        options = self._webauthn.build_authentication_options(
            challenge=challenge_bytes,
            allow_credential_ids=self._webauthn.decode_credential_ids(
                [credential.credential_id for credential in credentials]
            ),
        )
        self._audit.record(
            event_type=AuthEventType.LOGIN_BEGIN,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=user.id,
            details={"username": user.username},
        )
        return ChallengeBeginResult(challenge_id=record.challenge_id, options=options.options)

    def complete_login(
        self, *, challenge_id: str, credential: dict[str, Any], context: RequestContext
    ) -> TokenPair:
        """Шаг 2/2 входа: проверка assertion и выпуск access token."""
        try:
            record = self._consume_challenge(challenge_id, ChallengeOperation.LOGIN)
            user = self._login_user(record)
            stored_credential = self._login_credential(record, credential, user)
            verified = self._webauthn.verify_authentication(
                credential=credential,
                expected_challenge=record.challenge,
                credential_public_key=stored_credential.public_key,
                current_sign_count=stored_credential.sign_count,
            )
            self._check_user_handle(user, verified.user_handle)
            new_sign_count = self._validated_sign_count(stored_credential, verified.new_sign_count)
            with self._transaction.transaction():
                self._credentials.update_usage(
                    stored_credential, sign_count=new_sign_count, last_used=utc_now()
                )
        except DomainError as exc:
            self._record_failure(AuthEventType.LOGIN_COMPLETE, context, exc)
            raise
        self._audit.record(
            event_type=AuthEventType.LOGIN_COMPLETE,
            status=AuthLogStatus.SUCCESS,
            context=context,
            user_id=user.id,
            details={"username": user.username},
        )
        return self._security.create_access_token(user.id)

    # --------------------------------------------------------- внутреннее
    def _decoy_login_begin(self, *, username: str, context: RequestContext) -> ChallengeBeginResult:
        """Отвечает для неизвестных учётных записей и записей без passkey точно так же,
        как настоящий ``begin``.
        """
        record, challenge_bytes = self._issue_challenge(
            operation=ChallengeOperation.LOGIN, user_id=None, username=username
        )
        options = self._webauthn.build_authentication_options(
            challenge=challenge_bytes, allow_credential_ids=()
        )
        self._audit.record(
            event_type=AuthEventType.LOGIN_BEGIN,
            status=AuthLogStatus.FAILURE,
            context=context,
            user_id=None,
            details={"reason": "unknown_account_or_no_passkey", "username": username},
        )
        return ChallengeBeginResult(challenge_id=record.challenge_id, options=options.options)

    def _login_user(self, record: Challenge) -> User:
        """Определяет учётную запись за challenge входа."""
        if record.user_id is None:
            # Подставной challenge: учётная запись не существует или не имеет passkey.
            raise AuthenticationFailedError()
        user = self._users.get_by_id(record.user_id)
        if user is None:
            raise AuthenticationFailedError()
        if not user.is_active:
            raise AccountDisabledError()
        return user

    def _login_credential(
        self, record: Challenge, credential: dict[str, Any], user: User
    ) -> Credential:
        """Определяет сохранённый passkey, использованный для assertion."""
        credential_id = self._webauthn.extract_credential_id(credential)
        stored = self._credentials.get_by_credential_id(credential_id)
        if stored is None or stored.user_id != user.id:
            raise AuthenticationFailedError()
        return stored

    @staticmethod
    def _check_user_handle(user: User, returned_handle: bytes | None) -> None:
        """На обнаруживаемый credential должен прийти тот же user handle."""
        if returned_handle is None:
            return
        if not user.user_handle:
            return
        if bytes(returned_handle) != bytes(user.user_handle):
            raise AuthenticationFailedError()

    @staticmethod
    def _validated_sign_count(stored: Credential, new_sign_count: int) -> int:
        """Проверяет счётчик подписей аутентификатора.

        Raises:
            SignCounterMismatchError: счётчик не увеличился при ненулевом
                значении, что указывает на клонированный или подделанный
                аутентификатор.
        """
        stored_count = stored.sign_count
        if new_sign_count == 0 and stored_count == 0:
            # Платформенные аутентификаторы и синхронизируемые passkey всегда
            # сообщают 0.
            return 0
        if new_sign_count <= stored_count:
            raise SignCounterMismatchError()
        return new_sign_count
