"""Единственная точка сопряжения бизнес-логики с библиотекой ``py_webauthn``.

Всё, что связано с протоколом (генерация опций, разбор JSON, проверка attestation
и assertion, списки разрешённых алгоритмов и источников), сосредоточено здесь,
поэтому остальная часть слоя сервисов работает с обычными dataclass и может
покрываться модульными тестами без аутентификатора.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json_dict,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from src.utils.config import Settings
from src.utils.exceptions import InvalidCredentialError, WebAuthnVerificationError
from src.utils.logging_setup import get_logger

logger = get_logger(__name__)

#: Android Credential Manager / Windows Hello и браузеры согласованы на ES256;
#: некоторые сборки Windows Hello отвечают RS256, поэтому принимаются оба.
SUPPORTED_ALGORITHMS: tuple[COSEAlgorithmIdentifier, ...] = (
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
)


@dataclass(frozen=True)
class RegistrationOptionsData:
    """``PublicKeyCredentialCreationOptions`` плюс исходный challenge."""

    options: dict[str, Any]
    challenge: bytes


@dataclass(frozen=True)
class AuthenticationOptionsData:
    """``PublicKeyCredentialRequestOptions`` плюс исходный challenge."""

    options: dict[str, Any]
    challenge: bytes


@dataclass(frozen=True)
class VerifiedRegistrationData:
    """Результат успешно проверенной attestation."""

    credential_id: str
    public_key: bytes
    sign_count: int
    aaguid: str
    device_type: str
    backed_up: bool


@dataclass(frozen=True)
class VerifiedAuthenticationData:
    """Результат успешно проверенной assertion."""

    credential_id: str
    new_sign_count: int
    user_handle: bytes | None
    device_type: str
    backed_up: bool


@runtime_checkable
class WebAuthnGateway(Protocol):
    """Всё, что слою сервисов нужно от реализации WebAuthn.

    :class:`WebAuthnService` — это боевая реализация и единственный модуль,
    импортирующий ``py_webauthn``; церемонии зависят от этого контракта, поэтому
    их можно проверять тестовым двойником, а любая другая библиотека сможет
    его заменить.
    """

    def build_registration_options(
        self,
        *,
        challenge: bytes,
        user_id: bytes,
        username: str,
        email: str,
        exclude_credential_ids: Sequence[bytes] = (),
    ) -> RegistrationOptionsData:
        """Создаёт ``PublicKeyCredentialCreationOptions`` для нового пользователя."""
        ...

    def build_authentication_options(
        self,
        *,
        challenge: bytes,
        allow_credential_ids: Sequence[bytes] = (),
    ) -> AuthenticationOptionsData:
        """Создаёт ``PublicKeyCredentialRequestOptions`` для входа."""
        ...

    def verify_registration(
        self, *, credential: dict[str, Any], expected_challenge: bytes
    ) -> VerifiedRegistrationData:
        """Проверяет attestation и возвращает сохраняемый credential."""
        ...

    def verify_authentication(
        self,
        *,
        credential: dict[str, Any],
        expected_challenge: bytes,
        credential_public_key: bytes,
        current_sign_count: int,
    ) -> VerifiedAuthenticationData:
        """Проверяет assertion по сохранённому открытому ключу."""
        ...

    def decode_credential_ids(self, credential_ids: Sequence[str]) -> list[bytes]:
        """Преобразует сохранённые base64url идентификаторы credential в байты."""
        ...

    def extract_credential_id(self, credential: dict[str, Any]) -> str:
        """Возвращает base64url идентификатор credential из assertion."""
        ...


class WebAuthnService:
    """Строит опции WebAuthn и проверяет ответы WebAuthn."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    # ------------------------------------------------------------- опции
    def build_registration_options(
        self,
        *,
        challenge: bytes,
        user_id: bytes,
        username: str,
        email: str,
        exclude_credential_ids: Sequence[bytes] = (),
    ) -> RegistrationOptionsData:
        """Создаёт ``PublicKeyCredentialCreationOptions`` для нового пользователя."""
        options = generate_registration_options(
            rp_id=self._settings.rp_id,
            rp_name=self._settings.rp_name,
            user_id=user_id,
            user_name=username,
            user_display_name=email or username,
            challenge=challenge,
            timeout=self._settings.webauthn_timeout_ms,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=credential_id)
                for credential_id in exclude_credential_ids
            ],
            supported_pub_key_algs=list(SUPPORTED_ALGORITHMS),
        )
        return RegistrationOptionsData(options=options_to_json_dict(options), challenge=challenge)

    def build_authentication_options(
        self,
        *,
        challenge: bytes,
        allow_credential_ids: Sequence[bytes] = (),
    ) -> AuthenticationOptionsData:
        """Создаёт ``PublicKeyCredentialRequestOptions`` для входа."""
        options = generate_authentication_options(
            rp_id=self._settings.rp_id,
            challenge=challenge,
            timeout=self._settings.webauthn_timeout_ms,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=credential_id)
                for credential_id in allow_credential_ids
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return AuthenticationOptionsData(options=options_to_json_dict(options), challenge=challenge)

    # --------------------------------------------------------- проверка
    def verify_registration(
        self, *, credential: dict[str, Any], expected_challenge: bytes
    ) -> VerifiedRegistrationData:
        """Проверяет attestation и возвращает сохраняемый открытый ключ.

        Raises:
            InvalidCredentialError: структура JSON не является credential
                регистрации WebAuthn.
            WebAuthnVerificationError: attestation не удалось проверить.
        """
        try:
            parsed = parse_registration_credential_json(credential)
        except WebAuthnException as exc:
            raise InvalidCredentialError() from exc
        try:
            verified = verify_registration_response(
                credential=parsed,
                expected_challenge=expected_challenge,
                expected_rp_id=self._settings.rp_id,
                expected_origin=self._settings.allowed_origins,
                require_user_verification=self._settings.webauthn_require_user_verification,
                supported_pub_key_algs=list(SUPPORTED_ALGORITHMS),
            )
        except WebAuthnException as exc:
            logger.info("attestation_verification_failed", extra={"reason": type(exc).__name__})
            raise WebAuthnVerificationError() from exc
        return VerifiedRegistrationData(
            credential_id=bytes_to_base64url(verified.credential_id),
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            aaguid=verified.aaguid,
            device_type=str(verified.credential_device_type.value),
            backed_up=verified.credential_backed_up,
        )

    def verify_authentication(
        self,
        *,
        credential: dict[str, Any],
        expected_challenge: bytes,
        credential_public_key: bytes,
        current_sign_count: int,
    ) -> VerifiedAuthenticationData:
        """Проверяет assertion по сохранённому открытому ключу.

        Raises:
            InvalidCredentialError: структура JSON не является credential
                аутентификации WebAuthn.
            WebAuthnVerificationError: подпись не удалось проверить.
        """
        try:
            parsed = parse_authentication_credential_json(credential)
        except WebAuthnException as exc:
            raise InvalidCredentialError() from exc
        try:
            verified = verify_authentication_response(
                credential=parsed,
                expected_challenge=expected_challenge,
                expected_rp_id=self._settings.rp_id,
                expected_origin=self._settings.allowed_origins,
                credential_public_key=credential_public_key,
                credential_current_sign_count=current_sign_count,
                require_user_verification=self._settings.webauthn_require_user_verification,
            )
        except WebAuthnException as exc:
            logger.info("assertion_verification_failed", extra={"reason": type(exc).__name__})
            raise WebAuthnVerificationError() from exc
        return VerifiedAuthenticationData(
            credential_id=bytes_to_base64url(verified.credential_id),
            new_sign_count=verified.new_sign_count,
            user_handle=self._extract_user_handle(parsed),
            device_type=str(verified.credential_device_type.value),
            backed_up=verified.credential_backed_up,
        )

    # ------------------------------------------------------ идентификаторы
    @staticmethod
    def decode_credential_ids(credential_ids: Sequence[str]) -> list[bytes]:
        """Преобразует сохранённые base64url идентификаторы credential в байты."""
        return [base64url_to_bytes(credential_id) for credential_id in credential_ids]

    @staticmethod
    def _extract_user_handle(parsed: Any) -> bytes | None:
        """Возвращает user handle обнаруживаемого credential, если клиент его прислал."""
        user_handle = getattr(parsed, "user_handle", None)
        if user_handle is None:
            return None
        if isinstance(user_handle, bytes):
            return user_handle
        return base64url_to_bytes(str(user_handle))

    def extract_credential_id(self, credential: dict[str, Any]) -> str:
        """Возвращает base64url идентификатор credential из assertion.

        Сохранённый открытый ключ должен быть известен *до* проверки подписи,
        поэтому идентификатор читается из assertion заранее.

        Raises:
            InvalidCredentialError: полезная нагрузка не является assertion WebAuthn.
        """
        try:
            parsed = parse_authentication_credential_json(credential)
        except WebAuthnException as exc:
            raise InvalidCredentialError() from exc
        return bytes_to_base64url(parsed.raw_id)
