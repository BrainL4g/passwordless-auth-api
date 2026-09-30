"""Тестовые двойники, размещённые на границах приложения."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from src.services.webauthn_service import (
    AuthenticationOptionsData,
    RegistrationOptionsData,
    VerifiedAuthenticationData,
    VerifiedRegistrationData,
)
from src.utils.exceptions import InvalidCredentialError, WebAuthnVerificationError

REGISTRATION_CREDENTIAL_ID = "Y3JlZC1hYmM"  # base64url от b"cred-abc"
AUTHENTICATION_CREDENTIAL_ID = REGISTRATION_CREDENTIAL_ID
PUBLIC_KEY = b"fake-cose-public-key"


class FakeWebAuthnService:
    """Замена :class:`WebAuthnService`, которая никогда не обращается к аутентификатору.

    Она записывает опции, которые её попросили собрать, чтобы тесты могли
    повторить выданный challenge, и возвращает настраиваемые результаты
    проверки.
    """

    def __init__(self) -> None:
        self.registration_calls: list[dict[str, Any]] = []
        self.authentication_calls: list[dict[str, Any]] = []
        self.extracted_credential_ids: list[str] = []
        self.issued_challenges: list[bytes] = []
        self.registration_result = VerifiedRegistrationData(
            credential_id=REGISTRATION_CREDENTIAL_ID,
            public_key=PUBLIC_KEY,
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            device_type="singleDevice",
            backed_up=False,
        )
        self.authentication_result = VerifiedAuthenticationData(
            credential_id=AUTHENTICATION_CREDENTIAL_ID,
            new_sign_count=0,
            user_handle=None,
            device_type="singleDevice",
            backed_up=False,
        )
        self.registration_error: Exception | None = None
        self.authentication_error: Exception | None = None
        self.parse_error: Exception | None = None

    # ----------------------------------------------------------- опции
    def build_registration_options(
        self,
        *,
        challenge: bytes,
        user_id: bytes,
        username: str,
        email: str,
        exclude_credential_ids: Sequence[bytes] = (),
    ) -> RegistrationOptionsData:
        self.registration_calls.append(
            {
                "challenge": challenge,
                "user_id": user_id,
                "username": username,
                "email": email,
                "exclude_credential_ids": list(exclude_credential_ids),
            }
        )
        self.issued_challenges.append(challenge)
        return RegistrationOptionsData(
            options={
                "rp": {"id": "localhost", "name": "Test RP"},
                "user": {
                    "id": bytes_to_base64url(user_id),
                    "name": username,
                    "displayName": email,
                },
                "challenge": bytes_to_base64url(challenge),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "residentKey": "preferred",
                    "userVerification": "required",
                },
                "attestation": "none",
                "excludeCredentials": [
                    {"id": bytes_to_base64url(value), "type": "public-key"}
                    for value in exclude_credential_ids
                ],
            },
            challenge=challenge,
        )

    def build_authentication_options(
        self,
        *,
        challenge: bytes,
        allow_credential_ids: Sequence[bytes] = (),
    ) -> AuthenticationOptionsData:
        self.issued_challenges.append(challenge)
        return AuthenticationOptionsData(
            options={
                "challenge": bytes_to_base64url(challenge),
                "rpId": "localhost",
                "userVerification": "required",
                "allowCredentials": [
                    {"id": bytes_to_base64url(value), "type": "public-key"}
                    for value in allow_credential_ids
                ],
            },
            challenge=challenge,
        )

    # --------------------------------------------------- проверка
    def verify_registration(
        self, *, credential: dict[str, Any], expected_challenge: bytes
    ) -> VerifiedRegistrationData:
        if self.registration_error is not None:
            raise self.registration_error
        return self.registration_result

    def verify_authentication(
        self,
        *,
        credential: dict[str, Any],
        expected_challenge: bytes,
        credential_public_key: bytes,
        current_sign_count: int,
    ) -> VerifiedAuthenticationData:
        if self.authentication_error is not None:
            raise self.authentication_error
        self.authentication_calls.append(
            {
                "credential": credential,
                "expected_challenge": expected_challenge,
                "credential_public_key": credential_public_key,
                "current_sign_count": current_sign_count,
            }
        )
        return self.authentication_result

    def extract_credential_id(self, credential: dict[str, Any]) -> str:
        if self.parse_error is not None:
            raise self.parse_error
        return self.authentication_result.credential_id

    @staticmethod
    def decode_credential_ids(credential_ids: Sequence[str]) -> list[bytes]:
        return [base64url_to_bytes(credential_id) for credential_id in credential_ids]


class FakeRedisClient:
    """Минимальная внутрипроцессная замена клиента redis (с учётом ``GETDEL``/TTL)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.closed = False

    def set(self, name: str, value: str, ex: int, nx: bool) -> bool:
        if nx and name in self.store:
            return False
        self.store[name] = value
        self.ttl[name] = ex
        return True

    def getdel(self, name: str) -> str | None:
        return self.store.pop(name, None)

    def delete(self, *names: str) -> int:
        removed = 0
        for name in names:
            if self.store.pop(name, None) is not None:
                removed += 1
        return removed

    def keys(self, pattern: str) -> list[str]:
        prefix = pattern.rstrip("*")
        return [name for name in self.store if name.startswith(prefix)]

    def close(self) -> None:
        self.closed = True


def registration_payload(credential_id: str = REGISTRATION_CREDENTIAL_ID) -> dict[str, Any]:
    """Структурно корректный ``PublicKeyCredential`` для регистрации."""
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            "attestationObject": "o2NmbXRkbm9uZQ",
        },
    }


def authentication_payload(credential_id: str = AUTHENTICATION_CREDENTIAL_ID) -> dict[str, Any]:
    """Структурно корректный ``PublicKeyCredential`` для аутентификации."""
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
            "signature": "MEUC",
            "userHandle": None,
        },
    }


__all__ = [
    "AUTHENTICATION_CREDENTIAL_ID",
    "FakeRedisClient",
    "FakeWebAuthnService",
    "PUBLIC_KEY",
    "REGISTRATION_CREDENTIAL_ID",
    "InvalidCredentialError",
    "WebAuthnVerificationError",
    "authentication_payload",
    "registration_payload",
]
