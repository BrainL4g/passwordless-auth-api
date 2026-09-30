"""WebAuthnService: граница с ``py_webauthn``.

Функции библиотеки заменяются заглушками, поэтому полезная нагрузка опций и
перевод ошибок можно проверять без настоящего аутентификатора.
"""

from __future__ import annotations

from typing import Any

import pytest
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from src.services import webauthn_service as module_under_test
from src.services.webauthn_service import SUPPORTED_ALGORITHMS, WebAuthnService
from src.utils.exceptions import InvalidCredentialError, WebAuthnVerificationError
from tests.conftest import test_settings

REGISTRATION_JSON: dict[str, Any] = {
    "id": "Y3JlZA",
    "rawId": "Y3JlZA",
    "type": "public-key",
    "response": {"clientDataJSON": "e30", "attestationObject": "o30"},
}
AUTHENTICATION_JSON: dict[str, Any] = {
    "id": "Y3JlZA",
    "rawId": "Y3JlZA",
    "type": "public-key",
    "response": {"clientDataJSON": "e30", "authenticatorData": "Y3JlZA", "signature": "c2ln"},
}


@pytest.fixture
def service() -> WebAuthnService:
    return WebAuthnService(test_settings)


def test_supported_algorithms_are_es256_and_rs256() -> None:
    assert SUPPORTED_ALGORITHMS == (
        COSEAlgorithmIdentifier.ECDSA_SHA_256,
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    )
    assert [int(algorithm) for algorithm in SUPPORTED_ALGORITHMS] == [-7, -257]


def test_build_registration_options_passes_expected_configuration(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_generate(**kwargs: Any) -> PublicKeyCredentialCreationOptions:
        captured.update(kwargs)
        return PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=kwargs["rp_id"], name=kwargs["rp_name"]),
            user=PublicKeyCredentialUserEntity(
                id=kwargs["user_id"], name=kwargs["user_name"], display_name="alice@example.com"
            ),
            challenge=kwargs["challenge"],
            pub_key_cred_params=[],
        )

    monkeypatch.setattr(module_under_test, "generate_registration_options", fake_generate)
    result = service.build_registration_options(
        challenge=b"challenge-bytes",
        user_id=b"user-handle",
        username="alice",
        email="alice@example.com",
        exclude_credential_ids=[b"excluded"],
    )

    assert result.challenge == b"challenge-bytes"
    # JSON в WebAuthn переносит двоичные значения в кодировке base64url.
    assert result.options["user"]["id"] == bytes_to_base64url(b"user-handle")
    assert result.options["challenge"] == bytes_to_base64url(b"challenge-bytes")
    assert captured["attestation"] == AttestationConveyancePreference.NONE
    assert captured["timeout"] == test_settings.webauthn_timeout_ms
    selection = captured["authenticator_selection"]
    assert selection.authenticator_attachment is not None
    assert selection.authenticator_attachment.value == "platform"
    assert selection.resident_key is not None
    assert selection.resident_key.value == "preferred"
    assert selection.user_verification is not None
    assert selection.user_verification.value == "required"
    assert [descriptor.id for descriptor in captured["exclude_credentials"]] == [b"excluded"]
    assert captured["supported_pub_key_algs"] == list(SUPPORTED_ALGORITHMS)


def test_build_authentication_options(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_generate(**kwargs: Any) -> PublicKeyCredentialRequestOptions:
        captured.update(kwargs)
        return PublicKeyCredentialRequestOptions(
            challenge=kwargs["challenge"],
            rp_id=kwargs["rp_id"],
            allow_credentials=kwargs["allow_credentials"],
        )

    monkeypatch.setattr(module_under_test, "generate_authentication_options", fake_generate)
    result = service.build_authentication_options(
        challenge=b"challenge", allow_credential_ids=[b"cred-1", b"cred-2"]
    )
    assert result.options["rpId"] == test_settings.rp_id
    assert [item["id"] for item in result.options["allowCredentials"]] == [
        bytes_to_base64url(b"cred-1"),
        bytes_to_base64url(b"cred-2"),
    ]
    assert result.options["userVerification"] == "preferred"  # дефолт заглушки-библиотеки
    assert captured["user_verification"].value == "required"
    assert captured["timeout"] == test_settings.webauthn_timeout_ms


def test_verify_registration_success(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class FakeVerified:
        credential_id = b"cred-1"
        credential_public_key = b"public-key"
        sign_count = 7
        aaguid = "aaguid"
        credential_device_type = type("T", (), {"value": "multiDevice"})()
        credential_backed_up = True

    def fake_verify(**kwargs: Any) -> FakeVerified:
        captured.update(kwargs)
        return FakeVerified()

    monkeypatch.setattr(module_under_test, "verify_registration_response", fake_verify)
    result = service.verify_registration(credential=REGISTRATION_JSON, expected_challenge=b"c")

    assert result.credential_id == "Y3JlZC0x"
    assert result.public_key == b"public-key"
    assert result.sign_count == 7
    assert result.device_type == "multiDevice"
    assert result.backed_up is True
    assert captured["expected_rp_id"] == test_settings.rp_id
    assert captured["expected_origin"] == test_settings.allowed_origins
    assert captured["require_user_verification"] is True
    assert captured["expected_challenge"] == b"c"
    assert captured["supported_pub_key_algs"] == list(SUPPORTED_ALGORITHMS)


def test_verify_registration_parse_error(service: WebAuthnService) -> None:
    with pytest.raises(InvalidCredentialError):
        service.verify_registration(credential={"id": "x"}, expected_challenge=b"c")


def test_verify_registration_verification_error(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_verify(**_: Any) -> None:
        raise InvalidRegistrationResponse("nope")

    monkeypatch.setattr(module_under_test, "verify_registration_response", fake_verify)
    with pytest.raises(WebAuthnVerificationError):
        service.verify_registration(credential=REGISTRATION_JSON, expected_challenge=b"c")


def test_verify_authentication_success(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class FakeVerified:
        credential_id = b"cred-1"
        new_sign_count = 5
        user_handle = None
        credential_device_type = type("T", (), {"value": "singleDevice"})()
        credential_backed_up = False

    def fake_verify(**kwargs: Any) -> FakeVerified:
        captured.update(kwargs)
        return FakeVerified()

    monkeypatch.setattr(module_under_test, "verify_authentication_response", fake_verify)
    result = service.verify_authentication(
        credential=AUTHENTICATION_JSON,
        expected_challenge=b"c",
        credential_public_key=b"pk",
        current_sign_count=3,
    )
    assert result.credential_id == "Y3JlZC0x"
    assert result.new_sign_count == 5
    assert result.user_handle is None
    assert captured["credential_public_key"] == b"pk"
    assert captured["credential_current_sign_count"] == 3
    assert captured["expected_origin"] == test_settings.allowed_origins


def test_verify_authentication_extracts_user_handle(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = b"user-handle"
    encoded = bytes_to_base64url(handle)
    response: dict[str, Any] = AUTHENTICATION_JSON["response"] | {"userHandle": encoded}
    raw: dict[str, Any] = AUTHENTICATION_JSON | {"response": response}

    class Parsed:
        user_handle = encoded

    class FakeVerified:
        credential_id = b"cred-1"
        new_sign_count = 0
        credential_device_type = type("T", (), {"value": "singleDevice"})()
        credential_backed_up = False

    monkeypatch.setattr(
        module_under_test, "parse_authentication_credential_json", lambda _: Parsed()
    )
    monkeypatch.setattr(
        module_under_test, "verify_authentication_response", lambda **_: FakeVerified()
    )
    result = service.verify_authentication(
        credential=raw, expected_challenge=b"c", credential_public_key=b"pk", current_sign_count=0
    )
    assert result.user_handle == handle


def test_verify_authentication_errors(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(InvalidCredentialError):
        service.verify_authentication(
            credential={"id": "x"},
            expected_challenge=b"c",
            credential_public_key=b"pk",
            current_sign_count=0,
        )

    def fake_verify(**_: Any) -> None:
        raise InvalidAuthenticationResponse("bad signature")

    monkeypatch.setattr(module_under_test, "verify_authentication_response", fake_verify)
    with pytest.raises(WebAuthnVerificationError):
        service.verify_authentication(
            credential=AUTHENTICATION_JSON,
            expected_challenge=b"c",
            credential_public_key=b"pk",
            current_sign_count=0,
        )


def test_extract_credential_id(service: WebAuthnService) -> None:
    assert service.extract_credential_id(AUTHENTICATION_JSON) == "Y3JlZA"
    with pytest.raises(InvalidCredentialError):
        service.extract_credential_id({"nope": True})


def test_parse_errors_of_the_library_are_translated(
    service: WebAuthnService, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_: Any) -> None:
        raise InvalidJSONStructure("bad json")

    monkeypatch.setattr(module_under_test, "parse_registration_credential_json", boom)
    with pytest.raises(InvalidCredentialError):
        service.verify_registration(credential=REGISTRATION_JSON, expected_challenge=b"c")
