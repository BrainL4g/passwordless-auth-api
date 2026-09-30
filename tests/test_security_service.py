"""Выпуск и проверка JWT."""

from __future__ import annotations

import time

import jwt
import pytest

from src.services.security_service import SecurityService
from src.utils.exceptions import ExpiredTokenError, InvalidTokenError
from tests.conftest import test_settings


@pytest.fixture
def service() -> SecurityService:
    return SecurityService(test_settings)


def test_expires_in_matches_configuration(service: SecurityService) -> None:
    assert service.expires_in == test_settings.access_token_expire_seconds == 1800


def test_token_contains_sub_iat_exp(service: SecurityService) -> None:
    token = service.create_access_token(42)
    assert token.token_type == "bearer"
    assert token.expires_in == 1800
    payload = jwt.decode(
        token.access_token,
        test_settings.secret_key,
        algorithms=["HS256"],
        options={"require": ["exp", "iat", "sub"]},
    )
    assert payload["sub"] == "42"
    assert set(payload) == {"sub", "iat", "exp"}


def test_round_trip(service: SecurityService) -> None:
    assert service.decode_access_token(service.create_access_token(7).access_token) == 7


def test_expired_token(service: SecurityService) -> None:
    token = jwt.encode(
        {"sub": "1", "iat": int(time.time()) - 100, "exp": int(time.time()) - 10},
        test_settings.secret_key,
        algorithm="HS256",
    )
    with pytest.raises(ExpiredTokenError):
        service.decode_access_token(token)


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        "",
        "a.b.c",
    ],
)
def test_malformed_token(service: SecurityService, token: str) -> None:
    with pytest.raises(InvalidTokenError):
        service.decode_access_token(token)


def test_token_signed_with_another_secret(service: SecurityService) -> None:
    token = jwt.encode({"sub": "1", "iat": 1, "exp": 9999999999}, "another" * 8, algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        service.decode_access_token(token)


def test_token_alg_none_is_rejected(service: SecurityService) -> None:
    token = jwt.encode({"sub": "1", "iat": 1, "exp": 9999999999}, key="", algorithm="none")
    with pytest.raises(InvalidTokenError):
        service.decode_access_token(token)


def test_missing_claims_are_rejected(service: SecurityService) -> None:
    token = jwt.encode({"sub": "1"}, test_settings.secret_key, algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        service.decode_access_token(token)


def test_non_numeric_subject_is_rejected(service: SecurityService) -> None:
    token = jwt.encode(
        {"sub": "not-a-number", "iat": 1, "exp": 9999999999},
        test_settings.secret_key,
        algorithm="HS256",
    )
    with pytest.raises(InvalidTokenError):
        service.decode_access_token(token)
