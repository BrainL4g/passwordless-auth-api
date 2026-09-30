"""Доменные исключения и единое тело HTTP-ошибки."""

from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import FastAPI, Query
from fastapi.testclient import TestClient

from src.utils.exceptions import (
    AccountDisabledError,
    AuthenticationFailedError,
    ChallengeNotFoundError,
    ConflictError,
    DomainError,
    ExpiredTokenError,
    InvalidCredentialError,
    InvalidRequestError,
    InvalidTokenError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitExceededError,
    ServiceUnavailableError,
    SignCounterMismatchError,
    UserAlreadyExistsError,
    WebAuthnVerificationError,
    register_exception_handlers,
)


def test_default_message_and_payload() -> None:
    error = NotFoundError()
    assert error.to_payload() == {"detail": "Resource not found", "code": "not_found"}
    assert NotFoundError("Device not found").to_payload()["detail"] == "Device not found"


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (ChallengeNotFoundError(), 400, "challenge_not_found"),
        (InvalidCredentialError(), 400, "invalid_credential"),
        (InvalidRequestError(), 400, "invalid_request"),
        (NotFoundError(), 404, "not_found"),
        (ConflictError(), 409, "conflict"),
        (UserAlreadyExistsError(), 409, "user_already_exists"),
        (WebAuthnVerificationError(), 401, "webauthn_verification_failed"),
        (InvalidTokenError(), 401, "invalid_token"),
        (ExpiredTokenError(), 401, "token_expired"),
        (AuthenticationFailedError(), 401, "authentication_failed"),
        (SignCounterMismatchError(), 401, "sign_count_mismatch"),
        (PermissionDeniedError(), 403, "forbidden"),
        (AccountDisabledError(), 403, "account_disabled"),
        (RateLimitExceededError(), 429, "rate_limited"),
        (ServiceUnavailableError(), 503, "service_unavailable"),
    ],
)
def test_error_mapping(error: DomainError, status: int, code: str) -> None:
    assert error.status_code == status
    assert error.code == code


def test_subclasses_inherit_status_codes() -> None:
    assert issubclass(ExpiredTokenError, InvalidTokenError)
    assert issubclass(UserAlreadyExistsError, ConflictError)


def _app_with_handlers() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    def boom() -> None:
        raise ConflictError("already there")

    @app.get("/unauthorized")
    def unauthorized() -> None:
        raise InvalidTokenError

    @app.get("/items")
    def items(limit: Annotated[int, Query(ge=1)] = 10) -> dict[str, int]:
        return {"limit": limit}

    return app


def test_domain_error_handler_returns_uniform_body() -> None:
    with TestClient(_app_with_handlers(), raise_server_exceptions=False) as client:
        response = client.get("/boom")
    assert response.status_code == 409
    assert response.json() == {"detail": "already there", "code": "conflict"}


def test_http_exception_handler_uses_uniform_body() -> None:
    with TestClient(_app_with_handlers(), raise_server_exceptions=False) as client:
        response = client.get("/missing")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found", "code": "not_found"}


def test_validation_error_is_reported_as_400() -> None:
    with TestClient(_app_with_handlers(), raise_server_exceptions=False) as client:
        response = client.get("/items?limit=0")
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "validation_error"
    assert "limit" in body["detail"]
