"""Доменные исключения и единственный обработчик исключений FastAPI.

Сервисы никогда не импортируют FastAPI: они выбрасывают доменные ошибки,
определённые здесь, а обработчик, установленный в :mod:`src.main`, преобразует
их в единообразное тело ошибки ``{"detail": "...", "code": "..."}``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.utils.logging_setup import get_logger

logger = get_logger(__name__)


class DomainError(Exception):
    """Базовый класс для всех бизнес-ошибок, выбрасываемых слоем сервисов.

    Attributes:
        code: стабильный машинночитаемый код ошибки, возвращаемый клиентам.
        status_code: HTTP-статус, используемый обработчиком исключений.
        message: читаемое человеком описание, не содержащее секретов.
    """

    code: str = "domain_error"
    status_code: int = 400
    default_message: str = "Request could not be processed"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)

    def to_payload(self) -> dict[str, Any]:
        """Формирует единообразное тело ошибки."""
        return {"detail": self.message, "code": self.code}


class InvalidRequestError(DomainError):
    """Входные данные прошли валидацию, но неприемлемы для операции."""

    code = "invalid_request"
    status_code = 400
    default_message = "Invalid request"


class NotFoundError(DomainError):
    """Запрошенная сущность не существует (или не видна вызывающему)."""

    code = "not_found"
    status_code = 404
    default_message = "Resource not found"


class ConflictError(DomainError):
    """Сущность с такой же уникальной идентичностью уже существует."""

    code = "conflict"
    status_code = 409
    default_message = "Resource already exists"


class UserAlreadyExistsError(ConflictError):
    """Имя пользователя или e-mail уже заняты."""

    code = "user_already_exists"
    default_message = "Username or email is already registered"


class CredentialAlreadyExistsError(ConflictError):
    """Учётные данные аутентификатора уже привязаны к учётной записи."""

    code = "credential_already_exists"
    default_message = "Credential is already registered"


class ChallengeNotFoundError(InvalidRequestError):
    """Челлендж неизвестен, уже использован (одноразовый) или истёк."""

    code = "challenge_not_found"
    default_message = "Challenge not found, expired or already used"


class ChallengeOperationMismatchError(InvalidRequestError):
    """Челлендж был выдан для другой церемонии."""

    code = "challenge_operation_mismatch"
    default_message = "Challenge was issued for a different operation"


class InvalidCredentialError(InvalidRequestError):
    """Не удалось разобрать полезную нагрузку учётных данных WebAuthn."""

    code = "invalid_credential"
    default_message = "Invalid WebAuthn credential payload"


class WebAuthnVerificationError(DomainError):
    """Не удалось проверить attestation/assertion."""

    code = "webauthn_verification_failed"
    status_code = 401
    default_message = "WebAuthn verification failed"


class InvalidTokenError(DomainError):
    """JWT отсутствует, имеет некорректный формат или неожиданную подпись."""

    code = "invalid_token"
    status_code = 401
    default_message = "Invalid or missing access token"


class ExpiredTokenError(InvalidTokenError):
    """Поле JWT ``exp`` находится в прошлом."""

    code = "token_expired"
    default_message = "Access token has expired"


class AuthenticationFailedError(DomainError):
    """Общая ошибка аутентификации.

    Сообщение намеренно расплывчатое: оно не должно раскрывать, существует ли
    имя пользователя, заблокирована ли учётная запись или у неё просто нет
    зарегистрированного passkey.
    """

    code = "authentication_failed"
    status_code = 401
    default_message = "Authentication failed"


class SignCounterMismatchError(DomainError):
    """Счётчик подписей аутентификатора уменьшился (возможен клон устройства)."""

    code = "sign_count_mismatch"
    status_code = 401
    default_message = "Authentication failed"


class PermissionDeniedError(DomainError):
    """У аутентифицированной сущности нет требуемой роли."""

    code = "forbidden"
    status_code = 403
    default_message = "Administrator privileges are required"


class AccountDisabledError(DomainError):
    """Учётная запись отключена администратором."""

    code = "account_disabled"
    status_code = 403
    default_message = "Account is disabled"


class RateLimitExceededError(DomainError):
    """Слишком много запросов от одного и того же клиента."""

    code = "rate_limited"
    status_code = 429
    default_message = "Too many requests, please retry later"


class ServiceUnavailableError(DomainError):
    """Зависимость (база данных) недоступна."""

    code = "service_unavailable"
    status_code = 503
    default_message = "Service temporarily unavailable"


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


async def domain_error_handler(_: Request, exc: Exception) -> JSONResponse:
    """Преобразует :class:`DomainError` в HTTP-ответ."""
    assert isinstance(exc, DomainError)  # noqa: S101 - сужение типа для тайпчекеров
    return _error_response(exc.status_code, exc.message, exc.code)


async def validation_error_handler(_: Request, exc: Exception) -> JSONResponse:
    """Преобразует ошибки валидации запроса Pydantic/FastAPI в HTTP 400."""
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    errors = exc.errors()
    first = errors[0] if errors else {}
    location = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
    message = str(first.get("msg", "Request validation failed"))
    detail = f"{location}: {message}" if location else message
    # ``message`` — зарезервированный атрибут ``LogRecord``: его передача через
    # ``extra`` привела бы к ``KeyError`` и превратила 400 в 500.
    logger.info("request_validation_failed", extra={"field": location, "reason": message})
    return _error_response(400, detail, "validation_error")


async def http_error_handler(_: Request, exc: Exception) -> JSONResponse:
    """Преобразует HTTP-исключения Starlette/FastAPI в единообразное тело."""
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101
    codes: dict[int, str] = {
        400: "invalid_request",
        401: "invalid_token",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        429: "rate_limited",
    }
    detail = exc.detail if isinstance(exc.detail, str) else "Request could not be processed"
    return _error_response(exc.status_code, detail, codes.get(exc.status_code, "http_error"))


def register_exception_handlers(app: FastAPI) -> None:
    """Устанавливает в приложении единообразные обработчики ошибок."""
    # FastAPI типизирует обработчик как ``Callable[[Request, Exception], Response]``,
    # тогда как каждый обработчик ниже сужен до собственного типа исключения.
    handlers: tuple[tuple[type[Exception], Callable[..., Any]], ...] = (
        (DomainError, domain_error_handler),
        (RequestValidationError, validation_error_handler),
        (StarletteHTTPException, http_error_handler),
    )
    for exception_type, handler in handlers:
        app.add_exception_handler(exception_type, handler)
