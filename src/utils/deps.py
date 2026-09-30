"""Связывание зависимостей FastAPI (единственное место, где собираются слои).

Роутеры получают отсюда всё необходимое; они никогда не импортируют напрямую
репозитории или модели SQLAlchemy.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.database import SessionLocal
from src.models.user import User
from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.protocols import (
    AuthLogRepository,
    CredentialRepository,
    DeviceRepository,
    TransactionManager,
    UserRepository,
)
from src.repositories.transaction import SqlAlchemyTransactionManager
from src.repositories.user import SqlAlchemyUserRepository
from src.services.admin_service import AdminService
from src.services.audit import AuditLogger
from src.services.auth_service import AuthService
from src.services.challenge_store import (
    ChallengeStore,
    InMemoryChallengeStore,
    RedisChallengeStore,
)
from src.services.device_service import DeviceService
from src.services.dto import RequestContext
from src.services.log_service import LogService
from src.services.security_service import SecurityService
from src.services.webauthn_service import WebAuthnService
from src.utils.config import Settings, get_settings
from src.utils.exceptions import AccountDisabledError, InvalidTokenError, PermissionDeniedError
from src.utils.logging_setup import get_logger
from src.utils.rate_limit import InMemoryRateLimiter, NoopRateLimiter, RateLimiter

logger = get_logger(__name__)

bearer_scheme = HTTPBearer(
    auto_error=False, description="JWT access token, выданный эндпоинтом /auth"
)


# ------------------------------------------------------------------- настройки
@lru_cache(maxsize=1)
def cached_settings() -> Settings:
    """Общепроцессный синглтон настроек."""
    return get_settings()


# -------------------------------------------------------------- база данных
def get_db() -> Iterator[Session]:
    """Предоставляет SQLAlchemy-сессию в рамках одного запроса."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(cached_settings)]


# --------------------------------------------------------------- репозитории
def get_user_repository(session: DbSession) -> UserRepository:
    """Создаёт репозиторий пользователей для текущего запроса."""
    return SqlAlchemyUserRepository(session)


def get_device_repository(session: DbSession) -> DeviceRepository:
    """Создаёт репозиторий устройств для текущего запроса."""
    return SqlAlchemyDeviceRepository(session)


def get_credential_repository(session: DbSession) -> CredentialRepository:
    """Создаёт репозиторий учётных данных для текущего запроса."""
    return SqlAlchemyCredentialRepository(session)


def get_auth_log_repository(session: DbSession) -> AuthLogRepository:
    """Создаёт репозиторий журнала аудита для текущего запроса."""
    return SqlAlchemyAuthLogRepository(session)


def get_transaction_manager(session: DbSession) -> TransactionManager:
    """Создаёт unit of work, привязанный к сессии запроса."""
    return SqlAlchemyTransactionManager(session)


UserRepo = Annotated[UserRepository, Depends(get_user_repository)]
DeviceRepo = Annotated[DeviceRepository, Depends(get_device_repository)]
CredentialRepo = Annotated[CredentialRepository, Depends(get_credential_repository)]
AuthLogRepo = Annotated[AuthLogRepository, Depends(get_auth_log_repository)]
Transaction = Annotated[TransactionManager, Depends(get_transaction_manager)]


# ---------------------------------------------------- хранилище челленджей
@lru_cache(maxsize=4)
def _build_challenge_store(store: str, cleanup_interval: int, redis_url: str) -> ChallengeStore:
    """Создаёт общепроцессное хранилище челленджей (кеш по конфигурации)."""
    if store == "redis":
        logger.info("challenge_store_initialised", extra={"store": "redis"})
        return RedisChallengeStore.from_url(redis_url)
    logger.info("challenge_store_initialised", extra={"store": "memory"})
    return InMemoryChallengeStore(cleanup_interval_seconds=cleanup_interval)


def get_challenge_store(settings: AppSettings) -> ChallengeStore:
    """Возвращает настроенное хранилище челленджей (точка внедрения зависимости)."""
    return _build_challenge_store(
        settings.challenge_store,
        settings.challenge_cleanup_interval_seconds,
        settings.redis_url,
    )


ChallengeStoreDep = Annotated[ChallengeStore, Depends(get_challenge_store)]


# -------------------------------------------------------------------- сервисы
def get_webauthn_service(settings: AppSettings) -> WebAuthnService:
    """Создаёт сервис протокола WebAuthn."""
    return WebAuthnService(settings)


def get_security_service(settings: AppSettings) -> SecurityService:
    """Создаёт сервис JWT."""
    return SecurityService(settings)


def get_audit_logger(logs: AuthLogRepo, transaction: Transaction) -> AuditLogger:
    """Создаёт писатель аудита."""
    return AuditLogger(logs=logs, transaction=transaction)


def get_auth_service(
    users: UserRepo,
    devices: DeviceRepo,
    credentials: CredentialRepo,
    logs: AuthLogRepo,
    transaction: Transaction,
    audit: Annotated[AuditLogger, Depends(get_audit_logger)],
    challenges: ChallengeStoreDep,
    settings: AppSettings,
    webauthn: Annotated[WebAuthnService, Depends(get_webauthn_service)],
    security: Annotated[SecurityService, Depends(get_security_service)],
) -> AuthService:
    """Собирает сервис аутентификации."""
    return AuthService(
        users=users,
        devices=devices,
        credentials=credentials,
        logs=logs,
        webauthn=webauthn,
        security=security,
        challenges=challenges,
        transaction=transaction,
        audit=audit,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        user_handle_length=settings.user_handle_length,
    )


def get_device_service(
    devices: DeviceRepo,
    credentials: CredentialRepo,
    logs: AuthLogRepo,
    transaction: Transaction,
    audit: Annotated[AuditLogger, Depends(get_audit_logger)],
    challenges: ChallengeStoreDep,
    settings: AppSettings,
    webauthn: Annotated[WebAuthnService, Depends(get_webauthn_service)],
) -> DeviceService:
    """Собирает сервис устройств."""
    return DeviceService(
        devices=devices,
        credentials=credentials,
        logs=logs,
        webauthn=webauthn,
        challenges=challenges,
        transaction=transaction,
        audit=audit,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
    )


def get_admin_service(
    users: UserRepo,
    devices: DeviceRepo,
    logs: AuthLogRepo,
    transaction: Transaction,
    audit: Annotated[AuditLogger, Depends(get_audit_logger)],
) -> AdminService:
    """Собирает административный сервис."""
    return AdminService(
        users=users, devices=devices, logs=logs, transaction=transaction, audit=audit
    )


def get_log_service(logs: AuthLogRepo) -> LogService:
    """Собирает сервис журнала аудита."""
    return LogService(logs=logs)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
DeviceServiceDep = Annotated[DeviceService, Depends(get_device_service)]
AdminServiceDep = Annotated[AdminService, Depends(get_admin_service)]
LogServiceDep = Annotated[LogService, Depends(get_log_service)]


# --------------------------------------------------------- метаданные запроса
def get_request_context(request: Request) -> RequestContext:
    """Извлекает адрес клиента и user agent для журнала аудита."""
    client = request.client
    return RequestContext(
        ip_address=client.host if client else None,
        user_agent=request.headers.get("user-agent"),
    )


RequestCtx = Annotated[RequestContext, Depends(get_request_context)]


# -------------------------------------------------------- ограничение частоты
@lru_cache(maxsize=4)
def _build_rate_limiter(enabled: bool, max_requests: int, window: int) -> RateLimiter:
    """Создаёт общепроцессный ограничитель частоты (кеш по конфигурации)."""
    if not enabled:
        logger.info("rate_limit_disabled")
        return NoopRateLimiter()
    logger.info("rate_limit_initialised", extra={"max_requests": max_requests, "window": window})
    return InMemoryRateLimiter(max_requests=max_requests, window_seconds=window)


def get_rate_limiter(settings: AppSettings) -> RateLimiter:
    """Возвращает общепроцессный ограничитель частоты."""
    return _build_rate_limiter(
        settings.rate_limit_enabled,
        settings.rate_limit_max_requests,
        settings.rate_limit_window_seconds,
    )


def enforce_rate_limit(
    request: Request,
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> None:
    """Расходует один слот лимита на пару «IP-адрес клиента + маршрут»."""
    client = request.client
    key = f"{client.host if client else 'unknown'}:{request.url.path}"
    limiter.check(key)


RateLimit = Depends(enforce_rate_limit)


# ----------------------------------------------------------- аутентификация
def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: DbSession,
    security: Annotated[SecurityService, Depends(get_security_service)],
    users: UserRepo,
) -> User:
    """Определяет аутентифицированную учётную запись по bearer token."""
    if credentials is None or not credentials.credentials:
        raise InvalidTokenError("Authorization header with a bearer token is required")
    user_id = security.decode_access_token(credentials.credentials)
    user = users.get_by_id(user_id)
    if user is None:
        raise InvalidTokenError("Account no longer exists")
    if not user.is_active:
        raise AccountDisabledError()
    return user


def get_current_admin(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Проверяет, что аутентифицированная учётная запись является администратором."""
    if not user.is_admin:
        raise PermissionDeniedError()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentAdmin = Annotated[User, Depends(get_current_admin)]
