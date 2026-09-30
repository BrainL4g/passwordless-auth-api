"""Фабрика ASGI-приложения, middleware и служебные endpoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from src import __version__
from src.routers import admin_router, auth_router, devices_router, logs_router
from src.schemas.common import AssetLinkStatement, AssetLinkTarget, HealthResponse
from src.utils.config import Settings, get_settings
from src.utils.deps import AppSettings, DbSession
from src.utils.exceptions import ServiceUnavailableError, register_exception_handlers
from src.utils.logging_setup import configure_logging, get_logger

logger = get_logger(__name__)

settings: Settings = get_settings()
configure_logging(settings.log_level)

service_router = APIRouter(tags=["service"])


@service_router.get("/health", response_model=HealthResponse, summary="Проверка живости/готовности")
def health(session: DbSession) -> HealthResponse:
    """Возвращает 200, пока база данных отвечает, иначе 503."""
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        logger.warning("health_check_failed", extra={"reason": type(exc).__name__})
        raise ServiceUnavailableError("Database is not available") from exc
    return HealthResponse(
        status="ok", service=settings.app_name, version=__version__, database="ok"
    )


@service_router.get(
    "/.well-known/assetlinks.json",
    response_model=list[AssetLinkStatement],
    summary="Digital Asset Links для Android-клиента",
)
def assetlinks(app_settings: AppSettings) -> list[AssetLinkStatement]:
    """Отдавать файл Digital Asset Links, используемый Android Credential Manager."""
    if not app_settings.assetlinks_configured:
        logger.warning("assetlinks_not_configured")
        return []
    return [
        AssetLinkStatement(
            target=AssetLinkTarget(
                namespace="android_app",
                package_name=app_settings.android_package_name,
                sha256_cert_fingerprints=app_settings.android_cert_fingerprints,
            )
        )
    ]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Жизненный цикл приложения: настройка логирования и проверка конфигурации."""
    del app
    logger.info(
        "application_started",
        extra={
            "service": settings.app_name,
            "version": __version__,
            "environment": settings.environment,
            "rp_id": settings.rp_id,
            "challenge_store": settings.challenge_store,
        },
    )
    _warn_about_insecure_configuration(settings)
    yield
    logger.info("application_stopped")


def _warn_about_insecure_configuration(app_settings: Settings) -> None:
    """WebAuthn работает только в защищённом контексте.

    Предупреждаем о незащищённых http-источниках.
    """
    for origin in app_settings.allowed_origins:
        if origin.startswith("http://") and "localhost" not in origin and "127.0.0.1" not in origin:
            logger.warning("insecure_origin_configured", extra={"origin": origin})
    if app_settings.rp_id in {"localhost", "127.0.0.1"}:
        logger.warning(
            "development_rp_id_configured",
            extra={
                "rp_id": app_settings.rp_id,
                "hint": "use https and a real domain in production",
            },
        )
    if app_settings.web_concurrency > 1 and app_settings.challenge_store != "redis":
        logger.warning(
            "unsafe_worker_combination",
            extra={
                "web_concurrency": app_settings.web_concurrency,
                "hint": "several workers require a shared CHALLENGE_STORE=redis",
            },
        )


def create_app() -> FastAPI:
    """Собрать приложение FastAPI."""
    app = FastAPI(
        title="Passwordless Auth API",
        description=(
            "Бэкенд аутентификации WebAuthn / Passkeys. "
            "Клиенты: Android (Credential Manager) и Windows (Windows Hello)."
        ),
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )
    register_exception_handlers(app)
    app.include_router(service_router)
    app.include_router(auth_router)
    app.include_router(devices_router)
    app.include_router(admin_router)
    app.include_router(logs_router)
    return app


app = create_app()
