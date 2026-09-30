"""Настройки приложения, загружаемые из окружения / файла ``.env``.

Любое значение можно передать через переменную окружения с таким же именем
(без учёта регистра).  Сложные значения (списки) принимают либо JSON-массив
(``["a","b"]``), либо строку с разделителями-запятыми (``a,b``), что сохраняет
читаемость файлов ``docker-compose``.

Значения, связанные с безопасностью (``SECRET_KEY``, ``DATABASE_URL``, ``RP_ID``,
``ALLOWED_ORIGINS``), намеренно **не** имеют значений по умолчанию: процесс
отказывается запускаться, если они не переданы явно.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: Any) -> Any:
    """Приводит необработанное значение из окружения к списку строк.

    Принимает ``None`` (возвращает ``None``, чтобы Pydantic подставил значение
    по умолчанию), уже декодированный ``list``/``tuple``, а также необработанные
    строки в формате JSON или CSV.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value]
    if not isinstance(value, str):
        return value
    raw = value.strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            # Значение в скобках, не являющееся корректным JSON, трактуется как CSV.
            return [item.strip() for item in raw.strip("[]").split(",") if item.strip()]
        # Корректный JSON, начинающийся с "[", всегда декодируется в список.
        return [str(item).strip() for item in decoded]
    return [item.strip() for item in raw.split(",") if item.strip()]


CsvStrList = Annotated[list[str], NoDecode, BeforeValidator(_split_csv)]


class Settings(BaseSettings):
    """Типизированная конфигурация приложения."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------- приложение
    app_name: str = "passwordless-auth-api"
    app_version: str = "1.0.0"
    environment: Literal["local", "staging", "production"] = "local"
    debug: bool = False
    log_level: str = "INFO"
    web_concurrency: int = Field(default=1, ge=1, le=64)

    # --------------------------------------------------------- база данных
    database_url: str = Field(min_length=1)
    database_echo: bool = False
    database_pool_size: int = Field(default=5, ge=1, le=100)
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    database_pool_timeout_seconds: int = Field(default=30, ge=1, le=300)

    # ---------------------------------------------------------- безопасность
    secret_key: str = Field(min_length=32)
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=60, ge=1, le=60 * 24 * 30)

    # ------------------------------------------------------------------ cors
    cors_origins: CsvStrList = []
    cors_allow_credentials: bool = False
    cors_allow_methods: CsvStrList = ["GET", "POST", "DELETE", "OPTIONS"]
    cors_allow_headers: CsvStrList = ["Authorization", "Content-Type"]

    # -------------------------------------------------------------- webauthn
    rp_id: str = Field(min_length=1)
    rp_name: str = "Passwordless Auth API"
    allowed_origins: CsvStrList = Field(min_length=1)
    webauthn_timeout_ms: int = Field(default=300_000, ge=30_000, le=600_000)
    webauthn_require_user_verification: bool = True
    user_handle_length: int = Field(default=32, ge=16, le=64)

    # ------------------------------------------------------------- челленджи
    challenge_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    challenge_cleanup_interval_seconds: int = Field(default=60, ge=1, le=3600)
    challenge_store: Literal["memory", "redis"] = "memory"
    redis_url: str = "redis://localhost:6379/0"

    # ------------------------------------------------------- лимиты запросов
    rate_limit_enabled: bool = True
    rate_limit_max_requests: int = Field(default=30, ge=1, le=10_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)

    # ------------------------------------------------------ android assetlinks
    android_package_name: str = ""
    android_cert_fingerprints: CsvStrList = []

    @field_validator("rp_id")
    @classmethod
    def _validate_rp_id(cls, value: str) -> str:
        """RP ID должен быть «голым» доменом (без схемы, порта и пути)."""
        candidate = value.strip()
        if not candidate or "://" in candidate or "/" in candidate or ":" in candidate:
            raise ValueError(
                "RP_ID must be a bare domain without scheme, port or path, e.g. 'example.com'"
            )
        return candidate

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        if level not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return level

    @property
    def access_token_expire_seconds(self) -> int:
        """Время жизни access token в секундах."""
        return self.access_token_expire_minutes * 60

    @property
    def web_allowed_origins(self) -> list[str]:
        """Настроенные источники, являющиеся обычными web-источниками (используются CORS)."""
        return [origin for origin in self.allowed_origins if origin.startswith("http")]

    @property
    def android_origins(self) -> list[str]:
        """Настроенные источники вида ``android:apk-key-hash:``."""
        return [origin for origin in self.allowed_origins if origin.startswith("android:")]

    @property
    def assetlinks_configured(self) -> bool:
        """Можно ли отдавать Digital Asset Links."""
        return bool(self.android_package_name) and bool(self.android_cert_fingerprints)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Возвращает общепроцессный кешированный объект настроек.

    Четыре значения, связанных с безопасностью, не имеют значений по умолчанию,
    поэтому конструктор можно удовлетворить только из окружения / файла ``.env``.
    """
    return Settings()  # type: ignore[call-arg]
