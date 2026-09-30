"""Разбор и валидация Settings."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from src.utils.config import Settings, _split_csv, get_settings
from tests.conftest import build_settings

BASE: dict[str, object] = {
    "database_url": "postgresql+psycopg://user:pass@localhost/db",
    "secret_key": "x" * 32,
    "rp_id": "example.com",
    "allowed_origins": ["https://example.com"],
}

#: Все поля :class:`Settings` - они не должны просачиваться из окружения
#: процесса (``tests/conftest.py`` экспортирует часть из них) в вызов
#: ``Settings(**payload)``, который хочет передать только свои kwargs.
SETTINGS_ENV_VARS = tuple(name for name in os.environ if name.replace("-", "_").isupper()) + tuple(
    field.upper() for field in Settings.model_fields if field.upper() not in os.environ
)


@pytest.fixture(autouse=True)
def isolated_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Убирает все входные данные ``Settings`` из окружения и из ``.env``."""
    for name in SETTINGS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_required_values_have_no_defaults() -> None:
    for missing in ("database_url", "secret_key", "rp_id", "allowed_origins"):
        payload = dict(BASE)
        payload.pop(missing)
        with pytest.raises(ValidationError):
            build_settings(**payload)


@pytest.mark.parametrize("missing", ["database_url", "secret_key", "rp_id", "allowed_origins"])
def test_missing_setting_raises(missing: str) -> None:
    payload = {key: value for key, value in BASE.items() if key != missing}
    with pytest.raises(ValidationError) as exc_info:
        build_settings(**payload)
    assert missing in str(exc_info.value)


def test_short_secret_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_settings(**{**BASE, "secret_key": "too-short"})


@pytest.mark.parametrize(
    "bad_rp_id", ["https://example.com", "example.com:8443", "example.com/app"]
)
def test_rp_id_must_be_bare_domain(bad_rp_id: str) -> None:
    with pytest.raises(ValidationError):
        build_settings(**{**BASE, "rp_id": bad_rp_id})


def test_rp_id_is_stripped() -> None:
    assert build_settings(**{**BASE, "rp_id": " example.com "}).rp_id == "example.com"


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_settings(**{**BASE, "log_level": "TRACE"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('["a", "b"]', ["a", "b"]),
        ("a,b", ["a", "b"]),
        (" a , b ,, ", ["a", "b"]),
        ("", []),
        (["x"], ["x"]),
        (None, None),
    ],
)
def test_split_csv(raw: object, expected: object) -> None:
    assert _split_csv(raw) == expected


def test_split_csv_falls_back_to_csv_for_broken_json() -> None:
    assert _split_csv("[a, b") == ["a", "b"]


def test_list_settings_accept_csv_string() -> None:
    settings = build_settings(
        **{
            **BASE,
            "allowed_origins": "https://a.example,android:apk-key-hash:AAA",
            "cors_origins": "https://a.example",
        }
    )
    assert settings.allowed_origins == ["https://a.example", "android:apk-key-hash:AAA"]
    assert settings.web_allowed_origins == ["https://a.example"]
    assert settings.android_origins == ["android:apk-key-hash:AAA"]


def test_derived_properties() -> None:
    settings = build_settings(**{**BASE, "access_token_expire_minutes": 15})
    assert settings.access_token_expire_seconds == 900


def test_assetlinks_configured_flag() -> None:
    without = build_settings(**BASE)
    assert without.assetlinks_configured is False
    with_pkg = build_settings(
        **{
            **BASE,
            "android_package_name": "com.example.app",
            "android_cert_fingerprints": ["AAA"],
        }
    )
    assert with_pkg.assetlinks_configured is True


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
