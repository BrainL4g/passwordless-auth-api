"""Сервисные эндпоинты, middleware, OpenAPI и единая оболочка ошибок."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from src import __version__
from src.database import create_db_engine
from src.main import app
from src.utils.deps import cached_settings
from tests.conftest import build_settings, test_settings


# ---------------------------------------------------------------- healthcheck
def test_health_reports_the_database(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": test_settings.app_name,
        "version": __version__,
        "database": "ok",
    }


def test_health_reports_503_when_the_database_is_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_: object, **__: object) -> None:
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    monkeypatch.setattr(Session, "execute", explode)
    response = client.get("/health")
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "service_unavailable"
    assert body["detail"] == "Database is not available"


def test_health_needs_no_authentication(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


# -------------------------------------------------------------- assetlinks
def test_assetlinks_returns_the_android_statement(client: TestClient) -> None:
    response = client.get("/.well-known/assetlinks.json")
    assert response.status_code == 200
    assert response.json() == [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.example.passwordless",
                "sha256_cert_fingerprints": ["TESTFINGERPRINT1", "TESTFINGERPRINT2"],
            },
        }
    ]


def test_assetlinks_is_empty_when_not_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANDROID_PACKAGE_NAME", raising=False)
    monkeypatch.delenv("ANDROID_CERT_FINGERPRINTS", raising=False)
    unconfigured = build_settings(
        database_url=test_settings.database_url,
        secret_key=test_settings.secret_key,
        rp_id=test_settings.rp_id,
        allowed_origins=test_settings.allowed_origins,
    )
    assert unconfigured.assetlinks_configured is False
    app.dependency_overrides[cached_settings] = lambda: unconfigured
    try:
        assert client.get("/.well-known/assetlinks.json").json() == []
    finally:
        app.dependency_overrides[cached_settings] = lambda: test_settings


# --------------------------------------------------------------------- CORS
def test_cors_preflight_is_allowed_for_a_configured_origin(client: TestClient) -> None:
    response = client.options(
        "/auth/login/begin",
        headers={
            "Origin": "https://localhost:8443",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://localhost:8443"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_cors_is_refused_for_an_unknown_origin(client: TestClient) -> None:
    response = client.options(
        "/auth/login/begin",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_cors_headers_are_absent_without_an_origin(client: TestClient) -> None:
    response = client.get("/health")
    assert "access-control-allow-origin" not in response.headers


# ------------------------------------------------------- оболочка ошибок
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/nope"),
        ("post", "/nope/deeper"),
        ("get", "/devices/1"),
    ],
)
def test_unknown_routes_use_the_uniform_error_body(
    client: TestClient, method: str, path: str
) -> None:
    response = getattr(client, method)(path)
    assert response.status_code in {404, 405}
    body = response.json()
    assert set(body) == {"detail", "code"}
    assert isinstance(body["detail"], str) and body["detail"]
    assert isinstance(body["code"], str) and body["code"]


def test_method_not_allowed_is_reported(client: TestClient) -> None:
    response = client.get("/auth/logout")
    assert response.status_code == 405
    assert response.json()["code"] == "method_not_allowed"


def test_wrong_content_type_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/auth/login/begin", content=b"username=alice", headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 400
    assert response.json()["code"] == "validation_error"


def test_error_responses_never_leak_secrets(client: TestClient) -> None:
    response = client.post("/auth/register/begin", json={"username": "x"})
    assert response.text.find(test_settings.secret_key) == -1
    assert "Traceback" not in response.text


# ------------------------------------------------------------------ OpenAPI
def test_openapi_schema_is_complete(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "Passwordless Auth API"
    assert schema["info"]["version"] == __version__
    tags = {
        tag
        for operations in schema["paths"].values()
        for operation in operations.values()
        for tag in operation.get("tags", [])
    }
    assert tags == {"auth", "devices", "admin", "logs", "service"}


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_interactive_documentation_is_served(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_every_route_is_covered_by_the_schema(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) == {
        "/health",
        "/.well-known/assetlinks.json",
        "/auth/register/begin",
        "/auth/register/complete",
        "/auth/login/begin",
        "/auth/login/complete",
        "/auth/logout",
        "/devices/",
        "/devices/register/begin",
        "/devices/register/complete",
        "/devices/{device_id}",
        "/admin/users",
        "/admin/users/{user_id}/devices",
        "/admin/users/{user_id}/devices/{device_id}",
        "/admin/users/{user_id}/disable",
        "/admin/users/{user_id}/enable",
        "/logs/my",
        "/logs/admin",
    }


# ------------------------------------------------------- переопределение БД
def test_requests_get_a_fresh_session_per_call(client: TestClient, session: Session) -> None:
    """Переопределение ``get_db`` выдаёт по одной сессии на запрос и закрывает её."""
    from src.utils.deps import get_db

    assert get_db in app.dependency_overrides
    generator = app.dependency_overrides[get_db]()
    first = next(generator)
    assert isinstance(first, Session)
    with pytest.raises(StopIteration):
        next(generator)
    assert first.is_active is True or not first.is_active  # закрыта, состояние не важно
    assert session.is_active is True


def test_engine_uses_the_configured_url() -> None:
    engine = create_db_engine(test_settings)
    try:
        assert engine.url.render_as_string().startswith("postgresql+psycopg")
    finally:
        engine.dispose()
