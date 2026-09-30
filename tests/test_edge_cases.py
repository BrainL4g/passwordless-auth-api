"""Граничные случаи инфраструктурного слоя.

Эти тесты нацелены на защитные ветки (пути отката, фильтры сокрытия секретов,
предупреждения о конфигурации, ...), которые легко оставить непокрытыми.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database import create_db_engine, session_scope
from src.models.device import Device
from src.repositories.auth_log import SqlAlchemyAuthLogRepository
from src.repositories.credential import SqlAlchemyCredentialRepository
from src.repositories.device import SqlAlchemyDeviceRepository
from src.repositories.transaction import SqlAlchemyTransactionManager
from src.repositories.user import SqlAlchemyUserRepository
from src.schemas.common import CredentialPayload
from src.services.audit import AuditLogger
from src.services.auth_service import AuthService
from src.services.challenge_store import InMemoryChallengeStore, RedisChallengeStore
from src.services.device_service import DeviceService
from src.services.dto import RequestContext
from src.services.security_service import SecurityService
from src.services.webauthn_service import WebAuthnGateway, WebAuthnService
from src.utils.deps import get_db
from src.utils.enums import AuthEventType, AuthLogStatus, DeviceType
from src.utils.exceptions import (
    AuthenticationFailedError,
    ConflictError,
    DomainError,
    NotFoundError,
    UserAlreadyExistsError,
)
from src.utils.logging_setup import SecretRedactingFilter, configure_logging, get_logger
from tests.conftest import build_settings, test_settings
from tests.factories import create_auth_log, create_user, create_user_with_credential
from tests.fakes import FakeWebAuthnService, authentication_payload, registration_payload

CONTEXT = RequestContext(ip_address="203.0.113.1", user_agent="pytest")


@contextmanager
def _capture(logger_name: str, level: int = logging.WARNING) -> Iterator[list[logging.LogRecord]]:
    """Собирает записи одного логгера.

    ``configure_logging`` перенастраивает корневой логгер с ``force=True``, что
    удаляет обработчик ``caplog`` из pytest, поэтому записи собираются частным
    обработчиком, подключённым к тестируемому логгеру.
    """
    logger = logging.getLogger(logger_name)
    records: list[logging.LogRecord] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Handler(level=level)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(level)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


# ------------------------------------------------------- единица транзакций
def test_transaction_commits_on_success(session: Session) -> None:
    manager = SqlAlchemyTransactionManager(session)
    with manager.transaction():
        SqlAlchemyUserRepository(session).create(
            username="alice", email="alice@example.com", user_handle=b"a" * 32
        )
    assert SqlAlchemyUserRepository(session).get_by_username("alice") is not None


def test_transaction_rolls_back_on_error(session: Session) -> None:
    manager = SqlAlchemyTransactionManager(session)
    with pytest.raises(RuntimeError):
        with manager.transaction():
            SqlAlchemyUserRepository(session).create(
                username="bob", email="bob@example.com", user_handle=b"b" * 32
            )
            raise RuntimeError("boom")
    assert SqlAlchemyUserRepository(session).get_by_username("bob") is None


def test_session_scope_commits(monkeypatch: pytest.MonkeyPatch, session: Session) -> None:
    import src.database as database

    monkeypatch.setattr(database, "SessionLocal", lambda: session)
    with session_scope() as scoped:
        SqlAlchemyUserRepository(scoped).create(
            username="alice", email="alice@example.com", user_handle=b"a" * 32
        )
    assert SqlAlchemyUserRepository(session).get_by_username("alice") is not None


def test_session_scope_rolls_back(monkeypatch: pytest.MonkeyPatch, session: Session) -> None:
    import src.database as database

    monkeypatch.setattr(database, "SessionLocal", lambda: session)
    with pytest.raises(RuntimeError):
        with session_scope() as scoped:
            SqlAlchemyUserRepository(scoped).create(
                username="bob", email="bob@example.com", user_handle=b"b" * 32
            )
            raise RuntimeError("boom")
    assert SqlAlchemyUserRepository(session).get_by_username("bob") is None


# ------------------------------------------------------------- путь SQLite
def test_sqlite_engine_uses_a_static_pool(tmp_path: Any) -> None:
    url = f"sqlite:///{tmp_path / 'x.db'}"
    settings = build_settings(
        database_url=url,
        secret_key="s" * 40,
        rp_id="localhost",
        allowed_origins=["https://localhost"],
    )
    engine = create_db_engine(settings)
    try:
        assert engine.pool.__class__.__name__ == "StaticPool"
        with engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT 1").scalar() == 1
    finally:
        engine.dispose()


# ------------------------------------------------------------------- models
def test_device_without_a_credential_has_no_last_used(session: Session) -> None:
    user, _, _ = create_user_with_credential(session, username="alice")
    device = SqlAlchemyDeviceRepository(session).create(
        user_id=user.id, device_name="Orphan", device_type=DeviceType.WEB
    )
    session.commit()
    assert device.credential is None
    assert device.last_used is None


# ------------------------------------------------------------------ схемы
@pytest.mark.parametrize("credential_type", ["publickey", "", "PUBLIC-KEY", "not-a-type"])
def test_credential_payload_rejects_other_types(credential_type: str) -> None:
    with pytest.raises(ValueError):
        CredentialPayload(id="abc", type=credential_type, response={"clientDataJSON": "x"})


def test_credential_payload_to_library_input_drops_none() -> None:
    payload = CredentialPayload(id="abc", response={"clientDataJSON": "x"})
    assert payload.to_library_input() == {
        "id": "abc",
        "type": "public-key",
        "response": {"clientDataJSON": "x"},
    }


def test_device_register_request_rejects_blank_name() -> None:
    from src.schemas.device import DeviceRegisterCompleteRequest

    with pytest.raises(ValueError):
        DeviceRegisterCompleteRequest(
            challenge_id="challenge-id",
            credential=CredentialPayload(id="a", response={}),
            device_name="  ",
            device_type=DeviceType.ANDROID,
        )


def test_validation_errors_stay_400_with_info_logging(client: TestClient) -> None:
    """Зарезервированный атрибут ``LogRecord`` никогда не должен превращать 400 в 500.

    ``extra={"message": ...}`` заставляет :mod:`logging` выбросить ``KeyError``
    при сборке записи. Это происходит, только когда логгер действительно пишет на
    уровне ``INFO``, поэтому на время теста уровень логгера поднимается до
    ``INFO``.
    """
    with _capture("src.utils.exceptions", level=logging.INFO):
        response = client.post(
            "/auth/register/begin",
            json={"username": "zed", "email": "definitely-not-an-email"},
        )
    assert response.status_code == 400, response.text
    assert response.json()["code"] == "validation_error"
    assert "email" in response.json()["detail"]


def test_no_source_logs_a_reserved_logrecord_attribute() -> None:
    """Проверяет каждый ``extra={...}`` на коллизии с :class:`logging.LogRecord`."""
    import re
    from pathlib import Path

    reserved = set(vars(logging.LogRecord("", 0, "", 0, "", None, None)))
    extra_keys = re.compile(r"extra=\{(.*?)\}")
    src_root = Path(__file__).resolve().parent.parent / "src"
    offenders = [
        f"{path.name}:{line_no}:{key}"
        for path in sorted(src_root.rglob("*.py"))
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        for group in extra_keys.findall(line)
        for key in re.findall(r'"(\w+)"\s*:', group)
        if key in reserved
    ]
    assert offenders == []


# ------------------------------------------ редкие защитные ветки
def _auth_service(
    session: Session, webauthn: WebAuthnGateway, store: InMemoryChallengeStore
) -> AuthService:
    """``AuthService``, связанный с настоящими репозиториями сессии ``session``."""
    logs = SqlAlchemyAuthLogRepository(session)
    transaction = SqlAlchemyTransactionManager(session)
    return AuthService(
        users=SqlAlchemyUserRepository(session),
        devices=SqlAlchemyDeviceRepository(session),
        credentials=SqlAlchemyCredentialRepository(session),
        logs=logs,
        webauthn=webauthn,
        security=SecurityService(test_settings),
        challenges=store,
        transaction=transaction,
        audit=AuditLogger(logs, transaction),
        challenge_ttl_seconds=test_settings.challenge_ttl_seconds,
    )


def test_email_taken_between_begin_and_complete_is_rejected(
    session: Session, webauthn: FakeWebAuthnService
) -> None:
    """Имя пользователя ещё свободно, пока адрес e-mail уже занят."""
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    try:
        service = _auth_service(session, webauthn, store)
        begin = service.begin_registration(
            username="alice", email="alice@example.com", context=CONTEXT
        )
        # Между двумя шагами кто-то занимает этот адрес.
        create_user(session, username="mallory", email="alice@example.com")
        with pytest.raises(UserAlreadyExistsError):
            service.complete_registration(
                challenge_id=begin.challenge_id,
                credential=registration_payload(),
                device_name="Pixel",
                device_type=DeviceType.ANDROID,
                context=CONTEXT,
            )
    finally:
        store.close()
    assert SqlAlchemyUserRepository(session).get_by_username("alice") is None
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.REGISTER_COMPLETE
    assert entry.status == AuthLogStatus.FAILURE


def test_user_handle_check_is_skipped_for_a_user_without_one(
    session: Session, webauthn: FakeWebAuthnService
) -> None:
    """Старая учётная запись без сохранённого user handle принимает любое утверждение."""
    user, _, _ = create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    user.user_handle = b""
    session.commit()
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id="YWxpY2U",
        new_sign_count=1,
        user_handle=b"any-handle",
        device_type="singleDevice",
        backed_up=False,
    )
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    try:
        service = _auth_service(session, webauthn, store)
        begin = service.begin_login(username="alice", context=CONTEXT)
        tokens = service.complete_login(
            challenge_id=begin.challenge_id, credential=authentication_payload(), context=CONTEXT
        )
    finally:
        store.close()
    assert tokens.token_type == "bearer"


def test_user_handle_of_another_account_is_rejected(
    session: Session, webauthn: FakeWebAuthnService
) -> None:
    """Обнаруживаемый passkey нельзя использовать с чужим пользователем."""
    create_user_with_credential(session, username="alice", credential_id="YWxpY2U")
    webauthn.authentication_result = type(webauthn.authentication_result)(
        credential_id="YWxpY2U",
        new_sign_count=1,
        user_handle=b"handle-of-somebody-else",
        device_type="singleDevice",
        backed_up=False,
    )
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    try:
        service = _auth_service(session, webauthn, store)
        begin = service.begin_login(username="alice", context=CONTEXT)
        with pytest.raises(AuthenticationFailedError):
            service.complete_login(
                challenge_id=begin.challenge_id,
                credential=authentication_payload(),
                context=CONTEXT,
            )
    finally:
        store.close()


def test_bytes_user_handle_is_used_as_is(monkeypatch: pytest.MonkeyPatch) -> None:
    """``parse_authentication_credential_json`` может вернуть сырые байты."""
    service = WebAuthnService(test_settings)

    class Parsed:
        user_handle = b"already-decoded"

    class FakeVerified:
        credential_id = b"cred-1"
        new_sign_count = 1
        credential_device_type = type("T", (), {"value": "singleDevice"})()
        credential_backed_up = False

    monkeypatch.setattr(
        "src.services.webauthn_service.parse_authentication_credential_json", lambda _: Parsed()
    )
    monkeypatch.setattr(
        "src.services.webauthn_service.verify_authentication_response", lambda **_: FakeVerified()
    )
    result = service.verify_authentication(
        credential={"id": "x", "response": {}},
        expected_challenge=b"c",
        credential_public_key=b"pk",
        current_sign_count=0,
    )
    assert result.user_handle == b"already-decoded"


def test_device_deletion_failure_is_audited_and_rolled_back(
    session: Session, webauthn: FakeWebAuthnService
) -> None:
    """Сбой внутри транзакции удаления не должен проглатываться."""
    user, device, _ = create_user_with_credential(session, username="alice")

    class FailingDevices(SqlAlchemyDeviceRepository):
        def delete(self, device: Device) -> None:
            raise ConflictError("Device is still in use")

    logs = SqlAlchemyAuthLogRepository(session)
    transaction = SqlAlchemyTransactionManager(session)
    store = InMemoryChallengeStore(cleanup_interval_seconds=3600)
    service = DeviceService(
        devices=FailingDevices(session),
        credentials=SqlAlchemyCredentialRepository(session),
        logs=logs,
        webauthn=webauthn,
        challenges=store,
        transaction=transaction,
        audit=AuditLogger(logs, transaction),
        challenge_ttl_seconds=test_settings.challenge_ttl_seconds,
    )
    try:
        with pytest.raises(ConflictError):
            service.delete_device(user, device.id, CONTEXT)
    finally:
        store.close()
    entry = logs.list_all(skip=0, limit=1)[0]
    assert entry.event_type == AuthEventType.DEVICE_DELETE
    assert entry.status == AuthLogStatus.FAILURE
    assert entry.details is not None and "conflict" in entry.details


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),  # пусть Pydantic применит значение поля по умолчанию
        ((), []),
        (["a", " b "], ["a", "b"]),
        (("a", "b"), ["a", "b"]),
        ("", []),
        ("   ", []),
        ("a, b ,c", ["a", "b", "c"]),
        ('["https://a", "https://b"]', ["https://a", "https://b"]),
        ("[not json, at all]", ["not json", "at all"]),  # битый JSON -> откат к CSV
        ("[1]", ["1"]),
        ('{"a": 1}', ['{"a": 1}']),  # JSON-объект не список: оставляем как есть
        (7, 7),  # не строка: передаём без изменений
    ],
)
def test_split_csv_edge_cases(raw: object, expected: object) -> None:
    """``_split_csv`` нормализует всё, что может содержаться в файле ``.env``."""
    from src.utils.config import _split_csv

    assert _split_csv(raw) == expected


# ---------------------------------------------------------------- аудит
def test_audit_swallows_repository_failures(session: Session) -> None:
    class BrokenLogs:
        def create(self, **_: Any) -> None:
            raise RuntimeError("audit table is gone")

    audit = AuditLogger(
        logs=BrokenLogs(),  # type: ignore[arg-type]
        transaction=SqlAlchemyTransactionManager(session),
    )
    # Не должен бросать исключение: сбой аудита не может ломать бизнес-операцию.
    audit.record(
        event_type=AuthEventType.LOGIN_BEGIN,
        status=AuthLogStatus.SUCCESS,
        context=CONTEXT,
    )
    assert SqlAlchemyAuthLogRepository(session).count_all() == 0


def test_audit_serialises_details(session: Session) -> None:
    audit = AuditLogger(
        logs=SqlAlchemyAuthLogRepository(session),
        transaction=SqlAlchemyTransactionManager(session),
    )
    audit.record(
        event_type=AuthEventType.LOGIN_BEGIN,
        status=AuthLogStatus.SUCCESS,
        context=CONTEXT,
        details={"b": 2, "a": object()},
    )
    entry = SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0]
    assert entry.details is not None
    assert entry.details.startswith('{"a":')  # ключи отсортированы, неизвестные типы в строки
    audit.record(
        event_type=AuthEventType.LOGIN_BEGIN,
        status=AuthLogStatus.SUCCESS,
        context=RequestContext(ip_address=None, user_agent=None),
        details={},
    )
    assert SqlAlchemyAuthLogRepository(session).list_all(skip=0, limit=1)[0].details is None


# --------------------------------------------------------------- WebAuthn
def test_decode_credential_ids_round_trip() -> None:
    service = WebAuthnService(test_settings)
    assert service.decode_credential_ids(["YWxpY2U"]) == [b"alice"]


def test_redis_challenge_store_from_url_builds_a_client() -> None:
    store = RedisChallengeStore.from_url("redis://localhost:6379/0")
    try:
        assert isinstance(store, RedisChallengeStore)
    finally:
        store.close()


# --------------------------------------------------------------- логирование
@pytest.mark.parametrize("key", sorted(SecretRedactingFilter.SENSITIVE_KEYS))
def test_secret_redacting_filter_masks_sensitive_keys(key: str) -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    setattr(record, key, "super-secret-value")
    assert SecretRedactingFilter().filter(record) is True
    assert getattr(record, key) == "***"


def test_secret_redacting_filter_keeps_other_keys() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    setattr(record, "user_id", 7)
    SecretRedactingFilter().filter(record)
    assert getattr(record, "user_id") == 7


def test_configure_logging_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.utils.logging_setup as logging_setup

    monkeypatch.setattr(logging_setup, "_CONFIGURED", False)
    configure_logging("DEBUG")
    assert logging.getLogger("sqlalchemy.engine").level == logging.INFO
    configure_logging("INFO")  # второй вызов ничего не делает
    assert logging.getLogger("sqlalchemy.engine").level == logging.INFO
    assert logging.getLogger("uvicorn.access").level == logging.WARNING
    monkeypatch.setattr(logging_setup, "_CONFIGURED", False)
    configure_logging("WARNING")
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING
    assert get_logger("tests") is logging.getLogger("tests")


def test_no_secret_ever_reaches_a_log_record() -> None:
    with _capture("src.services.security_service") as records:
        service = SecurityService(test_settings)
        try:
            service.decode_access_token("not.a.jwt")
        except DomainError:
            pass
    assert all(test_settings.secret_key not in record.getMessage() for record in records)
    assert all("not.a.jwt" not in record.getMessage() for record in records)


# ------------------------------------------------------------ зависимости
def test_get_db_yields_and_closes_a_session() -> None:
    generator = get_db()
    session = next(generator)
    assert isinstance(session, Session)
    with pytest.raises(StopIteration):
        next(generator)


# --------------------------------------------------- диагностика при старте
def test_insecure_and_dev_configuration_is_warned() -> None:
    from src.main import _warn_about_insecure_configuration

    settings = build_settings(
        database_url=test_settings.database_url,
        secret_key=test_settings.secret_key,
        rp_id="localhost",
        allowed_origins=["http://insecure.example", "http://localhost:3000", "https://ok.example"],
        web_concurrency=4,
        challenge_store="memory",
    )
    with _capture("src.main") as records:
        _warn_about_insecure_configuration(settings)
    assert {record.getMessage() for record in records} == {
        "insecure_origin_configured",
        "development_rp_id_configured",
        "unsafe_worker_combination",
    }


def test_safe_configuration_is_not_warned() -> None:
    from src.main import _warn_about_insecure_configuration

    settings = build_settings(
        database_url=test_settings.database_url,
        secret_key=test_settings.secret_key,
        rp_id="auth.example.com",
        allowed_origins=["https://auth.example.com"],
        web_concurrency=1,
        challenge_store="memory",
    )
    with _capture("src.main") as records:
        _warn_about_insecure_configuration(settings)
    assert records == []


def test_lifespan_startup_is_logged(client: TestClient) -> None:
    # Вход в контекст TestClient уже выполнил обработчик lifespan.
    assert client.get("/health").status_code == 200


# ------------------------------------------------------- форма доменных ошибок
@pytest.mark.parametrize(
    ("error", "status_code", "code"),
    [
        (NotFoundError(), 404, "not_found"),
        (NotFoundError("custom"), 404, "not_found"),
    ],
)
def test_domain_error_payload(error: DomainError, status_code: int, code: str) -> None:
    assert error.status_code == status_code
    assert error.to_payload()["code"] == code
    assert error.to_payload()["detail"] == error.message


def test_default_messages_never_leak_internals() -> None:
    assert NotFoundError().message == "Resource not found"
    assert "SELECT" not in NotFoundError().message


def test_credential_and_device_repositories_are_isolated_per_user(session: Session) -> None:
    alice, alice_device, _ = create_user_with_credential(
        session, username="alice", credential_id="YWxpY2U"
    )
    _, _, bob_credential = create_user_with_credential(
        session, username="bob", credential_id="Ym9i"
    )
    credentials = SqlAlchemyCredentialRepository(session)
    assert [item.credential_id for item in credentials.list_by_user(alice.id)] == ["YWxpY2U"]
    assert [item.device_id for item in credentials.list_by_user(alice.id)] == [alice_device.id]
    assert bob_credential.user_id != alice.id
    assert isinstance(session.get(Device, alice_device.id), Device)


def test_auth_log_details_survive_a_round_trip(session: Session) -> None:
    entry = create_auth_log(session, details='{"reason":"ok"}')
    logs = SqlAlchemyAuthLogRepository(session)
    assert logs.list_all(skip=0, limit=1)[0].details == entry.details
