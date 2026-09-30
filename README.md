# passwordless-auth-api

Backend для беспарольной аутентификации (WebAuthn / Passkeys), написанный на
**FastAPI**, **SQLAlchemy 2.0**, **Alembic** и **PostgreSQL 16**.

API реализует обе церемонии WebAuthn (регистрация и аутентификация) для
**веб-браузеров** (Windows Hello, Touch ID, ключи безопасности) и **нативных
Android-приложений** через Digital Asset Links, выдаёт **JWT**-токены доступа и
предоставляет управление устройствами, административные методы и журнал аудита.

- 18 задокументированных эндпоинтов, интерактивный OpenAPI на `/docs`
- Жёсткое разделение слоёв: `routers` → `services` → `repositories` → `models`
- `py_webauthn` изолирован в одном модуле (`src/services/webauthn_service.py`)
- 355 тестов, 100 % покрытие операторов, чистые `mypy --strict` / `flake8` / `black` / `isort`
- Запускается через `docker compose up` (API + PostgreSQL, опционально Redis)

---

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Переменные окружения](#переменные-окружения)
3. [HTTPS обязателен](#https-обязателен)
4. [Android: как получить отпечаток сертификата](#android-как-получить-отпечаток-сертификата)
5. [Справочник API](#справочник-api)
6. [Сценарии регистрации и входа](#сценарии-регистрации-и-входа)
7. [Особенности WebAuthn](#особенности-webauthn)
8. [Архитектура](#архитектура)
9. [Разработка](#разработка)
10. [Заметки по безопасности и известные компромиссы](#заметки-по-безопасности-и-известные-компромиссы)

---

## Быстрый старт

### Через Docker Compose (рекомендуется)

```bash
cp .env.example .env
# поправьте .env: как минимум замените SECRET_KEY, RP_ID и ALLOWED_ORIGINS
docker compose up --build
```

API становится доступен на <http://localhost:8000>:

- `GET /health` — проверка живости и соединения с базой данных
- `GET /docs` — Swagger UI

Контейнер выполняет `alembic upgrade head` **до** запуска uvicorn и дожидается
перехода PostgreSQL в состояние `healthy` (`depends_on: condition:
service_healthy` в compose).

Чтобы добавить общее хранилище challenge (обязательно, как только воркеров больше
одного):

```bash
docker compose --profile redis up --build
# и в .env:
#   CHALLENGE_STORE=redis
#   WEB_CONCURRENCY=4
```

### Как открыть Swagger UI

Swagger UI включается всегда и отдельной настройки не требует.

| Адрес | Что это |
| --- | --- |
| <http://localhost:8000/docs> | **Swagger UI** — интерактивный интерфейс |
| <http://localhost:8000/redoc> | ReDoc — альтернативный просмотрщик |
| <http://localhost:8000/openapi.json> | сама спецификация OpenAPI 3.1 |

```bash
# Docker Compose: контейнер уже поднят
docker compose up -d --build
# затем откройте http://localhost:8000/docs

# локально
uvicorn src.main:app --reload --port 8000
# затем откройте http://localhost:8000/docs

# другой порт
uvicorn src.main:app --port 9000   # http://localhost:9000/docs
```

В Swagger UI доступны все 18 эндпоинтов с русскими описаниями. Авторизованные
методы (`/devices/*`, `/admin/*`, `/logs/*`, `/auth/logout`) требуют заголовок:

1. Нажмите кнопку **Authorize** в правом верхнем углу.
2. Вставьте JWT, полученный в `/auth/login/complete` (только сам токен, без
   префикса `Bearer `).
3. Нажмите **Authorize** — Swagger сам подставит заголовок
   `Authorization: Bearer <токен>`.

Чтобы получить токен, выполните `POST /auth/login/begin` и
`POST /auth/login/complete` прямо в интерфейсе: в поле **Authorize** нужна строка
`access_token` из ответа `login/complete`.

Полезные ярлыки справа: **Schemas** — модели запросов и ответов, **Authorizations** —
схема HTTP Bearer.

### Локально

```bash
python -m venv .venv
source .venv/Scripts/activate      # Windows
# source .venv/bin/activate        # Linux / macOS

pip install -e ".[dev]"

# экземпляр PostgreSQL 16 должен быть доступен по DATABASE_URL
alembic upgrade head
uvicorn src.main:app --reload --port 8000
```

Выдать права администратора первому пользователю:

```bash
python -m src.scripts.promote_admin alice           # выдать права
python -m src.scripts.promote_admin alice --revoke  # снять права
```

### Быстрая проверка

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/auth/register/begin \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "email": "alice@example.com"}'
```

---

## Переменные окружения

Конфигурация читается из переменных окружения и из файла `.env`
(`pydantic-settings`). Списки значений принимают **CSV** (`a,b,c`) или
**JSON-массив** (`["a","b"]`).

`DATABASE_URL`, `SECRET_KEY`, `RP_ID` и `ALLOWED_ORIGINS` — **обязательные, без
значений по умолчанию**: приложение не стартует без них.

| Переменная | Обязательна | По умолчанию | Описание |
| --- | --- | --- | --- |
| `ENVIRONMENT` | нет | `local` | `local` / `staging` / `production` |
| `DEBUG` | нет | `false` | Режим отладки FastAPI |
| `LOG_LEVEL` | нет | `INFO` | `CRITICAL`…`DEBUG` (проверяется) |
| `WEB_CONCURRENCY` | нет | `1` | Воркеры uvicorn, `1`–`64` |
| `DATABASE_URL` | **да** | — | URL SQLAlchemy, например `postgresql+psycopg://auth:auth@localhost:5432/auth` |
| `DATABASE_ECHO` | нет | `false` | Логировать каждый SQL-запрос |
| `DATABASE_POOL_SIZE` | нет | `5` | Базовый размер пула |
| `DATABASE_MAX_OVERFLOW` | нет | `10` | Дополнительные соединения под нагрузкой |
| `DATABASE_POOL_TIMEOUT_SECONDS` | нет | `30` | Ожидание свободного соединения |
| `SECRET_KEY` | **да** | — | Ключ подписи JWT, **минимум 32 символа** |
| `JWT_ALGORITHM` | нет | `HS256` | Допустим только `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | нет | `60` | Время жизни токена доступа |
| `CORS_ORIGINS` | нет | *(пусто)* | Разрешённые браузерные оригины |
| `CORS_ALLOW_CREDENTIALS` | нет | `false` | Отправлять cookie/credentials |
| `CORS_ALLOW_METHODS` | нет | `GET,POST,DELETE,OPTIONS` | |
| `CORS_ALLOW_HEADERS` | нет | `Authorization,Content-Type` | |
| `RP_ID` | **да** | — | Голый домен, без схемы/порта/пути, например `example.com` |
| `RP_NAME` | нет | `Passwordless Auth API` | Отображается аутентификатором |
| `ALLOWED_ORIGINS` | **да** | — | Веб-оригины **и** значения вида `android:apk-key-hash:…` |
| `WEBAUTHN_TIMEOUT_MS` | нет | `300000` | Таймаут церемонии, `30000`–`600000` |
| `WEBAUTHN_REQUIRE_USER_VERIFICATION` | нет | `true` | UV фактически всегда обязателен |
| `USER_HANDLE_LENGTH` | нет | `32` | Длина непрозрачного `user.id`, `16`–`64` |
| `CHALLENGE_TTL_SECONDS` | нет | `300` | Время жизни challenge, `1`–`3600` |
| `CHALLENGE_CLEANUP_INTERVAL_SECONDS` | нет | `60` | Интервал сборки мусора в памяти |
| `CHALLENGE_STORE` | нет | `memory` | `memory` или `redis` |
| `REDIS_URL` | нет | `redis://localhost:6379/0` | Используется при `CHALLENGE_STORE=redis` |
| `RATE_LIMIT_ENABLED` | нет | `true` | Главный переключатель ограничения частоты |
| `RATE_LIMIT_MAX_REQUESTS` | нет | `30` | Запросов на окно и на ключ |
| `RATE_LIMIT_WINDOW_SECONDS` | нет | `60` | Длина окна |
| `ANDROID_PACKAGE_NAME` | нет | *(пусто)* | Включает `/.well-known/assetlinks.json` |
| `ANDROID_CERT_FINGERPRINTS` | нет | *(пусто)* | base64url SHA-256 сертификата подписи |

Сгенерировать ключ:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## HTTPS обязателен

**Браузерный API WebAuthn доступен только в защищённом контексте.** На любом хосте,
кроме `localhost`, и `RP_ID`, и `ALLOWED_ORIGINS` должны отдаваться по **HTTPS** с
сертификатом, которому доверяет устройство. `http://192.168.1.10:8000` не
сработает — аутентификатор просто откажется создавать credential.

Для локальной разработки поставьте перед uvicorn обратный прокси (Caddy, nginx,
ngrok, mkcert, …) и задайте:

```env
RP_ID=localhost
ALLOWED_ORIGINS=https://localhost:8443
CORS_ORIGINS=https://localhost:8443
```

`RP_ID` должен быть **суффиксом регистрируемого домена** для оригина страницы:
страница с `https://auth.example.com` может использовать `RP_ID=example.com` (или
`auth.example.com`), но не `RP_ID=example.org`.

---

## Android: как получить отпечаток сертификата

Нативные Android-приложения получают свой WebAuthn-оригин из сертификата подписи
приложения. В `expected_origin` передаётся:

```
android:apk-key-hash:<base64url(SHA-256(der сертификата подписи))>
```

**Без base64-padding** — ровно тот формат, который Google публикует для Digital
Asset Links.

**Play App Signing (AAB):** используйте *ключ подписи приложения*, а не ключ
загрузки, потому что Google переподписывает распространяемый APK своим ключом.
Отпечатки публикуются в Play Console в разделе *Release → App integrity → App
signing*. Нужна колонка **SHA-256 certificate fingerprint**.

```bash
# 1. скачайте ключ подписи приложения (запрос на экспорт в Play Console)
#    либо используйте ~/.android/debug.keystore для debug-сборки
keytool -list -v -keystore ~/upload-keystore.jks -alias upload | grep "SHA256:"

# 2. значение после "SHA256:" дано в стандартном base64
# 3. переводим в base64url без padding
echo -n "1A:2B:3C..." | tr -d ':' | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=\n'
```

Из Gradle:

```kotlin
val signing = PackageManager.GET_SIGNING_CERTIFICATES
val info = packageManager.getPackageInfo(packageName, signing)
val fingerprint = info.signingInfo.apkContentsSigners[0].toByteArray()
    .let { java.security.MessageDigest.getInstance("SHA-256").digest(it) }
    .let { android.util.Base64.encodeToString(it, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP) }
```

Результат указывается **в обоих** местах:

```env
ALLOWED_ORIGINS=https://example.com,android:apk-key-hash:REPLACE_WITH_BASE64URL_SHA256
ANDROID_PACKAGE_NAME=com.example.passwordless
ANDROID_CERT_FINGERPRINTS=REPLACE_WITH_BASE64URL_SHA256
```

`GET /.well-known/assetlinks.json` отдаётся с хоста RP ID и возвращает:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.passwordless",
      "sha256_cert_fingerprints": ["REPLACE_WITH_BASE64URL_SHA256"]
    }
  }
]
```

Оба значения должны совпадать, иначе менеджер credentials на Android отклонит
assertion. Если `ANDROID_PACKAGE_NAME` или `ANDROID_CERT_FINGERPRINTS` пуст,
эндпоинт возвращает пустой список `[]` (и пишет в лог
`assetlinks_not_configured`).

---

## Справочник API

Все ошибки имеют единую плоскую форму:

```json
{ "detail": "Challenge is unknown, expired or already used", "code": "challenge_not_found" }
```

`code` — стабильный машинно-читаемый код; `detail` — человекочитаемое описание
без секретов.

### Аутентификация

| Метод | Путь | Авторизация | Описание |
| --- | --- | --- | --- |
| `POST` | `/auth/register/begin` | — | Создать аккаунт и начать регистрацию |
| `POST` | `/auth/register/complete` | — | Завершить регистрацию, привязать passkey |
| `POST` | `/auth/login/begin` | — | Начать аутентификацию |
| `POST` | `/auth/login/complete` | — | Завершить аутентификацию, вернуть JWT |
| `POST` | `/auth/logout` | Bearer | `204 No Content`, клиент сам избавляется от токена |

### Устройства (passkey текущего пользователя)

| Метод | Путь | Авторизация | Описание |
| --- | --- | --- | --- |
| `GET` | `/devices/` | Bearer | Список своих устройств |
| `POST` | `/devices/register/begin` | Bearer | Начать добавление ещё одного passkey |
| `POST` | `/devices/register/complete` | Bearer | Завершить добавление passkey |
| `DELETE` | `/devices/{device_id}` | Bearer | Удалить passkey, `204 No Content` |

`DELETE /devices/{device_id}` возвращает **`404`** для устройства, принадлежащего
другому пользователю, — он никогда не раскрывает, что устройство существует.

### Администрирование (только для администратора)

| Метод | Путь | Авторизация | Описание |
| --- | --- | --- | --- |
| `GET` | `/admin/users?skip=0&limit=50` | Bearer (admin) | Постраничный список пользователей |
| `GET` | `/admin/users/{user_id}/devices` | Bearer (admin) | Устройства одного пользователя |
| `DELETE` | `/admin/users/{user_id}/devices/{device_id}` | Bearer (admin) | `204 No Content` |
| `POST` | `/admin/users/{user_id}/disable` | Bearer (admin) | Деактивировать аккаунт |
| `POST` | `/admin/users/{user_id}/enable` | Bearer (admin) | Реактивировать аккаунт |

Токен не-администратора получает **`403 Forbidden`** на любом маршруте `/admin/*`.

### Журнал аудита

| Метод | Путь | Авторизация | Описание |
| --- | --- | --- | --- |
| `GET` | `/logs/my?skip=0&limit=50` | Bearer | Свои события аутентификации |
| `GET` | `/logs/admin?skip=0&limit=50` | Bearer (admin) | Все события |

### Служебные эндпоинты

| Метод | Путь | Авторизация | Описание |
| --- | --- | --- | --- |
| `GET` | `/health` | — | `{"status": "ok", "service": "passwordless-auth-api", "version": "1.0.0", "database": "ok"}` |
| `GET` | `/.well-known/assetlinks.json` | — | Android Digital Asset Links |

### Коды статусов

`200` успех · `201` создано · `204` нет содержимого · `400` ошибка валидации или
церемонии · `401` токен отсутствует, невалиден или истёк · `403` не администратор
или аккаунт отключён · `404` ресурс не найден · `409` конфликт (passkey уже
зарегистрирован, дубликат username/e-mail) · `429` превышен лимит запросов.

---

## Сценарии регистрации и входа

### 1. Регистрация

```bash
# begin
curl -X POST http://localhost:8000/auth/register/begin \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com"}'
```

```json
{
  "challenge_id": "b7f1…",
  "options": { "rp": {"id": "example.com", "name": "Passwordless Auth API"},
               "user": {"id": "…", "name": "alice", "displayName": "alice@example.com"},
               "challenge": "…", "pubKeyCredParams": [ … ], "timeout": 300000,
               "authenticatorSelection": { … }, "attestation": "none" }
}
```

Браузер / приложение:

```js
const cred = await navigator.credentials.create({ publicKey: options.options });
```

```bash
# complete
curl -X POST http://localhost:8000/auth/register/complete \
  -H "Content-Type: application/json" \
  -d '{"challenge_id":"b7f1…","credential":{ … },"device_name":"Pixel 8","device_type":"android"}'
```

```json
{ "user_id": 1, "username": "alice", "device_id": 1,
  "device_name": "Pixel 8", "device_type": "android", "created_at": "2026-01-01T12:00:00Z" }
```

`device_type` принимает значения `android`, `windows`, `ios`, `macos`, `linux`,
`web`, `other`. Неизвестное значение — это ошибка валидации `400`.

### 2. Вход

```bash
curl -X POST http://localhost:8000/auth/login/begin \
  -H "Content-Type: application/json" -d '{"username":"alice"}'
```

```js
const cred = await navigator.credentials.get({ publicKey: begin.options });
```

```bash
curl -X POST http://localhost:8000/auth/login/complete \
  -H "Content-Type: application/json" \
  -d '{"challenge_id":"c2a9…","credential":{ … }}'
```

```json
{ "access_token": "eyJ…", "token_type": "bearer", "expires_in": 3600 }
```

`/auth/login/begin` принимает и **полное отсутствие `username`** (discoverable /
usernameless вход): сервер отвечает пустым списком `allowCredentials`, и
аутентификатор предлагает каждый passkey, который у него есть для этого `RP_ID`.

### 3. Использование токена

```bash
curl http://localhost:8000/devices/ -H "Authorization: Bearer eyJ…"
```

### 4. Выход

```bash
curl -X POST http://localhost:8000/auth/logout -H "Authorization: Bearer eyJ…"
# 204 No Content — клиент избавляется от токена
```

---

## Особенности WebAuthn

**Двоичные значения передаются в base64url** без padding — именно так отдаёт
`options_to_json_dict` из `py_webauthn` и именно этого ожидает браузер.

| Настройка | Значение |
| --- | --- |
| `rpId` | `RP_ID` |
| `rp.name` | `RP_NAME` |
| `attestation` | `none` |
| `authenticatorSelection.authenticatorAttachment` | `platform` |
| `authenticatorSelection.residentKey` | `preferred` |
| `authenticatorSelection.userVerification` | `required` |
| `pubKeyCredParams` | `ES256` (`-7`) и `RS256` (`-257`) |
| `user.id` | 32 случайных байта в base64url, непрозрачные и стабильные для аккаунта |

**Challenge** — это 32 случайных байта, привязанных к `challenge_id`, к операции
(`register` / `login`) и, при входе, к сущности пользователя. Challenge
**одноразовый**: запись удаляется первым же успешным обращением, поэтому
повторная отправка того же `challenge_id` всегда даёт `400 challenge_not_found`.
In-memory хранилище чистит просроченные записи по фоновому таймеру.

**Счётчики подписи.** Значение `0` означает, что аутентификатор не ведёт счётчик
(типично для синхронизируемых passkey), и принимается всегда. Иначе новое
значение должно быть **больше либо равно** сохранённому; меньшее значение
трактуется как клонированный аутентификатор, отклоняет assertion с `400` и
записывает событие аудита со статусом `FAILURE` и указанием причины.

**Проверка `user.id` / `userHandle`.** При discoverable-входе assertion несёт
`userHandle`; если у аккаунта сохранён handle, они должны совпадать, иначе
assertion отклоняется.

---

## Архитектура

```
src/
├── main.py                 # фабрика приложения, CORS, обработчики ошибок,
│                           # /health, assetlinks
├── database.py             # engine, sessionmaker, session_scope
├── routers/                # только HTTP: валидация -> вызов сервиса -> ответ
│   ├── auth.py  devices.py  admin.py  logs.py
├── services/               # бизнес-логика, БЕЗ импорта fastapi
│   ├── auth_service.py     # церемонии регистрации и входа
│   ├── device_service.py   # управление passkey
│   ├── admin_service.py    # администрирование пользователей
│   ├── log_service.py      # запросы к журналу аудита
│   ├── security_service.py # создание и разбор JWT
│   ├── webauthn_service.py # ЕДИНСТВЕННЫЙ модуль, импортирующий py_webauthn
│   ├── challenge_store.py  # протокол ChallengeStore + in-memory / Redis
│   ├── audit.py            # AuditLogger (своя транзакция, ошибки не пробрасываются)
│   └── dto.py              # RequestContext, ChallengeBeginResult, TokenPair
├── repositories/           # реализации узких протоколов на SQLAlchemy
│   ├── protocols.py        # UserRepository, DeviceRepository, CredentialRepository,
│   │                       # AuthLogRepository, TransactionManager
│   ├── user.py  device.py  credential.py  auth_log.py  transaction.py
├── models/                 # декларативные модели (Mapped[]), без create_all()
├── schemas/                # модели запросов и ответов Pydantic v2
├── utils/
│   ├── config.py           # Settings (pydantic-settings)
│   ├── deps.py             # связывание зависимостей FastAPI Depends
│   ├── exceptions.py       # доменные ошибки + единый обработчик
│   └── enums.py  logging_setup.py  rate_limit.py  time.py
└── scripts/promote_admin.py
```

Правила, выдержанные по всему проекту:

- **Роутеры не ходят в базу данных** и не импортируют `sqlalchemy`.
- **Сервисы не импортируют `fastapi`**: зависимости передаются через конструктор, а
  данные запроса — через объект-значение `RequestContext`.
- **Репозитории — узкие `Protocol`**: `AuthService` зависит от `UserRepository`, а не
  от сессии SQLAlchemy.
- **`py_webauthn` встречается ровно в одном модуле**, за протоколом
  `WebAuthnGateway`, который же подменяется в тестах.
- **Схемой владеет Alembic**; `Base.metadata.create_all()` не вызывается никогда.

### Модель данных

```
users        id, username (unique), email (unique), is_active, is_admin,
             user_handle (BYTEA), created_at, updated_at
devices      id, device_name, device_type, user_id → users.id ON DELETE CASCADE,
             created_at
credentials  id, credential_id (unique, base64url), public_key (BYTEA), sign_count,
             user_id → users.id ON DELETE CASCADE,
             device_id → devices.id ON DELETE CASCADE (UNIQUE, 1:1),
             last_used (nullable)
auth_logs    id, user_id → users.id ON DELETE SET NULL, event_type, status,
             timestamp, ip_address, user_agent, details
```

Индексы: `users.username`, `users.email`, `credentials.credential_id`,
`credentials.user_id`, `devices.user_id`, `auth_logs.user_id`, `auth_logs.timestamp`.

### Журнал аудита

Каждая церемония пишет ровно одну строку в `auth_logs` — и при успехе, **и при
ошибке** — с типом события, статусом (`success` / `failure`), IP клиента,
User-Agent и произвольным JSON в `details`. Запись делегирована `AuditLogger`,
который использует **собственную** транзакцию и глотает собственные ошибки:
сломанный аудит не должен превращать успешную регистрацию в `500`.

---

## Разработка

```bash
pip install -e ".[dev]"

pytest                                   # 355 тестов
pytest --cov=src --cov-report=term-missing
mypy .                                    # строгий режим (настроен в pyproject.toml)
flake8 . && black --check . && isort --check .
```

Набор тестов создаёт **собственную** базу PostgreSQL (`passwordless_auth_test`),
применяет миграции через Alembic и очищает таблицы между тестами. Порядок
определения базы:

1. `TEST_DATABASE_URL`, если задан;
2. иначе доступный локальный PostgreSQL
   (`postgresql+psycopg://auth:auth@localhost:5432/auth`);
3. иначе временный файл SQLite, чтобы набор запускался где угодно.

`py_webauthn` подменяется на границе сервиса объектом
`tests/fakes.py::FakeWebAuthnService`; у настоящего `WebAuthnService` есть
собственные тесты. Приложение, сессия базы, настройки и хранилище challenge
подменяются через `dependency_overrides` в `tests/conftest.py`.

### Миграции

```bash
alembic revision --autogenerate -m "add something"
alembic upgrade head
alembic downgrade -1
alembic check          # падает, если модели разошлись с миграциями
```

---

## Заметки по безопасности и известные компромиссы

- **Перечисление пользователей на `login/begin`.** Неизвестным и известным
  пользователям отдаются структурно одинаковые ответы (challenge с пустым списком
  `allowCredentials`), чтобы браузер не смог их различить. Однако **отключённый**
  аккаунт получает явный `403` с понятным сообщением — это осознанный размен,
  делающий поддержку пользователей работоспособной, и единственное место, где API
  раскрывает существование аккаунта.
- **In-memory хранилище challenge работает только с одним воркером.** Именно
  поэтому `docker compose up` поставляется с `WEB_CONCURRENCY=1`. При большем
  числе воркеров **обязательно** нужно задать `CHALLENGE_STORE=redis`; при старте
  приложение пишет предупреждение в лог, если `WEB_CONCURRENCY > 1`, а хранилище не
  общее.
- **Токены нельзя отозвать.** `POST /auth/logout` возвращает `204`, и клиент сам
  избавляется от токена; JWT остаётся действительным до истечения срока. Задайте
  небольшой `ACCESS_TOKEN_EXPIRE_MINUTES` либо добавьте denylist, если нужен
  серверный выход.
- **У `SECRET_KEY` нет значения по умолчанию**, и оно никогда не попадает в лог;
  фильтр логов вычищает известные секреты из каждой записи.
- **Ограничение частоты** действует по IP и маршруту (`RATE_LIMIT_ENABLED`, по
  умолчанию включено, 30 запросов за 60 с) и может быть явно выключено.
- **HTTPS обязателен** для любого развёртывания, кроме `localhost` (см. раздел
  [выше](#https-обязателен)).
