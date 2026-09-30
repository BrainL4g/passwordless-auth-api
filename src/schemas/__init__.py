"""Контракты запросов/ответов HTTP API на Pydantic v2."""

from src.schemas.admin import AdminUserDevicesResponse, AdminUserResponse, UserListResponse
from src.schemas.auth import (
    AuthenticationBeginResponse,
    LoginBeginRequest,
    LoginCompleteRequest,
    RegistrationBeginRequest,
    RegistrationBeginResponse,
    RegistrationCompleteRequest,
    TokenResponse,
)
from src.schemas.common import (
    AssetLinkStatement,
    AssetLinkTarget,
    CredentialPayload,
    ErrorResponse,
    HealthResponse,
    PageResponse,
)
from src.schemas.device import (
    DeviceAddedResponse,
    DeviceBeginResponse,
    DeviceListResponse,
    DeviceRegisterCompleteRequest,
    DeviceResponse,
)
from src.schemas.log import AuthLogListResponse, AuthLogResponse

__all__ = [
    "AdminUserDevicesResponse",
    "AdminUserResponse",
    "AssetLinkStatement",
    "AssetLinkTarget",
    "AuthLogListResponse",
    "AuthLogResponse",
    "AuthenticationBeginResponse",
    "CredentialPayload",
    "DeviceAddedResponse",
    "DeviceBeginResponse",
    "DeviceListResponse",
    "DeviceRegisterCompleteRequest",
    "DeviceResponse",
    "ErrorResponse",
    "HealthResponse",
    "LoginBeginRequest",
    "LoginCompleteRequest",
    "PageResponse",
    "RegistrationBeginRequest",
    "RegistrationBeginResponse",
    "RegistrationCompleteRequest",
    "TokenResponse",
    "UserListResponse",
]
