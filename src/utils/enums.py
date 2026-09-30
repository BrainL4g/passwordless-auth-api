"""Перечисления, общие для всех слоёв (хранилище, сервисы и HTTP-схемы)."""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """Строковое перечисление, у которого ``str()`` возвращает чистое значение.

    Значение пригодно для прямого использования в SQL и JSON.
    """

    def __str__(self) -> str:
        return str(self.value)


class DeviceType(StrEnum):
    """Платформа, к которой относится passkey/устройство."""

    ANDROID = "android"
    WINDOWS = "windows"
    IOS = "ios"
    MACOS = "macos"
    LINUX = "linux"
    WEB = "web"
    OTHER = "other"


class AuthEventType(StrEnum):
    """Аудируемые события аутентификации, хранящиеся в ``auth_logs``."""

    REGISTER_BEGIN = "register_begin"
    REGISTER_COMPLETE = "register_complete"
    LOGIN_BEGIN = "login_begin"
    LOGIN_COMPLETE = "login_complete"
    DEVICE_ADD = "device_add"
    DEVICE_DELETE = "device_delete"
    ADMIN_LIST_USERS = "admin_list_users"
    ADMIN_LIST_USER_DEVICES = "admin_list_user_devices"
    ADMIN_DELETE_USER_DEVICE = "admin_delete_user_device"
    ADMIN_DISABLE_USER = "admin_disable_user"
    ADMIN_ENABLE_USER = "admin_enable_user"


class AuthLogStatus(StrEnum):
    """Результат аудируемого события."""

    SUCCESS = "success"
    FAILURE = "failure"


class ChallengeOperation(StrEnum):
    """Тип церемонии, к которой относится сохранённый челлендж."""

    REGISTER = "register"
    LOGIN = "login"
