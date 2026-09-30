"""Выпуск и проверка JWT (HS256)."""

from __future__ import annotations

from typing import Any

import jwt
from jwt import ExpiredSignatureError
from jwt import InvalidTokenError as PyJWTInvalidTokenError

from src.services.dto import TokenPair
from src.utils.config import Settings
from src.utils.exceptions import ExpiredTokenError, InvalidTokenError
from src.utils.logging_setup import get_logger
from src.utils.time import utc_now

logger = get_logger(__name__)

TOKEN_TYPE = "bearer"


class SecurityService:
    """Создаёт и проверяет stateless access token."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def expires_in(self) -> int:
        """Настроенное время жизни token в секундах."""
        return self._settings.access_token_expire_seconds

    def create_access_token(self, user_id: int) -> TokenPair:
        """Выпускает подписанный access token для ``user_id``."""
        issued_at = utc_now()
        payload: dict[str, Any] = {
            "sub": str(user_id),
            "iat": int(issued_at.timestamp()),
            "exp": int(issued_at.timestamp()) + self._settings.access_token_expire_seconds,
        }
        token = jwt.encode(
            payload, self._settings.secret_key, algorithm=self._settings.jwt_algorithm
        )
        return TokenPair(
            access_token=token,
            token_type=TOKEN_TYPE,
            expires_in=self._settings.access_token_expire_seconds,
        )

    def decode_access_token(self, token: str) -> int:
        """Возвращает идентификатор пользователя, закодированный в валидном token.

        Raises:
            ExpiredTokenError: срок действия token истёк.
            InvalidTokenError: token имеет некорректный формат или подпись.
        """
        try:
            payload = jwt.decode(
                token,
                self._settings.secret_key,
                algorithms=[self._settings.jwt_algorithm],
                options={"require": ["exp", "iat", "sub"]},
            )
        except ExpiredSignatureError as exc:
            raise ExpiredTokenError() from exc
        except PyJWTInvalidTokenError as exc:
            logger.info("token_rejected", extra={"reason": type(exc).__name__})
            raise InvalidTokenError() from exc
        subject = payload.get("sub")
        try:
            return int(str(subject))
        except (TypeError, ValueError) as exc:
            raise InvalidTokenError() from exc
