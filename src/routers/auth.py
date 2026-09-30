"""Роутер ``/auth``: церемонии регистрации, входа и выхода."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from src.schemas.auth import (
    AuthenticationBeginResponse,
    LoginBeginRequest,
    LoginCompleteRequest,
    RegistrationBeginRequest,
    RegistrationBeginResponse,
    RegistrationCompleteRequest,
    TokenResponse,
)
from src.utils.deps import AuthServiceDep, RateLimit, RequestCtx

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register/begin",
    response_model=RegistrationBeginResponse,
    status_code=status.HTTP_200_OK,
    summary="Начать регистрацию passkey",
    dependencies=[RateLimit],
)
def register_begin(
    payload: RegistrationBeginRequest,
    service: AuthServiceDep,
    context: RequestCtx,
) -> RegistrationBeginResponse:
    """Проверить, что имя пользователя и адрес почты свободны, и вернуть опции создания."""
    result = service.begin_registration(
        username=payload.username, email=str(payload.email), context=context
    )
    return RegistrationBeginResponse(challenge_id=result.challenge_id, options=result.options)


@router.post(
    "/register/complete",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Завершить регистрацию passkey",
    dependencies=[RateLimit],
)
def register_complete(
    payload: RegistrationCompleteRequest,
    service: AuthServiceDep,
    context: RequestCtx,
) -> TokenResponse:
    """Проверить аттестацию и атомарно создать user + device + credential."""
    tokens = service.complete_registration(
        challenge_id=payload.challenge_id,
        credential=payload.credential.to_library_input(),
        device_name=payload.device_name,
        device_type=payload.device_type,
        context=context,
    )
    return TokenResponse(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
    )


@router.post(
    "/login/begin",
    response_model=AuthenticationBeginResponse,
    status_code=status.HTTP_200_OK,
    summary="Начать аутентификацию по passkey",
    dependencies=[RateLimit],
)
def login_begin(
    payload: LoginBeginRequest,
    service: AuthServiceDep,
    context: RequestCtx,
) -> AuthenticationBeginResponse:
    """Вернуть опции запроса с ``allowCredentials`` учётной записи."""
    result = service.begin_login(username=payload.username, context=context)
    return AuthenticationBeginResponse(challenge_id=result.challenge_id, options=result.options)


@router.post(
    "/login/complete",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Завершить аутентификацию по passkey",
    dependencies=[RateLimit],
)
def login_complete(
    payload: LoginCompleteRequest,
    service: AuthServiceDep,
    context: RequestCtx,
) -> TokenResponse:
    """Проверить assertion и выдать access token."""
    tokens = service.complete_login(
        challenge_id=payload.challenge_id,
        credential=payload.credential.to_library_input(),
        context=context,
    )
    return TokenResponse(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Выход без сохранения состояния",
)
def logout() -> Response:
    """Token не хранятся на сервере: клиент просто отбрасывает свой access token."""
    return Response(status_code=status.HTTP_204_NO_CONTENT)
