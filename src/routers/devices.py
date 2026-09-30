"""Роутер ``/devices``: управление passkey аутентифицированного пользователя."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Response, status

from src.schemas.device import (
    DeviceAddedResponse,
    DeviceBeginResponse,
    DeviceListResponse,
    DeviceRegisterCompleteRequest,
    device_to_response,
)
from src.utils.deps import CurrentUser, DeviceServiceDep, RequestCtx

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get(
    "/",
    response_model=DeviceListResponse,
    summary="Список своих устройств",
)
def list_devices(
    service: DeviceServiceDep,
    user: CurrentUser,
) -> DeviceListResponse:
    """Вернуть все устройства (с их passkey) текущей учётной записи."""
    devices = service.list_devices(user)
    return DeviceListResponse(items=[device_to_response(device) for device in devices])


@router.post(
    "/register/begin",
    response_model=DeviceBeginResponse,
    status_code=status.HTTP_200_OK,
    summary="Начать добавление дополнительного passkey",
)
def begin_device_registration(
    service: DeviceServiceDep,
    user: CurrentUser,
    context: RequestCtx,
) -> DeviceBeginResponse:
    """Вернуть опции создания, исключающие уже зарегистрированные passkey."""
    result = service.begin_registration(user, context)
    return DeviceBeginResponse(challenge_id=result.challenge_id, options=result.options)


@router.post(
    "/register/complete",
    response_model=DeviceAddedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Завершить добавление дополнительного passkey",
)
def complete_device_registration(
    payload: DeviceRegisterCompleteRequest,
    service: DeviceServiceDep,
    user: CurrentUser,
    context: RequestCtx,
) -> DeviceAddedResponse:
    """Проверить аттестацию и привязать passkey к новому устройству."""
    result = service.complete_registration(
        user=user,
        challenge_id=payload.challenge_id,
        credential=payload.credential.to_library_input(),
        device_name=payload.device_name,
        device_type=payload.device_type,
        context=context,
    )
    return DeviceAddedResponse(device_id=result.device_id, credential_id=result.credential_id)


@router.delete(
    "/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Удалить одно из своих устройств",
)
def delete_device(
    service: DeviceServiceDep,
    user: CurrentUser,
    context: RequestCtx,
    device_id: Annotated[int, Path(ge=1)],
) -> Response:
    """Удалить своё устройство; чужой device id даёт ответ ``404``."""
    service.delete_device(user, device_id, context)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
