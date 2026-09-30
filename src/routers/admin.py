"""Роутер ``/admin``: только для администраторов (403 для всех остальных)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Response, status

from src.schemas.admin import AdminUserDevicesResponse, AdminUserResponse, UserListResponse
from src.schemas.device import device_to_response
from src.utils.deps import AdminServiceDep, CurrentAdmin, RequestCtx

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="Список всех учётных записей",
)
def list_users(
    service: AdminServiceDep,
    admin: CurrentAdmin,
    context: RequestCtx,
    skip: Annotated[int, Query(ge=0, description="Смещение")] = 0,
    limit: Annotated[int, Query(ge=1, le=200, description="Размер страницы")] = 50,
) -> UserListResponse:
    """Постраничный список всех учётных записей."""
    page = service.list_users(skip=skip, limit=limit, admin=admin, context=context)
    return UserListResponse(
        items=[AdminUserResponse.model_validate(user) for user in page.items],
        total=page.total,
        skip=page.skip,
        limit=page.limit,
    )


@router.get(
    "/users/{user_id}/devices",
    response_model=AdminUserDevicesResponse,
    summary="Устройства любой учётной записи",
)
def list_user_devices(
    service: AdminServiceDep,
    admin: CurrentAdmin,
    context: RequestCtx,
    user_id: Annotated[int, Path(ge=1)],
) -> AdminUserDevicesResponse:
    """Все passkey, зарегистрированные одной учётной записью."""
    devices = service.list_user_devices(user_id=user_id, admin=admin, context=context)
    return AdminUserDevicesResponse(
        user_id=user_id, items=[device_to_response(device) for device in devices]
    )


@router.delete(
    "/users/{user_id}/devices/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Удалить passkey любой учётной записи",
)
def delete_user_device(
    service: AdminServiceDep,
    admin: CurrentAdmin,
    context: RequestCtx,
    user_id: Annotated[int, Path(ge=1)],
    device_id: Annotated[int, Path(ge=1)],
) -> Response:
    """Удалить устройство (с его passkey) произвольной учётной записи."""
    service.delete_user_device(user_id=user_id, device_id=device_id, admin=admin, context=context)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/users/{user_id}/disable",
    response_model=AdminUserResponse,
    summary="Деактивировать учётную запись",
)
def disable_user(
    service: AdminServiceDep,
    admin: CurrentAdmin,
    context: RequestCtx,
    user_id: Annotated[int, Path(ge=1)],
) -> AdminUserResponse:
    """Заблокировать учётную запись: вход и доступ к API отклоняются с кодом 403."""
    user = service.set_user_active(user_id=user_id, is_active=False, admin=admin, context=context)
    return AdminUserResponse.model_validate(user)


@router.post(
    "/users/{user_id}/enable",
    response_model=AdminUserResponse,
    summary="Активировать учётную запись",
)
def enable_user(
    service: AdminServiceDep,
    admin: CurrentAdmin,
    context: RequestCtx,
    user_id: Annotated[int, Path(ge=1)],
) -> AdminUserResponse:
    """Разблокировать ранее деактивированную учётную запись."""
    user = service.set_user_active(user_id=user_id, is_active=True, admin=admin, context=context)
    return AdminUserResponse.model_validate(user)
