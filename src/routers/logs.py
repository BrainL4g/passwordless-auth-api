"""Роутер ``/logs``: доступ к журналу аудита."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from src.schemas.log import AuthLogListResponse, AuthLogResponse
from src.utils.deps import CurrentAdmin, CurrentUser, LogServiceDep

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get(
    "/my",
    response_model=AuthLogListResponse,
    summary="Записи аудита текущей учётной записи",
)
def list_my_logs(
    service: LogServiceDep,
    user: CurrentUser,
    skip: Annotated[int, Query(ge=0, description="Смещение")] = 0,
    limit: Annotated[int, Query(ge=1, le=200, description="Размер страницы")] = 50,
) -> AuthLogListResponse:
    """Возвращаются только события аутентифицированной учётной записи."""
    page = service.list_my_logs(user=user, skip=skip, limit=limit)
    return AuthLogListResponse(
        items=[AuthLogResponse.model_validate(entry) for entry in page.items],
        total=page.total,
        skip=page.skip,
        limit=page.limit,
    )


@router.get(
    "/admin",
    response_model=AuthLogListResponse,
    summary="Записи аудита всех учётных записей (только для администраторов)",
)
def list_all_logs(
    service: LogServiceDep,
    admin: CurrentAdmin,
    skip: Annotated[int, Query(ge=0, description="Смещение")] = 0,
    limit: Annotated[int, Query(ge=1, le=200, description="Размер страницы")] = 50,
) -> AuthLogListResponse:
    """Полный журнал аудита, сначала самые новые записи."""
    page = service.list_all_logs(skip=skip, limit=limit)
    return AuthLogListResponse(
        items=[AuthLogResponse.model_validate(entry) for entry in page.items],
        total=page.total,
        skip=page.skip,
        limit=page.limit,
    )
