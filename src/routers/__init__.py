"""HTTP-роутеры: только валидация запроса, вызов сервиса и формирование ответа."""

from src.routers.admin import router as admin_router
from src.routers.auth import router as auth_router
from src.routers.devices import router as devices_router
from src.routers.logs import router as logs_router

__all__ = ["admin_router", "auth_router", "devices_router", "logs_router"]
