"""Назначить существующую учётную запись администратором.

Использование (внутри контейнера)::

    docker compose exec api python -m src.scripts.promote_admin alice
    docker compose exec api python -m src.scripts.promote_admin alice --revoke
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy.orm import Session

from src.database import session_scope
from src.repositories.user import SqlAlchemyUserRepository
from src.utils.exceptions import NotFoundError
from src.utils.logging_setup import configure_logging, get_logger

logger = get_logger(__name__)


def set_admin_status(session: Session, username: str, *, is_admin: bool) -> str:
    """Выдать или отозвать права администратора; возвращает новый статус."""
    users = SqlAlchemyUserRepository(session)
    user = users.get_by_username(username)
    if user is None:
        raise NotFoundError(f"User {username!r} does not exist")
    user.is_admin = is_admin
    session.add(user)
    session.commit()
    return "granted" if is_admin else "revoked"


def main(argv: list[str] | None = None) -> int:
    """Точка входа из командной строки."""
    parser = argparse.ArgumentParser(
        description="Назначить/снять права администратора у учётной записи"
    )
    parser.add_argument("username", help="имя пользователя уже зарегистрированной учётной записи")
    parser.add_argument(
        "--revoke", action="store_true", help="отозвать права администратора вместо этого"
    )
    args = parser.parse_args(argv)
    configure_logging()
    try:
        with session_scope() as session:
            outcome = set_admin_status(session, args.username, is_admin=not args.revoke)
    except NotFoundError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    print(f"Administrator rights {outcome} for {args.username!r}")
    return 0


if __name__ == "__main__":  # pragma: no cover - ручная точка входа
    raise SystemExit(main())
