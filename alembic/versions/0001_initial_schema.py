"""Начальная схема: users, devices, credentials, auth_logs.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-30 13:42:45

Схема создаётся **только** этой миграцией; приложение никогда не вызывает
``Base.metadata.create_all``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Создать всю схему (порядок таблиц учитывает внешние ключи)."""
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("user_handle", sa.LargeBinary(length=32), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_handle"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)
    op.create_table(
        "auth_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column(
            "event_type",
            sa.Enum(
                "register_begin",
                "register_complete",
                "login_begin",
                "login_complete",
                "device_add",
                "device_delete",
                "admin_list_users",
                "admin_list_user_devices",
                "admin_delete_user_device",
                "admin_disable_user",
                "admin_enable_user",
                name="auth_event_type",
                native_enum=False,
                length=64,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "success",
                "failure",
                name="auth_log_status",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_auth_logs_timestamp"), "auth_logs", ["timestamp"], unique=False)
    op.create_index(op.f("ix_auth_logs_user_id"), "auth_logs", ["user_id"], unique=False)
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_name", sa.String(length=128), nullable=False),
        sa.Column(
            "device_type",
            sa.Enum(
                "android",
                "windows",
                "ios",
                "macos",
                "linux",
                "web",
                "other",
                name="device_type",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_devices_user_id"), "devices", ["user_id"], unique=False)
    op.create_table(
        "credentials",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("credential_id", sa.String(length=512), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("last_used", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_credentials_credential_id"), "credentials", ["credential_id"], unique=True
    )
    op.create_index(op.f("ix_credentials_device_id"), "credentials", ["device_id"], unique=True)
    op.create_index(op.f("ix_credentials_user_id"), "credentials", ["user_id"], unique=False)


def downgrade() -> None:
    """Удалить всю схему."""
    op.drop_index(op.f("ix_credentials_user_id"), table_name="credentials")
    op.drop_index(op.f("ix_credentials_device_id"), table_name="credentials")
    op.drop_index(op.f("ix_credentials_credential_id"), table_name="credentials")
    op.drop_table("credentials")
    op.drop_index(op.f("ix_devices_user_id"), table_name="devices")
    op.drop_table("devices")
    op.drop_index(op.f("ix_auth_logs_user_id"), table_name="auth_logs")
    op.drop_index(op.f("ix_auth_logs_timestamp"), table_name="auth_logs")
    op.drop_table("auth_logs")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
