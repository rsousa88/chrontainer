#!/usr/bin/env python3
"""Chrontainer v1.0 migration helper.

This script is intentionally conservative: it backs up the SQLite DB, ensures
schema tables exist, and applies safe idempotent updates.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import sqlite3
import sys

from app.config import Config
from app.db import init_db


def resolve_db_path(cli_path: str | None) -> str:
    if cli_path:
        return cli_path
    return os.getenv("DATABASE_PATH", Config.DATABASE_PATH)


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def backup_db(db_path: str, backup_dir: str | None) -> str | None:
    if not os.path.exists(db_path):
        return None
    timestamp = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup_dir = backup_dir or os.path.join(os.path.dirname(db_path), "backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f"chrontainer.db.{timestamp}.bak")
    shutil.copy2(db_path, backup_path)
    return backup_path


def apply_safe_updates(db_path: str) -> None:
    """Apply idempotent data/config migrations."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Ensure settings table contains default keys expected by v1.
    defaults = {
        "discord_webhook_url": "",
        "discord_username": "",
        "discord_avatar_url": "",
        "ntfy_topic": "",
        "ntfy_access_token": "",
    }
    for key, value in defaults.items():
        cur.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )

    conn.commit()
    conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Chrontainer v1 migration helper")
    parser.add_argument(
        "--db",
        dest="db_path",
        default=None,
        help="Path to SQLite DB (defaults to DATABASE_PATH or config)",
    )
    parser.add_argument(
        "--backup-dir",
        dest="backup_dir",
        default=None,
        help="Directory to store DB backups (default: <db dir>/backups)",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip DB backup",
    )
    args = parser.parse_args()

    db_path = resolve_db_path(args.db_path)
    ensure_parent_dir(db_path)

    if not args.no_backup:
        backup_path = backup_db(db_path, args.backup_dir)
        if backup_path:
            print(f"Backup created: {backup_path}")
        else:
            print("No existing DB found; skipping backup.")

    # Ensure the schema exists (idempotent).
    os.environ["DATABASE_PATH"] = db_path
    init_db()

    # Apply safe updates.
    apply_safe_updates(db_path)

    print("Migration completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
