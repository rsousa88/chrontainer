from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Container:
    id: str
    name: str
    image: str
    status: str
    host_id: int
    created: Optional[str] = None
    tags: list[dict] = field(default_factory=list)
    webui_url: Optional[str] = None
    update_status: Optional[dict] = None


@dataclass
class Schedule:
    id: int
    host_id: int
    container_id: str
    container_name: str
    action: str
    cron_expression: str
    enabled: bool = True
    one_time: bool = False
    run_at: Optional[datetime] = None
    last_run: Optional[datetime] = None


@dataclass
class Host:
    id: int
    name: str
    url: str
    enabled: bool = True
    color: Optional[str] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None


@dataclass
class User:
    id: int
    username: str
    role: str
    created_at: Optional[datetime] = None


@dataclass
class Image:
    id: str
    repository: str
    tag: str
    host_id: int
    size_bytes: Optional[int] = None
    containers: Optional[int] = None
    created: Optional[int] = None


@dataclass
class ApiKey:
    id: int
    user_id: int
    key_hash: str
    permissions: str
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


@dataclass
class Webhook:
    id: int
    name: str
    token: str
    container_id: Optional[str]
    host_id: Optional[int]
    action: str
    enabled: bool = True
    locked: bool = False
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    created_at: Optional[datetime] = None
