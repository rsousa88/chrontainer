from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Webhook:
    id: int
    name: str
    token: str
    action: str
    container_id: Optional[str] = None
    host_id: Optional[int] = None
    enabled: int = 1
    locked: int = 0
    last_triggered: Optional[str] = None
    trigger_count: int = 0
    created_at: Optional[str] = None
