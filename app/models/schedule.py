from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Schedule:
    id: int
    host_id: int
    container_id: str
    action: str
    cron_expression: str
    enabled: bool = True
    last_run: Optional[str] = None
