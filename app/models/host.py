from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Host:
    id: int
    name: str
    url: str
    enabled: bool = True
    color: Optional[str] = None
    last_seen: Optional[str] = None
