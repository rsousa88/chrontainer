from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Container:
    id: str
    name: str
    image: str
    status: str
    host_id: int
    created: Optional[str] = None
