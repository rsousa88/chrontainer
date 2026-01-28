from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    role: str
    created_at: Optional[str] = None
