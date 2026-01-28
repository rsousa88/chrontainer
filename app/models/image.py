from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Image:
    id: str
    repository: Optional[str]
    tag: Optional[str]
    size: Optional[int]
    created: Optional[str]
    host_id: int
