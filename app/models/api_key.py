from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ApiKey:
    id: int
    user_id: int
    name: str
    key_hash: str
    key_prefix: str
    permissions: str = 'read'
    last_used: Optional[str] = None
    expires_at: Optional[str] = None
    created_at: Optional[str] = None
