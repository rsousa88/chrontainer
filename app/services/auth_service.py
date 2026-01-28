from __future__ import annotations

from app.repositories import ApiKeyRepository, UserRepository


class AuthService:
    """Authentication and authorization logic."""

    def __init__(self, user_repo: UserRepository, api_key_repo: ApiKeyRepository):
        self._user_repo = user_repo
        self._api_key_repo = api_key_repo
