from __future__ import annotations

from app.repositories import ApiKeyRepository, UserRepository


class AuthService:
    """Authentication and authorization logic."""

    def __init__(self, user_repo: UserRepository, api_key_repo: ApiKeyRepository):
        self._user_repo = user_repo
        self._api_key_repo = api_key_repo

    def get_user_by_id(self, user_id: int):
        return self._user_repo.get_by_id(user_id)

    def get_api_key_record(self, key_hash: str):
        return self._api_key_repo.get_auth_record(key_hash)

    def touch_api_key(self, key_id: int) -> None:
        self._api_key_repo.touch_last_used(key_id)
