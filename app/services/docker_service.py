from __future__ import annotations

from typing import Dict

from app.services.docker_hosts import DockerHostManager


class DockerService:
    """Service wrapper for Docker host operations."""

    def __init__(self, docker_manager: DockerHostManager):
        self._docker_manager = docker_manager

    def get_all_clients(self) -> Dict[int, object]:
        return self._docker_manager.get_all_clients()

    def get_client(self, host_id: int):
        return self._docker_manager.get_client(host_id)
