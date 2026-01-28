from __future__ import annotations

from app.repositories import ContainerTagRepository, WebuiUrlRepository
from app.services.docker_service import DockerService


class ContainerService:
    """Container business logic."""

    def __init__(
        self,
        docker_service: DockerService,
        container_tag_repo: ContainerTagRepository,
        webui_url_repo: WebuiUrlRepository,
    ):
        self._docker_service = docker_service
        self._container_tag_repo = container_tag_repo
        self._webui_url_repo = webui_url_repo
