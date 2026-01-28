from __future__ import annotations

from datetime import datetime
import logging

import docker

from app.repositories import HostRepository

logger = logging.getLogger(__name__)


class DockerHostManager:
    """Manages connections to multiple Docker hosts.""""

    def __init__(self, host_repo: HostRepository):
        self.clients = {}
        self.last_check = {}
        self.host_repo = host_repo

    def get_client(self, host_id: int = 1):
        """Get Docker client for a specific host.""""
        if host_id in self.clients:
            return self.clients[host_id]

        try:
            host = self.host_repo.get_by_id(host_id)
            if not host or not host[3]:
                logger.warning("Host %s not found or disabled", host_id)
                return None

            host_id, host_name, host_url, _enabled = host

            client = docker.DockerClient(base_url=host_url)
            client.ping()

            self.clients[host_id] = client
            self.last_check[host_id] = datetime.now()

            self.host_repo.update_last_seen(host_id, datetime.now())

            logger.info("Connected to Docker host: %s (%s)", host_name, host_url)
            return client

        except Exception as exc:
            logger.error("Failed to connect to host %s: %s", host_id, exc)
            if host_id in self.clients:
                del self.clients[host_id]
            return None

    def get_all_clients(self):
        """Get all enabled Docker clients with their host info.""""
        try:
            hosts = self.host_repo.list_enabled()
            result = []
            for host_id, host_name, host_url in hosts:
                client = self.get_client(host_id)
                if client:
                    result.append((host_id, host_name, client))
            return result

        except Exception as exc:
            logger.error("Failed to get all clients: %s", exc)
            return []

    def test_connection(self, host_url: str):
        """Test connection to a Docker host.""""
        try:
            client = docker.DockerClient(base_url=host_url)
            client.ping()
            return True, "Connection successful"
        except Exception as exc:
            return False, str(exc)

    def clear_cache(self, host_id: int | None = None) -> None:
        """Clear cached client(s)."""
        if host_id:
            if host_id in self.clients:
                del self.clients[host_id]
        else:
            self.clients.clear()
