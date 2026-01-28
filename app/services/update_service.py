from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

import docker
from apscheduler.triggers.cron import CronTrigger


class UpdateService:
    """Container update status and scheduling logic."""

    def __init__(
        self,
        *,
        update_status_repo,
        docker_manager,
        scheduler,
        get_setting,
        validate_cron_expression,
        logger,
        cache_ttl_seconds: int,
        update_check_cron_default: str,
    ):
        self._update_status_repo = update_status_repo
        self._docker_manager = docker_manager
        self._scheduler = scheduler
        self._get_setting = get_setting
        self._validate_cron_expression = validate_cron_expression
        self._logger = logger
        self._cache_ttl_seconds = cache_ttl_seconds
        self._update_check_cron_default = update_check_cron_default
        self._cache = {}
        self._cache_lock = threading.RLock()

    def get_cached_update_status(self, container_id, host_id):
        with self._cache_lock:
            entry = self._cache.get((container_id, host_id))
            if not entry:
                return None
            if time.time() - entry['timestamp'] > self._cache_ttl_seconds:
                return None
            return entry['data']

    def set_cached_update_status(self, container_id, host_id, data):
        with self._cache_lock:
            self._cache[(container_id, host_id)] = {
                'timestamp': time.time(),
                'data': data,
            }

    def write_update_status(self, container_id, host_id, payload):
        self.set_cached_update_status(container_id, host_id, payload)
        try:
            self._update_status_repo.upsert(
                container_id=container_id,
                host_id=host_id,
                has_update=bool(payload.get('has_update')),
                remote_digest=payload.get('remote_digest'),
                error=payload.get('error'),
                note=payload.get('note'),
                checked_at=payload.get('checked_at'),
            )
        except Exception as error:
            self._logger.warning(
                "Failed to persist update status for %s/%s: %s",
                host_id,
                container_id,
                error,
            )

    def load_update_status_map(self):
        try:
            rows = self._update_status_repo.list_all()
        except Exception as error:
            self._logger.warning("Failed to load cached update status: %s", error)
            return {}

        status_map = {}
        for container_id, host_id, has_update, remote_digest, error, note, checked_at in rows:
            status_map[(container_id, host_id)] = {
                'has_update': bool(has_update),
                'remote_digest': remote_digest,
                'error': error,
                'note': note,
                'checked_at': checked_at,
            }
        return status_map

    def check_for_update(self, container, client) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Check if a container has an update available.

        Returns:
            Tuple of (has_update, remote_digest, error, note)
        """
        try:
            image_name = container.image.tags[0] if container.image.tags else container.attrs.get('Config', {}).get('Image', '')

            if not image_name or ':' not in image_name:
                return False, None, "Unable to determine image tag", None

            local_image = container.image
            local_digest = local_image.attrs.get('RepoDigests', [])
            if not local_digest:
                return False, None, None, "No local digest"
            local_digest = local_digest[0].split('@')[1] if '@' in local_digest[0] else None

            try:
                registry_data = client.images.get_registry_data(image_name)
                remote_digest = registry_data.attrs.get('Descriptor', {}).get('digest')

                if not remote_digest or not local_digest:
                    return False, None, None, "Digest missing"

                has_update = (remote_digest != local_digest)
                return has_update, remote_digest, None, None

            except docker.errors.APIError as error:
                message = str(error)
                if 'distribution' in message and 'Forbidden' in message:
                    return False, None, "Registry error: socket-proxy forbids distribution endpoint. Enable DISTRIBUTION=1.", None
                return False, None, f"Registry error: {message}", None

        except Exception as error:
            self._logger.error("Error checking for update: %s", error)
            return False, None, str(error), None

    def run_update_check_job(self):
        """System job that refreshes update status for all containers."""
        try:
            for host_id, host_name, docker_client in self._docker_manager.get_all_clients():
                try:
                    containers = docker_client.containers.list(all=True)
                    for container in containers:
                        container_id = container.id[:12]
                        has_update, remote_digest, error, note = self.check_for_update(container, docker_client)
                        payload = {
                            'has_update': has_update,
                            'remote_digest': remote_digest,
                            'error': error,
                            'note': note,
                            'checked_at': datetime.utcnow().isoformat(),
                        }
                        self.write_update_status(container_id, host_id, payload)
                except Exception as error:
                    self._logger.error("Scheduled update check failed for host %s: %s", host_name, error)
            self._logger.info("Scheduled update check completed")
        except Exception as error:
            self._logger.error("Scheduled update check failed: %s", error)

    def configure_update_check_schedule(self):
        """Configure or disable the system update-check job."""
        job_id = 'system_update_check'
        try:
            self._scheduler.remove_job(job_id)
        except Exception as error:
            self._logger.debug("Could not remove job %s (may not exist): %s", job_id, error)

        enabled_setting = self._get_setting('update_check_enabled', 'true').lower()
        cron_expression = self._get_setting('update_check_cron', self._update_check_cron_default)
        enabled = enabled_setting == 'true'

        if not enabled:
            return

        valid, error = self._validate_cron_expression(cron_expression)
        if not valid:
            self._logger.warning("Invalid update-check cron expression %s: %s", cron_expression, error)
            return

        parts = cron_expression.split()
        trigger = CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4],
        )
        self._scheduler.add_job(self.run_update_check_job, trigger, id=job_id, replace_existing=True)
