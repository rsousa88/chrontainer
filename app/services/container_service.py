from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

import docker

from app.repositories import ContainerTagRepository, LogsRepository, ScheduleRepository, WebuiUrlRepository
from app.services.docker_service import DockerService
from app.services.notification_service import NotificationService


@dataclass
class ContainerActionResult:
    success: bool
    message: str


class ContainerService:
    """Container business logic."""

    def __init__(
        self,
        docker_service: DockerService,
        logs_repo: LogsRepository,
        schedule_repo: ScheduleRepository,
        notification_service: NotificationService,
        container_tag_repo: ContainerTagRepository,
        webui_url_repo: WebuiUrlRepository,
    ):
        self._docker_service = docker_service
        self._logs_repo = logs_repo
        self._schedule_repo = schedule_repo
        self._notification_service = notification_service
        self._container_tag_repo = container_tag_repo
        self._webui_url_repo = webui_url_repo

    def resolve_container(self, docker_client, container_id, container_name=None):
        try:
            return docker_client.containers.get(container_id), False
        except docker.errors.NotFound:
            pass
        except Exception:
            pass

        if not container_name:
            return None, False

        try:
            matches = docker_client.containers.list(all=True, filters={'name': container_name}) or []
            for candidate in matches:
                if candidate.name == container_name:
                    return candidate, True
            if len(matches) == 1:
                return matches[0], True
        except Exception:
            return None, False

        return None, False

    def update_schedule_container_id(self, schedule_id, container_id):
        if not schedule_id or not container_id:
            return
        try:
            self._schedule_repo.update_container_id(schedule_id, container_id)
        except Exception:
            return

    def update_schedule_container_name(self, host_id: int, container_id: str, old_name: str, new_name: str) -> int:
        try:
            return self._schedule_repo.update_container_name(host_id, container_id, old_name, new_name)
        except Exception:
            return 0

    def disable_container_schedules(self, container_id: str, container_name: str, host_id: int) -> int:
        try:
            return self._schedule_repo.disable_by_container(host_id, container_id, container_name)
        except Exception:
            return 0

    def update_schedule_last_run(self, schedule_id: Optional[int]) -> None:
        if not schedule_id:
            return
        try:
            self._schedule_repo.update_last_run(schedule_id, datetime.now())
        except Exception:
            return

    def log_action(self, schedule_id, container_name, action, status, message, host_id):
        try:
            self._logs_repo.insert_action_log(
                schedule_id=schedule_id,
                container_name=container_name,
                action=action,
                status=status,
                message=message,
                host_id=host_id,
            )
        except Exception:
            return

    def _notify(self, container_name, action, status, message, schedule_id):
        self._notification_service.send_discord_notification(container_name, action, status, message, schedule_id)
        self._notification_service.send_ntfy_notification(container_name, action, status, message, schedule_id)

    def restart_container(self, container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, resolved_by_name = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")
            container.restart()
            if resolved_by_name:
                self.update_schedule_container_id(schedule_id, container.id[:12])
            message = f"Container {container_name} restarted successfully"
            self.log_action(schedule_id, container_name, 'restart', 'success', message, host_id)
            self._notify(container_name, 'restart', 'success', message, schedule_id)
            self.update_schedule_last_run(schedule_id)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to restart container {container_name}: {str(e)}"
            self.log_action(schedule_id, container_name, 'restart', 'error', message, host_id)
            self._notify(container_name, 'restart', 'error', message, schedule_id)
            return ContainerActionResult(False, message)

    def start_container(self, container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, resolved_by_name = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")
            container.start()
            if resolved_by_name:
                self.update_schedule_container_id(schedule_id, container.id[:12])
            message = f"Container {container_name} started successfully"
            self.log_action(schedule_id, container_name, 'start', 'success', message, host_id)
            self._notify(container_name, 'start', 'success', message, schedule_id)
            self.update_schedule_last_run(schedule_id)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to start container {container_name}: {str(e)}"
            self.log_action(schedule_id, container_name, 'start', 'error', message, host_id)
            self._notify(container_name, 'start', 'error', message, schedule_id)
            return ContainerActionResult(False, message)

    def stop_container(self, container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, resolved_by_name = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")
            container.stop()
            if resolved_by_name:
                self.update_schedule_container_id(schedule_id, container.id[:12])
            message = f"Container {container_name} stopped successfully"
            self.log_action(schedule_id, container_name, 'stop', 'success', message, host_id)
            self._notify(container_name, 'stop', 'success', message, schedule_id)
            self.update_schedule_last_run(schedule_id)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to stop container {container_name}: {str(e)}"
            self.log_action(schedule_id, container_name, 'stop', 'error', message, host_id)
            self._notify(container_name, 'stop', 'error', message, schedule_id)
            return ContainerActionResult(False, message)

    def pause_container(self, container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, resolved_by_name = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")
            container.pause()
            if resolved_by_name:
                self.update_schedule_container_id(schedule_id, container.id[:12])
            message = f"Container {container_name} paused successfully"
            self.log_action(schedule_id, container_name, 'pause', 'success', message, host_id)
            self._notify(container_name, 'pause', 'success', message, schedule_id)
            self.update_schedule_last_run(schedule_id)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to pause container {container_name}: {str(e)}"
            self.log_action(schedule_id, container_name, 'pause', 'error', message, host_id)
            self._notify(container_name, 'pause', 'error', message, schedule_id)
            return ContainerActionResult(False, message)

    def unpause_container(self, container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, resolved_by_name = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")
            container.unpause()
            if resolved_by_name:
                self.update_schedule_container_id(schedule_id, container.id[:12])
            message = f"Container {container_name} unpaused successfully"
            self.log_action(schedule_id, container_name, 'unpause', 'success', message, host_id)
            self._notify(container_name, 'unpause', 'success', message, schedule_id)
            self.update_schedule_last_run(schedule_id)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to unpause container {container_name}: {str(e)}"
            self.log_action(schedule_id, container_name, 'unpause', 'error', message, host_id)
            self._notify(container_name, 'unpause', 'error', message, schedule_id)
            return ContainerActionResult(False, message)

    def delete_container(self, container_id: str, container_name: str, remove_volumes: bool = False, force: bool = False, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, _ = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")

            container.reload()
            if container.status == 'running' and not force:
                container.stop()

            container.remove(v=remove_volumes, force=force)

            disabled = self.disable_container_schedules(container.id, container_name, host_id)

            message = f"Container {container_name} deleted successfully"
            if remove_volumes:
                message += " (volumes removed)"
            if disabled:
                message += f"; disabled {disabled} schedule(s)"

            self.log_action(None, container_name, 'delete', 'success', message, host_id)
            self._notify(container_name, 'delete', 'success', message, None)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to delete container {container_name}: {str(e)}"
            self.log_action(None, container_name, 'delete', 'error', message, host_id)
            self._notify(container_name, 'delete', 'error', message, None)
            return ContainerActionResult(False, message)

    def rename_container(self, container_id: str, container_name: str, new_name: str, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, _ = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")

            container.rename(new_name)
            updated = self.update_schedule_container_name(host_id, container.id, container_name, new_name)

            message = f"Container {container_name} renamed to {new_name}"
            if updated:
                message += f"; updated {updated} schedule(s)"

            self.log_action(None, container_name, 'rename', 'success', message, host_id)
            self._notify(container_name, 'rename', 'success', message, None)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to rename container {container_name}: {str(e)}"
            self.log_action(None, container_name, 'rename', 'error', message, host_id)
            self._notify(container_name, 'rename', 'error', message, None)
            return ContainerActionResult(False, message)

    def clone_container(self, container_id: str, container_name: str, new_name: str, start_after: bool = True, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception(f"Cannot connect to Docker host {host_id}")

            container, _ = self.resolve_container(docker_client, container_id, container_name)
            if not container:
                raise docker.errors.NotFound(f"No such container: {container_id}")

            container.reload()
            attrs = container.attrs or {}
            config = attrs.get('Config', {}) or {}
            host_config = attrs.get('HostConfig', {}) or {}

            image = (container.image.tags[0] if container.image.tags else config.get('Image'))
            if not image:
                raise Exception("Source image not available for clone")

            exposed_ports = config.get('ExposedPorts') or {}
            port_bindings = host_config.get('PortBindings') or None

            new_host_config = docker.types.HostConfig(
                binds=host_config.get('Binds'),
                port_bindings=port_bindings,
                restart_policy=host_config.get('RestartPolicy'),
                network_mode=host_config.get('NetworkMode'),
                privileged=host_config.get('Privileged', False),
                cap_add=host_config.get('CapAdd'),
                cap_drop=host_config.get('CapDrop'),
                extra_hosts=host_config.get('ExtraHosts'),
                devices=host_config.get('Devices'),
            )

            create_kwargs = {
                'image': image,
                'name': new_name,
                'command': config.get('Cmd'),
                'environment': config.get('Env'),
                'labels': config.get('Labels'),
                'entrypoint': config.get('Entrypoint'),
                'working_dir': config.get('WorkingDir'),
                'user': config.get('User'),
                'hostname': config.get('Hostname'),
                'domainname': config.get('Domainname'),
                'host_config': new_host_config,
            }

            if exposed_ports:
                create_kwargs['ports'] = list(exposed_ports.keys())

            new_container = docker_client.api.create_container(**create_kwargs)
            new_container_id = new_container.get('Id')

            if start_after:
                docker_client.api.start(new_container_id)

            message = f"Container {container_name} cloned to {new_name}"
            self.log_action(None, container_name, 'clone', 'success', message, host_id)
            self._notify(container_name, 'clone', 'success', message, None)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to clone container {container_name}: {str(e)}"
            self.log_action(None, container_name, 'clone', 'error', message, host_id)
            self._notify(container_name, 'clone', 'error', message, None)
            return ContainerActionResult(False, message)

    def update_container(self, container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> ContainerActionResult:
        try:
            docker_client = self._docker_service.get_client(host_id)
            if not docker_client:
                raise Exception("Cannot connect to Docker host")

            container = docker_client.containers.get(container_id)
            attrs = container.attrs
            image_name = attrs.get('Config', {}).get('Image', '')

            if not image_name:
                return ContainerActionResult(False, "Unable to determine container image")

            config = attrs.get('Config', {})
            host_config = attrs.get('HostConfig', {})

            container_settings = {
                'name': container.name,
                'image': image_name,
                'command': config.get('Cmd'),
                'environment': config.get('Env', []),
                'volumes': host_config.get('Binds', []),
                'ports': config.get('ExposedPorts', {}),
                'labels': config.get('Labels', {}),
                'restart_policy': host_config.get('RestartPolicy', {}),
                'network_mode': host_config.get('NetworkMode'),
                'detach': True,
            }

            container.stop(timeout=10)
            container.remove()

            docker_client.images.pull(image_name)

            docker_client.containers.run(**container_settings)

            message = f"Container {container_name} updated successfully"
            self.log_action(schedule_id, container_name, 'update', 'success', message, host_id)
            self._notify(container_name, 'update', 'success', message, schedule_id)
            self.update_schedule_last_run(schedule_id)
            return ContainerActionResult(True, message)
        except Exception as e:
            message = f"Failed to update container {container_name}: {str(e)}"
            self.log_action(schedule_id, container_name, 'update', 'error', message, host_id)
            self._notify(container_name, 'update', 'error', message, schedule_id)
            return ContainerActionResult(False, message)
