from __future__ import annotations

from typing import Any, Dict, Optional


class ContainerQueryService:
    """Container listing and stats cache logic."""

    def __init__(
        self,
        *,
        docker_manager,
        host_repo,
        container_tag_repo,
        webui_url_repo,
        update_service,
        host_default_color: str,
        get_contrast_text_color,
        strip_image_tag,
        get_image_links,
    ):
        self._docker_manager = docker_manager
        self._host_repo = host_repo
        self._container_tag_repo = container_tag_repo
        self._webui_url_repo = webui_url_repo
        self._update_service = update_service
        self._host_default_color = host_default_color
        self._get_contrast_text_color = get_contrast_text_color
        self._strip_image_tag = strip_image_tag
        self._get_image_links = get_image_links
        # no caching needed for container listing

    def _get_host_color_maps(self):
        host_color_map = {}
        host_text_color_map = {}

        for host_id_row, color in self._host_repo.list_colors():
            resolved_color = color or self._host_default_color
            host_color_map[host_id_row] = resolved_color
            host_text_color_map[host_id_row] = self._get_contrast_text_color(resolved_color)

        return host_color_map, host_text_color_map

    def fetch_all_containers(self) -> list[dict[str, Any]]:
        container_list = []
        host_color_map, host_text_color_map = self._get_host_color_maps()

        for host_id, host_name, docker_client in self._docker_manager.get_all_clients():
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    if container.image.tags:
                        image_name = container.image.tags[0]
                    else:
                        try:
                            image_name = container.attrs['Config']['Image']
                        except Exception:
                            image_name = container.image.short_id.replace('sha256:', '')

                    labels = container.attrs.get('Config', {}).get('Labels', {}) or {}
                    stack_name = None
                    if labels:
                        if 'com.docker.compose.project' in labels:
                            stack_name = labels['com.docker.compose.project']
                        elif 'com.docker.swarm.service.name' in labels:
                            stack_name = labels['com.docker.swarm.service.name']

                    webui_url_from_label = labels.get('dockpeek.link') or labels.get('dockpeek.webui')
                    if webui_url_from_label:
                        webui_url_from_label = webui_url_from_label.strip()

                    ip_addresses = []
                    networks = container.attrs.get('NetworkSettings', {}).get('Networks', {}) or {}
                    for network in networks.values():
                        ip_address = network.get('IPAddress')
                        if ip_address:
                            ip_addresses.append(ip_address)

                    health_status = None
                    try:
                        health = container.attrs.get('State', {}).get('Health', {})
                        if health:
                            health_status = health.get('Status')
                    except Exception:
                        pass

                    state = container.attrs.get('State', {}) or {}
                    status = state.get('Status') or container.status
                    exit_code = state.get('ExitCode')
                    status_display = status
                    status_class = status
                    if status == 'exited' and exit_code not in (None, 0):
                        status_display = 'error'
                        status_class = 'error'

                    image_display = self._strip_image_tag(image_name)
                    host_color = host_color_map.get(host_id, self._host_default_color)
                    host_text_color = host_text_color_map.get(host_id, self._get_contrast_text_color(host_color))

                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': status,
                        'status_display': status_display,
                        'status_class': status_class,
                        'exit_code': exit_code,
                        'health': health_status,
                        'image': image_name,
                        'image_display': image_display,
                        'created': container.attrs.get('Created'),
                        'host_id': host_id,
                        'host_name': host_name,
                        'host_color': host_color,
                        'host_text_color': host_text_color,
                        'ip_addresses': ', '.join(ip_addresses) if ip_addresses else 'N/A',
                        'stack': stack_name,
                        'webui_url_label': webui_url_from_label,
                    })
            except Exception:
                continue

        tags_map = {}
        for row in self._container_tag_repo.list_all():
            key = (row[0], row[1])
            if key not in tags_map:
                tags_map[key] = []
            tags_map[key].append({'id': row[2], 'name': row[3], 'color': row[4]})

        webui_map = {}
        for row in self._webui_url_repo.list_all():
            webui_map[(row[0], row[1])] = row[2]

        update_status_map = self._update_service.load_update_status_map()

        for container in container_list:
            key = (container['id'], container['host_id'])
            container['tags'] = tags_map.get(key, [])
            container['webui_url'] = webui_map.get(key) or container.get('webui_url_label')
            container['image_links'] = self._get_image_links(container['image'])
            cached_status = update_status_map.get(key)
            if cached_status:
                container['update_status'] = cached_status

        return container_list
