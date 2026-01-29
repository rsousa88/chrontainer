from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

import docker


class ImageService:
    """Image listing and cache management."""

    def __init__(
        self,
        *,
        docker_manager,
        host_repo,
        logger,
        host_default_color: str,
        get_contrast_text_color,
        split_image_reference,
        extract_repository_from_digest,
        get_cached_disk_usage,
        refresh_disk_usage_async,
        cache_ttl_seconds: int,
    ):
        self._docker_manager = docker_manager
        self._host_repo = host_repo
        self._logger = logger
        self._host_default_color = host_default_color
        self._get_contrast_text_color = get_contrast_text_color
        self._split_image_reference = split_image_reference
        self._extract_repository_from_digest = extract_repository_from_digest
        self._get_cached_disk_usage = get_cached_disk_usage
        self._refresh_disk_usage_async = refresh_disk_usage_async
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache = {}
        self._cache_lock = threading.RLock()
        self._inflight = set()
        self._inflight_lock = threading.Lock()

    def _get_host_color_maps(self):
        host_color_map = {}
        host_text_color_map = {}

        for host_id_row, color in self._host_repo.list_colors():
            resolved_color = color or self._host_default_color
            host_color_map[host_id_row] = resolved_color
            host_text_color_map[host_id_row] = self._get_contrast_text_color(resolved_color)

        return host_color_map, host_text_color_map

    def set_cached_image_usage(self, host_id: int, data: Dict[str, Any]) -> None:
        with self._cache_lock:
            self._cache[host_id] = {'timestamp': time.time(), 'data': data}

    def get_cached_image_usage(self, host_id: int) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            cached = self._cache.get(host_id)
            if not cached:
                return None
            if time.time() - cached['timestamp'] > self._cache_ttl_seconds:
                return None
            return cached['data']

    def refresh_image_usage_async(self, host_id: int, client: docker.DockerClient, host_name: str) -> None:
        def run():
            try:
                data = client.api.df()
                if data:
                    self.set_cached_image_usage(host_id, data)
            except Exception as error:
                self._logger.debug("Image usage refresh failed for host %s: %s", host_name, error)
            finally:
                with self._inflight_lock:
                    self._inflight.discard(host_id)

        with self._inflight_lock:
            if host_id in self._inflight:
                return
            self._inflight.add(host_id)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def clear_image_usage_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def fetch_all_images(self) -> list[dict[str, Any]]:
        image_list = []
        host_color_map, host_text_color_map = self._get_host_color_maps()

        for host_id, host_name, docker_client in self._docker_manager.get_all_clients():
            df_images = {}
            cached_df = self.get_cached_image_usage(host_id)
            cached_from_images = cached_df is not None
            if not cached_df:
                cached_df = self._get_cached_disk_usage(host_id)
            if cached_df:
                df_images = {entry.get('Id'): entry for entry in (cached_df.get('Images', []) or [])}
            if not cached_from_images:
                self.refresh_image_usage_async(host_id, docker_client, host_name)

            host_color = host_color_map.get(host_id, self._host_default_color)
            host_text_color = host_text_color_map.get(host_id, self._get_contrast_text_color(host_color))

            container_repo_map = {}
            container_count_map = {}
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    try:
                        image_id = container.image.id
                        if not image_id:
                            continue
                        container_count_map[image_id] = container_count_map.get(image_id, 0) + 1
                        image_name = None
                        if container.image.tags:
                            image_name = container.image.tags[0]
                        else:
                            image_name = container.attrs.get('Config', {}).get('Image')
                        if image_name:
                            repo, _ = self._split_image_reference(image_name)
                            container_repo_map[image_id] = repo or container_repo_map.get(image_id)
                    except Exception:
                        continue
            except Exception as error:
                self._logger.debug("Failed to map container images for host %s: %s", host_name, error)

            if df_images:
                for entry in df_images.values():
                    image_id = entry.get('Id') or ''
                    short_id = image_id.replace('sha256:', '')[:12]
                    created = entry.get('Created')
                    size = entry.get('Size')
                    shared_size = entry.get('SharedSize')
                    containers_count = entry.get('Containers')
                    if containers_count is None:
                        containers_count = container_count_map.get(image_id)
                    if containers_count is not None and containers_count < 0:
                        containers_count = None
                    repo_tags = entry.get('RepoTags') or []
                    repo_digests = entry.get('RepoDigests') or []
                    if not repo_tags:
                        repo_tags = ['(none):(none)']

                    for tag in repo_tags:
                        repository, tag_name = self._split_image_reference(tag)
                        if repository in ('', '(none)') and repo_digests:
                            digest_repo = self._extract_repository_from_digest(repo_digests[0])
                            repository = digest_repo or '(none)'
                        if repository in ('', '(none)'):
                            repository = container_repo_map.get(image_id) or repository
                        repository = repository or '(none)'
                        image_list.append({
                            'id': image_id,
                            'short_id': short_id,
                            'image_id': image_id,
                            'repository': repository,
                            'tag': tag_name,
                            'full_name': tag,
                            'size_bytes': size,
                            'shared_size_bytes': shared_size,
                            'containers': containers_count,
                            'created': created,
                            'host_id': host_id,
                            'host_name': host_name,
                            'host_color': host_color,
                            'host_text_color': host_text_color,
                        })
                continue

            try:
                images = docker_client.api.images(all=True)
                for entry in images:
                    image_id = entry.get('Id') or ''
                    short_id = image_id.replace('sha256:', '')[:12]
                    created = entry.get('Created')
                    size = entry.get('Size')
                    shared_size = entry.get('SharedSize')
                    containers_count = entry.get('Containers')
                    if containers_count is None:
                        containers_count = container_count_map.get(image_id)
                    if containers_count is not None and containers_count < 0:
                        containers_count = None
                    repo_tags = entry.get('RepoTags') or []
                    repo_digests = entry.get('RepoDigests') or []
                    if not repo_tags:
                        repo_tags = ['(none):(none)']

                    for tag in repo_tags:
                        repository, tag_name = self._split_image_reference(tag)
                        if repository in ('', '(none)') and repo_digests:
                            digest_repo = self._extract_repository_from_digest(repo_digests[0])
                            repository = digest_repo or '(none)'
                        if repository in ('', '(none)'):
                            repository = container_repo_map.get(image_id) or repository
                        repository = repository or '(none)'
                        image_list.append({
                            'id': image_id,
                            'short_id': short_id,
                            'image_id': image_id,
                            'repository': repository,
                            'tag': tag_name,
                            'full_name': tag,
                            'size_bytes': size,
                            'shared_size_bytes': shared_size,
                            'containers': containers_count,
                            'created': created,
                            'host_id': host_id,
                            'host_name': host_name,
                            'host_color': host_color,
                            'host_text_color': host_text_color,
                        })
            except Exception as error:
                self._logger.error("Error getting images from host %s: %s", host_name, error)

        return image_list
