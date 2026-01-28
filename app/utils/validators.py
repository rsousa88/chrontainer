"""Validation helpers for Chrontainer."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from apscheduler.triggers.cron import CronTrigger


def validate_container_id(container_id: str) -> Tuple[bool, str]:
    """Validate Docker container ID format (12 or 64 hex chars)."""
    if not container_id:
        return False, "Container ID is required"
    if not isinstance(container_id, str):
        return False, "Container ID must be a string"
    if not re.match(r'^[a-f0-9]{12}$|^[a-f0-9]{64}$', container_id.lower()):
        return False, "Container ID must be 12 or 64 hexadecimal characters"
    return True, ""


def validate_host_id(host_id: Any) -> Tuple[bool, str]:
    """Validate Docker host ID."""
    if host_id is None:
        return False, "Host ID is required"
    try:
        host_id_int = int(host_id)
        if host_id_int < 1:
            return False, "Host ID must be a positive integer"
        return True, ""
    except (ValueError, TypeError):
        return False, "Host ID must be a valid integer"


def validate_cron_expression(expression: str) -> Tuple[bool, str]:
    """Validate cron expression format."""
    if not expression:
        return False, "Cron expression is required"
    if not isinstance(expression, str):
        return False, "Cron expression must be a string"
    try:
        CronTrigger.from_crontab(expression)
        return True, ""
    except Exception as exc:
        return False, f"Invalid cron expression: {str(exc)}"


def validate_action(action: str) -> Tuple[bool, str]:
    """Validate container action type."""
    valid_actions = ['restart', 'start', 'stop', 'pause', 'unpause', 'update', 'delete', 'rename', 'clone']
    if not action:
        return False, "Action is required"
    if not isinstance(action, str):
        return False, "Action must be a string"
    if action.lower() not in valid_actions:
        return False, f"Action must be one of: {', '.join(valid_actions)}"
    return True, ""


def validate_container_name(name: str) -> Tuple[bool, str]:
    """Validate container name (Docker naming rules)."""
    if not name:
        return False, "Container name is required"
    if not isinstance(name, str):
        return False, "Container name must be a string"
    if len(name) > 255:
        return False, "Container name is too long"
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]+$', name):
        return False, "Container name must start with alphanumeric and use only letters, numbers, '.', '_' or '-'"
    return True, ""


def validate_required_fields(data: Dict, required_fields: List[str]) -> Tuple[bool, str]:
    """Validate that required fields are present in a dictionary."""
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == '':
            return False, f"Missing required field: {field}"
    return True, ""


def validate_color(color: str) -> Tuple[bool, str]:
    """Validate hex color values."""
    if not color:
        return False, 'Color is required'
    if not re.match(r'^#[0-9a-fA-F]{6}$', color):
        return False, 'Color must be a hex value like #1ea7e1'
    return True, ''


def validate_url(url: str, schemes: List[str] | None = None) -> Tuple[bool, str]:
    """Validate URL format."""
    if schemes is None:
        schemes = ['http', 'https']
    if not url:
        return False, "URL is required"
    if len(url) > 2048:
        return False, "URL is too long"
    scheme_pattern = '|'.join(schemes)
    pattern = rf'^({scheme_pattern}|unix|tcp)://[^\s]+'
    if not re.match(pattern, url):
        return False, "Invalid URL format"
    return True, ""


def validate_webhook_url(url: str) -> Tuple[bool, str]:
    """Validate Discord webhook URL."""
    if not url:
        return True, ""
    if not url.startswith('https://discord.com/api/webhooks/'):
        return False, "Invalid Discord webhook URL. Must start with https://discord.com/api/webhooks/"
    return validate_url(url)


def sanitize_string(value: str, max_length: int = 255) -> str:
    """Sanitize string input."""
    if not value:
        return ""
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(value))
    return value[:max_length].strip()
