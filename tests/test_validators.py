"""Tests for validation helpers."""

from app.utils import validators


def test_validate_url_accepts_http():
    valid, error = validators.validate_url('https://example.com')
    assert valid is True
    assert error == ''


def test_validate_url_rejects_invalid():
    valid, error = validators.validate_url('not-a-url')
    assert valid is False
    assert 'Invalid URL format' in error


def test_validate_webhook_url_requires_discord_prefix():
    valid, error = validators.validate_webhook_url('https://example.com/hook')
    assert valid is False
    assert 'Invalid Discord webhook URL' in error


def test_validate_webhook_url_accepts_discord():
    valid, error = validators.validate_webhook_url('https://discord.com/api/webhooks/123/abc')
    assert valid is True
    assert error == ''


def test_validate_cron_expression():
    valid, error = validators.validate_cron_expression('0 2 * * *')
    assert valid is True
    assert error == ''


def test_validate_container_id():
    valid, error = validators.validate_container_id('abcdef123456')
    assert valid is True
    assert error == ''

    valid, error = validators.validate_container_id('bad')
    assert valid is False
    assert 'Container ID must be' in error
