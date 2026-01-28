"""Centralized configuration for Chrontainer."""
from __future__ import annotations

import os


class Config:
    """Base configuration loaded from environment variables."""
    SECRET_KEY = os.getenv('SECRET_KEY')
    DATABASE_PATH = os.getenv('DATABASE_PATH', '/data/chrontainer.db')
    TIMEZONE = os.getenv('TZ', 'UTC')
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'false').lower() == 'true'
    PORT = int(os.getenv('PORT', '5000'))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
