"""Centralized configuration for Chrontainer."""
from __future__ import annotations

import os


class Config:
    """Base configuration loaded from environment variables."""
    SECRET_KEY = os.getenv('SECRET_KEY')
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'data/chrontainer.db')
    TIMEZONE = os.getenv('TZ', 'UTC')
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
