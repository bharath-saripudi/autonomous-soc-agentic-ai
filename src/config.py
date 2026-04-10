"""Centralized configuration loaded from environment variables."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """All config pulled from .env / environment variables."""

    # ── Anthropic ──
    anthropic_api_key: str = ""

    # ── PostgreSQL ──
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "soc_db"
    db_user: str = "soc_user"
    db_password: str = "soc_secret_2024"
    database_url: str = "postgresql+asyncpg://soc_user:soc_secret_2024@localhost:5432/soc_db"

    # ── Redis ──
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_url: str = "redis://localhost:6379/0"

    # ── Qdrant ──
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333

    # ── Threat Intel APIs ──
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── Application ──
    soc_api_host: str = "0.0.0.0"
    soc_api_port: int = 8000
    log_level: str = "INFO"

    # ── Kafka ──
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "security-alerts"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()