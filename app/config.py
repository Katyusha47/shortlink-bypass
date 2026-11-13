"""Application configuration and runtime settings."""

from pydantic import BaseModel, Field
import os


class Settings(BaseModel):
    # Application Info
    APP_NAME: str = "Universal Shortlink Bypasser"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Fast, lightweight, privacy-focused URL shortener and link-gating resolution platform."
    SITE_URL: str = os.getenv("SITE_URL", "http://localhost:8000")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # Network & Resolution Limits
    DEFAULT_TIMEOUT_SECONDS: float = 8.0
    MAX_REDIRECT_HOPS: int = 10
    MAX_RESPONSE_BODY_BYTES: int = 2 * 1024 * 1024  # 2 MB max body read
    USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 (Compatible ShortlinkBypasser/1.0)"
    )

    # Security & SSRF
    ALLOW_PRIVATE_IPS: bool = False
    BLOCKED_PORTS: list[int] = Field(
        default_factory=lambda: [
            21, 22, 23, 25, 53, 69, 110, 111, 135, 137, 138, 139, 143, 389, 445,
            636, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017
        ]
    )

    # Rate Limiting (in-memory token bucket / sliding window)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 30
    RATE_LIMIT_BURST: int = 10

    # Cache Settings
    CACHE_ENABLED: bool = True
    CACHE_TTL_SECONDS: int = 600  # 10 minutes
    CACHE_MAX_ENTRIES: int = 1000


settings = Settings()

