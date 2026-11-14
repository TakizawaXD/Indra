"""
GOJO INFINITY SECURITY ∞ — CONFIGURATION MANAGEMENT
Provides centralized configuration with environment overrides and defaults suitable for Termux.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import os

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    # System Identity
    APP_NAME: str = "INDRA INFINITY SECURITY ∞"
    APP_VERSION: str = "1.0.0"
    APP_SLOGAN: str = "Nothing gets through Infinity."
    CREATOR: str = "Takizawa"
    TARGET_ENTITY: str = "Indra"
    ENVIRONMENT: str = Field(default="production", validation_alias="GOJO_ENV")
    DEBUG: bool = Field(default=False, validation_alias="GOJO_DEBUG")

    # Paths
    BASE_DIR: Path = BASE_DIR
    DB_DIR: Path = BASE_DIR / "database"
    LOGS_DIR: Path = BASE_DIR / "logs"
    REPORTS_DIR: Path = BASE_DIR / "reports"
    BACKUPS_DIR: Path = BASE_DIR / "backups"
    QUARANTINE_DIR: Path = BASE_DIR / "quarantine"
    CONFIG_DIR: Path = BASE_DIR / "config"

    # Database
    DATABASE_URL: str = Field(
        default=f"sqlite:///{BASE_DIR / 'database' / 'gojo_infinity.db'}",
        validation_alias="DATABASE_URL"
    )

    # Server Configuration (Termux localhost default)
    HOST: str = Field(default="127.0.0.1", validation_alias="GOJO_HOST")
    PORT: int = Field(default=8000, validation_alias="GOJO_PORT")
    SECRET_KEY: str = Field(
        default="satoru_gojo_infinity_boundless_domain_expansion_key_2026",
        validation_alias="GOJO_SECRET_KEY"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # Six Eyes AI (Optional external AI assistant)
    AI_ENABLED: bool = Field(default=False, validation_alias="GOJO_AI_ENABLED")
    AI_PROVIDER: str = Field(default="offline", validation_alias="GOJO_AI_PROVIDER")  # offline, gemini, openai
    AI_API_KEY: str = Field(default="", validation_alias="GOJO_AI_KEY")

    # Infinity Shield Defaults
    INFINITY_SHIELD_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 120
    IP_BAN_DURATION_SECONDS: int = 1800  # 30 minutes
    MAX_LOGIN_ATTEMPTS: int = 5

    # Network Engine Constraints
    DEFAULT_SCAN_TIMEOUT: float = 1.5
    MAX_CONCURRENT_SOCKETS: int = 64  # safe for mobile Termux limits
    DNS_RESOLVERS: list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Singleton Settings Instance
settings = Settings()

# Ensure directories exist
for path in [
    settings.DB_DIR,
    settings.LOGS_DIR,
    settings.REPORTS_DIR,
    settings.BACKUPS_DIR,
    settings.QUARANTINE_DIR,
    settings.CONFIG_DIR
]:
    path.mkdir(parents=True, exist_ok=True)
