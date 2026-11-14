"""
INDRA INFINITY SECURITY ∞ — CONFIGURATION MANAGEMENT
Provides centralized configuration with environment overrides and defaults suitable for Termux.
"""

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


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
    # Root for all runtime data (DB, logs, reports, backups, quarantine).
    DATA_DIR: Path = Field(default=BASE_DIR, validation_alias="GOJO_DATA_DIR")
    CONFIG_DIR: Path = BASE_DIR / "config"
    DB_DIR: Optional[Path] = None
    LOGS_DIR: Optional[Path] = None
    REPORTS_DIR: Optional[Path] = None
    BACKUPS_DIR: Optional[Path] = None
    QUARANTINE_DIR: Optional[Path] = None

    # Database (defaults to <DATA_DIR>/database/gojo_infinity.db)
    DATABASE_URL: str = Field(default="", validation_alias="DATABASE_URL")

    # Server Configuration (Termux localhost default)
    HOST: str = Field(default="127.0.0.1", validation_alias="GOJO_HOST")
    PORT: int = Field(default=8000, validation_alias="GOJO_PORT")

    # Optional API token. When set, every /api request must send it
    # in the "X-API-Key" header (or "?token=" for the WebSocket).
    API_TOKEN: str = Field(default="", validation_alias="GOJO_API_TOKEN")
    # Comma-separated list of accepted Host headers (DNS-rebinding protection).
    ALLOWED_HOSTS: str = Field(default="", validation_alias="GOJO_ALLOWED_HOSTS")
    # Comma-separated list of cross-origin sites allowed to call the API (empty = same-origin only).
    CORS_ORIGINS: str = Field(default="", validation_alias="GOJO_CORS_ORIGINS")

    # Six Eyes AI (Optional external AI assistant)
    AI_ENABLED: bool = Field(default=False, validation_alias="GOJO_AI_ENABLED")
    AI_PROVIDER: str = Field(default="offline", validation_alias="GOJO_AI_PROVIDER")
    AI_API_KEY: str = Field(default="", validation_alias="GOJO_AI_KEY")

    # Infinity Shield Defaults
    INFINITY_SHIELD_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(default=240, validation_alias="GOJO_RATE_LIMIT")
    IP_BAN_DURATION_SECONDS: int = 1800  # 30 minutes
    MAX_LOGIN_ATTEMPTS: int = 5
    IP_HISTORY_RETENTION_DAYS: int = Field(default=30, validation_alias="GOJO_IP_RETENTION_DAYS")

    # Network Engine Constraints
    DEFAULT_SCAN_TIMEOUT: float = 1.5
    MAX_CONCURRENT_SOCKETS: int = 64  # safe for mobile Termux limits
    MAX_PORTS_PER_SCAN: int = 1024
    DNS_RESOLVERS: list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def model_post_init(self, __context) -> None:
        data = Path(self.DATA_DIR)
        self.DB_DIR = self.DB_DIR or data / "database"
        self.LOGS_DIR = self.LOGS_DIR or data / "logs"
        self.REPORTS_DIR = self.REPORTS_DIR or data / "reports"
        self.BACKUPS_DIR = self.BACKUPS_DIR or data / "backups"
        self.QUARANTINE_DIR = self.QUARANTINE_DIR or data / "quarantine"
        if not self.DATABASE_URL:
            self.DATABASE_URL = f"sqlite:///{(self.DB_DIR / 'gojo_infinity.db').as_posix()}"

    # ---- Derived helpers -------------------------------------------------
    @property
    def is_loopback_bind(self) -> bool:
        return self.HOST in LOOPBACK_HOSTS

    @property
    def allowed_hosts(self) -> list[str]:
        explicit = [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]
        if explicit:
            return explicit
        if self.HOST in ("0.0.0.0", "::"):
            return ["*"]
        return sorted(LOOPBACK_HOSTS | {self.HOST})

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


# Singleton Settings Instance
settings = Settings()

# Ensure directories exist
for path in [
    settings.DB_DIR,
    settings.LOGS_DIR,
    settings.REPORTS_DIR,
    settings.BACKUPS_DIR,
    settings.QUARANTINE_DIR,
    settings.CONFIG_DIR,
]:
    path.mkdir(parents=True, exist_ok=True)
