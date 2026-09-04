from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration loaded from environment variables and a local .env file."""

    model_config = SettingsConfigDict(
        env_prefix="INTELGENZ_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Intelgenz API"
    app_env: str = "local"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    mitre_attack_data_path: Path = Path("data/mitre_attack.json")
    attack_d3fend_mappings_path: Path = Path("data/attack_d3fend_mappings.json")
    d3fend_nist_mappings_path: Path = Path("data/d3fend_nist_800_53_rev5.json")
    database_url: str | None = None
    database_host: str | None = Field(
        default=None,
        validation_alias=AliasChoices("INTELGENZ_DATABASE_HOST", "PUBLIC_IP"),
    )
    database_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("INTELGENZ_DATABASE_NAME", "DB"),
    )
    database_user: str | None = Field(
        default=None,
        validation_alias=AliasChoices("INTELGENZ_DATABASE_USER", "POSTGRESQL_USER"),
    )
    database_password: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("INTELGENZ_DATABASE_PASSWORD", "POSTGRESQL_PASSWORD"),
    )
    database_port: int = 5432

    @property
    def resolved_database_url(self) -> str | None:
        """Return a PostgreSQL URL from a full URL or individual connection fields."""
        if self.database_url:
            return self.database_url
        if (
            self.database_host is None
            or self.database_name is None
            or self.database_user is None
            or self.database_password is None
        ):
            return None

        username = quote(self.database_user, safe="")
        password = quote(self.database_password.get_secret_value(), safe="")
        database_name = quote(self.database_name, safe="")
        return (
            f"postgresql+asyncpg://{username}:{password}@{self.database_host}:"
            f"{self.database_port}/{database_name}"
        )


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance for the running process."""
    return Settings()


settings = get_settings()
