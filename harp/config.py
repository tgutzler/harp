from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    secret_key: str = "change-this-in-production-minimum-32-chars!!"
    database_url: str = "sqlite+aiosqlite:///./dnsctl.db"
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    session_max_age: int = 86400
    reload: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
