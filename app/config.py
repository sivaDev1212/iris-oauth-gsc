from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Search Console + Indexing API + identity (so we can key tokens to a stable Google user id)
SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/webmasters",
    "https://www.googleapis.com/auth/indexing",
]
INDEXING_SCOPE = "https://www.googleapis.com/auth/indexing"
WEBMASTERS_SCOPE = "https://www.googleapis.com/auth/webmasters"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_client_id: str = ""
    google_client_secret: str = ""
    redirect_uri: str = "http://localhost:8000/auth/callback"
    session_secret: str = "change-me"
    token_encryption_keys: str = ""  # comma-separated Fernet keys, first = active
    database_url: str = "sqlite:///./iris.db"
    https_only_cookies: bool = False
    indexing_daily_quota: int = 200


@lru_cache
def get_settings() -> Settings:
    return Settings()
