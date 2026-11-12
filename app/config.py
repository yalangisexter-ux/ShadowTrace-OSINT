from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./shadowtrace.db"
    secret_key: str = "local-development-only-change-me"
    access_token_minutes: int = 60
    app_env: str = "development"
    cors_origins: str = ""

settings = Settings()

def normalized_database_url() -> str:
    url = settings.database_url.strip() or "sqlite:///./shadowtrace.db"
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url
