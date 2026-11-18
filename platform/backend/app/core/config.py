from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ShadowTrace Intelligence"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    http_timeout_seconds: float = 8.0
    max_concurrent_collectors: int = 5
    cors_origins: str = "http://localhost:3000"

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
