from pydantic import BaseSettings

class Settings(BaseSettings):
    VT_API_KEY: str
    REDIS_URL: str
    SLACK_WEBHOOK_URL: str = ""
    EMAIL_ALERTS: str = ""

    class Config:
        env_file = ".env"

settings = Settings()