from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    VIRUSTOTAL_API: str = ""
    SAFEBROWSING_API: str = ""
    REDIS_URL: str = "redis://redis:6379"
    MODEL_PATH: str = "/app/models/scam_detector_v1.pkl"
    RATE_LIMIT: int = 100  # Requests per minute
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()