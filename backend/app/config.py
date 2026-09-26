import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "PRISM Threat Detection & Response Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    
    # Response Engine
    RESPONSE_MODE: str = os.getenv("RESPONSE_MODE", "simulation")
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql+asyncpg://postgres:postgres@postgres:5432/prism_db"
    )
    
    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000", "*"]
    
    # NVD API
    NVD_API_KEY: str | None = os.getenv("NVD_API_KEY", None)

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
