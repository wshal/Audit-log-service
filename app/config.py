import os
from pydantic import BaseModel


class Settings(BaseModel):
    APP_NAME: str = "Schwab Audit Log Service"
    APP_VERSION: str = "2.0.0"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///audit_ledger.db")
    DEBUG: bool = False
    CORS_ORIGINS: str = os.getenv("AUDIT_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")


settings = Settings()
