import os
from pydantic import BaseModel


class Settings(BaseModel):
    APP_NAME: str = "Schwab Audit Log Service"
    APP_VERSION: str = "2.0.0"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///audit_ledger.db")
    DEBUG: bool = False


settings = Settings()
