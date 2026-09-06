from pydantic import BaseModel, Field


class Settings(BaseModel):
    environment: str = "development"
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8000, ge=1, le=65535)
    allow_private_targets: bool = False


settings = Settings()

