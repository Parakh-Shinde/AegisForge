import os

from pydantic import BaseModel, Field

from aegisforge.core.enforcement_policy import EnforcementMode


def _enforcement_mode_from_environment() -> EnforcementMode:
    value = os.getenv("AEGISFORGE_ENFORCEMENT_MODE", EnforcementMode.BLOCK.value)
    return EnforcementMode(value.casefold())


class Settings(BaseModel):
    environment: str = "development"
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8000, ge=1, le=65535)
    allow_private_targets: bool = False
    enforcement_mode: EnforcementMode = Field(
        default_factory=_enforcement_mode_from_environment
    )


settings = Settings()
