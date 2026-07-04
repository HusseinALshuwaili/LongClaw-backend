from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=8)
    team: str | None = Field(None, examples=["network", "cloud", "endpoint", "soc"])
    role: str = Field(default="analyst", examples=["analyst", "admin"])


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    team: str | None
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
