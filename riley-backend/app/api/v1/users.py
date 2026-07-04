from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import http_404, http_409
from app.core.logging import get_logger
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserOut

router = APIRouter(prefix="/users", tags=["Users"])
logger = get_logger(__name__)

DB = Annotated[AsyncSession, Depends(get_db)]

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED,
             summary="Create a new analyst user")
async def create_user(body: UserCreate, db: DB) -> UserOut:
    # Duplicate check
    existing = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if existing.scalar_one_or_none():
        raise http_409("Username or email already registered")

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=_pwd_ctx.hash(body.password),
        team=body.team,
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("user_created", id=user.id, username=user.username)
    return UserOut.model_validate(user)


@router.get("/", response_model=list[UserOut], summary="List all users")
async def list_users(db: DB) -> list[UserOut]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.get("/{user_id}", response_model=UserOut, summary="Get user by ID")
async def get_user(user_id: int, db: DB) -> UserOut:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise http_404(f"User {user_id} not found")
    return UserOut.model_validate(user)
