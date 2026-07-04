from fastapi import APIRouter

from app.api.v1 import alerts, feedback, patterns, simulate, stats, users

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(alerts.router)
api_router.include_router(feedback.router)
api_router.include_router(users.router)
api_router.include_router(stats.router)
api_router.include_router(simulate.router)
api_router.include_router(patterns.router)
