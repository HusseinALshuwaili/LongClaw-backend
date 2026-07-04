from __future__ import annotations

from fastapi import HTTPException, status


class RileyException(Exception):
    """Base exception for Riley backend."""


class AlertNotFound(RileyException):
    def __init__(self, alert_id: int) -> None:
        self.alert_id = alert_id
        super().__init__(f"Alert {alert_id} not found")


class UserNotFound(RileyException):
    def __init__(self, user_id: int) -> None:
        super().__init__(f"User {user_id} not found")


class DuplicateAlert(RileyException):
    def __init__(self, external_id: str) -> None:
        super().__init__(f"Alert with external_id={external_id} already exists")


class InvalidVerdict(RileyException):
    def __init__(self, verdict: str) -> None:
        super().__init__(f"Invalid verdict '{verdict}'. Must be 'fp' or 'true_positive'")


# ── HTTP helpers ────────────────────────────────────────────────

def http_404(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def http_409(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def http_422(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)
