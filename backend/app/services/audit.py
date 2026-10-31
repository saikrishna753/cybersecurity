"""Audit trail helpers (admin/security actions)."""
from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog


def audit(
    db: Session,
    *,
    action: str,
    resource: str = "",
    user_id: str | None = None,
    user_email: str = "",
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    ip = ""
    if request is not None and request.client:
        ip = request.client.host or ""
    db.add(
        AuditLog(
            user_id=user_id,
            user_email=user_email,
            action=action,
            resource=resource,
            detail=detail or {},
            ip=ip,
        )
    )
    db.flush()
