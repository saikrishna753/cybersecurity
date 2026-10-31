"""Security alerts routes: list/filter/search/ack/update/status."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db.session import get_db
from app.models import IncidentNote, SecurityAlert, User
from app.schemas import AlertOut, AlertUpdate, Page
from app.services.audit import audit

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    source_ip: str | None = None,
    search: str | None = None,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(SecurityAlert)
    if status:
        q = q.where(SecurityAlert.status == status)
    if severity:
        q = q.where(SecurityAlert.severity == severity)
    if attack_type:
        q = q.where(SecurityAlert.attack_type == attack_type)
    if source_ip:
        q = q.where(SecurityAlert.source_ip == source_ip)
    if search:
        like = f"%{search.strip()}%"
        q = q.where(
            or_(
                SecurityAlert.source_ip.like(like),
                SecurityAlert.destination_ip.like(like),
                SecurityAlert.attack_type.like(like),
                SecurityAlert.alert_id.like(like),
            )
        )
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(SecurityAlert.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page[AlertOut](items=rows, total=total, page=page, size=size)


@router.get("/summary")
def alert_summary(_=Depends(require_role("viewer")), db: Session = Depends(get_db)):
    by_status = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(SecurityAlert.status, func.count()).group_by(SecurityAlert.status)
        ).all()
    }
    by_severity = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(SecurityAlert.severity, func.count()).group_by(SecurityAlert.severity)
        ).all()
    }
    by_attack = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(SecurityAlert.attack_type, func.count())
            .group_by(SecurityAlert.attack_type)
            .order_by(func.count(SecurityAlert.id).desc())
        ).all()
    }
    return {"by_status": by_status, "by_severity": by_severity, "by_attack": by_attack}


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: str,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(SecurityAlert).where(
            or_(SecurityAlert.id == alert_id, SecurityAlert.alert_id == alert_id)
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: str,
    body: AlertUpdate,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    row = db.scalar(
        select(SecurityAlert).where(
            or_(SecurityAlert.id == alert_id, SecurityAlert.alert_id == alert_id)
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    changes = {}
    if body.status:
        row.status = body.status
        changes["status"] = body.status
    if body.assignee_id is not None:
        row.assignee_id = body.assignee_id
        changes["assignee"] = body.assignee_id
    if body.note:
        # notes on an alert land in its incident timeline when linked
        if row.incident_id:
            db.add(
                IncidentNote(
                    incident_id=row.incident_id,
                    author_id=None,
                    author_name=user.sub,
                    body=f"[alert {row.alert_id[:8]}] {body.note}",
                )
            )
        changes["note_len"] = len(body.note)
    audit(db, action="alert_updated", user_id=user.sub, user_email=user.sub,
          resource=alert_id, detail=changes, request=request)
    db.commit()
    db.refresh(row)
    return row


@router.post("/{alert_id}/ack", response_model=AlertOut)
def ack_alert(
    alert_id: str,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Convenience: acknowledge with dedup counter reset semantics."""
    row = db.scalar(
        select(SecurityAlert).where(
            or_(SecurityAlert.id == alert_id, SecurityAlert.alert_id == alert_id)
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if row.status == "New":
        row.status = "Acknowledged"
    if row.assignee_id is None:
        u = db.scalar(select(User).where(User.email == user.sub))
        row.assignee_id = u.id if u else None
    audit(db, action="alert_acked", user_id=user.sub, user_email=user.sub,
          resource=alert_id, request=request)
    db.commit()
    db.refresh(row)
    return row
