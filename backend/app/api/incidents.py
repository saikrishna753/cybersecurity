"""Incident management routes (CRUD + notes + assignment + timeline)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db.session import get_db
from app.models import Incident, IncidentNote, SecurityAlert, User
from app.schemas import (
    IncidentCreate,
    IncidentNoteCreate,
    IncidentNoteOut,
    IncidentOut,
    IncidentUpdate,
    Page,
)
from app.services.audit import audit

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _serialize(inc: Incident, alert_count: int = 0) -> dict:
    return IncidentOut(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        assignee_id=inc.assignee_id,
        created_by=inc.created_by,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        closed_at=inc.closed_at,
        notes=[IncidentNoteOut.model_validate(n) for n in inc.notes],
        alert_count=alert_count,
    ).model_dump()


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(Incident)
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    if search:
        like = f"%{search.strip()}%"
        q = q.where(or_(Incident.title.like(like), Incident.description.like(like)))
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(Incident.updated_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    counts = dict(
        db.execute(
            select(SecurityAlert.incident_id, func.count())
            .where(SecurityAlert.incident_id.in_([r.id for r in rows] or [""]))
            .group_by(SecurityAlert.incident_id)
        ).all()
    )
    items = [_serialize(r, counts.get(r.id, 0)) for r in rows]
    return Page[IncidentOut](items=items, total=total, page=page, size=size)


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    body: IncidentCreate,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    u = db.scalar(select(User).where(User.email == user.sub))
    inc = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        created_by=u.id if u else None,
        assignee_id=u.id if u else None,
    )
    db.add(inc)
    db.flush()
    linked = 0
    if body.alert_ids:
        rows = db.scalars(
            select(SecurityAlert).where(
                or_(
                    SecurityAlert.id.in_(body.alert_ids),
                    SecurityAlert.alert_id.in_(body.alert_ids),
                )
            )
        ).all()
        for a in rows:
            a.incident_id = inc.id
            if a.status == "New":
                a.status = "Investigating"
            linked += 1
    db.add(IncidentNote(
        incident_id=inc.id, author_id=u.id if u else None,
        author_name=user.sub, body="Incident created.",
    ))
    audit(db, action="incident_created", user_id=user.sub, user_email=user.sub,
          resource=inc.id, detail={"linked_alerts": linked}, request=request)
    db.commit()
    db.refresh(inc)
    return _serialize(inc, linked)


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: str,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    count = db.scalar(
        select(func.count(SecurityAlert.id)).where(SecurityAlert.incident_id == inc.id)
    ) or 0
    return _serialize(inc, count)


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = body.model_dump(exclude_unset=True)
    timeline_bits = []
    if "status" in data and data["status"]:
        old = inc.status
        inc.status = data.pop("status")
        timeline_bits.append(f"status {old}→{inc.status}")
        if inc.status in {"Resolved", "Closed"}:
            inc.closed_at = datetime.now(timezone.utc)
    if "severity" in data and data["severity"] is not None:
        inc.severity = data.pop("severity")
    if "assignee_id" in data:
        inc.assignee_id = data.pop("assignee_id")
    if "title" in data and data["title"]:
        inc.title = data.pop("title")
    if "description" in data and data["description"] is not None:
        inc.description = data.pop("description")
    if timeline_bits:
        db.add(IncidentNote(
            incident_id=inc.id, author_name=user.sub,
            body=" · ".join(timeline_bits),
        ))
    audit(db, action="incident_updated", user_id=user.sub, user_email=user.sub,
          resource=inc.id, detail={"changes": timeline_bits}, request=request)
    db.commit()
    db.refresh(inc)
    count = db.scalar(
        select(func.count(SecurityAlert.id)).where(SecurityAlert.incident_id == inc.id)
    ) or 0
    return _serialize(inc, count)


@router.post("/{incident_id}/notes", response_model=IncidentNoteOut, status_code=201)
def add_note(
    incident_id: str,
    body: IncidentNoteCreate,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    u = db.scalar(select(User).where(User.email == user.sub))
    note = IncidentNote(
        incident_id=inc.id, author_id=u.id if u else None,
        author_name=user.sub, body=body.body,
    )
    db.add(note)
    inc.updated_at = datetime.now(timezone.utc)
    audit(db, action="incident_note_added", user_id=user.sub, user_email=user.sub,
          resource=inc.id, request=request)
    db.commit()
    db.refresh(note)
    return note


@router.get("/{incident_id}/timeline")
def timeline(
    incident_id: str,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    notes = db.execute(
        select(IncidentNote).where(IncidentNote.incident_id == inc.id)
        .order_by(IncidentNote.created_at)
    ).scalars().all()
    alerts = db.execute(
        select(SecurityAlert).where(SecurityAlert.incident_id == inc.id)
        .order_by(SecurityAlert.created_at)
    ).scalars().all()
    events = [
        {"at": n.created_at.isoformat(), "kind": "note",
         "actor": n.author_name, "body": n.body}
        for n in notes
    ] + [
        {"at": a.created_at.isoformat(), "kind": "alert",
         "actor": "system", "body": f"{a.severity} {a.attack_type} from {a.source_ip} ({a.status})"}
        for a in alerts
    ]
    events.sort(key=lambda e: e["at"])
    return {"incident_id": inc.id, "events": events}
