"""Network monitoring: flows listing, capture control, interface authorization."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import require_role
from app.db.session import SessionLocal, get_db
from app.models import DetectionResult, NetworkFlow, NetworkInterface
from app.schemas import CaptureStartRequest, CaptureStatus, FlowOut, InterfaceOut, Page
from app.network.capture import capture_service, check_capture_permission, list_interfaces
from app.services.audit import audit

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.get("/flows", response_model=Page[FlowOut])
def list_flows(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    source: str | None = None,
    malicious: bool | None = None,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(NetworkFlow)
    if src_ip:
        q = q.where(NetworkFlow.src_ip == src_ip)
    if dst_ip:
        q = q.where(NetworkFlow.dst_ip == dst_ip)
    if protocol:
        q = q.where(NetworkFlow.protocol == protocol.upper())
    if source:
        q = q.where(NetworkFlow.source == source)
    if malicious is not None:
        q = q.join(DetectionResult, DetectionResult.flow_pk == NetworkFlow.id).where(
            DetectionResult.is_malicious.is_(malicious)
        )
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(NetworkFlow.timestamp.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page[FlowOut](items=rows, total=total, page=page, size=size)


@router.get("/interfaces", response_model=list[InterfaceOut])
def interfaces(
    _=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    discovered = list_interfaces()
    # merge with DB authorization state
    stored = {r.name: r for r in db.scalars(select(NetworkInterface)).all()}
    out = []
    for d in discovered:
        row = stored.get(d["name"])
        if row is None:
            row = NetworkInterface(name=d["name"], description=d["description"],
                                   is_up=d["is_up"])
            db.add(row)
            db.flush()
        else:
            row.is_up = d["is_up"]
            row.description = d["description"]
            row.last_seen_at = datetime.now(timezone.utc)
        out.append(InterfaceOut(
            name=row.name,
            description=row.description or d["description"],
            is_up=row.is_up,
            is_authorized=row.is_authorized,
            capture_permission=d["capture_permission"],
        ))
    db.commit()
    return out


@router.post("/interfaces/{name}/authorize", response_model=InterfaceOut)
def authorize_interface(
    name: str,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Explicit admin authorization required before capture may start."""
    row = db.scalar(select(NetworkInterface).where(NetworkInterface.name == name))
    if row is None:
        # accept freshly discovered names
        known = {d["name"] for d in list_interfaces()}
        if name not in known:
            raise HTTPException(status_code=404, detail="Interface not found")
        row = NetworkInterface(name=name, is_up=True)
        db.add(row)
    row.is_authorized = True
    row.capture_permission = check_capture_permission()
    capture_service.authorize(name)
    audit(db, action="interface_authorized", user_id=user.sub, user_email=user.sub,
          resource=name, request=request)
    db.commit()
    return InterfaceOut(
        name=row.name, description=row.description, is_up=row.is_up,
        is_authorized=True, capture_permission=row.capture_permission,
    )


@router.post("/interfaces/{name}/deauthorize", response_model=InterfaceOut)
def deauthorize_interface(
    name: str,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    row = db.scalar(select(NetworkInterface).where(NetworkInterface.name == name))
    if row:
        row.is_authorized = False
    capture_service.deauthorize(name)
    if capture_service.running and capture_service.status()["interface"] == name:
        capture_service.stop()
    audit(db, action="interface_deauthorized", user_id=user.sub, user_email=user.sub,
          resource=name, request=request)
    db.commit()
    return InterfaceOut(name=name, description=row.description if row else "",
                        is_up=row.is_up if row else False, is_authorized=False,
                        capture_permission=row.capture_permission if row else "unknown")


@router.get("/capture/status", response_model=CaptureStatus)
def capture_status(_=Depends(require_role("viewer"))):
    return CaptureStatus(**capture_service.status())


def _ingest_flow(flow: dict) -> None:
    """Background callback: persist flow → detect → broadcast + alert."""
    from app.detection.engine import detection_engine
    from app.services.alerts import alert_service
    from app.ws.manager import ws_manager

    with SessionLocal() as db:
        row = NetworkFlow(
            flow_id=flow["flow_id"],
            timestamp=datetime.fromisoformat(flow["timestamp"]),
            src_ip=flow["src_ip"], dst_ip=flow["dst_ip"],
            src_port=flow["src_port"], dst_port=flow["dst_port"],
            protocol=flow["protocol"],
            flow_duration=flow["flow_duration"],
            total_fwd_packets=flow["total_fwd_packets"],
            total_bwd_packets=flow["total_bwd_packets"],
            total_fwd_bytes=flow.get("total_fwd_bytes", 0),
            total_bwd_bytes=flow.get("total_bwd_bytes", 0),
            flow_bytes_per_sec=flow.get("flow_bytes_per_sec", 0.0),
            flow_packets_per_sec=flow.get("flow_packets_per_sec", 0.0),
            flow_features=flow.get("flow_features"),
            source="live",
        )
        db.add(row)
        db.commit()
        result = detection_engine.detect_flow(flow)
        det = DetectionResult(
            flow_id=result["flow_id"], flow_pk=row.id,
            prediction=result["prediction"], is_malicious=result["is_malicious"],
            confidence=result["confidence"], anomaly_score=result["anomaly_score"],
            severity=result["severity"], model_version=result["model_version"],
            timestamp=datetime.now(timezone.utc),
        )
        db.add(det)
        db.commit()
        ws_manager.broadcast_threadsafe("flow_event", {k: flow.get(k) for k in
            ("flow_id", "src_ip", "dst_ip", "dst_port", "protocol", "timestamp")})
        if result["is_malicious"]:
            ws_manager.broadcast_threadsafe("detection_event", result)
        ws_manager.broadcast_threadsafe("stats_update", {"event": "new_flow"})


@router.post("/capture/start", response_model=CaptureStatus)
def capture_start(
    body: CaptureStartRequest,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    result = capture_service.start(
        body.interface, _ingest_flow,
        authorized=body.authorized, bpf_filter=body.bpf_filter,
        batch_size=body.batch_size,
    )
    audit(db, action="capture_start_attempt", user_id=user.sub, user_email=user.sub,
          resource=body.interface, detail=result, request=request)
    db.commit()
    if not result.get("ok"):
        # graceful fallback: report offline mode + reason instead of pretending
        return CaptureStatus(
            running=False, interface=None, started_at=None,
            packets_captured=0, flows_emitted=0, queue_size=0,
            error=result.get("error"), mode="offline",
        )
    return CaptureStatus(**capture_service.status())


@router.post("/capture/stop", response_model=CaptureStatus)
def capture_stop(
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    status = capture_service.stop()
    audit(db, action="capture_stop", user_id=user.sub, user_email=user.sub,
          resource=str(status.get("interface")), request=request)
    db.commit()
    return CaptureStatus(**status)
