"""Flow prediction + PCAP analysis routes."""
from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import require_role
from app.db.session import SessionLocal, get_db
from app.models import DatasetRecord, DetectionResult, NetworkFlow
from app.schemas import DetectionEvent, DetectionOut, FlowPredictRequest, Page
from app.detection.engine import detection_engine
from app.ml.predict import registry
from app.services.audit import audit
from app.services.alerts import alert_service
from app.ws.manager import ws_manager

logger = logging.getLogger("aiids.predict")
router = APIRouter(tags=["prediction"])


@router.post("/predict/flow")
def predict_flow(
    body: FlowPredictRequest,
    _=Depends(require_role("viewer")),
):
    """Classify a single flow (contract Detection Result shape)."""
    from app.ml.features import flow_to_features

    if body.features:
        feats = dict(body.features)
    else:
        feats = flow_to_features(
            dst_port=body.dst_port, src_port=body.src_port,
            flow_duration=body.flow_duration * 1_000_000,
            total_fwd_packets=body.total_fwd_packets,
            total_bwd_packets=body.total_bwd_packets,
            total_fwd_bytes=body.total_fwd_bytes,
            total_bwd_bytes=body.total_bwd_bytes,
        )
    flow = {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": body.src_ip, "dst_ip": body.dst_ip,
        "src_port": body.src_port, "dst_port": body.dst_port,
        "protocol": body.protocol,
        "flow_duration": body.flow_duration,
        "total_fwd_packets": body.total_fwd_packets,
        "total_bwd_packets": body.total_bwd_packets,
        "total_fwd_bytes": body.total_fwd_bytes,
        "total_bwd_bytes": body.total_bwd_bytes,
        "flow_bytes_per_sec": 0.0, "flow_packets_per_sec": 0.0,
        "flow_features": feats,
    }
    result = detection_engine.detect_flow(flow)
    ws_manager.broadcast_threadsafe("detection_event", result)
    return result


@router.get("/predict/detections", response_model=Page[DetectionOut])
def list_detections(
    page: int = 1,
    size: int = 20,
    malicious: bool | None = None,
    prediction: str | None = None,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(DetectionResult)
    if malicious is not None:
        q = q.where(DetectionResult.is_malicious.is_(malicious))
    if prediction:
        q = q.where(DetectionResult.prediction == prediction)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(DetectionResult.timestamp.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page[DetectionOut](items=rows, total=total, page=page, size=size)


@router.post("/pcap/analyze")
def analyze_pcap(
    body: dict,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Analyze an uploaded PCAP: extract flows → classify → alerts.

    Body: {"dataset_id": "..."}
    Runs synchronously for small files; large files return a job id quickly.
    """
    dataset_id = body.get("dataset_id")
    if not dataset_id:
        raise HTTPException(status_code=400, detail="dataset_id is required")
    ds = db.get(DatasetRecord, dataset_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    if ds.kind != "pcap":
        raise HTTPException(status_code=400, detail="dataset is not a PCAP")
    audit(db, action="pcap_analyze", user_id=user.sub, user_email=user.sub,
          resource=ds.name, request=request)
    db.commit()

    from app.network.pcap import PcapValidationError, extract_flows_from_pcap

    try:
        flows = extract_flows_from_pcap(ds.file_path)
    except PcapValidationError as exc:
        ds.status = "failed"
        ds.error = str(exc)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        ds.status = "failed"
        ds.error = str(exc)[:500]
        db.commit()
        raise HTTPException(status_code=500, detail=f"PCAP processing failed: {exc}") from exc

    ds.status = "ready"
    ds.rows = len(flows)
    db.commit()

    stats = _process_flows(flows, source="pcap", dataset_id=ds.id)
    ws_manager.broadcast_threadsafe("stats_update", {"event": "pcap_analysis", **stats})
    return {
        "dataset_id": ds.id,
        "filename": ds.name,
        "flows_extracted": len(flows),
        "detections": stats["detections"],
        "malicious": stats["malicious"],
        "alerts_created": stats["alerts_created"],
        "top_attacks": stats["top_attacks"],
        "preview": [
            {k: f.get(k) for k in ("flow_id", "src_ip", "dst_ip", "dst_port",
                                    "protocol", "flow_duration", "timestamp")}
            for f in flows[:10]
        ],
    }


def _process_flows(flows: list[dict], source: str, dataset_id: str | None = None) -> dict:
    """Persist flows + run detection in batches; return stats."""
    alerts_before = _alert_counter["created"]
    detections = 0
    malicious = 0
    attack_counts: dict[str, int] = {}
    batch_size = 500

    for i in range(0, len(flows), batch_size):
        chunk = flows[i:i + batch_size]
        with SessionLocal() as db:
            rows = []
            for f in chunk:
                ts = f.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts)
                    except ValueError:
                        ts = datetime.now(timezone.utc)
                rows.append(NetworkFlow(
                    flow_id=f["flow_id"], timestamp=ts,
                    src_ip=f["src_ip"], dst_ip=f["dst_ip"],
                    src_port=f["src_port"], dst_port=f["dst_port"],
                    protocol=f["protocol"], flow_duration=f["flow_duration"],
                    total_fwd_packets=f["total_fwd_packets"],
                    total_bwd_packets=f["total_bwd_packets"],
                    total_fwd_bytes=f.get("total_fwd_bytes", 0),
                    total_bwd_bytes=f.get("total_bwd_bytes", 0),
                    flow_bytes_per_sec=f.get("flow_bytes_per_sec", 0.0),
                    flow_packets_per_sec=f.get("flow_packets_per_sec", 0.0),
                    flow_features=f.get("flow_features"),
                    source=source, dataset_id=dataset_id,
                ))
            db.add_all(rows)
            db.flush()
            flow_pk_map = {r.flow_id: r.id for r in rows}
            for f in chunk:
                result = detection_engine.detect_flow(f)
                detections += 1
                db.add(DetectionResult(
                    flow_id=result["flow_id"], flow_pk=flow_pk_map.get(result["flow_id"]),
                    prediction=result["prediction"], is_malicious=result["is_malicious"],
                    confidence=result["confidence"], anomaly_score=result["anomaly_score"],
                    severity=result["severity"], model_version=result["model_version"],
                    shap_summary=None,
                ))
                if result["is_malicious"]:
                    malicious += 1
                    attack_counts[result["prediction"]] = attack_counts.get(result["prediction"], 0) + 1
            db.commit()

    return {
        "detections": detections,
        "malicious": malicious,
        "alerts_created": _alert_counter["created"] - alerts_before,
        "top_attacks": dict(sorted(attack_counts.items(), key=lambda kv: -kv[1])[:8]),
    }


# Wire detection-engine alert events → alert service (dedup + persistence + WS).
_alert_counter = {"created": 0}


def _on_alert_event(alert: dict) -> None:
    try:
        stored, created = alert_service.ingest(alert)
        if created:
            _alert_counter["created"] += 1
            ws_manager.broadcast_threadsafe("alert_event", stored)
    except Exception:
        logger.exception("failed to persist alert")


detection_engine.subscribe_alerts(_on_alert_event)
