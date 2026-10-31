"""Explainability + threat intelligence + reports + settings routes."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db.session import get_db
from app.models import DetectionResult, Incident, NetworkFlow, SecurityAlert, SystemSetting
from app.schemas import (
    ExplainRequest,
    ExplainResponse,
    GlobalImportance,
    ReportOut,
    ReportRequest,
    SettingOut,
    SettingsUpdate,
    ThreatIntelOut,
)
from app.services.audit import audit
from app.services.threat_intel import threat_intel

logger = logging.getLogger("aiids.api")
router = APIRouter(tags=["misc"])


# --------------------------------------------------------------- explainability
@router.post("/explain/prediction", response_model=ExplainResponse)
def explain_prediction(
    body: ExplainRequest,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    from app.services.explain import explain_instance

    det = None
    if body.detection_id:
        det = db.get(DetectionResult, body.detection_id)
    elif body.flow_id:
        det = db.scalar(select(DetectionResult).where(DetectionResult.flow_id == body.flow_id))
    if det is None:
        raise HTTPException(status_code=404, detail="Detection not found")

    feats: dict = {}
    if det.flow_pk:
        flow = db.get(NetworkFlow, det.flow_pk)
        if flow and flow.flow_features:
            feats = flow.flow_features
    if not feats and det.shap_summary:
        feats = det.shap_summary.get("features", {})

    out = explain_instance(feats, top_k=body.top_k)
    out["flow_id"] = det.flow_id
    out["prediction"] = det.prediction
    out["confidence"] = det.confidence

    # cache the explanation on the detection row
    det.shap_summary = {"method": out["method"], "features": out["features"],
                        "narrative": out["narrative"]}
    db.commit()
    return out


@router.get("/explain/global", response_model=GlobalImportance)
def global_explain(
    top_k: int = 20,
    _=Depends(require_role("viewer")),
):
    from app.services.explain import global_importance

    return global_importance(top_k=min(top_k, 50))


# --------------------------------------------------------------- threat intel
@router.get("/threat-intel/ip/{ip}", response_model=ThreatIntelOut)
def ti_lookup(
    ip: str,
    force: bool = False,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    try:
        rec = threat_intel.lookup(db, ip, force=force)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Threat intel lookup failed: {exc}") from exc
    if rec is None:
        raise HTTPException(status_code=404, detail="No record")
    return rec


@router.get("/threat-intel/recent")
def ti_recent(_=Depends(require_role("viewer")), db: Session = Depends(get_db)):
    from app.models import ThreatIntelRecord

    rows = db.execute(
        select(ThreatIntelRecord).order_by(ThreatIntelRecord.fetched_at.desc()).limit(50)
    ).scalars().all()
    return {
        "items": [
            {
                "id": r.id, "ip": r.ip, "provider": r.provider,
                "is_malicious": r.is_malicious, "score": r.score,
                "categories": r.categories, "is_private_ip": r.is_private_ip,
                "fetched_at": r.fetched_at.isoformat() if r.fetched_at else None,
                "error": r.error,
            }
            for r in rows
        ]
    }


# --------------------------------------------------------------- reports
@router.post("/reports/generate", response_model=ReportOut)
def generate_report(
    body: ReportRequest,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    from app.services.reports import generate_csv_report, generate_pdf_report

    if body.format == "csv":
        filename, content, rows = generate_csv_report(
            db, date_from=body.date_from, date_to=body.date_to,
            report_type=body.report_type,
        )
        # store as text so the endpoint can return it directly later
        from app.core.config import get_settings

        path = get_settings().reports_dir / filename
        path.write_text(content, encoding="utf-8")
        audit(db, action="report_generated", user_id=user.sub, user_email=user.sub,
              resource=filename, detail={"rows": rows}, request=request)
        db.commit()
        return ReportOut(filename=filename, url=f"/api/reports/download/{filename}",
                         generated_at=datetime.now(timezone.utc), rows=rows,
                         report_type=body.report_type, format="csv")

    filename, path, rows = generate_pdf_report(
        db, date_from=body.date_from, date_to=body.date_to,
        report_type=body.report_type, title=body.title,
        incident_id=body.incident_id,
    )
    audit(db, action="report_generated", user_id=user.sub, user_email=user.sub,
          resource=filename, detail={"rows": rows}, request=request)
    db.commit()
    return ReportOut(filename=filename, url=f"/api/reports/download/{filename}",
                     generated_at=datetime.now(timezone.utc), rows=rows,
                     report_type=body.report_type, format="pdf")


@router.get("/reports/download/{filename}")
def download_report(
    filename: str,
    _=Depends(require_role("viewer")),
):
    from pathlib import Path

    from app.core.config import get_settings

    safe = Path(filename).name
    if safe != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = get_settings().reports_dir / safe
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    media = "application/pdf" if safe.endswith(".pdf") else "text/csv"
    return FileResponse(path, media_type=media, filename=safe)


@router.get("/reports/list")
def list_reports(_=Depends(require_role("viewer"))):
    from app.core.config import get_settings

    items = []
    for p in sorted(get_settings().reports_dir.glob("aiids_*"), reverse=True)[:50]:
        if p.suffix.lower() not in {".pdf", ".csv"}:
            continue
        items.append({
            "filename": p.name,
            "url": f"/api/reports/download/{p.name}",
            "size_bytes": p.stat().st_size,
            "generated_at": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
            "format": p.suffix.lstrip("."),
        })
    return {"items": items}


# --------------------------------------------------------------- settings
@router.get("/settings", response_model=list[SettingOut])
def get_settings_route(_=Depends(require_role("analyst")), db: Session = Depends(get_db)):
    return db.scalars(select(SystemSetting).order_by(SystemSetting.key)).all()


@router.put("/settings")
def update_settings(
    body: SettingsUpdate,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    from app.core.config import get_settings

    protected = {"theme"}
    changed = {}
    for k, v in body.settings.items():
        key = str(k).strip()[:100]
        if not key or not isinstance(v, str):
            raise HTTPException(status_code=400, detail="Invalid settings payload")
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == key))
        if row is None:
            row = SystemSetting(key=key, value=v[:8000])
            db.add(row)
        else:
            if key in protected:
                # theme can be changed by admins too; nothing restricted hard
                pass
            row.value = v[:8000]
        changed[key] = v
    audit(db, action="settings_updated", user_id=user.sub, user_email=user.sub,
          resource="system_settings", detail={"keys": list(changed)}, request=request)
    db.commit()
    # reflect into process env for providers that read at startup
    if "ti_provider" in changed:
        import os

        os.environ["TI_PROVIDER"] = changed["ti_provider"]
    if "alert_email_enabled" in changed:
        import os

        os.environ["ALERT_EMAIL_ENABLED"] = changed["alert_email_enabled"]
    return {"updated": list(changed)}


# --------------------------------------------------------------- health
@router.get("/health")
def health(db: Session = Depends(get_db)):
    from app.ml.predict import registry
    from app.network.capture import capture_service

    try:
        db.execute(select(SystemSetting).limit(1))
        db_ok = True
    except Exception:
        db_ok = False
    reg = registry.info()
    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "models": reg,
        "capture": capture_service.status(),
        "time": datetime.now(timezone.utc).isoformat(),
    }
