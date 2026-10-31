"""Dataset upload + validation + analysis routes (CSV and PCAP)."""
from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi import Query as Q
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import require_role
from app.db.session import get_db
from app.models import DatasetRecord
from app.schemas import DatasetOut, Page
from app.services.audit import audit

logger = logging.getLogger("aiids.datasets")
router = APIRouter(prefix="/datasets", tags=["datasets"])

ALLOWED_CSV = {".csv"}
ALLOWED_PCAP = {".pcap", ".pcapng", ".cap"}


def _safe_name(name: str) -> str:
    """Strip any path components / traversal from client-provided filenames."""
    base = Path(name or "upload.bin").name
    cleaned = "".join(ch for ch in base if ch.isalnum() or ch in "._- ").strip()
    cleaned = cleaned.lstrip(".") or "upload.bin"
    return cleaned[:180]


def _validate_and_store(file: UploadFile, kind: str) -> Path:
    settings = get_settings()
    safe = _safe_name(file.filename or "upload.bin")
    ext = Path(safe).suffix.lower()
    allowed = ALLOWED_CSV if kind == "csv" else ALLOWED_PCAP
    if ext not in allowed:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Allowed: {sorted(allowed)}",
        )
    dest_dir = settings.upload_path / kind
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{uuid.uuid4().hex[:8]}_{safe}"

    max_bytes = settings.max_upload_mb * 1024 * 1024
    written = 0
    try:
        with dest.open("wb") as out:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {settings.max_upload_mb} MB limit",
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}") from exc
    if written == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Empty file")
    return dest


@router.get("", response_model=Page[DatasetOut])
def list_datasets(
    page: int = Q(1, ge=1),
    size: int = Q(20, ge=1, le=200),
    kind: str | None = None,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(DatasetRecord)
    if kind:
        q = q.where(DatasetRecord.kind == kind)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(DatasetRecord.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page[DatasetOut](items=rows, total=total, page=page, size=size)


@router.post("/upload", response_model=DatasetOut, status_code=201)
async def upload_dataset(
    file: UploadFile = File(...),
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """CSV (labeled CIC dataset) or PCAP upload. Files are never executed."""
    filename = _safe_name(file.filename or "")
    ext = Path(filename).suffix.lower()
    kind = "csv" if ext in ALLOWED_CSV else "pcap" if ext in ALLOWED_PCAP else ""
    if not kind:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Allowed: {sorted(ALLOWED_CSV | ALLOWED_PCAP)}",
        )

    dest = _validate_and_store(file, kind)
    size = dest.stat().st_size

    row = DatasetRecord(
        name=filename, kind=kind, file_path=str(dest), size_bytes=size,
        uploaded_by=user.sub, status="uploaded",
    )
    db.add(row)
    audit(db, action="dataset_uploaded", user_id=user.sub, user_email=user.sub,
          resource=filename, detail={"kind": kind, "bytes": size}, request=request)
    db.commit()
    db.refresh(row)

    # Validate + profile asynchronously (keeps request fast).
    import threading

    threading.Thread(
        target=_validate_dataset, args=(row.id, kind, str(dest)), daemon=True
    ).start()
    return row


def _validate_dataset(dataset_id: str, kind: str, path: str) -> None:
    from app.ml.preprocess import label_distribution, read_cic_csv
    from app.network.pcap import PcapValidationError, validate_pcap

    with SessionLocal() as db:
        row = db.get(DatasetRecord, dataset_id)
        if row is None:
            return
        try:
            if kind == "csv":
                df = read_cic_csv(path, max_rows=200_000)
                row.rows = int(len(df))
                row.label_distribution = label_distribution(path, max_rows=200_000)
                row.status = "ready"
            else:
                max_bytes = get_settings().max_upload_mb * 1024 * 1024
                validate_pcap(path, max_bytes)
                row.status = "ready"
        except (Exception, PcapValidationError) as exc:
            row.status = "failed"
            row.error = str(exc)[:1000]
            logger.warning("dataset validation failed: %s", exc)
        db.commit()


@router.get("/{dataset_id}", response_model=DatasetOut)
def get_dataset(
    dataset_id: str,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    row = db.get(DatasetRecord, dataset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return row


@router.post("/{dataset_id}/analyze")
def analyze_dataset(
    dataset_id: str,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Profile a dataset: labels, class balance, feature summary (no training)."""
    from app.ml.preprocess import clean_dataset, read_cic_csv

    row = db.get(DatasetRecord, dataset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    if row.kind != "csv":
        raise HTTPException(status_code=400, detail="Analysis is only defined for CSV datasets")
    try:
        df = read_cic_csv(row.file_path, max_rows=150_000)
        cleaned, report = clean_dataset(df)
        row.status = "ready"
        row.rows = report["rows_out"]
        row.label_distribution = report["labels"]
        db.commit()
        audit(db, action="dataset_analyzed", user_id=user.sub, user_email=user.sub,
              resource=row.name, request=request)
        db.commit()
        return {
            "dataset_id": row.id,
            "report": report,
            "feature_count": int(cleaned.shape[1] - 1),
            "class_balance_pct": {
                k: round(100 * v / max(report["rows_out"], 1), 3)
                for k, v in report["labels"].items()
            },
        }
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Analysis failed: {exc}") from exc


@router.delete("/{dataset_id}", status_code=204)
def delete_dataset(
    dataset_id: str,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    row = db.get(DatasetRecord, dataset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    audit(db, action="dataset_deleted", user_id=user.sub, user_email=user.sub,
          resource=row.name, request=request)
    db.delete(row)
    db.commit()
    try:
        Path(row.file_path).unlink(missing_ok=True)
    except Exception:
        pass
    return None
