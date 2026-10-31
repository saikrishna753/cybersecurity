"""ML model registry + training job routes."""
from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db.session import SessionLocal, get_db
from app.models import DatasetRecord, MlModel, TrainingJob
from app.schemas import ModelOut, Page, TrainRequest, TrainingJobOut
from app.ml.predict import registry
from app.services.audit import audit

logger = logging.getLogger("aiids.models")
router = APIRouter(prefix="/models", tags=["models"])


def _model_out(m: MlModel) -> dict:
    return {
        "id": m.id, "name": m.name, "version": m.version, "algorithm": m.algorithm,
        "task": m.task, "metrics": m.metrics, "is_active": m.is_active,
        "training_job_id": m.training_job_id,
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "feature_count": len(m.feature_columns or []),
    }


@router.get("", response_model=Page[ModelOut])
def list_models(
    page: int = 1,
    size: int = 20,
    task: str | None = None,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(MlModel)
    if task:
        q = q.where(MlModel.task == task)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(MlModel.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page[ModelOut](items=[_model_out(m) for m in rows], total=total, page=page, size=size)


@router.get("/registry")
def registry_status(_=Depends(require_role("viewer"))):
    return registry.info()


@router.get("/training-jobs", response_model=Page[TrainingJobOut])
def training_jobs(
    page: int = 1,
    size: int = 20,
    _=Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(TrainingJob)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.execute(
        q.order_by(TrainingJob.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page[TrainingJobOut](items=rows, total=total, page=page, size=size)


@router.get("/training-jobs/{job_id}", response_model=TrainingJobOut)
def training_job(job_id: str, _=Depends(require_role("viewer")), db: Session = Depends(get_db)):
    row = db.get(TrainingJob, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return row


@router.post("/train")
def train(
    body: TrainRequest,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Kick off an asynchronous training job over uploaded/known datasets."""
    # Resolve datasets: explicit ids, else every ready CSV dataset.
    paths: list[str] = []
    if body.dataset_ids:
        rows = db.scalars(
            select(DatasetRecord).where(DatasetRecord.id.in_(body.dataset_ids))
        ).all()
        if not rows:
            raise HTTPException(status_code=404, detail="No datasets matched")
    else:
        rows = db.scalars(
            select(DatasetRecord).where(
                DatasetRecord.kind == "csv", DatasetRecord.status.in_(["ready", "validated", "uploaded"])
            )
        ).all()
        if not rows:
            raise HTTPException(status_code=400,
                                detail="No CSV datasets available — upload CIC-IDS2017 CSVs first")
    paths = [r.file_path for r in rows]

    job = TrainingJob(
        id=str(uuid.uuid4()),
        status="pending",
        dataset_ids=[r.id for r in rows],
        algorithms=body.algorithms,
        task=body.task,
        params={
            "test_size": body.test_size, "max_rows": body.max_rows,
            "random_state": body.random_state, "activate_best": body.activate_best,
        },
        created_by=user.sub,
    )
    db.add(job)
    audit(db, action="training_started", user_id=user.sub, user_email=user.sub,
          resource=job.id, detail={"algorithms": body.algorithms, "task": body.task},
          request=request)
    db.commit()

    threading.Thread(
        target=_run_training_job,
        args=(job.id, paths, body.model_dump(), user.sub),
        daemon=True,
    ).start()
    return {"job_id": job.id, "status": "pending"}


def _run_training_job(job_id: str, paths: list[str], params: dict, created_by: str) -> None:
    from app.ml.preprocess import read_cic_csv
    from app.ml.train import train_models
    import pandas as pd

    with SessionLocal() as db:
        job = db.get(TrainingJob, job_id)
        if job is None:
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.stage = "loading"
        db.commit()

    try:
        frames = []
        for i, p in enumerate(paths):
            with SessionLocal() as db:
                job = db.get(TrainingJob, job_id)
                job.progress = int(5 * i / max(len(paths), 1))
                job.stage = f"loading {p.rsplit('/', 1)[-1]}"
                db.commit()
            frames.append(read_cic_csv(p))
        df = pd.concat(frames, ignore_index=True)

        def progress(pct: int, stage: str) -> None:
            with SessionLocal() as db:
                job = db.get(TrainingJob, job_id)
                if job:
                    job.progress = pct
                    job.stage = stage
                    db.commit()

        results = train_models(
            df,
            task=params["task"],
            algorithms=params["algorithms"],
            test_size=params.get("test_size", 0.2),
            max_rows=params.get("max_rows"),
            random_state=params.get("random_state", 42),
            progress=progress,
        )

        with SessionLocal() as db:
            job = db.get(TrainingJob, job_id)
            job.status = "completed"
            job.finished_at = datetime.now(timezone.utc)
            job.progress = 100
            job.stage = "completed"
            job.metrics = {
                r.algorithm: {
                    k: v for k, v in r.metrics.items()
                    if k in {"accuracy", "precision", "recall", "f1", "f1_macro",
                             "fpr", "roc_auc", "roc_auc_ovr_macro", "train_seconds"}
                }
                for r in results
            }
            for r in results:
                db.add(MlModel(
                    name=f"{r.algorithm}-{r.task}",
                    version=r.version,
                    algorithm=r.algorithm,
                    task=r.task,
                    artifact_path=r.artifact_path,
                    feature_columns=r.feature_columns,
                    metrics=r.metrics,
                    training_job_id=job.id,
                    is_active=False,
                ))
            db.commit()

        # Register artifacts into the live inference registry.
        best = _best_result(results, params["task"])
        if best is not None:
            with SessionLocal() as db:
                row = db.scalar(
                    select(MlModel).where(MlModel.artifact_path == best.artifact_path)
                )
                if row is not None and params.get("activate_best", True):
                    _activate(db, row, register=True)
    except Exception as exc:
        logger.exception("training job %s failed", job_id)
        with SessionLocal() as db:
            job = db.get(TrainingJob, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)[:4000]
                job.finished_at = datetime.now(timezone.utc)
                db.commit()


def _best_result(results, task: str):
    cands = [r for r in results if r.algorithm != "isolation_forest"]
    if not cands:
        return None
    key = "f1" if task == "binary" else "f1_macro"
    return max(cands, key=lambda r: (r.metrics.get(key) or 0))


def _activate(db: Session, row: MlModel, register: bool = True) -> None:
    for other in db.scalars(
        select(MlModel).where(MlModel.task == row.task, MlModel.is_active.is_(True))
    ).all():
        other.is_active = False
    if row.task in {"binary", "multiclass", "anomaly"}:
        row.is_active = True
    db.commit()
    if register:
        registry.register(
            algorithm=row.algorithm, task=row.task, version=row.version,
            artifact_path=row.artifact_path, feature_columns=row.feature_columns or [],
        )


@router.post("/{model_id}/activate")
def activate(
    model_id: str,
    user=Depends(require_role("analyst")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    row = db.get(MlModel, model_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Model not found")
    _activate(db, row, register=True)
    audit(db, action="model_activated", user_id=user.sub, user_email=user.sub,
          resource=row.name, request=request)
    db.commit()
    return _model_out(row)


@router.get("/{model_id}/metrics")
def metrics(model_id: str, _=Depends(require_role("viewer")), db: Session = Depends(get_db)):
    row = db.get(MlModel, model_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return {
        "model": _model_out(row),
        "confusion_matrix": (row.metrics or {}).get("confusion_matrix"),
        "classification_report": (row.metrics or {}).get("classification_report"),
    }


@router.delete("/{model_id}", status_code=204)
def delete_model(
    model_id: str,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    row = db.get(MlModel, model_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Model not found")
    audit(db, action="model_deleted", user_id=user.sub, user_email=user.sub,
          resource=row.name, request=request)
    db.delete(row)
    db.commit()
    return None
