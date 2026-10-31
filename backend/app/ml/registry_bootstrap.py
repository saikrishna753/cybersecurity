"""Register freshly trained artifacts as active models in the DB."""
from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import MlModel
from app.ml.predict import registry

logger = logging.getLogger("aiids.registry")


def ensure_models_registered() -> None:
    """For every artifact on disk with no DB row, create one; keep one active
    per task (the newest). Idempotent."""
    settings = get_settings()
    with SessionLocal() as db:
        known_paths = set(db.scalars(select(MlModel.artifact_path)).all())
        for path in sorted(settings.models_dir.glob("*.joblib")):
            if str(path) in known_paths:
                continue
            name = path.stem
            # filename: {algorithm}_{task}_{version}  (algorithm may contain _)
            parts = name.rsplit("_", 2)
            if len(parts) != 3:
                continue
            algorithm, task, version = parts
            if task not in {"binary", "multiclass", "anomaly"}:
                continue
            metrics = None
            summary = settings.models_dir / f"training_summary_{version}.json"
            if summary.exists():
                try:
                    import json

                    data = json.loads(summary.read_text())
                    for r in data.get("results", []):
                        if r.get("artifact") == str(path):
                            metrics = r.get("metrics")
                            break
                except Exception:
                    pass
            db.add(
                MlModel(
                    name=f"{algorithm}-{task}",
                    version=version,
                    algorithm=algorithm,
                    task=task,
                    artifact_path=str(path),
                    feature_columns=[],
                    metrics=metrics,
                    is_active=False,
                )
            )
        db.commit()

        # activate newest per task
        for task in ("binary", "multiclass", "anomaly"):
            rows = db.scalars(
                select(MlModel).where(MlModel.task == task)
                .order_by(MlModel.created_at.desc())
            ).all()
            if not rows:
                continue
            newest = rows[0]
            changed = False
            for r in rows:
                want = r.id == newest.id
                if r.is_active != want:
                    r.is_active = want
                    changed = True
            if changed:
                db.commit()
            registry.register(
                algorithm=newest.algorithm, task=newest.task, version=newest.version,
                artifact_path=newest.artifact_path,
                feature_columns=newest.feature_columns or [],
            )
    logger.info("registry bootstrap complete")
