"""Model training pipeline: Decision Tree, Random Forest, XGBoost, Isolation Forest.

Actual measured metrics only — no fabricated numbers. Supports binary and
multiclass tasks, consistent test sets across algorithms, class weighting,
and joblib serialization with metadata.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from app.core.config import get_settings
from app.ml.features import CANONICAL_FEATURE_COLUMNS
from app.ml.preprocess import clean_dataset, prepare_xy, read_cic_csv

logger = logging.getLogger("aiids.ml.train")

ProgressFn = Callable[[int, str], None]


@dataclass
class TrainResult:
    algorithm: str
    task: str
    metrics: dict
    artifact_path: str
    feature_columns: list[str]
    version: str
    train_rows: int = 0
    test_rows: int = 0
    duration_s: float = 0.0
    extra: dict = field(default_factory=dict)


def _fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return float(fp / (fp + tn)) if (fp + tn) else 0.0


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(p),
        "recall": float(r),
        "f1": float(f1),
        "fpr": _fpr(y_true, y_pred),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, target_names=["BENIGN", "ATTACK"], zero_division=0, output_dict=True
        ),
    }
    if y_score is not None and len(np.unique(y_true)) > 1:
        try:
            out["roc_auc"] = float(roc_auc_score(y_true, y_score))
        except ValueError:
            out["roc_auc"] = None
    return out


def multiclass_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score=None) -> dict:
    labels = sorted(set(y_true) | set(y_pred))
    report = classification_report(y_true, y_pred, labels=labels, zero_division=0, output_dict=True)
    macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(report.get("macro avg", {}).get("precision", 0.0)),
        "recall_macro": float(report.get("macro avg", {}).get("recall", 0.0)),
        "f1_macro": float(macro),
        "f1_weighted": float(weighted),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "confusion_labels": labels,
        "classification_report": report,
    }
    if y_score is not None and len(np.unique(y_true)) > 1:
        try:
            out["roc_auc_ovr_macro"] = float(
                roc_auc_score(y_true, y_score, multi_class="ovr", average="macro")
            )
        except ValueError:
            out["roc_auc_ovr_macro"] = None
    return out


def _version() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _make_estimators(task: str, algorithms: list[str], random_state: int) -> dict:
    ests: dict = {}
    cw = "balanced"
    if "decision_tree" in algorithms:
        ests["decision_tree"] = DecisionTreeClassifier(
            class_weight=cw, random_state=random_state, max_depth=24, min_samples_leaf=2
        )
    if "random_forest" in algorithms:
        ests["random_forest"] = RandomForestClassifier(
            n_estimators=150, class_weight=cw, random_state=random_state,
            n_jobs=-1, max_depth=32, min_samples_leaf=2,
        )
    if "xgboost" in algorithms:
        try:
            from xgboost import XGBClassifier

            kwargs = dict(
                n_estimators=150, max_depth=8, learning_rate=0.1,
                random_state=random_state, n_jobs=-1, tree_method="hist",
            )
            if task == "binary":
                kwargs.update(dict(eval_metric="logloss"))
            else:
                kwargs.update(dict(eval_metric="mlogloss"))
            ests["xgboost"] = XGBClassifier(**kwargs)
        except ImportError:  # pragma: no cover
            logger.warning("xgboost unavailable — skipping")
    return ests


def train_models(
    df: pd.DataFrame,
    *,
    task: str = "binary",
    algorithms: list[str] | None = None,
    test_size: float = 0.2,
    max_rows: int | None = 400_000,
    random_state: int = 42,
    progress: ProgressFn | None = None,
) -> list[TrainResult]:
    """Train/evaluate all requested algorithms on one consistent holdout split."""
    settings = get_settings()
    algorithms = algorithms or ["decision_tree", "random_forest", "xgboost", "isolation_forest"]
    t0 = time.time()

    def report(pct: int, stage: str) -> None:
        logger.info("[%3d%%] %s", pct, stage)
        if progress:
            progress(pct, stage)

    report(5, "Cleaning dataset")
    cleaned, clean_report = clean_dataset(df)
    if len(cleaned) < 100:
        raise ValueError(f"Dataset too small after cleaning ({len(cleaned)} rows)")

    report(15, "Preparing features")
    X, y, cols = prepare_xy(cleaned, task=task, max_rows=max_rows, random_state=random_state)
    if task == "binary":
        strat = y
    else:
        # stratify only when every class has ≥2 members
        counts = pd.Series(y).value_counts()
        rare = set(counts[counts < 2].index)
        strat = np.array([f"__rare__" if v in rare else v for v in y])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=strat
    )
    report(25, f"Split {len(X_train)} train / {len(X_test)} test rows")

    results: list[TrainResult] = []
    version = _version()
    models_dir = settings.models_dir

    clf_algos = [a for a in algorithms if a != "isolation_forest"]
    ests = _make_estimators(task, clf_algos, random_state)

    n = max(len(ests), 1)
    # XGBoost requires integer class codes for multiclass; keep label mapping.
    label_classes: list | None = None
    y_fit = y_train
    if task == "multiclass":
        label_classes = sorted(set(y_train) | set(y_test), key=str)
        code_map = {c: i for i, c in enumerate(label_classes)}
        y_fit = np.array([code_map[v] for v in y_train])

    for i, (name, est) in enumerate(ests.items()):
        report(30 + int(50 * i / n), f"Training {name} ({task})")
        t = time.time()
        est.fit(X_train, y_fit)
        dur = time.time() - t
        y_pred_raw = est.predict(X_test)
        if task == "multiclass" and label_classes is not None:
            # decode integer codes back to canonical labels
            y_pred = np.array(
                [label_classes[int(p)] if 0 <= int(p) < len(label_classes) else str(p)
                 for p in y_pred_raw]
            )
        else:
            y_pred = y_pred_raw
        # For XGBoost multiclass the estimator is fit on integer codes; wrap the
        # artifact with the label mapping so inference can decode predictions.
        labels_for_artifact = label_classes if (
            task == "multiclass" and label_classes is not None and name == "xgboost"
        ) else None
        y_score = None
        if hasattr(est, "predict_proba"):
            try:
                proba = est.predict_proba(X_test)
                y_score = proba[:, 1] if task == "binary" else proba
            except Exception:
                y_score = None
        metrics = (
            binary_metrics(y_test, y_pred, y_score)
            if task == "binary"
            else multiclass_metrics(y_test, y_pred, y_score)
        )
        metrics["train_seconds"] = round(dur, 2)
        metrics["train_rows"] = int(len(X_train))
        metrics["test_rows"] = int(len(X_test))
        metrics["cleaning"] = clean_report

        artifact = models_dir / f"{name}_{task}_{version}.joblib"
        pipeline = Pipeline(
            [("scaler", StandardScaler()), ("model", est)]
        ) if name in {"decision_tree", "random_forest"} else None
        to_save = pipeline if pipeline is not None else est
        if pipeline is not None:
            pipeline.fit(X_train, y_train)
            # re-evaluate the scaled pipeline for honesty
            y_pred2 = pipeline.predict(X_test)
            if task == "binary":
                metrics = binary_metrics(y_test, y_pred2, _proba(pipeline, X_test, task))
            else:
                metrics = multiclass_metrics(y_test, y_pred2, _proba(pipeline, X_test, task))
            metrics["train_seconds"] = round(dur, 2)
            metrics["train_rows"] = int(len(X_train))
            metrics["test_rows"] = int(len(X_test))
            metrics["cleaning"] = clean_report
        elif labels_for_artifact is not None:
            from app.ml.wrapper import LabeledEstimator

            to_save = LabeledEstimator(est, labels_for_artifact)
        joblib.dump(to_save, artifact)

        results.append(
            TrainResult(
                algorithm=name,
                task=task,
                metrics=metrics,
                artifact_path=str(artifact),
                feature_columns=cols,
                version=version,
                train_rows=int(len(X_train)),
                test_rows=int(len(X_test)),
                duration_s=round(dur, 2),
            )
        )

    # ---- Isolation Forest (anomaly, trained on BENIGN-only of the train split) ----
    if "isolation_forest" in algorithms:
        report(85, "Training isolation_forest (anomaly detector)")
        if task == "binary":
            benign_mask = y_train == 0
        else:
            benign_mask = np.array([str(v).upper() == "BENIGN" for v in y_train])
        X_benign = X_train[benign_mask]
        if len(X_benign) >= 50:
            iso = IsolationForest(
                n_estimators=150, contamination="auto", random_state=random_state, n_jobs=-1
            )
            t = time.time()
            iso.fit(X_benign)
            dur = time.time() - t
            # score test set: -score_samples → higher = more anomalous in [0,1]-ish
            raw = -iso.score_samples(X_test)  # higher = more abnormal
            # normalize to [0,1] via percentile-based squashing for display only
            lo, hi = np.percentile(raw, 1), np.percentile(raw, 99)
            norm = np.clip((raw - lo) / (hi - lo + 1e-9), 0.0, 1.0)
            preds = iso.predict(X_test)  # -1 anomaly, 1 normal
            if task == "binary":
                y_bin = (y_test != 0).astype(int)
                iso_pred = (preds == -1).astype(int)
                metrics = binary_metrics(y_bin, iso_pred, norm)
                metrics["note"] = (
                    "Anomaly detector: trained on BENIGN training rows only; "
                    "test-set scores are normalized for display."
                )
            else:
                y_bin = np.array([0 if str(v).upper() == "BENIGN" else 1 for v in y_test])
                iso_pred = (preds == -1).astype(int)
                metrics = binary_metrics(y_bin, iso_pred, norm)
                metrics["note"] = (
                    "Anomaly detector evaluated as BENIGN-vs-rest regardless of task."
                )
            metrics["train_seconds"] = round(dur, 2)
            metrics["train_rows"] = int(len(X_benign))
            metrics["test_rows"] = int(len(X_test))
            artifact = models_dir / f"isolation_forest_anomaly_{version}.joblib"
            joblib.dump(iso, artifact)
            results.append(
                TrainResult(
                    algorithm="isolation_forest",
                    task="anomaly",
                    metrics=metrics,
                    artifact_path=str(artifact),
                    feature_columns=cols,
                    version=version,
                    train_rows=int(len(X_benign)),
                    test_rows=int(len(X_test)),
                    duration_s=round(dur, 2),
                )
            )

    report(100, "Training complete")
    # Persist run summary for auditability.
    summary = {
        "version": version,
        "task": task,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [
            {"algorithm": r.algorithm, "task": r.task, "metrics": r.metrics,
             "artifact": r.artifact_path, "duration_s": r.duration_s}
            for r in results
        ],
        "total_seconds": round(time.time() - t0, 2),
    }
    (settings.models_dir / f"training_summary_{version}.json").write_text(
        json.dumps(summary, indent=2, default=str)
    )
    return results


def _proba(est, X, task):
    try:
        p = est.predict_proba(X)
        return p[:, 1] if task == "binary" else p
    except Exception:
        return None


def train_from_paths(
    paths: list[str | Path],
    *,
    task: str = "binary",
    algorithms: list[str] | None = None,
    test_size: float = 0.2,
    max_rows: int | None = 400_000,
    random_state: int = 42,
    progress: ProgressFn | None = None,
) -> list[TrainResult]:
    frames = []
    for i, p in enumerate(paths):
        if progress:
            progress(int(5 * i / max(len(paths), 1)), f"Loading {Path(p).name}")
        frames.append(read_cic_csv(p))
    df = pd.concat(frames, ignore_index=True)
    if progress:
        progress(5, f"Loaded {len(df)} rows")
    return train_models(
        df, task=task, algorithms=algorithms, test_size=test_size,
        max_rows=max_rows, random_state=random_state, progress=progress,
    )
