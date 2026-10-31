"""Model registry + inference (classification + anomaly scoring)."""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from app.core.config import get_settings
from app.ml.features import CANONICAL_FEATURE_COLUMNS, features_to_vector

logger = logging.getLogger("aiids.ml.predict")

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

# Contract severity mapping (docs/INTEGRATION_CONTRACT.md §5)
_SEVERITY_BY_PREDICTION = {
    "DDoS": "Critical",
    "DoS": "High",
    "Infiltration": "Critical",
    "Bot": "Critical",
    "Brute Force": "High",
    "PortScan": "Medium",
    "Web Attack": "Medium",
    "Heartbleed": "High",
    "FTP-Patator": "Medium",
    "SSH-Patator": "Medium",
}


@dataclass
class LoadedModel:
    name: str
    algorithm: str
    task: str  # binary|multiclass|anomaly
    version: str
    model: object
    feature_columns: list[str]


class ModelRegistry:
    """Thread-safe lazy registry of active models loaded from joblib artifacts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._binary: LoadedModel | None = None
        self._multiclass: LoadedModel | None = None
        self._anomaly: LoadedModel | None = None
        self._importances: dict[str, list] | None = None

    # ------------------------------------------------------------------ load
    def load(self, *, prefer_versions: dict[str, str] | None = None) -> None:
        """Load newest artifacts from models_dir (or versions from DB registry)."""
        settings = get_settings()
        with self._lock:
            for task in ("binary", "multiclass", "anomaly"):
                loaded = self._newest_artifact(task, settings.models_dir, prefer_versions)
                setattr(self, f"_{task}", loaded)
            if self._binary:
                self._importances = self._extract_importances(self._binary)

    def _newest_artifact(self, task: str, models_dir: Path, prefer: dict[str, str] | None) -> LoadedModel | None:
        if task == "anomaly":
            candidates = sorted(
                models_dir.glob("isolation_forest_anomaly_*.joblib"),
                key=lambda p: p.stat().st_mtime,
            )
            if not candidates:  # tolerate legacy naming
                candidates = sorted(
                    (p for p in models_dir.glob("isolation_forest_*.joblib")
                     if "_anomaly_" not in p.name),
                    key=lambda p: p.stat().st_mtime,
                )
                legacy_task = "binary" if any("_binary_" in p.name for p in candidates) else "multiclass"
                candidates = [p for p in candidates if f"_{legacy_task}_" in p.name]
        else:
            # classifier slots must never pick up the anomaly detector
            candidates = sorted(
                (p for p in models_dir.glob(f"*_{task}_*.joblib")
                 if not p.name.startswith("isolation_forest")),
                key=lambda p: p.stat().st_mtime,
            )
        if not candidates:
            return None
        path = candidates[-1]
        # filename: {algorithm}_{task}_{version}.joblib (algorithm may contain '_')
        stem_parts = path.stem.split("_")
        version = stem_parts[-1]
        algo = path.stem.rsplit("_", 2)[0]
        try:
            model = joblib.load(path)
        except Exception as exc:
            logger.error("Failed to load %s: %s", path, exc)
            return None
        logger.info("Loaded %s model from %s", task, path.name)
        return LoadedModel(
            name=f"{algo}_{task}",
            algorithm=algo,
            task=task,
            version=version,
            model=model,
            feature_columns=list(CANONICAL_FEATURE_COLUMNS),
        )

    def register(self, *, algorithm: str, task: str, version: str, artifact_path: str,
                 feature_columns: list[str]) -> None:
        try:
            model = joblib.load(artifact_path)
        except Exception as exc:
            logger.error("register failed: %s", exc)
            return
        lm = LoadedModel(
            name=f"{algorithm}_{task}", algorithm=algorithm, task=task,
            version=version, model=model, feature_columns=feature_columns or list(CANONICAL_FEATURE_COLUMNS),
        )
        with self._lock:
            if task == "anomaly":
                self._anomaly = lm
            elif task == "multiclass":
                self._multiclass = lm
            else:
                self._binary = lm
                self._importances = self._extract_importances(lm)

    # ------------------------------------------------------------- inference
    @property
    def ready(self) -> bool:
        return self._binary is not None or self._multiclass is not None

    def info(self) -> dict:
        with self._lock:
            return {
                "binary": self._describe(self._binary),
                "multiclass": self._describe(self._multiclass),
                "anomaly": self._describe(self._anomaly),
            }

    @staticmethod
    def _describe(lm: LoadedModel | None) -> dict | None:
        if lm is None:
            return None
        return {"name": lm.name, "algorithm": lm.algorithm, "version": lm.version,
                "feature_count": len(lm.feature_columns)}

    def predict(self, features: dict[str, float]) -> dict:
        """Full detection: classification + optional anomaly score + severity.

        confidence = model decision/proba — NOT a calibrated probability.
        """
        vector = np.array(
            [float(features.get(c, 0.0) or 0.0) for c in CANONICAL_FEATURE_COLUMNS],
            dtype=np.float32,
        ).reshape(1, -1)

        with self._lock:
            bin_lm, mc_lm, an_lm = self._binary, self._multiclass, self._anomaly

        prediction = "Unknown"
        confidence = 0.0
        model_version = ""
        is_malicious = False

        active = mc_lm or bin_lm
        if active is None:
            return {
                "prediction": "Unknown", "is_malicious": False, "confidence": 0.0,
                "anomaly_score": None, "severity": "Informational",
                "model_version": "none", "model_loaded": False,
            }
        model_version = active.version

        try:
            if active.task == "multiclass" and mc_lm is not None:
                pred = mc_lm.model.predict(vector)[0]
                prediction = str(pred)
                if hasattr(mc_lm.model, "predict_proba"):
                    proba = mc_lm.model.predict_proba(vector)[0]
                    classes = list(mc_lm.model.classes_)
                    idx = classes.index(pred) if pred in classes else int(np.argmax(proba))
                    confidence = float(np.max(proba)) if idx == int(np.argmax(proba)) else float(proba[idx])
                else:
                    confidence = 1.0
                is_malicious = prediction.upper() != "BENIGN"
            elif bin_lm is not None:
                pred = bin_lm.model.predict(vector)[0]
                if hasattr(bin_lm.model, "predict_proba"):
                    confidence = float(bin_lm.model.predict_proba(vector)[0][1])
                elif hasattr(bin_lm.model, "decision_function"):
                    score = float(bin_lm.model.decision_function(vector)[0])
                    confidence = float(1 / (1 + np.exp(-score)))
                else:
                    confidence = 1.0
                # For binary, coarse attack-type hint from simple flow cues:
                prediction = "ATTACK" if int(pred) == 1 else "BENIGN"
                is_malicious = int(pred) == 1
        except Exception as exc:
            logger.error("prediction failed: %s", exc)

        anomaly_score = None
        if an_lm is not None:
            try:
                raw = -float(an_lm.model.score_samples(vector)[0])
                anomaly_score = float(min(max((raw + 3.0) / 6.0, 0.0), 1.0))
            except Exception as exc:
                logger.warning("anomaly score failed: %s", exc)

        severity = severity_for(prediction, is_malicious, confidence, anomaly_score)
        return {
            "prediction": prediction,
            "is_malicious": is_malicious,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else None,
            "severity": severity,
            "model_version": model_version,
            "model_loaded": True,
        }

    def predict_flow_tuple(self, **flow_kwargs) -> dict:
        from app.ml.features import flow_to_features

        feats = flow_to_features(**flow_kwargs)
        out = self.predict(feats)
        out["features"] = feats
        return out

    def explain_importances(self, top_k: int = 15) -> list[dict]:
        """Global feature importance (impurity/Gain-based fallback when SHAP absent)."""
        imp = self._importances or []
        paired = sorted(
            ({"feature": f, "importance": float(w)} for f, w in imp),
            key=lambda d: d["importance"], reverse=True,
        )
        return paired[:top_k]

    @staticmethod
    def _extract_importances(lm: LoadedModel) -> list | None:
        est = lm.model
        if hasattr(est, "named_steps"):
            est = est.named_steps.get("model", est)
        if hasattr(est, "feature_importances_"):
            fi = est.feature_importances_
            cols = lm.feature_columns or CANONICAL_FEATURE_COLUMNS
            if len(fi) == len(cols):
                return list(zip(cols, fi.tolist()))
        return None


def severity_for(prediction: str, is_malicious: bool, confidence: float,
                 anomaly_score: float | None = None) -> str:
    if not is_malicious:
        # still surface notable anomalies
        if anomaly_score is not None and anomaly_score >= 0.85:
            return "Low"
        return "Informational"
    base = _SEVERITY_BY_PREDICTION.get(prediction)
    if base is None:
        base = "Medium"  # Unknown / binary ATTACK
    # high-confidence DDoS/Infiltration/Bot escalate handled by base; demote low-confidence
    if confidence < 0.7 and base in {"Critical", "High"}:
        return "Medium"
    if prediction == "Unknown" and anomaly_score and anomaly_score >= 0.85:
        return "High"
    return base


registry = ModelRegistry()
