"""Explainable AI: SHAP (TreeExplainer) with graceful fallbacks.

Methods in order of preference:
1. shap.TreeExplainer on the active tree model (exact for RF/DT/XGB)
2. per-feature perturbation on the active model
3. global impurity-based feature importance (always available for tree models)
"""
from __future__ import annotations

import logging
import threading

import numpy as np

from app.ml.features import CANONICAL_FEATURE_COLUMNS
from app.ml.predict import registry

logger = logging.getLogger("aiids.shap")

_shap_lock = threading.Lock()
_tree_explainer_cache: dict[str, object] = {}

try:
    import shap  # noqa: F401

    SHAP_AVAILABLE = True
except Exception:  # pragma: no cover
    shap = None
    SHAP_AVAILABLE = False


def _active_model():
    info = registry.info()
    # prefer binary, then multiclass
    for task in ("binary", "multiclass"):
        meta = info.get(task)
        if meta:
            with _shap_lock:
                lm = getattr(registry, f"_{task}")
                if lm is not None:
                    return lm
    return None


def _unwrap(model):
    # LabeledEstimator → its inner model for SHAP; sklearn Pipeline → named step.
    from app.ml.wrapper import LabeledEstimator

    if isinstance(model, LabeledEstimator):
        return model.model
    if hasattr(model, "named_steps"):
        inner = model.named_steps.get("model", model)
        if isinstance(inner, LabeledEstimator):
            return inner.model
        return inner
    return model


def explain_instance(feature_values: dict[str, float], top_k: int = 8) -> dict:
    """Per-flow explanation. Returns method + top attributed features + narrative."""
    lm = _active_model()
    if lm is None:
        return {
            "flow_id": "", "prediction": "", "confidence": 0.0,
            "method": "none", "features": [],
            "narrative": "No model is active — train or activate a model first.",
        }
    vec = np.array(
        [[float(feature_values.get(c, 0.0) or 0.0) for c in CANONICAL_FEATURE_COLUMNS]],
        dtype=np.float32,
    )
    model = _unwrap(lm.model)
    prediction, confidence = "", 0.0
    try:
        pred = model.predict(vec)[0]
        if hasattr(model, "predict_proba"):
            confidence = float(model.predict_proba(vec)[0].max())
        prediction = str(pred)
    except Exception as exc:
        logger.warning("predict in explain failed: %s", exc)

    method = "none"
    attribs: list[tuple[str, float, float]] = []

    # ---- 1. SHAP TreeExplainer ----
    if SHAP_AVAILABLE and hasattr(model, "feature_importances_"):
        try:
            key = f"{lm.name}:{lm.version}"
            explainer = _tree_explainer_cache.get(key)
            if explainer is None:
                from shap import TreeExplainer

                bg = np.zeros((1, len(CANONICAL_FEATURE_COLUMNS)), dtype=np.float32)
                explainer = TreeExplainer(model, data=bg)
                _tree_explainer_cache[key] = explainer
            shap_values = explainer.shap_values(vec)
            arr = shap_values[0] if isinstance(shap_values, list) else np.asarray(shap_values)
            if arr.ndim == 2:  # (n_classes, n_features) for multiclass
                arr = arr.sum(axis=0) if arr.shape[0] <= 16 else arr.mean(axis=0)
            if hasattr(arr, "shape") and len(np.shape(arr)) == 2:
                arr = np.asarray(arr).ravel()
            arr = np.asarray(arr).ravel()
            if arr.shape[0] == len(CANONICAL_FEATURE_COLUMNS):
                method = "shap"
                idx = np.argsort(np.abs(arr))[::-1][:top_k]
                attribs = [
                    (CANONICAL_FEATURE_COLUMNS[int(i)],
                     float(feature_values.get(CANONICAL_FEATURE_COLUMNS[int(i)], 0.0)),
                     float(arr[int(i)]))
                    for i in idx
                ]
        except Exception as exc:
            logger.info("SHAP failed (%s); falling back", exc)

    # ---- 2. perturbation fallback ----
    if method == "none" and hasattr(model, "predict_proba"):
        try:
            base = float(model.predict_proba(vec)[0].max())
            deltas = []
            for i, col in enumerate(CANONICAL_FEATURE_COLUMNS):
                perturbed = vec.copy()
                perturbed[0, i] = 0.0 if abs(perturbed[0, i]) < 1e-9 else 0.0
                alt = float(model.predict_proba(perturbed)[0].max())
                deltas.append((col, float(vec[0, i]), base - alt))
            method = "perturbation"
            deltas.sort(key=lambda t: abs(t[2]), reverse=True)
            attribs = deltas[:top_k]
        except Exception as exc:
            logger.info("perturbation fallback failed: %s", exc)

    # ---- 3. global importance fallback ----
    if method == "none":
        imp = registry.explain_importances(top_k=top_k)
        if imp:
            method = "tree_importance_fallback"
            attribs = [
                (d["feature"], float(feature_values.get(d["feature"], 0.0)), float(d["importance"]))
                for d in imp
            ]

    features = [
        {"feature": f, "value": v, "attribution": round(a, 6)}
        for f, v, a in attribs
    ]
    narrative = _narrative(features, prediction, method)
    return {
        "flow_id": "",
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "method": method,
        "features": features,
        "narrative": narrative,
    }


def _narrative(features: list[dict], prediction: str, method: str) -> str:
    if not features:
        return "No attributions available for this flow."
    top = sorted(features, key=lambda d: abs(d["attribution"]), reverse=True)[:3]
    phrases = []
    for f in top:
        name = f["feature"].lower()
        direction = "elevated" if f["attribution"] > 0 else "reduced"
        phrases.append(f"{direction} {name} (value {f['value']:,.2f})")
    joined = ", ".join(phrases[:-1]) + (" and " + phrases[-1] if len(phrases) > 1 else "")
    head = f"Classification as '{prediction}' was driven by {joined}."
    if method == "shap":
        head += " (SHAP TreeExplainer attributions)"
    elif method == "tree_importance_fallback":
        head += " Note: based on global tree feature importance (SHAP unavailable for this model)."
    return head


def global_importance(top_k: int = 20) -> dict:
    lm = _active_model()
    imp = registry.explain_importances(top_k=top_k)
    method = "gini_importance"
    # Prefer SHAP mean |value| on a small synthetic background when available.
    if SHAP_AVAILABLE and lm is not None and imp:
        try:
            model = _unwrap(lm.model)
            if hasattr(model, "feature_importances_"):
                rng = np.random.default_rng(42)
                X = np.abs(rng.standard_normal((32, len(CANONICAL_FEATURE_COLUMNS)))).astype(np.float32)
                explainer = shap.TreeExplainer(model)
                sv = explainer.shap_values(X)
                arr = sv[0] if isinstance(sv, list) else np.asarray(sv)
                if isinstance(arr, list):
                    arr = np.mean([np.abs(a) for a in arr], axis=0)
                arr = np.asarray(arr)
                if arr.ndim == 3:
                    arr = np.abs(arr).mean(axis=0).mean(axis=0)
                elif arr.ndim == 2 and arr.shape[-1] == len(CANONICAL_FEATURE_COLUMNS):
                    arr = np.abs(arr).mean(axis=0)
                arr = np.ravel(arr)
                if arr.shape[0] == len(CANONICAL_FEATURE_COLUMNS):
                    pairs = sorted(
                        zip(CANONICAL_FEATURE_COLUMNS, arr.tolist()),
                        key=lambda t: t[1], reverse=True,
                    )
                    imp = [{"feature": f, "importance": float(w)} for f, w in pairs[:top_k]]
                    method = "shap_mean_abs"
        except Exception as exc:
            logger.info("SHAP global failed (%s); using Gini importance", exc)
    return {
        "method": method,
        "model_version": lm.version if lm else "",
        "features": imp,
    }
