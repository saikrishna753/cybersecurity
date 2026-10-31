"""Artifact wrappers that keep inference contracts intact after joblib load."""
from __future__ import annotations

import numpy as np


class LabeledEstimator:
    """Wraps an estimator fit on integer codes so predict() returns real labels.

    Used for XGBoost multiclass (which requires int-coded targets).
    Exposes classes_/feature_importances_ so metrics, SHAP and registry code
    treat it like a plain sklearn estimator.
    """

    def __init__(self, model, labels: list) -> None:
        self.model = model
        self.labels = [str(l) for l in labels]

    # ------------------------------------------------------------- sklearn API
    def predict(self, X):
        idx = np.asarray(self.model.predict(X)).astype(int).ravel()
        return np.array([self.labels[i] if 0 <= i < len(self.labels) else str(i)
                         for i in idx])

    def predict_proba(self, X):
        return self.model.predict_proba(X)

    def fit(self, X, y):  # pragma: no cover - artifacts are pre-fit
        raise RuntimeError("LabeledEstimator artifacts are pre-trained and read-only")

    @property
    def classes_(self) -> np.ndarray:
        if hasattr(self.model, "classes_"):
            raw = list(self.model.classes_)
            try:
                return np.array([self.labels[int(c)] if str(c).lstrip("-").isdigit()
                                 and 0 <= int(c) < len(self.labels) else str(c)
                                 for c in raw])
            except (ValueError, TypeError):
                pass
        return np.array(self.labels)

    @property
    def feature_importances_(self):
        return self.model.feature_importances_

    def __getattr__(self, item):
        # During unpickling, `model` may not be set yet — guard against recursion.
        if item in {"model", "labels"}:
            raise AttributeError(item)
        model = self.__dict__.get("model")
        if model is None:
            raise AttributeError(item)
        return getattr(model, item)
