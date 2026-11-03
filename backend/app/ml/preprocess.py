"""Dataset loading, validation and cleaning for CIC-style CSVs."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from app.ml.features import (
    CANONICAL_FEATURE_COLUMNS,
    LABEL_COLUMN,
    is_malicious_label,
    normalize_label,
)

logger = logging.getLogger("aiids.ml")

MAX_ROWS_HARD_CAP = 2_000_000


class DatasetValidationError(ValueError):
    pass


def read_cic_csv(path: str | Path, max_rows: int | None = None) -> pd.DataFrame:
    """Read a CICFlowMeter CSV, normalizing headers (dedupes 'Fwd Header Length')."""
    path = Path(path)
    if not path.exists():
        raise DatasetValidationError(f"File not found: {path.name}")
    if path.stat().st_size == 0:
        raise DatasetValidationError("File is empty")

    df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    if df.shape[1] == 0:
        raise DatasetValidationError("CSV has no columns")

    # Strip whitespace from headers (CIC exports pad them).
    df.columns = [str(c).strip() for c in df.columns]
    if LABEL_COLUMN not in df.columns:
        # tolerate case variants
        labelish = [c for c in df.columns if c.lower() == "label"]
        if not labelish:
            raise DatasetValidationError(
                "Missing 'Label' column — not a labeled CIC-IDS dataset export."
            )
        df = df.rename(columns={labelish[0]: LABEL_COLUMN})

    # Resolve duplicated feature header (CICFlowMeter emits 'Fwd Header Length' twice).
    seen: dict[str, int] = {}
    renamed = []
    for c in df.columns:
        if c in seen:
            seen[c] += 1
            renamed.append(f"{c}.{seen[c]}")
        else:
            seen[c] = 0
            renamed.append(c)
    df.columns = renamed

    missing = [c for c in CANONICAL_FEATURE_COLUMNS if c not in df.columns]
    if missing and len(missing) == len(CANONICAL_FEATURE_COLUMNS):
        raise DatasetValidationError(
            "CSV does not contain CICFlowMeter feature columns (feature schema mismatch)."
        )
    if missing:
        logger.warning("CSV missing %d features (will be filled with 0): %s", len(missing), missing[:6])
    return df


def clean_dataset(df: pd.DataFrame, *, drop_duplicates: bool = True) -> tuple[pd.DataFrame, dict]:
    """Validate + clean: inf/nan handling, dedupe, label normalization.

    Returns (cleaned_df, report).

    Memory-bounded implementation: builds ONE consolidated float64 matrix
    column-by-column instead of chaining frame-level copy/replace/isna steps.
    The naive chain needs >3.5 GB simultaneously on the full 971k-row CIC set
    and gets OOM-killed on a 4 GB host; this path peaks near 2 GB with identical
    row order, dedupe decisions, and label handling (float64 throughout, so
    downstream sampling/metrics match the original semantics exactly).
    """
    report: dict = {
        "rows_in": int(len(df)),
        "duplicates_removed": 0,
        "non_finite_replaced": 0,
        "labels": {},
    }
    if LABEL_COLUMN not in df.columns:
        raise DatasetValidationError("Missing Label column")

    labels = df[LABEL_COLUMN].astype(str).str.strip().to_numpy()
    present = [c for c in CANONICAL_FEATURE_COLUMNS if c in df.columns]

    n = len(df)
    arr = np.empty((n, len(present)), dtype=np.float64)
    for i, c in enumerate(present):
        col = pd.to_numeric(df[c], errors="coerce")
        arr[:, i] = col.to_numpy(dtype=np.float64, copy=False)

    inf_mask = np.isinf(arr)
    report["non_finite_replaced"] = int(inf_mask.sum())
    arr[inf_mask] = np.nan

    # Rows whose label is unusable... original semantics: astype(str) runs first,
    # so label-NaN never survives as NaN — keep = rows with all-finite features.
    bad = np.isnan(arr).any(axis=1)
    if bad.any():
        arr = arr[~bad]
        labels = labels[~bad]

    out = pd.DataFrame(arr, columns=present)
    out[LABEL_COLUMN] = labels

    if drop_duplicates:
        dupes = out.duplicated()
        report["duplicates_removed"] = int(dupes.sum())
        if dupes.any():
            out = out[~dupes]

    out[LABEL_COLUMN] = out[LABEL_COLUMN].map(normalize_label)
    report["rows_out"] = int(len(out))
    report["labels"] = {str(k): int(v) for k, v in out[LABEL_COLUMN].value_counts().items()}
    return out.reset_index(drop=True), report


def prepare_xy(
    df: pd.DataFrame, task: str = "binary", max_rows: int | None = None, random_state: int = 42
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Feature matrix X, label vector y (binary → {0,1}; multiclass → canonical strings)."""
    cols = [c for c in CANONICAL_FEATURE_COLUMNS if c in df.columns]
    X = df[cols].to_numpy(dtype=np.float32)
    if task == "binary":
        y = df[LABEL_COLUMN].apply(lambda l: 0 if str(l).upper() == "BENIGN" else 1).to_numpy(np.int8)
    else:
        y = df[LABEL_COLUMN].astype(str).to_numpy()

    if max_rows and len(X) > max_rows:
        rng = np.random.default_rng(random_state)
        idx = rng.choice(len(X), size=max_rows, replace=False)
        idx.sort()
        X, y = X[idx], y[idx]
        logger.info("Subsampled to %d rows for training", max_rows)
    return X, y, cols


def label_distribution(path: str | Path, max_rows: int | None = 200_000) -> dict:
    try:
        df = read_cic_csv(path, max_rows=max_rows)
        labels = df[LABEL_COLUMN].astype(str).apply(normalize_label)
        return {str(k): int(v) for k, v in labels.value_counts().items()}
    except Exception as exc:  # pragma: no cover
        logger.warning("label_distribution failed for %s: %s", path, exc)
        return {"error": str(exc)}


def iter_dataset_paths(paths: Iterable[str | Path]) -> list[Path]:
    out = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out.extend(sorted(p.glob("*.csv")))
        elif p.exists():
            out.append(p)
    return out
