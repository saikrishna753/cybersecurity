#!/usr/bin/env python3
"""CLI: train AI-IDS models on CIC-IDS2017 CSVs.

Usage:
  python scripts/train_models.py --data /path/to/csvs --task binary --max-rows 300000
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.ml.train import train_from_paths  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Train AI-IDS models")
    ap.add_argument("--data", default=str(BACKEND.parent / "data" / "cicids2017"))
    ap.add_argument("--task", choices=["binary", "multiclass"], default="binary")
    ap.add_argument(
        "--algorithms",
        default="decision_tree,random_forest,xgboost,isolation_forest",
    )
    ap.add_argument("--max-rows", type=int, default=300_000)
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--random-state", type=int, default=42)
    args = ap.parse_args()

    data = Path(args.data)
    if data.is_dir():
        paths = sorted(data.glob("*.csv"))
    else:
        paths = [data]
    if not paths:
        print(f"No CSVs found under {data}", file=sys.stderr)
        return 1

    print(f"Training {args.task} models on {len(paths)} file(s):")
    for p in paths:
        print(f"  - {p.name}")

    def progress(pct: int, stage: str) -> None:
        print(f"[{pct:3d}%] {stage}", flush=True)

    results = train_from_paths(
        paths,
        task=args.task,
        algorithms=[a.strip() for a in args.algorithms.split(",") if a.strip()],
        test_size=args.test_size,
        max_rows=args.max_rows,
        random_state=args.random_state,
        progress=progress,
    )
    print("\n=== ACTUAL MEASURED METRICS ===")
    for r in results:
        m = r.metrics
        headline = {
            k: (round(v, 4) if isinstance(v, float) else v)
            for k, v in m.items()
            if k in {"accuracy", "precision", "recall", "f1", "f1_macro", "fpr", "roc_auc",
                     "roc_auc_ovr_macro", "train_seconds", "train_rows", "test_rows"}
        }
        print(f"\n{r.algorithm} ({r.task}):")
        print(json.dumps(headline, indent=2))
        print(f"  artifact: {r.artifact_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
