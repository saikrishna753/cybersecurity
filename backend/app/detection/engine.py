"""Detection engine: flow → features → model inference → severity → alert event."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from app.ml.features import CANONICAL_FEATURE_COLUMNS, flow_to_features
from app.ml.predict import registry, severity_for

logger = logging.getLogger("aiids.detection")

AlertSink = Callable[[dict], None]


class DetectionEngine:
    """Connects flow extraction with ML models; persists results via callback."""

    def __init__(self) -> None:
        self._alert_sinks: list[AlertSink] = []

    def subscribe_alerts(self, sink: AlertSink) -> None:
        self._alert_sinks.append(sink)

    # ------------------------------------------------------------------ API
    def detect_flow(self, flow: dict, *, publish: bool = True) -> dict:
        """Run the full detection workflow on a contract flow dict.

        1. validate  2. features  3. classify  4. anomaly  5. severity
        6. result    7. publish alert event when malicious
        Set publish=False when the caller persists alerts itself (batch paths
        must not open a second DB session while a write txn is open).
        """
        feats = flow.get("flow_features")
        if not isinstance(feats, dict) or not feats:
            feats = flow_to_features(
                dst_port=int(flow.get("dst_port", 0)),
                src_port=int(flow.get("src_port", 0)),
                flow_duration=float(flow.get("flow_duration", 0.0)) * 1_000_000,
                total_fwd_packets=int(flow.get("total_fwd_packets", 0)),
                total_bwd_packets=int(flow.get("total_bwd_packets", 0)),
                total_fwd_bytes=int(flow.get("total_fwd_bytes", 0)),
                total_bwd_bytes=int(flow.get("total_bwd_bytes", 0)),
            )
        # Guard schema drift: missing keys → 0.0 (training contract).
        for col in CANONICAL_FEATURE_COLUMNS:
            feats.setdefault(col, 0.0)

        inference = registry.predict(feats)
        ts = flow.get("timestamp") or datetime.now(timezone.utc).isoformat()
        if isinstance(ts, datetime):
            ts = ts.isoformat()

        result = {
            "flow_id": flow.get("flow_id") or str(uuid.uuid4()),
            "prediction": inference["prediction"],
            "is_malicious": bool(inference["is_malicious"]),
            "confidence": float(inference["confidence"]),
            "anomaly_score": inference.get("anomaly_score"),
            "severity": inference.get("severity") or severity_for(
                inference["prediction"], inference["is_malicious"],
                inference["confidence"], inference.get("anomaly_score"),
            ),
            "model_version": inference.get("model_version", ""),
            "timestamp": ts,
            "src_ip": flow.get("src_ip", ""),
            "dst_ip": flow.get("dst_ip", ""),
            "dst_port": int(flow.get("dst_port", 0)),
            "protocol": flow.get("protocol", "TCP"),
            "model_loaded": inference.get("model_loaded", False),
        }

        if result["is_malicious"] and publish:
            alert = self._alert_event(result, flow)
            for sink in self._alert_sinks:
                try:
                    sink(alert)
                except Exception:
                    logger.exception("alert sink failed")
        return result

    def detect_many(self, flows: list[dict]) -> list[dict]:
        return [self.detect_flow(f) for f in flows]

    @staticmethod
    def _alert_event(result: dict, flow: dict) -> dict:
        """Contract Security Alert shape (docs/INTEGRATION_CONTRACT.md §3)."""
        return {
            "alert_id": str(uuid.uuid4()),
            "flow_id": result["flow_id"],
            "attack_type": result["prediction"],
            "source_ip": result["src_ip"],
            "destination_ip": result["dst_ip"],
            "destination_port": result["dst_port"],
            "protocol": result["protocol"],
            "severity": result["severity"],
            "status": "New",
            "confidence": result["confidence"],
            "model_version": result["model_version"],
            "dedup_count": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "anomaly_score": result.get("anomaly_score"),
        }


detection_engine = DetectionEngine()
