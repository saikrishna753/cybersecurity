"""Flow features: CIC schema, label normalization, stats semantics."""
from __future__ import annotations

import math

from app.ml.features import (
    CANONICAL_FEATURE_COLUMNS,
    flow_to_features,
    is_malicious_label,
    normalize_label,
)


def test_schema_is_78_features():
    assert len(CANONICAL_FEATURE_COLUMNS) == 78
    assert len(set(CANONICAL_FEATURE_COLUMNS)) == 78


def test_label_normalization():
    assert normalize_label("BENIGN") == "BENIGN"
    assert normalize_label(" DDoS ") == "DDoS"
    assert normalize_label("Web Attack � Brute Force") == "Web Attack"
    assert normalize_label("web attack – xss") == "Web Attack"
    assert is_malicious_label("PortScan")
    assert not is_malicious_label("BENIGN")


def test_flow_to_features_counts():
    f = flow_to_features(
        dst_port=443, flow_duration=1_000_000,
        total_fwd_packets=4, total_bwd_packets=6,
        total_fwd_bytes=400, total_bwd_bytes=1600,
        fwd_pkt_sizes=[100, 100, 100, 100],
        bwd_pkt_sizes=[400, 400, 400, 200, 100, 100],
    )
    assert f["Destination Port"] == 443
    assert f["Flow Duration"] == 1_000_000
    assert f["Total Fwd Packets"] == 4
    assert f["Flow Bytes/s"] == 2000.0
    assert f["Fwd Packet Length Mean"] == 100.0
    assert f["Bwd Packet Length Max"] == 400.0
    # every canonical key present
    assert all(c in f for c in CANONICAL_FEATURE_COLUMNS)


def test_zero_duration_rates_are_zero():
    f = flow_to_features(
        dst_port=80, flow_duration=0,
        total_fwd_packets=1, total_bwd_packets=1,
        total_fwd_bytes=0, total_bwd_bytes=0)
    assert f["Flow Bytes/s"] == 0.0
    assert f["Flow Packets/s"] == 0.0


def test_sample_std_matches_cic_semantics():
    # CICFlowMeter uses n-1 denominator: [2,6] → std 2.828…
    f = flow_to_features(
        dst_port=80, flow_duration=671,
        total_fwd_packets=2, total_bwd_packets=1,
        total_fwd_bytes=8, total_bwd_bytes=2,
        fwd_pkt_sizes=[2, 6], bwd_pkt_sizes=[2])
    assert math.isclose(f["Fwd Packet Length Std"], math.sqrt(8), rel_tol=1e-6)
