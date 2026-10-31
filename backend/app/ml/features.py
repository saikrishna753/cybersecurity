"""Canonical ML feature schema (CICFlowMeter v1) + flow→feature derivation.

The feature order/names here are THE contract between training, prediction,
SHAP explainability, and the network flow extractor.
"""
from __future__ import annotations

import math

# 78 CICFlowMeter columns (excluding Label), in training order.
# Note: CICFlowMeter emits 'Fwd Header Length' twice; we keep both positions
# but disambiguate names for internal bookkeeping.
_BASE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

CANONICAL_FEATURE_COLUMNS: list[str] = list(_BASE_COLUMNS)  # 78 features

# CIC CSV header name used at read time (duplicate resolved by position).
CIC_CSV_HEADER: list[str] = [
    c.replace("Fwd Header Length.1", "Fwd Header Length") for c in _BASE_COLUMNS
]

LABEL_COLUMN = "Label"

# --------------------------------------------------------------------------- #
# Label normalization
# --------------------------------------------------------------------------- #
CANONICAL_LABELS = [
    "BENIGN", "DoS", "DDoS", "PortScan", "Web Attack", "Brute Force",
    "Bot", "Infiltration", "FTP-Patator", "SSH-Patator", "Heartbleed",
    "DoS GoldenEye", "DoS Slowloris", "DoS Hulk", "DoS Slowhttptest",
]

_LABEL_MAP = {
    "benign": "BENIGN",
    "ddos": "DDoS",
    "dos": "DoS",
    "portscan": "PortScan",
    "web attack � brute force": "Web Attack",
    "web attack – brute force": "Web Attack",
    "web attack — brute force": "Web Attack",
    "web attack brute force": "Web Attack",
    "web attack � xss": "Web Attack",
    "web attack – xss": "Web Attack",
    "web attack xss": "Web Attack",
    "web attack � sql injection": "Web Attack",
    "web attack – sql injection": "Web Attack",
    "web attack sql injection": "Web Attack",
    "web attack": "Web Attack",
    "infiltration": "Infiltration",
    "bot": "Bot",
    "ftp-patator": "FTP-Patator",
    "ssh-patator": "SSH-Patator",
    "heartbleed": "Heartbleed",
    "dos goldeneye": "DoS GoldenEye",
    "dos slowloris": "DoS Slowloris",
    "dos hulk": "DoS Hulk",
    "dos slowhttptest": "DoS Slowhttptest",
}


def normalize_label(raw: str) -> str:
    """Map any known CIC label variant to its canonical form."""
    if raw is None:
        return "BENIGN"
    key = str(raw).strip()
    low = key.lower()
    if low in _LABEL_MAP:
        return _LABEL_MAP[low]
    # tolerate replacement-garbled separators: "Web Attack • Brute Force" etc.
    if low.replace("�", " ").replace("–", " ").replace("—", " ").replace("•", " ").startswith(
        "web attack"
    ):
        return "Web Attack"
    return key


def is_malicious_label(label: str) -> bool:
    return normalize_label(label).upper() != "BENIGN"


# --------------------------------------------------------------------------- #
# Flow tuple → canonical feature vector (used by PCAP/live/API prediction)
# --------------------------------------------------------------------------- #
def _safe_div(a: float, b: float) -> float:
    return float(a) / float(b) if b else 0.0


def flow_to_features(
    *,
    dst_port: int,
    flow_duration: float,
    total_fwd_packets: int,
    total_bwd_packets: int,
    total_fwd_bytes: int,
    total_bwd_bytes: int,
    src_port: int = 0,
    fwd_pkt_sizes: list[int] | None = None,
    bwd_pkt_sizes: list[int] | None = None,
    tcp_flags_fwd: list[int] | None = None,
    tcp_flags_bwd: list[int] | None = None,
    fwd_header_len: int | None = None,
    bwd_header_len: int | None = None,
    init_win_fwd: int | None = None,
    init_win_bwd: int | None = None,
) -> dict[str, float]:
    """Build a feature dict consistent with CICFlowMeter semantics.

    Where packet-level detail is unavailable (CSV/API minimal inputs), derived
    statistics degrade gracefully (means from totals, zeros for IAT etc.).
    Values are computed in CIC units: Flow Duration in µs, rates per second.
    """
    fwd = fwd_pkt_sizes or []
    bwd = bwd_pkt_sizes or []
    dur_us = max(flow_duration, 0.0)
    total_pkts = total_fwd_packets + total_bwd_packets
    total_bytes = total_fwd_bytes + total_bwd_bytes

    def stats(vals: list[int]) -> tuple[float, float, float, float]:
        if not vals:
            return 0.0, 0.0, 0.0, 0.0
        n = len(vals)
        mean = sum(vals) / n
        # CICFlowMeter uses the sample standard deviation (n-1 denominator);
        # matching it keeps live PCAP features on the training distribution.
        var = sum((v - mean) ** 2 for v in vals) / (n - 1) if n > 1 else 0.0
        return float(max(vals)), float(min(vals)), mean, math.sqrt(var)

    f_max, f_min, f_mean, f_std = stats(fwd)
    b_max, b_min, b_mean, b_std = stats(bwd)
    all_sizes = fwd + bwd
    a_max, a_min, a_mean, a_std = stats(all_sizes) if all_sizes else (
        float(max(total_fwd_bytes, total_bwd_bytes)), 0.0,
        _safe_div(total_bytes, total_pkts), 0.0,
    )

    dur_s = dur_us / 1_000_000.0 if dur_us > 1000 else (dur_us if dur_us < 600 else dur_us / 1_000_000.0)
    # CIC duration is µs; assume µs when large.
    dur_s = dur_us / 1_000_000.0

    def flag_count(flags: list[int], mask: int) -> int:
        return sum(1 for f in flags if f & mask)

    all_flags = (tcp_flags_fwd or []) + (tcp_flags_bwd or [])

    # IAT approximation when packet timestamps aren't provided: uniform spacing.
    iat_mean = _safe_div(dur_us, max(total_pkts - 1, 1)) if total_pkts > 1 else 0.0

    fwd_hdr = fwd_header_len if fwd_header_len is not None else 20 * total_fwd_packets
    bwd_hdr = bwd_header_len if bwd_header_len is not None else 20 * total_bwd_packets

    feats = {
        "Destination Port": float(dst_port),
        "Flow Duration": float(dur_us),
        "Total Fwd Packets": float(total_fwd_packets),
        "Total Backward Packets": float(total_bwd_packets),
        "Total Length of Fwd Packets": float(total_fwd_bytes),
        "Total Length of Bwd Packets": float(total_bwd_bytes),
        "Fwd Packet Length Max": f_max or _safe_div(total_fwd_bytes, total_fwd_packets or 1),
        "Fwd Packet Length Min": f_min,
        "Fwd Packet Length Mean": f_mean or _safe_div(total_fwd_bytes, total_fwd_packets or 1),
        "Fwd Packet Length Std": f_std,
        "Bwd Packet Length Max": b_max,
        "Bwd Packet Length Min": b_min,
        "Bwd Packet Length Mean": b_mean or _safe_div(total_bwd_bytes, total_bwd_packets or 1),
        "Bwd Packet Length Std": b_std,
        "Flow Bytes/s": _safe_div(total_bytes, dur_s) if dur_s > 0 else 0.0,
        "Flow Packets/s": _safe_div(total_pkts, dur_s) if dur_s > 0 else 0.0,
        "Flow IAT Mean": iat_mean,
        "Flow IAT Std": 0.0,
        "Flow IAT Max": iat_mean,
        "Flow IAT Min": 0.0,
        "Fwd IAT Total": float(dur_us) if total_fwd_packets > 1 else 0.0,
        "Fwd IAT Mean": iat_mean,
        "Fwd IAT Std": 0.0,
        "Fwd IAT Max": iat_mean,
        "Fwd IAT Min": 0.0,
        "Bwd IAT Total": float(dur_us) if total_bwd_packets > 1 else 0.0,
        "Bwd IAT Mean": iat_mean,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": iat_mean,
        "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": float(flag_count(tcp_flags_fwd or [], 0x08)),
        "Bwd PSH Flags": float(flag_count(tcp_flags_bwd or [], 0x08)),
        "Fwd URG Flags": float(flag_count(tcp_flags_fwd or [], 0x20)),
        "Bwd URG Flags": float(flag_count(tcp_flags_bwd or [], 0x20)),
        "Fwd Header Length": float(fwd_hdr),
        "Bwd Header Length": float(bwd_hdr),
        "Fwd Packets/s": _safe_div(total_fwd_packets, dur_s) if dur_s > 0 else 0.0,
        "Bwd Packets/s": _safe_div(total_bwd_packets, dur_s) if dur_s > 0 else 0.0,
        "Min Packet Length": a_min if all_sizes else float(total_bytes and min(total_fwd_bytes, total_bwd_bytes) or 0),
        "Max Packet Length": a_max,
        "Packet Length Mean": a_mean,
        "Packet Length Std": a_std,
        "Packet Length Variance": a_std ** 2,
        "FIN Flag Count": float(flag_count(all_flags, 0x01)),
        "SYN Flag Count": float(flag_count(all_flags, 0x02)),
        "RST Flag Count": float(flag_count(all_flags, 0x04)),
        "PSH Flag Count": float(flag_count(all_flags, 0x08)),
        "ACK Flag Count": float(flag_count(all_flags, 0x10)),
        "URG Flag Count": float(flag_count(all_flags, 0x20)),
        "CWE Flag Count": float(flag_count(all_flags, 0x40)),
        "ECE Flag Count": float(flag_count(all_flags, 0x80)),
        "Down/Up Ratio": _safe_div(total_bwd_packets, total_fwd_packets or 1),
        "Average Packet Size": _safe_div(total_bytes, total_pkts or 1),
        "Avg Fwd Segment Size": _safe_div(total_fwd_bytes, total_fwd_packets or 1),
        "Avg Bwd Segment Size": _safe_div(total_bwd_bytes, total_bwd_packets or 1),
        "Fwd Header Length.1": float(fwd_hdr),
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": float(total_fwd_packets),
        "Subflow Fwd Bytes": float(total_fwd_bytes),
        "Subflow Bwd Packets": float(total_bwd_packets),
        "Subflow Bwd Bytes": float(total_bwd_bytes),
        "Init_Win_bytes_forward": float(init_win_fwd if init_win_fwd is not None else 8192),
        "Init_Win_bytes_backward": float(init_win_bwd if init_win_bwd is not None else 8192),
        "act_data_pkt_fwd": float(sum(1 for s in fwd if s > 0)),
        "min_seg_size_forward": float(min(fwd) if fwd else 20),
        "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0, "Active Min": 0.0,
        "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0,
    }
    return feats


def features_to_vector(features: dict[str, float]) -> list[float]:
    """Ordered float vector per CANONICAL_FEATURE_COLUMNS (missing → 0.0)."""
    return [float(features.get(c, 0.0) or 0.0) for c in CANONICAL_FEATURE_COLUMNS]
