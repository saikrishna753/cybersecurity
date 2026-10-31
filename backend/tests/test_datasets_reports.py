"""Dataset upload validation, dashboard stats, explainability, reports."""
from __future__ import annotations

import io

CIC_HEADER = (
    "Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,"
    "Total Length of Fwd Packets,Total Length of Bwd Packets,Fwd Packet Length Max,"
    "Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
    "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,"
    "Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,"
    "Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,"
    "Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
    "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,"
    "Bwd Header Length,Fwd Packets/s,Bwd Packets/s,Min Packet Length,Max Packet Length,"
    "Packet Length Mean,Packet Length Std,Packet Length Variance,FIN Flag Count,"
    "SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,"
    "CWE Flag Count,ECE Flag Count,Down/Up Ratio,Average Packet Size,Avg Fwd Segment Size,"
    "Avg Bwd Segment Size,Fwd Header Length,Fwd Avg Bytes/Bulk,Fwd Avg Packets/Bulk,"
    "Fwd Avg Bulk Rate,Bwd Avg Bytes/Bulk,Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate,"
    "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,"
    "Init_Win_bytes_forward,Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,"
    "Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label\n"
)


def _csv_bytes(rows: int = 20) -> bytes:
    buf = io.StringIO()
    buf.write(CIC_HEADER + "\n")
    for i in range(rows):
        vals = [str((i * 37 + j) % 1000) for j in range(78)]
        label = "BENIGN" if i % 4 else "DDoS"
        buf.write(",".join(vals) + f",{label}\n")
    return buf.getvalue().encode()


def test_dataset_upload_and_list(client, analyst_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("sample.csv", _csv_bytes(), "text/csv")},
                    headers=analyst_headers)
    assert r.status_code == 201, r.text
    ds = r.json()
    assert ds["kind"] == "csv"
    r = client.get("/api/datasets", headers=analyst_headers)
    assert r.status_code == 200
    assert any(d["id"] == ds["id"] for d in r.json()["items"])


def test_dataset_rejects_non_csv(client, analyst_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
                    headers=analyst_headers)
    assert r.status_code == 415


def test_dataset_rejects_path_traversal_name(client, analyst_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("../../etc/passwd.csv", _csv_bytes(3), "text/csv")},
                    headers=analyst_headers)
    # either rejected or sanitized — never written outside upload dir
    if r.status_code == 201:
        assert ".." not in r.json()["name"]
    else:
        assert r.status_code == 400


def test_dataset_analyze(client, analyst_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("analyze_me.csv", _csv_bytes(30), "text/csv")},
                    headers=analyst_headers)
    assert r.status_code == 201
    ds_id = r.json()["id"]
    r = client.post(f"/api/datasets/{ds_id}/analyze", headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dataset_id"] == ds_id
    assert "report" in body
    assert "class_balance_pct" in body
    assert sum(body["report"]["labels"].values()) == 30


def test_dashboard_stats(client, admin_headers):
    r = client.get("/api/dashboard/stats", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    for key in ("total_flows", "total_attacks", "total_normal", "total_alerts"):
        assert key in body, f"missing {key}"


def test_explain_global(client, admin_headers):
    r = client.get("/api/explain/global", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    feats = body["features"]
    assert len(feats) >= 5
    assert all("feature" in f and "importance" in f for f in feats)


def test_explain_prediction(client, analyst_headers):
    """Explain a detection produced from the DDoS fixture PCAP."""
    from pathlib import Path

    fx = Path(__file__).resolve().parents[2] / "data" / "fixtures" / "lab_portscan.pcap"
    if not fx.exists():
        import pytest
        pytest.skip("fixtures not generated")
    with fx.open("rb") as fh:
        r = client.post("/api/datasets/upload",
                        files={"file": ("lab_portscan.pcap", fh, "application/vnd.tcpdump.pcap")},
                        headers=analyst_headers)
    assert r.status_code == 201
    ds_id = r.json()["id"]
    r = client.post("/api/pcap/analyze", json={"dataset_id": ds_id}, headers=analyst_headers)
    assert r.status_code == 200
    # pick a malicious detection flow id from the alerts
    r = client.get("/api/alerts", params={"size": 1}, headers=analyst_headers)
    items = r.json()["items"]
    assert items, "expected alerts from portscan fixture"
    flow_id = items[0]["flow_id"]
    r = client.post("/api/explain/prediction", json={"flow_id": flow_id, "top_k": 8},
                    headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["prediction"]
    assert len(body["features"]) >= 5
    assert body["method"]


def test_reports_generate_csv_list_download(client, analyst_headers):
    r = client.post("/api/reports/generate",
                    json={"report_type": "daily", "format": "csv"}, headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["filename"].endswith(".csv")
    assert body["rows"] >= 0
    r = client.get("/api/reports/list", headers=analyst_headers)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(i["filename"] == body["filename"] for i in items)
    r = client.get(f"/api/reports/download/{body['filename']}", headers=analyst_headers)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


def test_reports_generate_pdf(client, analyst_headers):
    r = client.post("/api/reports/generate",
                    json={"report_type": "daily", "format": "pdf"}, headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["filename"].endswith(".pdf")
    r = client.get(f"/api/reports/download/{body['filename']}", headers=analyst_headers)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_reports_download_traversal_blocked(client, analyst_headers):
    r = client.get("/api/reports/download/..%2F..%2Fetc%2Fpasswd", headers=analyst_headers)
    assert r.status_code in (400, 404)
