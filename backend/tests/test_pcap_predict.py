"""PCAP extraction + prediction API + alert workflow (end-to-end).

PCAP flow contract: upload via /datasets/upload (kind=pcap) → analyze via
/predict/analyze with {"dataset_id": ...}.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.network.pcap import extract_flows_from_pcap

FIXTURES = Path(__file__).resolve().parents[2] / "data" / "fixtures"


def _upload_pcap(client, headers, name: str) -> str:
    path = FIXTURES / name
    with path.open("rb") as fh:
        r = client.post("/api/datasets/upload",
                        files={"file": (name, fh, "application/vnd.tcpdump.pcap")},
                        headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.mark.skipif(not (FIXTURES / "lab_ddos_flood.pcap").exists(),
                    reason="fixtures not generated")
def test_pcap_extraction_ddos_fixture():
    flows = extract_flows_from_pcap(str(FIXTURES / "lab_ddos_flood.pcap"))
    assert len(flows) >= 50
    f = flows[0]
    assert f["protocol"] in ("TCP", "UDP")
    assert f["flow_features"]["Total Fwd Packets"] >= 1
    assert f["src_ip"] and f["dst_ip"]


@pytest.mark.skipif(not (FIXTURES / "lab_benign.pcap").exists(),
                    reason="fixtures not generated")
def test_pcap_benign_fixture_zero_malicious(client, analyst_headers):
    ds_id = _upload_pcap(client, analyst_headers, "lab_benign.pcap")
    r = client.post("/api/pcap/analyze", json={"dataset_id": ds_id}, headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["flows_extracted"] > 0
    assert body["malicious"] == 0


@pytest.mark.skipif(not (FIXTURES / "lab_ddos_flood.pcap").exists(),
                    reason="fixtures not generated")
def test_pcap_ddos_fixture_generates_alerts(client, analyst_headers):
    ds_id = _upload_pcap(client, analyst_headers, "lab_ddos_flood.pcap")
    r = client.post("/api/pcap/analyze", json={"dataset_id": ds_id}, headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["flows_extracted"] >= 50
    assert body["malicious"] >= 30
    assert body["alerts_created"] >= 1
    assert body["top_attacks"].get("DDoS", 0) >= 30


def test_predict_flow_api(client, analyst_headers):
    r = client.post("/api/predict/flow", json={
        "src_ip": "192.168.1.10", "dst_ip": "192.168.1.5",
        "src_port": 44321, "dst_port": 80, "protocol": "TCP",
        "flow_duration": 1.293792,
        "total_fwd_packets": 3, "total_bwd_packets": 8,
        "total_fwd_bytes": 26, "total_bwd_bytes": 11607,
    }, headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["prediction"]
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["model_loaded"] is True


def test_predict_requires_auth(client):
    r = client.post("/api/predict/flow", json={"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
                                               "src_port": 1, "dst_port": 2})
    assert r.status_code == 401


def test_upload_pcap_rejects_bad_extension(client, analyst_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("evil.exe", b"MZ", "application/octet-stream")},
                    headers=analyst_headers)
    assert r.status_code == 415


def test_upload_pcap_rejects_empty_file(client, analyst_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")},
                    headers=analyst_headers)
    assert r.status_code == 400


def test_viewer_cannot_upload_pcap(client, viewer_headers):
    r = client.post("/api/datasets/upload",
                    files={"file": ("x.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 24,
                                    "application/vnd.tcpdump.pcap")},
                    headers=viewer_headers)
    assert r.status_code == 403


def test_alert_status_workflow(client, analyst_headers):
    """New → Acknowledged → Investigating → Resolved → False Positive.
    Alerts come from the fixture PCAP path (full packet-level features)."""
    from pathlib import Path
    import pytest

    fx = Path(__file__).resolve().parents[2] / "data" / "fixtures" / "lab_ddos_flood.pcap"
    if not fx.exists():
        pytest.skip("fixtures not generated")
    with fx.open("rb") as fh:
        r = client.post("/api/datasets/upload",
                        files={"file": ("wf_ddos.pcap", fh, "application/vnd.tcpdump.pcap")},
                        headers=analyst_headers)
    assert r.status_code == 201
    ds_id = r.json()["id"]
    r = client.post("/api/pcap/analyze", json={"dataset_id": ds_id}, headers=analyst_headers)
    assert r.status_code == 200
    # alerts may dedup-fold into ones created by an earlier fixture test
    # (same deterministic IPs inside the dedup window) — that's correct behavior

    r = client.get("/api/alerts", params={"size": 50}, headers=analyst_headers)
    items = r.json()["items"]
    match = [a for a in items if a["attack_type"] == "DDoS"]
    assert match, "expected a DDoS alert from the fixture"
    aid = match[0]["id"]
    assert match[0]["status"] == "New"

    for status in ("Acknowledged", "Investigating", "Resolved"):
        r = client.patch(f"/api/alerts/{aid}", json={"status": status},
                         headers=analyst_headers)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == status

    r = client.post(f"/api/alerts/{aid}/ack", headers=analyst_headers)
    assert r.status_code == 200

    r = client.patch(f"/api/alerts/{aid}", json={"status": "False Positive"},
                     headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "False Positive"


def test_alert_invalid_status_rejected(client, analyst_headers):
    r = client.get("/api/alerts", params={"size": 1}, headers=analyst_headers)
    if not r.json()["items"]:
        pytest.skip("no alerts")
    aid = r.json()["items"][0]["id"]
    r = client.patch(f"/api/alerts/{aid}", json={"status": "MadeUp"}, headers=analyst_headers)
    assert r.status_code == 422
