"""Incidents API: CRUD, notes, timeline."""
from __future__ import annotations


def test_incident_lifecycle(client, analyst_headers):
    r = client.post("/api/incidents", json={
        "title": "Lab DDoS triage", "severity": "High",
        "description": "Synthetic flood detected in fixture"}, headers=analyst_headers)
    assert r.status_code == 201, r.text
    inc = r.json()
    iid = inc["id"]

    r = client.get(f"/api/incidents/{iid}", headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["title"] == "Lab DDoS triage"

    r = client.post(f"/api/incidents/{iid}/notes", json={
        "body": "Investigating source 10.0.0.0/24"}, headers=analyst_headers)
    assert r.status_code == 201, r.text

    r = client.get(f"/api/incidents/{iid}/timeline", headers=analyst_headers)
    assert r.status_code == 200
    events = r.json()["events"]
    assert any(e["kind"] == "note" for e in events)
    assert any(e["kind"] == "created" for e in events)

    r = client.patch(f"/api/incidents/{iid}", json={"status": "Contained"},
                     headers=analyst_headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "Contained"


def test_incident_list_pagination(client, analyst_headers):
    r = client.get("/api/incidents", params={"limit": 5}, headers=analyst_headers)
    assert r.status_code == 200
    body = r.json()
    assert "items" in body and "total" in body
    assert len(body["items"]) <= 5


def test_incident_bad_status_rejected(client, analyst_headers):
    r = client.post("/api/incidents", json={
        "title": "t", "severity": "Weird", "description": "d"}, headers=analyst_headers)
    assert r.status_code == 422  # pydantic pattern validation
