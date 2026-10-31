"""Auth API: login, /me, user management, RBAC enforcement."""
from __future__ import annotations


def test_login_ok(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@ai-ids.local", "password": "ChangeMe!123"})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["role"] == "admin"


def test_login_bad_password(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@ai-ids.local", "password": "nope"})
    assert r.status_code in (401, 403)


def test_me(client, admin_headers):
    r = client.get("/api/auth/me", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["email"] == "admin@ai-ids.local"


def test_me_requires_token(client):
    assert client.get("/api/auth/me").status_code == 401


def test_viewer_cannot_create_user(client, viewer_headers):
    r = client.post("/api/auth/users", json={
        "email": "x@test.local", "username": "xuser", "password": "Passw0rd!x", "role": "viewer"},
        headers=viewer_headers)
    assert r.status_code == 403


def test_analyst_cannot_list_users(client, analyst_headers):
    assert client.get("/api/auth/users", headers=analyst_headers).status_code == 403


def test_admin_creates_and_lists_users(client, admin_headers):
    r = client.post("/api/auth/users", json={
        "email": "second@test.local", "username": "second", "password": "Passw0rd!2",
        "role": "analyst"}, headers=admin_headers)
    assert r.status_code == 201
    r = client.get("/api/auth/users", headers=admin_headers)
    assert r.status_code == 200
    emails = [u["email"] for u in r.json()]
    assert "second@test.local" in emails


def test_viewer_role_enforced_on_incidents(client, viewer_headers):
    # viewers may read but not create
    r = client.post("/api/incidents", json={
        "title": "nope", "severity": "High", "description": "x"}, headers=viewer_headers)
    assert r.status_code == 403
