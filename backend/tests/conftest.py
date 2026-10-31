"""Shared pytest fixtures: isolated SQLite DB, TestClient with lifespan, RBAC users."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Isolate the test DB & uploads BEFORE any app import resolves settings.
_TMP = Path(tempfile.mkdtemp(prefix="aiids_test_"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'test.db'}"
os.environ["UPLOAD_DIR"] = str(_TMP / "uploads")
os.environ["APP_ENV"] = "testing"
os.environ["APP_SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long!!"
os.environ["LIVE_CAPTURE_ENABLED"] = "false"
os.environ["TI_PROVIDER"] = "none"


@pytest.fixture(scope="session")
def client():
    """FastAPI TestClient with lifespan (init_db, admin bootstrap, model registry)."""
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


@pytest.fixture(scope="session")
def admin_token(client) -> str:
    r = client.post("/api/auth/login", json={
        "email": os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "admin@ai-ids.local"),
        "password": os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe!123"),
    })
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


def _register_and_login(client, email: str, password: str, role: str, admin_headers: dict) -> str:
    r = client.post("/api/auth/users", json={
        "email": email, "username": email.split("@")[0], "password": password,
        "role": role, "full_name": f"Test {role}",
    }, headers=admin_headers)
    assert r.status_code == 201, r.text
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def analyst_headers(client, admin_headers) -> dict:
    tok = _register_and_login(client, "analyst@test.local", "Analyst!123", "analyst", admin_headers)
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="session")
def viewer_headers(client, admin_headers) -> dict:
    tok = _register_and_login(client, "viewer@test.local", "Viewer!1234", "viewer", admin_headers)
    return {"Authorization": f"Bearer {tok}"}
