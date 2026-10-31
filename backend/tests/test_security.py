"""Security primitives: password hashing, JWT, RBAC ranking."""
from __future__ import annotations

import pytest

from app.core.security import (
    ROLE_RANK,
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_password_hash_roundtrip():
    stored = hash_password("S3cret!pw")
    assert stored.startswith("pbkdf2$")
    assert verify_password("S3cret!pw", stored)
    assert not verify_password("wrong", stored)


def test_password_unique_salts():
    assert hash_password("same") != hash_password("same")


def test_jwt_roundtrip():
    tok = create_access_token("user-1", "admin")
    payload = decode_token(tok)
    assert payload["sub"] == "user-1"
    assert payload["role"] == "admin"


def test_role_ordering():
    assert ROLE_RANK["viewer"] < ROLE_RANK["analyst"] < ROLE_RANK["admin"]


def test_jwt_tampered_rejected():
    tok = create_access_token("u", "viewer") + "x"
    with pytest.raises(Exception):
        decode_token(tok)
