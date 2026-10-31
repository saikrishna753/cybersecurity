"""Password hashing, JWT issuing/verification, RBAC helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings

_bearer = HTTPBearer(auto_error=False)

# Ordered roles; higher rank = more privileges.
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

# PBKDF2 parameters
_PBKDF2_ITERATIONS = 260_000
_PBKDF2_DIGEST = "sha256"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        _PBKDF2_DIGEST, password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return f"pbkdf2${_PBKDF2_DIGEST}${_PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, digest, iters, salt, expected = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac(
            digest, password.encode("utf-8"), bytes.fromhex(salt), int(iters)
        )
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


def create_access_token(
    subject: str, role: str, expires_minutes: int | None = None, extra: dict[str, Any] | None = None
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp_minutes = expires_minutes if expires_minutes is not None else settings.jwt_expire_minutes
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=exp_minutes),
        "jti": secrets.token_hex(8),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


class CurrentUser(dict):
    """Lightweight authenticated principal."""

    @property
    def sub(self) -> str:
        return self["sub"]

    @property
    def role(self) -> str:
        return self.get("role", "viewer")


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> CurrentUser:
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    payload.setdefault("role", "viewer")
    payload.setdefault("sub", "")
    return CurrentUser(**payload)


def require_role(minimum: str):
    min_rank = ROLE_RANK.get(minimum, 0)

    def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if ROLE_RANK.get(user.role, -1) < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum} role or higher",
            )
        return user

    return checker


# Convenience dependencies
RequireViewer = Depends(get_current_user)
RequireAnalyst = Depends(require_role("analyst"))
RequireAdmin = Depends(require_role("admin"))
