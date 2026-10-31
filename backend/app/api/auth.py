"""Auth + user management routes."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from app.db.session import get_db
from app.models import User
from app.schemas import (
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.services.audit import audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if user is None or not verify_password(body.password, user.hashed_password):
        audit(db, action="login_failed", user_email=body.email, request=request)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    user.last_login_at = datetime.now(timezone.utc)
    audit(db, action="login", user_id=user.id, user_email=user.email,
          resource="auth", request=request)
    db.commit()
    from app.core.config import get_settings

    settings = get_settings()
    token = create_access_token(user.email, user.role)
    return TokenResponse(
        access_token=token,
        role=user.role,
        email=user.email,
        username=user.username,
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get("/me", response_model=UserOut)
def me(user=Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.scalar(select(User).where(User.email == user.sub))
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return row


@router.put("/me", response_model=UserOut)
def update_me(
    body: UserUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(select(User).where(User.email == user.sub))
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.full_name is not None:
        row.full_name = body.full_name
    if body.password:
        row.hashed_password = hash_password(body.password)
    # users may not self-elevate role
    audit(db, action="profile_update", user_id=row.id, user_email=row.email, resource="users")
    db.commit()
    db.refresh(row)
    return row


@router.get("/users", response_model=list[UserOut])
def list_users(
    _=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    return db.scalars(select(User).order_by(User.created_at)).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    admin=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    email = body.email.lower()
    if db.scalar(select(User).where((User.email == email) | (User.username == body.username))):
        raise HTTPException(status_code=409, detail="User already exists")
    row = User(
        email=email,
        username=body.username,
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(row)
    audit(db, action="user_created", user_id=admin.sub, user_email=admin.sub,
          resource=email, detail={"role": body.role}, request=request)
    db.commit()
    db.refresh(row)
    return row


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    admin=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    request: Request = None,
):
    row = db.get(User, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role is not None:
        row.role = body.role
    if body.is_active is not None:
        row.is_active = body.is_active
    if body.full_name is not None:
        row.full_name = body.full_name
    if body.password:
        row.hashed_password = hash_password(body.password)
    audit(db, action="user_updated", user_id=admin.sub, user_email=admin.sub,
          resource=row.email, detail={"role": row.role, "active": row.is_active},
          request=request)
    db.commit()
    db.refresh(row)
    return row
