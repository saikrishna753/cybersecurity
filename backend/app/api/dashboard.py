"""Dashboard + analytics routes (real DB data only)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas import AnalyticsSummary, DashboardStats, ReportRequest  # noqa: F401
from app.services.analytics import analytics_summary, dashboard_stats
from app.ws.manager import ws_manager

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)):
    data = dashboard_stats(db)
    data["data_sources"]["ws_clients"] = ws_manager.connection_count
    return data


@router.get("/analytics", response_model=AnalyticsSummary)
def analytics(
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
):
    return analytics_summary(db, date_from, date_to)
