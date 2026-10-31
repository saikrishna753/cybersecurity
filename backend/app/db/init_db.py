"""Database bootstrap: create tables + seed admin + seed settings."""
from __future__ import annotations

import logging

from app.core.config import get_settings
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import (  # noqa: F401  (register tables)
    AuditLog,
    DatasetRecord,
    DetectionResult,
    Incident,
    IncidentNote,
    MlModel,
    NetworkFlow,
    NetworkInterface,
    SecurityAlert,
    SystemSetting,
    ThreatIntelRecord,
    TrainingJob,
    User,
)

logger = logging.getLogger("aiids.db")

DEFAULT_SETTINGS = {
    "alert_dedup_window_minutes": "10",
    "alert_email_enabled": "false",
    "default_confidence_threshold": "0.75",
    "anomaly_detection_enabled": "true",
    "anomaly_score_threshold": "0.70",
    "capture_retention_days": "7",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_from": "alerts@ai-ids.local",
    "ti_provider": "none",
    "ti_api_key": "",
    "theme": "dark",
}


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == settings.bootstrap_admin_email).first():
            admin = User(
                email=settings.bootstrap_admin_email,
                username="admin",
                full_name="System Administrator",
                hashed_password=hash_password(settings.bootstrap_admin_password),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            logger.info("Bootstrapped admin user %s", settings.bootstrap_admin_email)
        for key, value in DEFAULT_SETTINGS.items():
            from app.models import SystemSetting as SS

            if not db.query(SS).filter(SS.key == key).first():
                db.add(SS(key=key, value=value))
        db.commit()
