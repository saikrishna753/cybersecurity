"""Alert persistence with deduplication + optional SMTP notifications."""
from __future__ import annotations

import logging
import smtplib
import threading
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import SecurityAlert, SystemSetting

logger = logging.getLogger("aiids.alerts")

DEDUP_WINDOW_DEFAULT_MIN = 10


def _setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if row and row.value is not None else default


def _parse_ts(v: str | datetime | None) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class AlertService:
    def __init__(self) -> None:
        self._notify_hooks: list[Callable[[dict], None]] = []

    def subscribe_notifications(self, hook: Callable[[dict], None]) -> None:
        self._notify_hooks.append(hook)

    # ------------------------------------------------------------------ create
    def ingest(self, alert: dict, db: Session | None = None) -> tuple[dict, bool]:
        """Store alert with dedup folding. Returns (alert_out, created)."""
        own = db is None
        db = db or SessionLocal()
        try:
            created, row, out = self._ingest_inner(db, alert)
            db.commit()
            if created:
                for hook in self._notify_hooks:
                    try:
                        hook(out)
                    except Exception:
                        logger.exception("notification hook failed")
                if _setting(db, "alert_email_enabled", "false").lower() == "true":
                    self._send_email_async(out)
            return out, created
        except Exception:
            db.rollback()
            raise
        finally:
            if own:
                db.close()

    def _ingest_inner(self, db: Session, alert: dict) -> tuple[bool, SecurityAlert, dict]:
        window_min = int(_setting(db, "alert_dedup_window_minutes", str(DEDUP_WINDOW_DEFAULT_MIN)) or DEDUP_WINDOW_DEFAULT_MIN)
        created_at = _parse_ts(alert.get("created_at")) or datetime.now(timezone.utc)
        since = created_at - timedelta(minutes=max(window_min, 0))

        dedup_key = "|".join(
            str(alert.get(k, "")) for k in ("attack_type", "source_ip", "destination_ip")
        )
        existing = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.dedup_key == dedup_key,
                SecurityAlert.status == "New",
                SecurityAlert.created_at >= since,
            )
            .first()
        )
        if existing:
            existing.dedup_count += 1
            existing.confidence = max(existing.confidence, float(alert.get("confidence") or 0))
            existing.updated_at = created_at
            return False, existing, self._out(existing)

        row = SecurityAlert(
            alert_id=str(alert.get("alert_id") or ""),
            flow_id=str(alert.get("flow_id") or ""),
            attack_type=str(alert.get("attack_type") or "Unknown"),
            source_ip=str(alert.get("source_ip") or ""),
            destination_ip=str(alert.get("destination_ip") or ""),
            destination_port=int(alert.get("destination_port") or 0),
            protocol=str(alert.get("protocol") or "TCP"),
            severity=str(alert.get("severity") or "Medium"),
            status=str(alert.get("status") or "New"),
            confidence=float(alert.get("confidence") or 0),
            model_version=str(alert.get("model_version") or ""),
            dedup_key=dedup_key,
            first_seen_at=created_at,
            created_at=created_at,
            details={"anomaly_score": alert.get("anomaly_score")},
        )
        db.add(row)
        db.flush()
        return True, row, self._out(row)

    @staticmethod
    def _out(row: SecurityAlert) -> dict:
        return {
            "id": row.id,
            "alert_id": row.alert_id,
            "flow_id": row.flow_id,
            "attack_type": row.attack_type,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "destination_port": row.destination_port,
            "protocol": row.protocol,
            "severity": row.severity,
            "status": row.status,
            "confidence": row.confidence,
            "model_version": row.model_version,
            "dedup_count": row.dedup_count,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
            "incident_id": row.incident_id,
        }

    # ----------------------------------------------------------------- email
    def _send_email_async(self, alert: dict) -> None:
        t = threading.Thread(target=self._send_email, args=(alert,), daemon=True)
        t.start()

    def _send_email(self, alert: dict) -> None:
        settings = get_settings()
        try:
            with SessionLocal() as db:
                host = _setting(db, "smtp_host", settings.smtp_host)
                if not host:
                    return
                port = int(_setting(db, "smtp_port", str(settings.smtp_port)) or 587)
                frm = _setting(db, "smtp_from", settings.smtp_from)
            body = (
                f"AI-IDS Security Alert\n\n"
                f"Type: {alert['attack_type']}\nSeverity: {alert['severity']}\n"
                f"Source: {alert['source_ip']} → {alert['destination_ip']}:{alert['destination_port']} "
                f"({alert['protocol']})\nConfidence: {alert['confidence']:.2f}\n"
                f"Time: {alert['created_at']}\nDedup count: {alert['dedup_count']}\n"
            )
            msg = MIMEText(body)
            msg["Subject"] = f"[AI-IDS] {alert['severity']} alert: {alert['attack_type']}"
            msg["From"] = frm
            msg["To"] = settings.smtp_from
            with smtplib.SMTP(host, port, timeout=10) as s:
                s.starttls()
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
            logger.info("Alert email sent for %s", alert["attack_type"])
        except Exception as exc:
            logger.warning("SMTP notification failed: %s", exc)

    # ------------------------------------------------------------------ stats
    @staticmethod
    def counts(db: Session) -> dict:
        total = db.scalar(select(func.count(SecurityAlert.id))) or 0
        new = db.scalar(
            select(func.count(SecurityAlert.id)).where(SecurityAlert.status == "New")
        ) or 0
        critical = db.scalar(
            select(func.count(SecurityAlert.id)).where(
                SecurityAlert.severity == "Critical",
                SecurityAlert.status.in_(["New", "Acknowledged", "Investigating"]),
            )
        ) or 0
        return {"total": total, "new": new, "critical": critical}


alert_service = AlertService()
