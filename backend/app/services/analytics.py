"""Aggregated analytics over stored flows/detections/alerts (real DB data only)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    DetectionResult,
    MlModel,
    NetworkFlow,
    SecurityAlert,
)


def _window(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def dashboard_stats(db: Session) -> dict:
    total_flows = db.scalar(select(func.count(NetworkFlow.id))) or 0
    total_detect = db.scalar(select(func.count(DetectionResult.id))) or 0
    attacks = db.scalar(
        select(func.count(DetectionResult.id)).where(DetectionResult.is_malicious.is_(True))
    ) or 0
    normal = db.scalar(
        select(func.count(DetectionResult.id)).where(DetectionResult.is_malicious.is_(False))
    ) or 0
    suspicious = attacks  # contract: suspicious == classified malicious

    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    attacks_hour = db.scalar(
        select(func.count(DetectionResult.id)).where(
            DetectionResult.is_malicious.is_(True), DetectionResult.timestamp >= hour_ago
        )
    ) or 0
    flows_hour = db.scalar(
        select(func.count(NetworkFlow.id)).where(NetworkFlow.timestamp >= hour_ago)
    ) or 0

    alert_counts = SecurityAlert.__table__
    total_alerts = db.scalar(select(func.count(SecurityAlert.id))) or 0
    open_alerts = db.scalar(
        select(func.count(SecurityAlert.id)).where(
            SecurityAlert.status.in_(["New", "Acknowledged", "Investigating"])
        )
    ) or 0
    critical_alerts = db.scalar(
        select(func.count(SecurityAlert.id)).where(
            SecurityAlert.severity == "Critical",
            SecurityAlert.status.in_(["New", "Acknowledged", "Investigating"]),
        )
    ) or 0

    active_model = db.scalar(
        select(MlModel.name).where(MlModel.is_active.is_(True)).limit(1)
    )
    active_version = db.scalar(
        select(MlModel.version).where(MlModel.is_active.is_(True)).limit(1)
    )
    active_label = f"{active_model} v{active_version}" if active_model else None

    # confidence buckets
    buckets = [(0, .5), (.5, .7), (.7, .85), (.85, .95), (.95, 1.01)]
    conf_dist = []
    for lo, hi in buckets:
        c = db.scalar(
            select(func.count(DetectionResult.id)).where(
                DetectionResult.confidence >= lo, DetectionResult.confidence < hi
            )
        ) or 0
        conf_dist.append({"bucket": f"{int(lo*100)}-{int(min(hi,1)*100)}%", "count": c})

    severity_dist = _group(db, DetectionResult.severity, DetectionResult)

    protocol_dist = _group(db, NetworkFlow.protocol, NetworkFlow, limit=8)

    top_sources = [
        {"ip": r[0], "count": int(r[1])}
        for r in db.execute(
            select(NetworkFlow.src_ip, func.count(NetworkFlow.id))
            .group_by(NetworkFlow.src_ip).order_by(func.count(NetworkFlow.id).desc()).limit(8)
        ).all()
    ]
    top_ports = [
        {"port": int(r[0]), "count": int(r[1])}
        for r in db.execute(
            select(NetworkFlow.dst_port, func.count(NetworkFlow.id))
            .group_by(NetworkFlow.dst_port).order_by(func.count(NetworkFlow.id).desc()).limit(8)
        ).all()
    ]

    attack_dist = [
        {"attack": r[0], "count": int(r[1])}
        for r in db.execute(
            select(DetectionResult.prediction, func.count(DetectionResult.id))
            .where(DetectionResult.is_malicious.is_(True))
            .group_by(DetectionResult.prediction)
            .order_by(func.count(DetectionResult.id).desc()).limit(10)
        ).all()
    ]

    traffic_timeline = _timeline(db, NetworkFlow.__table__.name, "timestamp", days=1)
    detection_timeline = _timeline(db, DetectionResult.__table__.name, "timestamp", days=1,
                                   malicious_only=True)

    recent = db.execute(
        select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(8)
    ).scalars().all()
    recent_alerts = [
        {
            "alert_id": a.alert_id, "attack_type": a.attack_type,
            "severity": a.severity, "status": a.status,
            "source_ip": a.source_ip, "destination_ip": a.destination_ip,
            "destination_port": a.destination_port, "confidence": a.confidence,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "dedup_count": a.dedup_count,
        }
        for a in recent
    ]

    from app.network.capture import capture_service

    first_flow_ts = db.scalar(select(func.min(NetworkFlow.timestamp)))
    uptime_h = 0.0
    if isinstance(first_flow_ts, datetime):
        ts = first_flow_ts if first_flow_ts.tzinfo else first_flow_ts.replace(tzinfo=timezone.utc)
        uptime_h = max((datetime.now(timezone.utc) - ts).total_seconds() / 3600.0, 0.0)

    return {
        "total_flows": total_flows,
        "total_attacks": attacks,
        "total_normal": normal,
        "total_suspicious": suspicious,
        "detection_rate": round(attacks / total_detect, 4) if total_detect else 0.0,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "active_model": active_label,
        "attacks_last_hour": attacks_hour,
        "flows_last_hour": flows_hour,
        "uptime_hours": round(uptime_h, 2),
        "confidence_distribution": conf_dist,
        "severity_distribution": severity_dist,
        "protocol_distribution": protocol_dist,
        "top_source_ips": top_sources,
        "top_destination_ports": top_ports,
        "attack_distribution": attack_dist,
        "traffic_timeline": traffic_timeline,
        "detection_timeline": detection_timeline,
        "recent_alerts": recent_alerts,
        "data_sources": {
            "live_capture": capture_service.running,
            "ws_clients": 0,  # filled by API layer
            "model_active": active_model is not None,
        },
    }


def _group(db: Session, column, model, limit: int = 12) -> list[dict]:
    rows = db.execute(
        select(column, func.count(model.id)).group_by(column)
        .order_by(func.count(model.id).desc()).limit(limit)
    ).all()
    return [{"name": str(r[0]), "count": int(r[1])} for r in rows]


def _timeline(db: Session, table: str, ts_col: str, days: int = 1,
              malicious_only: bool = False) -> list[dict]:
    """Hourly buckets for the last N days (UTC)."""
    from sqlalchemy import text

    where = f"WHERE {ts_col} >= :since"
    if malicious_only:
        where += " AND is_malicious = 1"
    sql = text(
        f"SELECT strftime('%Y-%m-%dT%H:00:00', {ts_col}) AS bucket, COUNT(*) AS c "
        f"FROM {table} {where} GROUP BY bucket ORDER BY bucket"
    )
    rows = db.execute(sql, {"since": (_window(days)).isoformat()}).all()
    return [{"time": r[0], "count": int(r[1])} for r in rows]


def analytics_summary(db: Session, date_from: datetime | None = None,
                      date_to: datetime | None = None) -> dict:
    q = select(DetectionResult)
    if date_from:
        q = q.where(DetectionResult.timestamp >= date_from)
    if date_to:
        q = q.where(DetectionResult.timestamp <= date_to)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    mal_q = q.where(DetectionResult.is_malicious.is_(True))
    malicious = db.scalar(select(func.count()).select_from(mal_q.subquery())) or 0

    by_attack = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(DetectionResult.prediction, func.count())
            .where(DetectionResult.is_malicious.is_(True))
            .group_by(DetectionResult.prediction)
        ).all()
    }
    by_severity = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(DetectionResult.severity, func.count()).group_by(DetectionResult.severity)
        ).all()
    }
    by_status = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(SecurityAlert.status, func.count()).group_by(SecurityAlert.status)
        ).all()
    }
    by_protocol = {
        str(r[0]): int(r[1])
        for r in db.execute(
            select(NetworkFlow.protocol, func.count()).group_by(NetworkFlow.protocol)
        ).all()
    }
    fp = db.scalar(
        select(func.count(SecurityAlert.id)).where(SecurityAlert.status == "False Positive")
    ) or 0
    top_sources = [
        {"ip": r[0], "count": int(r[1])}
        for r in db.execute(
            select(SecurityAlert.source_ip, func.count(SecurityAlert.id))
            .group_by(SecurityAlert.source_ip)
            .order_by(func.count(SecurityAlert.id).desc()).limit(10)
        ).all()
    ]
    top_ports = [
        {"port": int(r[0]), "count": int(r[1])}
        for r in db.execute(
            select(SecurityAlert.destination_port, func.count(SecurityAlert.id))
            .group_by(SecurityAlert.destination_port)
            .order_by(func.count(SecurityAlert.id).desc()).limit(10)
        ).all()
    ]
    timeline = _timeline(db, DetectionResult.__table__.name, "timestamp", days=7,
                         malicious_only=True)

    model_rows = db.execute(
        select(MlModel).order_by(MlModel.created_at.desc()).limit(10)
    ).scalars().all()
    model_trends = []
    for m in model_rows:
        met = m.metrics or {}
        f1 = met.get("f1", met.get("f1_macro"))
        model_trends.append({
            "version": m.version, "algorithm": m.algorithm,
            "f1": round(float(f1), 4) if isinstance(f1, (int, float)) else None,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        })

    return {
        "total_traffic": total,
        "normal": max(total - malicious, 0),
        "malicious": malicious,
        "by_attack": by_attack,
        "by_severity": by_severity,
        "by_protocol": by_protocol,
        "by_status": by_status,
        "false_positives": fp,
        "top_sources": top_sources,
        "top_ports": top_ports,
        "timeline": timeline,
        "model_trends": model_trends,
    }
