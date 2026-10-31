"""Optional IP reputation enrichment with caching and private-IP protection.

Works fully without API keys (provider 'none'). Private addresses are NEVER
sent to external services by default.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ThreatIntelRecord

logger = logging.getLogger("aiids.ti")

_PROVIDERS = {
    # name -> (url template, needs key)
    "none": (None, False),
    "abuseipdb": ("https://api.abuseipdb.com/api/v2/check", True),
    "virustotal": ("https://www.virustotal.com/api/v3/ip_addresses/{ip}", True),
}


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True  # unparseable → treat as non-shareable


class ThreatIntelService:
    def _provider(self) -> str:
        p = (get_settings().ti_provider or "none").lower()
        return p if p in _PROVIDERS else "none"

    def lookup(self, db: Session, ip: str, *, force: bool = False) -> ThreatIntelRecord | None:
        provider = self._provider()
        private = is_private(ip)

        # Private IPs are classified locally only — never sent externally.
        if private:
            row = self._local_record(db, ip)
            return row

        ttl = get_settings().ti_cache_ttl_seconds
        cached = (
            db.query(ThreatIntelRecord)
            .filter(
                ThreatIntelRecord.ip == ip,
                ThreatIntelRecord.provider == provider,
                ThreatIntelRecord.error.is_(None),
            )
            .first()
        )
        if cached and not force and cached.expires_at and cached.expires_at > datetime.now(timezone.utc):
            return cached

        if provider == "none":
            # No external provider configured: record unknown state locally.
            return self._upsert(db, ip, provider, False, None, ["unconfigured"], None)

        url_tpl, needs_key = _PROVIDERS[provider]
        key = get_settings().ti_api_key
        if needs_key and not key:
            return self._upsert(db, ip, provider, False, None, ["missing_api_key"], None,
                                error="API key not configured")

        try:
            if provider == "abuseipdb":
                r = httpx.get(
                    url_tpl,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": key, "Accept": "application/json"},
                    timeout=8.0,
                )
                r.raise_for_status()
                d = r.json().get("data", {})
                score = float(d.get("abuseConfidenceScore", 0))
                cats = [d.get("totalReports", 0)]
                return self._upsert(
                    db, ip, provider, score >= 50, score / 100.0,
                    [f"abuse_confidence={score}"], d, ttl=ttl,
                )
            if provider == "virustotal":
                r = httpx.get(
                    url_tpl.format(ip=ip),
                    headers={"x-apikey": key},
                    timeout=8.0,
                )
                r.raise_for_status()
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                return self._upsert(
                    db, ip, provider, malicious > 0, None,
                    [f"vt_malicious={malicious}"], stats, ttl=ttl,
                )
        except Exception as exc:
            logger.warning("TI lookup failed for %s via %s: %s", ip, provider, exc)
            return self._upsert(db, ip, provider, False, None, [], None,
                                error=str(exc)[:240], ttl=ttl)
        return cached or self._upsert(db, ip, provider, False, None, ["unconfigured"], None)

    def _local_record(self, db: Session, ip: str) -> ThreatIntelRecord:
        row = db.query(ThreatIntelRecord).filter(
            ThreatIntelRecord.ip == ip, ThreatIntelRecord.provider == "local"
        ).first()
        if row is None:
            row = ThreatIntelRecord(
                ip=ip, provider="local", is_malicious=False,
                categories=["private_network"], is_private_ip=True,
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            db.add(row)
            db.commit()
            db.refresh(row)
        return row

    def _upsert(self, db: Session, ip, provider, malicious, score, categories, raw,
                ttl: int = 86400, error: str | None = None) -> ThreatIntelRecord:
        row = db.query(ThreatIntelRecord).filter(
            ThreatIntelRecord.ip == ip, ThreatIntelRecord.provider == provider
        ).first()
        now = datetime.now(timezone.utc)
        if row is None:
            row = ThreatIntelRecord(ip=ip, provider=provider)
            db.add(row)
        row.is_malicious = bool(malicious)
        row.score = score
        row.categories = list(categories or [])
        row.raw = raw
        row.fetched_at = now
        row.expires_at = now + timedelta(seconds=ttl) if ttl else now + timedelta(days=1)
        row.error = error
        row.is_private_ip = is_private(ip)
        db.commit()
        db.refresh(row)
        return row

    def bulk_enrich(self, db: Session, ips: list[str], limit: int = 50) -> list[dict]:
        out = []
        for ip in ips[:limit]:
            try:
                rec = self.lookup(db, ip)
                if rec:
                    out.append(
                        {
                            "id": rec.id, "ip": rec.ip, "provider": rec.provider,
                            "is_malicious": rec.is_malicious, "score": rec.score,
                            "categories": rec.categories, "is_private_ip": rec.is_private_ip,
                            "fetched_at": rec.fetched_at.isoformat(),
                            "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
                            "error": rec.error,
                        }
                    )
            except Exception as exc:
                logger.warning("bulk_enrich failed for %s: %s", ip, exc)
        return out


threat_intel = ThreatIntelService()
