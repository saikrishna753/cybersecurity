"""Authorized live capture with bounded queues and graceful fallback.

Safety:
- Capture only starts when an administrator explicitly marks an interface as
  authorized AND the process has packet-capture permission.
- If permissions/deps are unavailable we degrade to offline mode with a clear
  status instead of pretending capture works.
- Bounded queue + background thread → never blocks the web server event loop.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

from app.core.config import get_settings

logger = logging.getLogger("aiids.capture")

FlowHandler = Callable[[dict], None]


def list_interfaces() -> list[dict]:
    """Enumerate interfaces via psutil (no external commands, no root needed)."""
    out: list[dict] = []
    try:
        import psutil

        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, st in stats.items():
            ips = []
            for a in addrs.get(name, []):
                if a.family.name in {"AF_INET", "AF_INET6"}:
                    ips.append(a.address)
            out.append(
                {
                    "name": name,
                    "description": ", ".join(ips[:3]),
                    "is_up": bool(st.isup),
                    "is_authorized": False,  # authorization is an explicit admin action
                    "capture_permission": check_capture_permission(),
                }
            )
    except Exception as exc:  # pragma: no cover
        logger.warning("interface enumeration failed: %s", exc)
    return sorted(out, key=lambda d: (not d["is_up"], d["name"]))


def check_capture_permission() -> str:
    """Return 'granted' | 'denied' | 'unknown' without raising."""
    try:
        import socket

        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.close()
            return "granted"
        except PermissionError:
            return "denied"
        except (AttributeError, OSError):
            # AF_PACKET not available (non-Linux) → try scapy open_live probe
            pass
    except Exception:
        pass
    try:  # last resort probe
        from scapy.all import conf

        if conf.use_pcap is None:
            return "unknown"
        return "unknown"
    except Exception:
        return "unknown"


class LiveCaptureService:
    """Start/stop authorized packet capture in a background thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._queue: deque[dict] = deque()
        self._interface: str | None = None
        self._started_at: datetime | None = None
        self._packets = 0
        self._flows_emitted = 0
        self._error: str | None = None
        self._bpf = ""
        self._batch_size = 100
        self._handler: FlowHandler | None = None
        self._authorized: set[str] = set()

    # -------------------------------------------------------------- status
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        return {
            "running": self.running,
            "interface": self._interface if self.running else None,
            "started_at": self._started_at.isoformat() if self._started_at and self.running else None,
            "packets_captured": self._packets,
            "flows_emitted": self._flows_emitted,
            "queue_size": len(self._queue),
            "error": self._error,
            "mode": "live" if self.running else "offline",
            "authorized_interfaces": sorted(self._authorized),
        }

    # ----------------------------------------------------------- authorize
    def authorize(self, interface: str) -> None:
        with self._lock:
            self._authorized.add(interface)

    def deauthorize(self, interface: str) -> None:
        with self._lock:
            self._authorized.discard(interface)

    # ---------------------------------------------------------------- start
    def start(self, interface: str, handler: FlowHandler, *, authorized: bool = False,
              bpf_filter: str = "", batch_size: int = 100) -> dict:
        settings = get_settings()
        if not settings.live_capture_enabled:
            return {"ok": False, "error": "Live capture disabled by configuration", "mode": "offline"}
        if self.running:
            return {"ok": False, "error": "Capture already running", "mode": "live"}
        if not authorized and interface not in self._authorized:
            return {
                "ok": False,
                "error": "Interface not authorized. An administrator must explicitly "
                         "authorize monitoring of this interface.",
                "mode": "offline",
            }
        perm = check_capture_permission()
        if perm == "denied":
            self._error = (
                "Packet capture permission denied. Run with CAP_NET_RAW or use the "
                "offline PCAP analysis mode."
            )
            return {"ok": False, "error": self._error, "mode": "offline"}
        try:
            from scapy.all import conf  # noqa: F401
            import scapy  # noqa: F401
        except ImportError:
            self._error = "scapy not installed — live capture unavailable (offline mode)"
            return {"ok": False, "error": self._error, "mode": "offline"}

        self._stop.clear()
        self._interface = interface
        self._handler = handler
        self._bpf = bpf_filter.strip()
        self._batch_size = max(1, min(batch_size, 1000))
        self._packets = 0
        self._flows_emitted = 0
        self._error = None
        self._started_at = datetime.now(timezone.utc)
        if authorized:
            self.authorize(interface)

        self._thread = threading.Thread(target=self._run, name="pcap-capture", daemon=True)
        self._thread.start()
        logger.info("Live capture started on %s", interface)
        return {"ok": True, "mode": "live"}

    def stop(self) -> dict:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=10)
        self._thread = None
        logger.info("Live capture stopped")
        return self.status()

    # ----------------------------------------------------------------- run
    def _run(self) -> None:
        from scapy.all import AsyncSniffer, conf

        conf.verb = 0
        sniffer = None
        batch: list = []

        def _on_packet(pkt) -> None:
            nonlocal batch
            self._packets += 1
            batch.append(pkt)
            if len(batch) >= self._batch_size:
                self._flush_batch(batch)
                batch = []

        try:
            sniffer = AsyncSniffer(
                iface=self._interface,
                filter=self._bpf or None,
                prn=_on_packet,
                store=False,
            )
            sniffer.start()
            while not self._stop.is_set():
                time.sleep(0.5)
            if sniffer is not None:
                sniffer.stop(join=False)
            if batch:
                self._flush_batch(batch)
        except PermissionError:
            self._error = "Permission denied while opening capture socket"
            logger.error(self._error)
        except Exception as exc:  # pragma: no cover
            self._error = f"Capture failed: {exc}"
            logger.exception("capture thread crashed")

    def _flush_batch(self, packets: list) -> None:
        """Aggregate packet batch → flows → handler (non-blocking, bounded)."""
        from app.network.pcap import FlowAggregator

        agg = FlowAggregator(idle_timeout=5.0)
        for p in packets:
            try:
                agg.add_packet(p)
            except Exception:
                continue
        for rec in agg.flush():
            flow = rec.to_contract()
            if len(self._queue) >= get_settings().live_capture_queue_max:
                self._queue.popleft()  # bounded: drop oldest to protect memory
            self._queue.append(flow)
            self._flows_emitted += 1
            if self._handler:
                try:
                    self._handler(flow)
                except Exception:
                    logger.exception("flow handler failed")
            self._queue.popleft() if self._queue else None


capture_service = LiveCaptureService()
