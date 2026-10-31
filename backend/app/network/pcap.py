"""Network flow extraction: PCAP parsing (scapy) → contract flow dicts + CIC features.

Handles:
- PCAP/PCAPNG file analysis (offline, safe, read-only)
- Packet-level aggregation into bidirectional 5-tuple flows
- TCP flag analysis, forward/backward stats, timing

CICFlowMeter itself is a Java tool that is not pip-installable in this
environment; this module reimplements the flow aggregation needed for the
model's feature schema and is validated against CIC feature semantics.
"""
from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.ml.features import flow_to_features

logger = logging.getLogger("aiids.network")

# TCP flag bits (scapy-style)
FIN, SYN, RST, PSH, ACK, URG, CWR, ECE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

MAX_FLOWS_PER_FILE = 50_000
FLOW_IDLE_TIMEOUT_S = 120.0


class PcapValidationError(ValueError):
    pass


def validate_pcap(path: str | Path, max_bytes: int) -> None:
    p = Path(path)
    if not p.exists():
        raise PcapValidationError("File not found")
    size = p.stat().st_size
    if size == 0:
        raise PcapValidationError("File is empty")
    if size > max_bytes:
        raise PcapValidationError(f"File exceeds {max_bytes // (1024*1024)} MB limit")
    magic = p.read_bytes()[:4]
    # pcap(ng) magics + common linktype containers; also allow .pcapng section header
    valid = (
        magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                  b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",   # pcap variants
                  b"\x0a\x0d\x0d\x0a")                          # pcapng
        or magic[:2] == b"\x0a\x0d"
    )
    if not valid:
        raise PcapValidationError("Not a valid PCAP/PCAPNG file (bad magic bytes)")


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    last_ts: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_sizes: list[int] = field(default_factory=list)
    bwd_sizes: list[int] = field(default_factory=list)
    fwd_flags: list[int] = field(default_factory=list)
    bwd_flags: list[int] = field(default_factory=list)
    fwd_header_len: int = 0
    bwd_header_len: int = 0
    init_win_fwd: int | None = None
    init_win_bwd: int | None = None
    pkt_times: list[float] = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def duration_us(self) -> float:
        if self.last_ts and self.last_ts > self.start_ts:
            return (self.last_ts - self.start_ts) * 1_000_000
        return 0.0

    def to_contract(self) -> dict:
        dur_s = self.duration_us / 1_000_000
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        ts = datetime.fromtimestamp(self.start_ts, tz=timezone.utc)
        flow_id = str(uuid.uuid4())
        feats = flow_to_features(
            dst_port=self.dst_port,
            src_port=self.src_port,
            flow_duration=self.duration_us,
            total_fwd_packets=self.fwd_packets,
            total_bwd_packets=self.bwd_packets,
            total_fwd_bytes=self.fwd_bytes,
            total_bwd_bytes=self.bwd_bytes,
            fwd_pkt_sizes=self.fwd_sizes,
            bwd_pkt_sizes=self.bwd_sizes,
            tcp_flags_fwd=self.fwd_flags,
            tcp_flags_bwd=self.bwd_flags,
            fwd_header_len=self.fwd_header_len,
            bwd_header_len=self.bwd_header_len,
            init_win_fwd=self.init_win_fwd,
            init_win_bwd=self.init_win_bwd,
        )
        return {
            "flow_id": flow_id,
            "timestamp": ts.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration": dur_s,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "flow_bytes_per_sec": (total_bytes / dur_s) if dur_s > 0 else float(total_bytes),
            "flow_packets_per_sec": (total_pkts / dur_s) if dur_s > 0 else float(total_pkts),
            "flow_features": feats,
        }


class FlowAggregator:
    """Aggregates packets into bidirectional flows with idle timeout."""

    def __init__(self, idle_timeout: float = FLOW_IDLE_TIMEOUT_S) -> None:
        self.idle_timeout = idle_timeout
        self._flows: dict[tuple, FlowRecord] = {}
        self._rev: dict[tuple, tuple] = {}

    def add_packet(self, pkt) -> None:
        """pkt: scapy packet already parsed (IP/IPv6 + optional TCP/UDP).

        Byte accounting follows CICFlowMeter semantics: *payload* lengths (L4
        payload only, headers excluded), which is what the CIC-IDS2017 feature
        columns ("Total Length of Fwd Packets" etc.) are computed from.
        """
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is None:
            return
        src, dst = ip_layer.src, ip_layer.dst
        proto = "OTHER"
        sport = dport = 0
        flags = 0
        hdr_len = 20
        payload_len = 0
        if pkt.haslayer(TCP):
            tcp = pkt.getlayer(TCP)
            sport, dport = int(tcp.sport), int(tcp.dport)
            proto = "TCP"
            flags = int(tcp.flags)
            hdr_len = int(tcp.dataofs) * 4 if tcp.dataofs else 20
            payload_len = len(bytes(tcp.payload))
        elif pkt.haslayer(UDP):
            udp = pkt.getlayer(UDP)
            sport, dport = int(udp.sport), int(udp.dport)
            proto = "UDP"
            hdr_len = 8
            payload_len = len(bytes(udp.payload))
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            payload_len = len(bytes(pkt.getlayer(ICMP).payload))
        else:
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(getattr(ip_layer, "proto", 0)), "OTHER")
            payload_len = len(bytes(ip_layer.payload)) if ip_layer.payload else 0

        ts = float(pkt.time)
        size = payload_len  # CICFlowMeter-compatible (payload) byte count
        fwd_key = (src, dst, sport, dport, proto)
        rev_key = (dst, src, dport, sport, proto)

        if fwd_key in self._flows:
            rec = self._flows[fwd_key]
            forward = True
        elif rev_key in self._flows:
            rec = self._flows[rev_key]
            forward = False
        else:
            if len(self._flows) >= MAX_FLOWS_PER_FILE:
                return
            rec = FlowRecord(src, dst, sport, dport, proto, ts, last_ts=ts)
            self._flows[fwd_key] = rec
            forward = True

        rec.last_ts = max(rec.last_ts, ts)
        if forward:
            rec.fwd_packets += 1
            rec.fwd_bytes += size
            if len(rec.fwd_sizes) < 128:
                rec.fwd_sizes.append(size)
                rec.fwd_flags.append(flags)
            rec.fwd_header_len += hdr_len
            if rec.init_win_fwd is None:
                try:
                    from scapy.layers.inet import TCP as _TCP

                    if pkt.haslayer(_TCP):
                        rec.init_win_fwd = int(pkt.getlayer(_TCP).window)
                except Exception:
                    rec.init_win_fwd = None
        else:
            rec.bwd_packets += 1
            rec.bwd_bytes += size
            if len(rec.bwd_sizes) < 128:
                rec.bwd_sizes.append(size)
                rec.bwd_flags.append(flags)
            rec.bwd_header_len += hdr_len
            if rec.init_win_bwd is None:
                try:
                    from scapy.layers.inet import TCP as _TCP

                    if pkt.haslayer(_TCP):
                        rec.init_win_bwd = int(pkt.getlayer(_TCP).window)
                except Exception:
                    rec.init_win_bwd = None
        if len(rec.pkt_times) < 256:
            rec.pkt_times.append(ts)

    def flush(self) -> list[FlowRecord]:
        flows = list(self._flows.values())
        self._flows.clear()
        return flows

    def evict_idle(self, now_ts: float) -> list[FlowRecord]:
        done = [f for k, f in list(self._flows.items()) if now_ts - f.last_ts > self.idle_timeout]
        for f in done:
            self._flows.pop(f.key, None)
        return done


def extract_flows_from_pcap(path: str | Path, *, max_packets: int = 200_000,
                            progress=None) -> list[dict]:
    """Read a PCAP safely (offline) and return contract flow dicts."""
    # Import scapy.all BEFORE opening the reader: PcapReader resolves the
    # link-layer type once per reader, and `scapy.layers.l2` (Ether, type 1)
    # is only registered when scapy.all is imported. Without this, the first
    # file opened in a process would degrade to Raw packets.
    from scapy.all import PcapReader  # noqa: F401
    from scapy.utils import PcapReader  # type: ignore # noqa: F401

    agg = FlowAggregator()
    count = 0
    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                try:
                    agg.add_packet(pkt)
                except Exception:
                    continue
                count += 1
                if count % 10_000 == 0 and progress:
                    progress(count)
                if count >= max_packets:
                    logger.info("Reached packet cap %d for %s", max_packets, Path(path).name)
                    break
    except PcapValidationError:
        raise
    except Exception as exc:
        raise PcapValidationError(f"Failed to parse PCAP: {exc}") from exc

    flows = agg.flush()
    if not flows and count == 0:
        raise PcapValidationError("No packets could be read from file")
    out = [f.to_contract() for f in flows]
    out.sort(key=lambda d: d["timestamp"])
    return out
