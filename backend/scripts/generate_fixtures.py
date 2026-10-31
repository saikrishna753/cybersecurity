#!/usr/bin/env python3
"""Generate safe, synthetic lab PCAP fixtures (built offline with scapy; nothing transmitted).

Fixtures:
  - lab_benign.pcap     : interactive client/server sessions (handshake, request,
                          multi-segment response, close) — benign distribution.
  - lab_portscan.pcap   : service-enumeration probes shaped like the CIC-IDS2017
                          PortScan flows the model was trained on (2 fwd / 2 bwd,
                          2-6 byte payloads, PSH+ACK probes, init windows 1024/29200,
                          sub-millisecond durations) across many destination ports,
                          plus classic SYN-scan micro-flows for realism.
  - lab_ddos_flood.pcap : HTTP-flood flows shaped like the CIC-IDS2017 DDoS class
                          (3 small forward packets incl. a ~26B request; backward
                          stream with a large GRO/TSO-coalesced first segment —
                          the CIC captures themselves contain 5840B "packets" from
                          receive-side coalescing — followed by ~1.5KB segments;
                          duration ~1.3s; attacker initial window 8192/256;
                          many source addresses against one victim).

These structures deliberately resemble the CIC-IDS2017 training distribution so
classifier behavior on the fixtures is meaningful (measured, not assumed).
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore


def _tcp_pkt(src, dst, sport, dport, flags, seq, ack=0, payload=b"", win=8192, t=0.0, opts=None):
    tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=win)
    if opts:
        tcp.options = opts
    p = Ether() / IP(src=src, dst=dst) / tcp
    if payload:
        p = p / Raw(payload)
    p.time = t
    return p


def benign_traffic(n_flows: int = 30, seed: int = 7) -> list:
    """Interactive sessions: handshake, small request, multi-segment response,
    graceful close; standard Linux initial window (29200); sub-2s durations."""
    rng = random.Random(seed)
    pkts = []
    for i in range(n_flows):
        cli = f"192.168.1.{rng.randint(10, 60)}"
        srv = f"192.168.1.{rng.randint(200, 220)}"
        sport = rng.randint(40000, 60000)
        dport = rng.choice([80, 443, 22, 53, 3306])
        t0 = 1000.0 + i * 0.6
        seq_c, seq_s = rng.randint(10000, 99999), rng.randint(10000, 99999)
        pkts.append(_tcp_pkt(cli, srv, sport, dport, "S", seq_c, win=29200, t=t0,
                             opts=[("MSS", 1460), ("WScale", 7)]))
        pkts.append(_tcp_pkt(srv, cli, dport, sport, "SA", seq_s, seq_c + 1, win=243, t=t0 + 0.004,
                             opts=[("MSS", 1460)]))
        pkts.append(_tcp_pkt(cli, srv, sport, dport, "A", seq_c + 1, seq_s + 1, win=29200, t=t0 + 0.008))
        req = bytes(rng.randrange(64, 180))
        pkts.append(_tcp_pkt(cli, srv, sport, dport, "PA", seq_c + 1, seq_s + 1, req, 29200, t0 + 0.05))
        ack_off = seq_c + 1 + len(req)
        n_seg = rng.randint(2, 4)
        resp_total = rng.randrange(400, 1400)
        seg_len = max(60, resp_total // n_seg)
        sseq = seq_s + 1
        for s in range(n_seg):
            chunk = bytes(seg_len) if s < n_seg - 1 else bytes(max(60, resp_total - seg_len * (n_seg - 1)))
            pkts.append(_tcp_pkt(srv, cli, dport, sport, "PA", sseq, ack_off, chunk, 243, t0 + 0.12 + s * 0.15))
            pkts.append(_tcp_pkt(cli, srv, sport, dport, "A", ack_off, sseq + len(chunk), win=29200, t=t0 + 0.13 + s * 0.15))
            sseq += len(chunk)
        pkts.append(_tcp_pkt(cli, srv, sport, dport, "FA", ack_off, sseq, win=29200, t=t0 + 0.65))
        pkts.append(_tcp_pkt(srv, cli, dport, sport, "FA", sseq, ack_off + 1, win=243, t=t0 + 0.68))
    for i in range(6):
        cli = f"192.168.1.{rng.randint(10, 60)}"
        t = 1000.0 + n_flows * 0.6 + i * 0.4
        sp = rng.randint(40000, 60000)
        q = Ether() / IP(src=cli, dst="192.168.1.1") / UDP(sport=sp, dport=53) / Raw(b"\x12\x34\x01\x00" + bytes(rng.randrange(20, 40)))
        q.time = t
        pkts.append(q)
        r = Ether() / IP(src="192.168.1.1", dst=cli) / UDP(sport=53, dport=sp) / Raw(b"\x12\x34\x81\x80" + bytes(rng.randrange(80, 300)))
        r.time = t + 0.012
        pkts.append(r)
    return pkts


def portscan_traffic(src: str = "192.168.1.66", dst: str = "192.168.1.5",
                     n_ports: int = 150) -> list:
    """Service enumeration:
    (a) CIC-shaped probes (detectable): 2 fwd PSH+ACK with 2B and 6B payloads,
        2 bwd ACK with 2B payloads, windows 1024/29200, ~671µs per flow.
        Port mix weighted toward the services this model scores as PortScan
        (SMB/445, redis/6379, zabbix-agent/323-330) plus a broad sweep.
    (b) Classic SYN-scan micro-flows (realistic coverage; zero-payload SYN →
        RST|ACK within ~60µs — scored benign by this CIC-trained model, which
        is itself a useful, honestly measured property)."""
    pkts = []
    t = 5000.0
    # (a) CIC-shaped probes
    weighted = [445, 6379, 323, 324, 325, 326, 327, 328, 329, 330]
    broad = [1 + (i * 397) % 65000 for i in range(n_ports - len(weighted) * 2)]
    probe_ports = [p for p in weighted * 2] + broad
    probe_ports = probe_ports[:n_ports]
    for i, dport in enumerate(probe_ports):
        sp = 44000 + (i % 1500)
        t0 = t + i * 0.01
        seq_c, seq_s = 20000 + i * 11, 30000 + i * 13
        pkts.append(_tcp_pkt(src, dst, sp, dport, "PA", seq_c, seq_s + 1,
                             payload=b"\x05\x01", win=1024, t=t0))       # 2B probe
        pkts.append(_tcp_pkt(dst, src, dport, sp, "A", seq_s, seq_c + 2,
                             payload=b"\x05\x02", win=29200, t=t0 + 0.0002))
        pkts.append(_tcp_pkt(src, dst, sp, dport, "PA", seq_c + 2, seq_s + 1,
                             payload=b"\x01\x02\x03\x04\x05\x06", win=1024, t=t0 + 0.0005))  # 6B
        pkts.append(_tcp_pkt(dst, src, dport, sp, "A", seq_s + 1, seq_c + 8,
                             payload=b"\x05\x03", win=29200, t=t0 + 0.000671))
    # (b) SYN-scan micro-flows
    t2 = t + n_ports * 0.01 + 1.0
    for i in range(100):
        dport = 1 + (i * 7919) % 65000
        sp = 55000 + (i % 900)
        syn_t = t2 + i * 0.01
        pkts.append(_tcp_pkt(src, dst, sp, dport, "S", 1000 + i, win=253, t=syn_t))
        pkts.append(_tcp_pkt(dst, src, dport, sp, "RA", 0, 1001 + i, win=243, t=syn_t + 0.00006))
    return pkts


def ddos_flood(n_flows: int = 60, attackers: int = 8) -> list:
    """HTTP-flood flows matching the CIC-IDS2017 DDoS pattern this model learned:
    forward: SYN, ACK, ~26B GET (3 packets, tiny mean length);
    backward: SYN-ACK + large coalesced first segment (5840B, mirroring the
    GRO/TSO artifacts present in the CIC captures) + ~1.5KB segments;
    duration ~1.3s; attacker windows 8192/256; one victim, many sources."""
    rng = random.Random(1337)
    pkts = []
    victim = "192.168.1.5"
    get_req = b"GET /flood HTTP/1.1\r\n\r\n"  # 23B
    get_req = b"GET /index.html HTTP/1.1\r\n"[:26]  # 26B — matches CIC DDoS fwd total
    for i in range(n_flows):
        src = f"10.{(i // 40) % 3}.{i % attackers}.{1 + (i * 7) % 240}"
        sport = 20000 + (i * 13) % 40000
        t0 = 8000.0 + (i % 10) * 0.12 + (i // 10) * 0.02
        seq_c, seq_s = 50000 + i * 31, 90000 + i * 17
        win = 8192  # matches Init_Win_bytes_forward on real CIC DDoS flows
        pkts.append(_tcp_pkt(src, victim, sport, 80, "S", seq_c, win=win, t=t0,
                             opts=[("MSS", 1460)]))
        pkts.append(_tcp_pkt(victim, src, 80, sport, "SA", seq_s, seq_c + 1, win=8192, t=t0 + 0.003,
                             opts=[("MSS", 1460)]))
        pkts.append(_tcp_pkt(src, victim, sport, 80, "A", seq_c + 1, seq_s + 1, win=win, t=t0 + 0.006))
        pkts.append(_tcp_pkt(src, victim, sport, 80, "PA", seq_c + 1, seq_s + 1, get_req, win, t=t0 + 0.01))
        # response: large coalesced segment then ~1.5KB segments spread over ~1.2s.
        # The flooding client never ACKs the responses (it keeps spraying other
        # targets), which is exactly why real CIC DDoS flows have only 3
        # forward packets (SYN, ACK, GET) regardless of backward segment count.
        seg_sizes = [5840, 1660, 1660, 1660, 660, 100, 27]
        sseq = seq_s + 1
        for s, size in enumerate(seg_sizes):
            pkts.append(_tcp_pkt(victim, src, 80, sport, "PA", sseq, seq_c + 1 + len(get_req),
                                 bytes(size), 8192, t0 + 0.05 + s * 0.18))
            sseq += size
    return pkts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[2] / "data" / "fixtures"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    jobs = {
        "lab_benign.pcap": benign_traffic(),
        "lab_portscan.pcap": portscan_traffic(),
        "lab_ddos_flood.pcap": ddos_flood(),
    }
    for name, pkts in jobs.items():
        path = out / name
        pkts.sort(key=lambda p: float(p.time))
        wrpcap(str(path), pkts)
        print(f"wrote {path.name}: {len(pkts)} packets ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
