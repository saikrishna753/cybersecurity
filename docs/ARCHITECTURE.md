# AI-IDS Architecture

## System overview

```
┌────────────────────────────────────────────────────────────────────┐
│  React SPA (Vite, Tailwind, shadcn/ui, Recharts, TanStack Query)   │
│  15 pages · SOC dark theme · JWT in localStorage · WS live feed    │
└───────────────┬────────────────────────────────┬───────────────────┘
                │ REST /api/*                   │ WS /api/ws
┌───────────────▼───────────────────────────────▼───────────────────┐
│  FastAPI (uvicorn)                                                 │
│  ├── auth.py        login · me · user mgmt (RBAC)                 │
│  ├── dashboard.py   stats · analytics                             │
│  ├── datasets.py    upload (CSV/PCAP) · analyze · delete          │
│  ├── models.py      list · train · activate · metrics             │
│  ├── predict.py     single-flow predict · PCAP analyze            │
│  ├── monitoring.py  flows · interfaces · capture start/stop       │
│  ├── alerts.py      list · status workflow · ack                  │
│  ├── incidents.py   CRUD · notes · timeline                       │
│  ├── explain.py     SHAP per-prediction + global · threat-intel   │
│  │                  · reports (PDF/CSV) · settings                │
│  └── ws.py          connection manager + broadcast loop           │
│                                                                   │
│  Services: alerts(dedup) · analytics · audit · explain · reports  │
│            threat_intel · settings                                │
│  DetectionEngine: flow → 78-feature vector → registry → severity  │
│  ModelRegistry: binary / multiclass / anomaly slots (joblib)      │
│  NetworkFlowStore: scapy PcapReader → 5-tuple flow aggregation    │
│  SQLAlchemy (SQLite WAL, FK on; Postgres-compatible models)       │
└───────────────────────────────────────────────────────────────────┘
```

## Key flows

### PCAP analysis
1. `POST /api/datasets/upload` (analyst) — extension allow-list, size limit,
   path-traversal-safe name, stored under `UPLOAD_DIR/pcap/`.
2. Background thread validates (scapy PcapReader magic check).
3. `POST /api/pcap/analyze {"dataset_id"}` — extract flows (CICFlowMeter
   payload-byte semantics), persist `NetworkFlow` rows, classify each with the
   active multiclass model + anomaly score, store `DetectionResult` rows, and
   ingest alerts (dedup window) **in the same DB transaction**.
4. WS `alert_event` / `detection_event` / `stats_update` broadcast to consoles.

### Detection & severity
- Features: 78 CICFlowMeter columns; sample std (n−1) to match training data;
  zero-duration flows get 0.0 rates (not raw counts).
- `is_malicious` ⇔ multiclass prediction ≠ BENIGN.
- Severity: DDoS/Infiltration/Bot=Critical, DoS/Brute Force/Heartbleed=High,
  PortScan/Web Attack/Patators=Medium, benign=Informational; anomaly ≥0.85 on a
  benign flow surfaces as Low; Critical/High demote to Medium when confidence
  < 0.70 (score, not probability).
- Alerts dedup on (attack_type, src, dst) within a configurable window,
  folding repeats into `dedup_count`.

### Training
- `POST /api/models/train` (admin): rows cap + algorithm + task; stratified
  split (seed 42); conservative hyperparameters for the 2-core/4 GB profile;
  writes `backend/artifacts/models/{algo}_{task}_{runid}.joblib` + JSON summary;
  registers metrics on `MlModel`; activation swaps the registry slot live.
- Class guard: labels with <2 members after cleaning are dropped from
  stratification (Infiltration=32, SQLi=21 in this subset).

## Deployment topology
- Dev: uvicorn :8000 + Vite :5173 (proxy /api + ws).
- Docker: backend image (python:3.11-slim) + frontend (node build → nginx);
  nginx terminates SPA and proxies /api and /api/ws; persistent volume /data.
- Live capture: optional, off by default (`LIVE_CAPTURE_ENABLED=false`);
  offline PCAP analysis is the documented, always-available path.

## Security design
- PBKDF2-SHA256 260k iters; JWT HS256 12h; role rank viewer<analyst<admin
  enforced by `require_role` on every route; rate limit 30/min on auth.
- Uploads: never executed; extension allow-list; `MAX_UPLOAD_MB` (default 200);
  sanitized filenames; destination confined to upload dir.
- Threat intel: RFC1918/link-local/loopback never leave the host; default
  provider `none`.
- Audit: login, user changes, uploads, training, alert/incident mutations,
  captures, report generation.

## Notable engineering decisions
1. **Sample std (n−1)** in flow features — matches CICFlowMeter's dataset
   semantics; population std measurably shifted the decision boundary.
2. **Payload-byte accounting** — CICFlowMeter counts TCP/UDP payload bytes;
   Ethernet-frame sizes put live flows off-distribution.
3. **Batch alert ingest in one transaction** — a second session per alert
   deadlocked SQLite writers (fixed; tests cover it).
4. **LabeledEstimator wrapper** — XGBoost sklearn-API class-name changes broke
   unpickling/decoding; the wrapper pins label names per artifact.
5. **Honest OOD reporting** — zero-payload SYN-scan micro-flows score BENIGN
   under this CIC-trained model; documented rather than patched away.
