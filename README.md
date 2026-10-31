# AI-IDS — AI-Powered Network Intrusion Detection & Threat Monitoring Platform

Full-stack SOC platform: FastAPI backend, React/TypeScript frontend, supervised +
unsupervised ML (scikit-learn / XGBoost) on **CIC-IDS2017**, SHAP explainability,
PCAP flow analysis, alert & incident workflow, audit logging, and WebSocket live
updates.

> **Honest-metrics policy:** every accuracy/F1/AUC number in this repo was measured
> by actually executing training on the included CIC-IDS2017 subset (run IDs below).
> Confidence values are model scores, **not** calibrated probabilities.

## Architecture (short)

```
frontend (React+Vite+Tailwind, :5173 dev / nginx in Docker)
    │  REST + WS (/api, /api/ws)
backend (FastAPI + SQLAlchemy + SQLite-WAL, :8000)
    ├── auth/RBAC (JWT, viewer<analyst<admin, PBKDF2-SHA256)
    ├── datasets  (CSV/PCAP upload, validation, size limits, never executed)
    ├── ml        (train: DecisionTree/RandomForest/XGBoost/IsolationForest)
    ├── detection (CICFlowMeter-compatible 78-feature flow features → registry)
    ├── explain   (SHAP per-flow + global importances)
    ├── alerts/Incidents (New→Acknowledged→Investigating→Resolved/False Positive)
    ├── reports   (PDF w/ charts + CSV, generated from live DB rows)
    └── ws        (live detections/alerts/stats)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details and
[docs/INTEGRATION_CONTRACT.md](docs/INTEGRATION_CONTRACT.md) for the API contract.

## Quick start (dev)

```bash
# backend (Python 3.11+)
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && uvicorn app.main:app --reload --port 8000

# frontend (Node 22+)
cd frontend && npm install && npm run dev    # http://localhost:5173
```

Login: `admin@ai-ids.local` / `ChangeMe!123` (change via `.env`).

## Quick start (Docker Compose)

```bash
docker compose up --build -d
# frontend → http://localhost:8080   API → http://localhost:8000/api/health
```

> Compose files follow standard conventions but were authored on a host without
> Docker; they are documented, not executed here. Containers default to offline
> PCAP mode (`LIVE_CAPTURE_ENABLED=false`).

## Measured model performance (real training runs)

Trained on 4 of 8 CIC-IDS2017 days (~971k rows; Friday-PortScan 286k, Friday-DDoS
226k, Thursday-Infiltration 289k, Thursday-WebAttacks 170k), stratified
train/holdout, seed 42.

**Binary (run 20261031165647 — 400k rows → 235,994 train / 80,000 holdout, 143 s):**

| Model | Accuracy | F1 | FPR | AUC |
|---|---|---|---|---|
| Decision Tree | 0.9985 | 0.9972 | 0.0019 | 0.9996 |
| Random Forest | 0.9987 | 0.9976 | 0.0016 | 0.9999 |
| **XGBoost (active)** | **0.9988** | **0.9976** | **0.0016** | **0.9999** |
| Isolation Forest | 0.7497 | 0.3791 | 0.0871 | 0.6761 |

**Multiclass (run 20261031165915 — 300k → 240k/60k, 92 s):**

| Model | Accuracy | Macro-F1 | AUC |
|---|---|---|---|
| Decision Tree | 0.9986 | 0.9564 | 0.9641 |
| Random Forest | 0.9985 | 0.9530 | 0.9998 |
| **XGBoost (active)** | **0.9987** | **0.8972** | **0.9949** |
| Isolation Forest (anomaly slot) | 0.7619 | 0.4336 | 0.6852 |

Active registry: `xgboost_binary`, `xgboost_multiclass`, `isolation_forest_anomaly`.
Raw metrics: `backend/artifacts/models/training_summary_*.json`.

## PCAP lab fixtures (measured behavior)

`backend/scripts/generate_fixtures.py` builds synthetic, offline lab PCAPs shaped
to CIC-IDS2017 traffic patterns (payload-byte accounting, GRO-style coalesced
segments, CIC window/timing characteristics). Measured on the shipped artifacts:

| Fixture | Flows | Classified malicious | Notes |
|---|---|---|---|
| lab_benign.pcap | 36 | 0 | interactive sessions → all BENIGN |
| lab_ddos_flood.pcap | 60 | 60 DDoS (Medium) | HTTP-flood shape w/ 5840B coalesced segment |
| lab_portscan.pcap | 250 | 24 PortScan (Medium) | CIC-shaped probes flag; zero-payload SYN-scan micro-flows score benign (OOD — documented limitation) |

## Tests

```bash
cd backend && ../.venv/bin/python -m pytest -q     # 41 passed
cd frontend && npm test                            # 20 passed (vitest)
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, data flow, decisions
- [docs/USER_MANUAL.md](docs/USER_MANUAL.md) — operator guide (all 15 pages)
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — automated + manual test results
- [docs/TASK_BOARD.md](docs/TASK_BOARD.md) — workstream status
- [docs/INTEGRATION_CONTRACT.md](docs/INTEGRATION_CONTRACT.md) — API contract

## Security posture

- Defensive-only: no auto-blocking in v1; authorized monitoring of your own networks.
- Uploads: extension allow-list (CSV/PCAP only), size limits, path-traversal-safe
  storage, files never executed.
- RBAC enforced server-side on every route; admin actions audit-logged.
- Threat intel: private/internal IPs are never sent to external providers (default
  provider is `none`; enrichment is local heuristics only).
- Credentials: PBKDF2-SHA256 (260k iterations), JWT HS256; secrets via env.
