# AI-IDS Task Board

Status: ✅ done · 🟡 in progress · ⬜ todo

## Phase 1 — Foundation ✅
- ✅ Repo scaffold, venv, requirements, .env.example, .gitignore
- ✅ Config, DB models (SQLAlchemy, SQLite WAL+FK, Postgres-compatible), schemas
- ✅ Security: PBKDF2, JWT, RBAC, rate limiting, audit service

## Phase 2 — Core development ✅
- ✅ CIC-IDS2017 subset acquired (4 days, ~971k rows) + row/label audit
- ✅ Feature schema (78 CICFlowMeter cols) + flow→features derivation
- ✅ Training pipeline (DT/RF/XGB/IF, stratified, seed 42) + measured metrics
- ✅ Model registry + LabeledEstimator wrapper (XGBoost decode fix)
- ✅ PCAP flow extraction (scapy, payload-byte CIC semantics, linktype fixes)
- ✅ Detection engine (classify + anomaly + severity policy)
- ✅ API routers: auth, dashboard, datasets, models, predict/pcap, monitoring,
      alerts, incidents, explain, reports, settings, ws
- ✅ Alert service with dedup window; incident notes/timeline
- ✅ SHAP explainability (per-flow + global)
- ✅ PDF/CSV reports from live DB (reportlab + matplotlib charts)
- ✅ Live capture manager (opt-in) + offline PCAP fallback

## Phase 3 — Integration ✅
- ✅ Frontend scaffold (Vite + TS + Tailwind + shadcn/ui + Recharts + Router + Query)
- ✅ Auth context, API client with 401 handling, WS hook w/ reconnect
- ✅ All 15 pages wired to real backend endpoints
- ✅ Contract doc (docs/INTEGRATION_CONTRACT.md) + type generation
- ✅ Vite proxy (/api → :8000, ws:true); production nginx config

## Phase 4 — Validation 🟡
- ✅ Backend pytest suite — 41/41 green
- ✅ Frontend vitest suite — 20/20 green
- ✅ tsc --noEmit + vite build gates
- ✅ Real-row ML validation (DDoS/BENIGN/PortScan samples)
- ✅ PCAP fixture end-to-end (benign 0 FP; DDoS 60/60; PortScan 24/250 documented)
- 🟡 Live preview verification (backend+frontend via start_process)
- ✅ Defect fixes: SQLite deadlock, PDF chart lifecycle, CIC sample-std, timeline

## Phase 5 — Delivery 🟡
- ✅ README with measured metrics + honest-metrics policy
- ✅ Architecture doc, user manual, test report, task board
- ✅ Docker: backend/frontend Dockerfiles, compose, nginx proxy config
- ⬜ Final commit + push of docs/compose
- ⬜ Live servers up + preview link verified

## Workstreams (10-agent simulation)
1. Foundation/infra ✅ 2. Data & features ✅ 3. ML training ✅ 4. Backend API ✅
5. Detection/PCAP ✅ 6. Frontend UI ✅ 7. Integration ✅ 8. Validation 🟡
9. Security/audit ✅ 10. Docs/delivery 🟡
