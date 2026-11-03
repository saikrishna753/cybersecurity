# AI-IDS Test Report

Date: 2026-10-31 · Branch: `arena/f3ebb39c-cybersecurity` · Commit: see git log

## 1. Automated backend suite (pytest)

Command: `cd backend && ../.venv/bin/python -m pytest -q`
Result: **41 passed, 0 failed** (~12 s, session-scoped TestClient + isolated SQLite)

| Area | Tests | Covers |
|---|---|---|
| Security primitives | 5 | PBKDF2 round-trip, unique salts, JWT round-trip/tamper, role order |
| Auth API | 8 | login ok/bad, /me ±token, viewer/analyst RBAC denials, admin user CRUD |
| Features | 5 | 78-col schema, label normalization, counts, zero-duration rates, sample-std semantics |
| PCAP/predict/alerts | 10 | extraction, benign fixture → 0 malicious, DDoS fixture → ≥30 malicious + alerts, predict API, auth required, extension/empty upload rejection, viewer denial, full alert status workflow (New→…→False Positive), invalid status 422 |
| Incidents | 3 | lifecycle (create/notes/timeline/contain), pagination, severity pattern rejection |
| Datasets/reports | 10 | CSV upload/list, non-CSV 415, traversal-name handling, analyze report shape, dashboard KPIs, global+per-flow explain, CSV report generate/list/download, PDF generate (%PDF magic), traversal download blocked |

## 2. Automated frontend suite (vitest)

Command: `cd frontend && npm test`
Result: **20 passed, 0 failed** (3 files)

| Area | Covers |
|---|---|
| utils | cn merge, fmtInt/fmtPct/fmtBytes/timeAgo/shortIp edge cases |
| api client | token from localStorage (null/corrupt/valid), ApiError shape, 404 detail mapping, 200 JSON parsing (fetch mocked) |
| components/tokens | Badge render + variant, severity/status token maps, chart palette, Login page smoke render inside AuthProvider |

Build gates: `npx tsc --noEmit` exit 0; `npx vite build` succeeds.

## 3. ML validation (measured, not synthetic)

| Check | Result |
|---|---|
| Binary holdout (80k) | XGBoost acc 0.9988 / F1 0.9976 / AUC 0.9999 |
| Multiclass holdout (60k) | XGBoost acc 0.9987 / macro-F1 0.8972 |
| Real CIC DDoS rows → predict | 5/5 → DDoS, Critical, score 1.000 |
| Real CIC BENIGN rows → predict | 5/5 → BENIGN |
| Real CIC PortScan rows sample (200) | 192/200 correct class (8 → Web Attack, still malicious) |
| Real CIC DDoS rows sample (200) | 200/200 correct class |

## 4. PCAP end-to-end (measured)

| Fixture | Flows | Malicious | Detail |
|---|---|---|---|
| lab_benign.pcap | 36 | 0 | no false alerts |
| lab_ddos_flood.pcap | 60 | 60 | all DDoS/Medium via full upload→analyze→alert path |
| lab_portscan.pcap | 250 | 24 | CIC-shaped probes detected; SYN-scan micro-flows benign (documented OOD behavior) |

## 5. Manual API smoke (live uvicorn)

Verified against a running server: login 200 · POST /predict/flow 200 with alert
dedup · GET /dashboard/stats real KPIs · GET /explain/global top features
(Total Length of Fwd Packets, Packet Length Std, Init_Win_bytes_forward, …) ·
PCAP upload→analyze 200 · WS connect + detection events.

## 6. Defects found & fixed during testing

1. **SQLite writer deadlock** — batch PCAP analysis opened a second session per
   alert while a write txn was open → `database is locked`. Fixed: alerts ingest
   inline in the same session; `detect_flow(publish=False)` for batch paths.
2. **PDF chart lifecycle** — chart PNG unlinked before `doc.build()` read it →
   `FileNotFoundError`. Fixed: unlink after build.
3. **Timeline gap** — incidents had no creation event. Fixed: added `created`.
4. **CIC std semantics** — extractor used population std; CIC used sample std
   (n−1), shifting live features off the training distribution. Fixed.
5. **Training OOM on 4 GB host** — `clean_dataset` chained frame-level
   copy/replace/isna (>3.5 GB peak) and was SIGKILLed mid-run. Fixed with a
   single consolidated float64 matrix path (peak ~2.4 GB, identical row order
   and dedupe decisions — retrained metrics reproduce the originals exactly).
6. **Missing requirements pins** — `pydantic-settings`/`python-dotenv` were
   required by the app but absent from `requirements.txt` (worked only because
   the original venv had them). Added.

## 7. Known limitations (documented, not bugs)

- Docker Compose authored without Docker on this host — config files only.
- Live packet capture disabled by default; offline PCAP mode is the supported path.
- Zero-payload SYN-scan flows score BENIGN under the CIC-trained model (OOD).
- Confidence is a model score, never presented as a calibrated probability.
