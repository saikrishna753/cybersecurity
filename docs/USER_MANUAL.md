# AI-IDS User Manual

## 1. Getting started

| Item | Value |
|---|---|
| Dev frontend | http://localhost:5173 |
| Dev API | http://localhost:8000 (docs at /docs) |
| Docker frontend | http://localhost:8080 |
| Default admin | `admin@ai-ids.local` / `ChangeMe!123` — **change immediately** |

Roles: **viewer** (read-only), **analyst** (alerts, incidents, uploads, PCAP
analysis, reports), **admin** (everything + users, training, model activation,
settings, interface authorization).

## 2. Pages

### Login
Email + password. JWT stored in localStorage; session expires per backend policy.

### Dashboard
Live KPIs from the backend database: total flows, attacks, open/critical alerts,
detection rate, attack distribution, recent alerts, active model. Numbers are
computed from real rows — nothing is mocked.

### Live Monitor
WebSocket-driven feed of detections, alerts and stats. If the socket drops it
reconnects with backoff. Use it during PCAP analysis to watch results stream in.

### Dataset Analysis
Upload labeled CIC-format CSVs (extension `.csv`, size-capped). The backend
validates, profiles label distribution, and runs an analysis pass (class
balance, feature summary). Datasets can then feed training.

### PCAP Analysis
Upload a `.pcap`/`.pcapng`/`.cap`, then run analysis. Output: flow count,
malicious count, alerts created, top attacks, and a preview table. Lab fixtures
live in `data/fixtures/` (see README for measured detection rates).

### Detection (manual)
Enter a flow tuple (or full feature vector) for an on-demand classification.
Shows prediction, confidence (model score — not a calibrated probability),
severity, and anomaly score.

### Alerts
Filterable list with severity/status. Workflow: **New → Acknowledged →
Investigating → Resolved** or **False Positive** (analyst+). Summary endpoint
powers the badge counts.

### Incidents
Create incidents (optionally linked alert IDs), add notes, view the timeline
(creation, notes, linked alerts). Statuses: Open, Investigating, Contained,
Resolved, Closed.

### Models
List trained artifacts with **measured** metrics (accuracy, F1, FPR, AUC per
task). Admins can launch training runs (algorithm + task + row cap); progress
streams over WS. Activate a model to switch the live registry slot.

### Explainability
- **Global**: top SHAP/tree importances for the active model.
- **Per-prediction**: pick a detection id → SHAP values, contribution chart,
  and a plain-language narrative. Confidence is explicitly labeled as a model
  score, not a probability.

### Threat Intel
Local-only enrichment view. Private/internal IPs are never sent to external
services (default provider `none`).

### Reports
Generate **PDF** (KPIs, charts, alert table, measured model metrics) or **CSV**
(alert rows) for a date range. Files list with download links; generated from
live database records only.

### Settings / Profile
Admin: dedup window, alert email toggle, capture defaults. Profile: update your
name/password; shows role.

## 3. Operating notes

- **Offline PCAP mode**: live capture is disabled by default and requires OS
  capabilities; upload-based PCAP analysis is the supported path everywhere.
- **Upload safety**: only `.csv`/`.pcap`/`.pcapng`/`.cap` are accepted; files
  are never executed; names are sanitized; size limit `MAX_UPLOAD_MB`.
- **What "confidence" means**: the model's decision score. It is not calibrated;
  do not read 0.95 as "95% probability".
- **Known limitation (measured)**: the CIC-trained classifier scores
  zero-payload SYN-scan micro-flows as benign (out-of-distribution). CIC-shaped
  service-enumeration probes and HTTP-flood flows are detected (see README
  fixture table).
