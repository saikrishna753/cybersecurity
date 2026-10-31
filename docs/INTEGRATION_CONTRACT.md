# AI-IDS Integration Contract (v1)

All workstreams MUST use these exact field names, timestamp conventions (ISO-8601 UTC,
`...Z` or `+00:00`), and response envelopes. This document is the source of truth; the
Pydantic schemas in `backend/app/schemas/` and TypeScript types in
`frontend/src/types/contract.ts` mirror it.

## 1. Network Flow (canonical keys)

Produced by: PCAP analysis, live capture, CSV ingestion (mapped), prediction API.

| field | type | notes |
|---|---|---|
| flow_id | string (uuid4) | unique id |
| timestamp | ISO-8601 datetime | flow start time |
| src_ip | string | source IPv4/IPv6 |
| dst_ip | string | destination IPv4/IPv6 |
| src_port | int | 0-65535 |
| dst_port | int | 0-65535 |
| protocol | string | `TCP`/`UDP`/`ICMP`/`OTHER` (upper-case) |
| flow_duration | float | seconds (µs in CIC CSVs converted to s in API) |
| total_fwd_packets | int | forward packets |
| total_bwd_packets | int | backward packets |
| total_fwd_bytes | int | forward bytes |
| total_bwd_bytes | int | backward bytes |
| flow_bytes_per_sec | float | derived |
| flow_packets_per_sec | float | derived |
| payload_bytes? | int | optional extras allowed |

The **ML feature vector** is kept separately: `flow_features` (dict of canonical model
feature names → float). It must exactly match the trained model's schema
(`model.feature_columns`). Feature names are the CICFlowMeter canonical set, e.g.
`Destination Port`, `Flow Duration`, ... (see `app/ml/features.py::CANONICAL_FEATURE_COLUMNS`).

## 2. Detection Result

| field | type |
|---|---|
| flow_id | string |
| prediction | string (`BENIGN`, `DoS`, `DDoS`, `PortScan`, `Web Attack`, `Bot`, `Infiltration`, `Unknown`, ...) |
| is_malicious | bool |
| confidence | float 0-1 (model score; NOT a calibrated probability) |
| anomaly_score | float 0-1 \| null (IsolationForest score, higher = more anomalous) |
| severity | enum `Critical` \| `High` \| `Medium` \| `Low` \| `Informational` |
| model_version | string |
| timestamp | ISO-8601 |

## 3. Security Alert

| field | type |
|---|---|
| alert_id | string (uuid) |
| flow_id | string |
| attack_type | string |
| source_ip | string |
| destination_ip | string |
| destination_port | int |
| protocol | string |
| severity | enum (as above) |
| status | `New` \| `Acknowledged` \| `Investigating` \| `Resolved` \| `False Positive` |
| confidence | float |
| model_version | string |
| dedup_count | int (repeated occurrences folded into one alert) |
| created_at | ISO-8601 |

## 4. API Conventions

- Base path: `/api`.
- Auth: `Authorization: Bearer <JWT>` on all routes except `/api/auth/login`,
  `/api/health`, `/api/auth/bootstrap-status`.
- Success: resource JSON directly (lists as `{items, total, page, size}`).
- Error: `{"detail": "..."}` with proper HTTP status (FastAPI default).
- Pagination params: `page` (1-based), `size` (default 20, max 200), plus filters.
- Roles: `admin` > `analyst` > `viewer`. Viewer = read-only; analyst = operational
  actions (ack alerts, train models, upload); admin = users, settings, destructive ops.
- WebSocket: `/ws?token=<jwt>` → server pushes `{type, data}` events:
  `stats_update`, `flow_event`, `detection_event`, `alert_event`, `capture_status`.

## 5. Severity mapping (detection engine, single implementation)

- `Critical`: DDoS, Infiltration, Botnet/Bot with confidence ≥ 0.9
- `High`: DDoS/DoS/Infiltration/Bot below 0.9, Brute Force
- `Medium`: PortScan, Web Attack, Unknown anomaly (score high)
- `Low`: suspicious-but-benign-leaning (0.75 ≤ conf < threshold or anomaly medium)
- `Informational`: BENIGN / informational events

## 6. Label normalization (training + inference)

Raw CIC labels → canonical: `BENIGN`, `DoS`, `DDoS`, `PortScan`, `Web Attack`,
`Brute Force`, `Bot`, `Infiltration`, `FTP-Patator`, `SSH-Patator`, `Heartbleed`,
`Web Attack` (Brute Force/XSS/SQLi collapsed to `Web Attack` in binary→multiclass
mapping unless kept separate in multiclass training).
