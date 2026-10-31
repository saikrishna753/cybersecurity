"""Pydantic request/response schemas — mirrors docs/INTEGRATION_CONTRACT.md."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

# Internal/on-prem addresses (e.g. admin@ai-ids.local) are legitimate for an
# air-gapped SOC, so we use a pragmatic pattern instead of strict EmailStr.
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$"


def EmailField(default=None, **kwargs):  # noqa: N802
    return Field(default=default, pattern=EMAIL_PATTERN, **kwargs)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ auth
class LoginRequest(BaseModel):
    email: str = EmailField()
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str
    username: str
    expires_in: int


class UserCreate(BaseModel):
    email: str = EmailField()
    username: str = Field(min_length=3, max_length=100)
    full_name: str = ""
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class UserUpdate(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|analyst|viewer)$")
    is_active: bool | None = None
    full_name: str | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserOut(ORMModel):
    id: str
    email: str
    username: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


# ------------------------------------------------------------------ pagination
class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int


# ------------------------------------------------------------------ flow / detection
class FlowOut(ORMModel):
    id: str
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    total_fwd_bytes: int
    total_bwd_bytes: int
    flow_bytes_per_sec: float
    flow_packets_per_sec: float
    source: str


class FlowPredictRequest(BaseModel):
    """Raw flow tuple (features derived server-side) OR explicit feature vector."""

    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = "TCP"
    flow_duration: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0
    features: dict[str, float] | None = None


class DetectionOut(ORMModel):
    id: str
    flow_id: str
    prediction: str
    is_malicious: bool
    confidence: float
    anomaly_score: float | None
    severity: str
    model_version: str
    timestamp: datetime


class DetectionEvent(BaseModel):
    """Contract shape emitted to WS clients and alert engine."""

    flow_id: str
    prediction: str
    is_malicious: bool
    confidence: float
    anomaly_score: float | None = None
    severity: str
    model_version: str
    timestamp: datetime
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "TCP"


# ------------------------------------------------------------------ alerts
class AlertUpdate(BaseModel):
    status: str | None = Field(
        default=None, pattern="^(New|Acknowledged|Investigating|Resolved|False Positive)$"
    )
    assignee_id: str | None = None
    note: str | None = None


class AlertOut(ORMModel):
    id: str
    alert_id: str
    flow_id: str
    attack_type: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    severity: str
    status: str
    confidence: float
    model_version: str
    dedup_count: int
    created_at: datetime
    updated_at: datetime
    assignee_id: str | None = None
    incident_id: str | None = None
    notified: bool = False
    first_seen_at: datetime


# ------------------------------------------------------------------ incidents
class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = ""
    severity: str = Field(default="Medium", pattern="^(Critical|High|Medium|Low|Informational)$")
    alert_ids: list[str] = []


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = Field(default=None, pattern="^(Open|Investigating|Contained|Resolved|Closed)$")
    assignee_id: str | None = None


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=20000)


class IncidentNoteOut(ORMModel):
    id: str
    author_id: str | None
    author_name: str
    body: str
    created_at: datetime


class IncidentOut(ORMModel):
    id: str
    title: str
    description: str
    severity: str
    status: str
    assignee_id: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    notes: list[IncidentNoteOut] = []
    alert_count: int = 0


# ------------------------------------------------------------------ datasets
class DatasetOut(ORMModel):
    id: str
    name: str
    kind: str
    size_bytes: int
    rows: int | None
    label_distribution: dict | None
    status: str
    error: str | None
    created_at: datetime


# ------------------------------------------------------------------ models / training
class ModelOut(ORMModel):
    id: str
    name: str
    version: str
    algorithm: str
    task: str
    metrics: dict | None
    is_active: bool
    training_job_id: str | None
    created_at: datetime
    feature_count: int = 0


class TrainRequest(BaseModel):
    dataset_ids: list[str] = []
    algorithms: list[str] = ["decision_tree", "random_forest", "xgboost", "isolation_forest"]
    task: str = Field(default="binary", pattern="^(binary|multiclass)$")
    test_size: float = Field(default=0.2, ge=0.05, le=0.5)
    max_rows: int = Field(default=400_000, ge=1000, le=2_000_000)
    random_state: int = 42
    activate_best: bool = True


class TrainingJobOut(ORMModel):
    id: str
    status: str
    algorithms: list[str]
    task: str
    progress: int
    stage: str
    metrics: dict | None
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


# ------------------------------------------------------------------ analytics / dashboard
class DashboardStats(BaseModel):
    total_flows: int
    total_attacks: int
    total_normal: int
    total_suspicious: int
    detection_rate: float
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    active_model: str | None
    attacks_last_hour: int
    flows_last_hour: int
    uptime_hours: float
    confidence_distribution: list[dict]
    severity_distribution: list[dict]
    protocol_distribution: list[dict]
    top_source_ips: list[dict]
    top_destination_ports: list[dict]
    attack_distribution: list[dict]
    traffic_timeline: list[dict]
    detection_timeline: list[dict]
    recent_alerts: list[dict]
    data_sources: dict


class AnalyticsSummary(BaseModel):
    total_traffic: int
    normal: int
    malicious: int
    by_attack: dict
    by_severity: dict
    by_protocol: dict
    by_status: dict
    false_positives: int
    top_sources: list[dict]
    top_ports: list[dict]
    timeline: list[dict]
    model_trends: list[dict]


# ------------------------------------------------------------------ explainability
class ExplainRequest(BaseModel):
    detection_id: str | None = None
    flow_id: str | None = None
    top_k: int = Field(default=8, ge=1, le=30)


class FeatureAttribution(BaseModel):
    feature: str
    value: float | None
    attribution: float


class ExplainResponse(BaseModel):
    flow_id: str
    prediction: str
    confidence: float
    method: str  # shap | permutation | tree_importance_fallback
    features: list[FeatureAttribution]
    narrative: str


class GlobalImportance(BaseModel):
    method: str
    model_version: str
    features: list[dict]


# ------------------------------------------------------------------ threat intel
class ThreatIntelOut(ORMModel):
    id: str
    ip: str
    provider: str
    is_malicious: bool
    score: float | None
    categories: list | None
    is_private_ip: bool
    fetched_at: datetime
    expires_at: datetime | None
    error: str | None


# ------------------------------------------------------------------ capture
class InterfaceOut(BaseModel):
    name: str
    description: str = ""
    is_up: bool = False
    is_authorized: bool = False
    capture_permission: str = "unknown"


class CaptureStartRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    authorized: bool = False
    bpf_filter: str = ""
    batch_size: int = Field(default=100, ge=1, le=1000)


class CaptureStatus(BaseModel):
    running: bool
    interface: str | None
    started_at: datetime | None
    packets_captured: int
    flows_emitted: int
    queue_size: int
    error: str | None = None
    mode: str = "offline"  # offline | live


# ------------------------------------------------------------------ reports
class ReportRequest(BaseModel):
    report_type: str = Field(pattern="^(daily|weekly|investigation|custom)$")
    format: str = Field(default="pdf", pattern="^(pdf|csv)$")
    date_from: datetime | None = None
    date_to: datetime | None = None
    incident_id: str | None = None
    title: str = ""


class ReportOut(BaseModel):
    filename: str
    url: str
    generated_at: datetime
    rows: int | None = None
    report_type: str
    format: str


# ------------------------------------------------------------------ settings
class SettingOut(BaseModel):
    key: str
    value: str
    updated_at: datetime


class SettingsUpdate(BaseModel):
    settings: dict[str, str]


class WsEvent(BaseModel):
    type: str
    data: dict[str, Any]
    ts: datetime
