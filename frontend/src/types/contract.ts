/**
 * Integration contract mirror — TypeScript side.
 * MUST match backend/app/schemas + docs/INTEGRATION_CONTRACT.md.
 */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type AlertStatus = 'New' | 'Acknowledged' | 'Investigating' | 'Resolved' | 'False Positive';
export type Role = 'admin' | 'analyst' | 'viewer';

export interface NetworkFlow {
  id: string;
  flow_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  flow_duration: number;
  total_fwd_packets: number;
  total_bwd_packets: number;
  total_fwd_bytes: number;
  total_bwd_bytes: number;
  flow_bytes_per_sec: number;
  flow_packets_per_sec: number;
  source: string;
}

export interface DetectionResult {
  id?: string;
  flow_id: string;
  prediction: string;
  is_malicious: boolean;
  confidence: number;
  anomaly_score: number | null;
  severity: Severity;
  model_version: string;
  timestamp?: string;
}

export interface SecurityAlert {
  id: string;
  alert_id: string;
  flow_id: string;
  attack_type: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  severity: Severity;
  status: AlertStatus;
  confidence: number;
  model_version: string;
  dedup_count: number;
  created_at: string;
  updated_at: string;
  assignee_id: string | null;
  incident_id: string | null;
  notified: boolean;
  first_seen_at: string;
}

export interface IncidentNote {
  id: string;
  author_id: string | null;
  author_name: string;
  body: string;
  created_at: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: 'Open' | 'Investigating' | 'Contained' | 'Resolved' | 'Closed';
  assignee_id: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  notes: IncidentNote[];
  alert_count: number;
}

export interface MlModel {
  id: string;
  name: string;
  version: string;
  algorithm: string;
  task: string;
  metrics: Record<string, any> | null;
  is_active: boolean;
  training_job_id: string | null;
  created_at: string;
  feature_count: number;
}

export interface TrainingJob {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  algorithms: string[];
  task: string;
  progress: number;
  stage: string;
  metrics: Record<string, any> | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface DatasetRecord {
  id: string;
  name: string;
  kind: 'csv' | 'pcap';
  size_bytes: number;
  rows: number | null;
  label_distribution: Record<string, number> | null;
  status: string;
  error: string | null;
  created_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export interface DashboardStats {
  total_flows: number;
  total_attacks: number;
  total_normal: number;
  total_suspicious: number;
  detection_rate: number;
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  active_model: string | null;
  attacks_last_hour: number;
  flows_last_hour: number;
  uptime_hours: number;
  confidence_distribution: { bucket: string; count: number }[];
  severity_distribution: { name: string; count: number }[];
  protocol_distribution: { name: string; count: number }[];
  top_source_ips: { ip: string; count: number }[];
  top_destination_ports: { port: number; count: number }[];
  attack_distribution: { attack: string; count: number }[];
  traffic_timeline: { time: string; count: number }[];
  detection_timeline: { time: string; count: number }[];
  recent_alerts: Record<string, any>[];
  data_sources: { live_capture: boolean; ws_clients: number; model_active: boolean };
}

export interface ExplainFeature {
  feature: string;
  value: number | null;
  attribution: number;
}

export interface ExplainResponse {
  flow_id: string;
  prediction: string;
  confidence: number;
  method: string;
  features: ExplainFeature[];
  narrative: string;
}

export interface GlobalImportance {
  method: string;
  model_version: string;
  features: { feature: string; importance: number }[];
}

export interface WsEvent {
  type: 'hello' | 'stats_update' | 'flow_event' | 'detection_event' | 'alert_event' | 'capture_status' | 'pong';
  data: Record<string, any>;
  ts: string | null;
}

export interface AuthUser {
  email: string;
  username: string;
  role: Role;
  token: string;
  expires_in: number;
}
