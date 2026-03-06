// ─── Severity ────────────────────────────────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

// ─── AI explanation ───────────────────────────────────────────────────────────
export interface ThreatExplanation {
  what:          string;   // one-sentence executive summary
  why:           string;   // technical evidence behind detection
  impact:        string;   // attack scenario / blast radius
  remediation:   string;   // concrete fix: safe version, removal command, alternative
  confidence:    number;   // combined score 0–1
  generated_by?: string;   // provider id (anthropic / openai / ollama)
  generated_at?: string;   // ISO 8601 timestamp
  cache_hit?:    boolean;
}

// ─── Threat ──────────────────────────────────────────────────────────────────
export interface Threat {
  id:           string;
  type:         string;
  severity:     Severity;
  title?:       string;   // optional — synthesised from type when not stored
  description:  string;
  package:      string;
  registry:     string;
  confidence:   number;
  similar_to?:  string;
  cve_id?:      string;
  cvss_score?:  number;
  detected_at:  string;
  explanation?: ThreatExplanation;  // AI-generated — arrives async via SSE
}

// ─── Warning ─────────────────────────────────────────────────────────────────
export interface Warning {
  code:    string;
  message: string;
}

// ─── Analysis result ─────────────────────────────────────────────────────────
export interface AnalysisResult {
  package_name: string;
  registry:     string;
  version?:     string;
  threats:      Threat[];
  warnings:     Warning[];
  risk_level:   number;
  risk_score:   number;
  is_typosquat: boolean;
  analyzed_at:  string;
  scan_duration_ms?: number;
}

// ─── Batch ───────────────────────────────────────────────────────────────────
export interface BatchPackage {
  name:      string;
  registry:  string;
  version?:  string;
}

export interface BatchResult {
  results:    AnalysisResult[];
  total:      number;
  flagged:    number;
  duration_ms: number;
}

// ─── Scan history ────────────────────────────────────────────────────────────
// Mirrors the database.ScanRecord Go struct returned by GET /v1/scans.
export interface ScanRecord {
  id:          string;
  package:     string;   // scanned target path or package name
  name:        string;   // package identifier
  registry:    string;
  status:      'completed' | 'running' | 'failed';
  threats:     number;
  warnings:    number;
  duration_ms: number;
  created_at:  string;
}

// ─── Dashboard metrics ───────────────────────────────────────────────────────
export interface DashboardMetrics {
  total_scans:         number;
  total_packages:      number;
  total_threats:       number;
  critical_threats:    number;
  high_threats:        number;
  medium_threats:      number;
  low_threats:         number;
  avg_risk_score:      number;
  scans_today:         number;
  threats_today:       number;
  top_ecosystems:      EcosystemStat[];
  threat_trend:        TrendPoint[];
  recent_threats:      Threat[];
}

export interface EcosystemStat {
  ecosystem: string;
  count:     number;
  threats:   number;
}

export interface TrendPoint {
  date:     string;
  threats:  number;
  scans:    number;
}

// ─── Performance ─────────────────────────────────────────────────────────────
export interface PerfMetrics {
  scan_duration_p50:  number;
  scan_duration_p95:  number;
  scan_duration_p99:  number;
  requests_per_minute: number;
  error_rate:         number;
  cache_hit_rate:     number;
}

// ─── API status ──────────────────────────────────────────────────────────────
export interface APIStatus {
  status:    string;
  version:   string;
  uptime:    number;
  mode:      string;
  timestamp: string;
}

// ─── Stats ───────────────────────────────────────────────────────────────────
export interface APIStats {
  total_scans:    number;
  total_threats:  number;
  uptime_seconds: number;
  version:        string;
  api_calls:      number;
}

// ─── SSE events ──────────────────────────────────────────────────────────────
export interface ExplanationEvent {
  threat_id:   string;
  package:     string;
  registry:    string;
  type:        string;
  explanation: ThreatExplanation;
}

export type SSEEvent =
  | { type: 'threat';      data: Threat }
  | { type: 'explanation'; data: ExplanationEvent }
  | { type: 'done';        data: { threat_count: number; warning_count: number } }
  | { type: 'ping';        data: { timestamp: string } };

// ─── Auth ────────────────────────────────────────────────────────────────────
export interface AuthToken {
  token:      string;
  expires_at: string;
}
