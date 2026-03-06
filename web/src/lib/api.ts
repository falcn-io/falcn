import type {
  AnalysisResult, BatchPackage, BatchResult, DashboardMetrics,
  PerfMetrics, APIStatus, APIStats, AuthToken, ScanRecord, Threat,
} from '@/types';

// ─── Config ───────────────────────────────────────────────────────────────────
const BASE = import.meta.env.VITE_API_URL ?? '';
const API_KEY_STORAGE = 'falcn_api_key';
const JWT_STORAGE     = 'falcn_jwt';

// ─── Token management ────────────────────────────────────────────────────────
export const auth = {
  setKey: (key: string) => localStorage.setItem(API_KEY_STORAGE, key),
  getKey: () => localStorage.getItem(API_KEY_STORAGE) ?? '',
  setJWT: (token: string) => sessionStorage.setItem(JWT_STORAGE, token),
  getJWT: () => sessionStorage.getItem(JWT_STORAGE) ?? '',
  clear:  () => { localStorage.removeItem(API_KEY_STORAGE); sessionStorage.removeItem(JWT_STORAGE); },
};

// ─── Core fetch ──────────────────────────────────────────────────────────────
async function req<T>(
  method: string,
  path:   string,
  body?:  unknown,
): Promise<T> {
  const jwt    = auth.getJWT();
  const apiKey = auth.getKey();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  if (jwt)    headers['Authorization'] = `Bearer ${jwt}`;
  else if (apiKey) headers['X-API-Key'] = apiKey;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}${text ? ': ' + text : ''}`);
  }

  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) return res.json() as Promise<T>;
  return undefined as unknown as T;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
export async function issueToken(apiKey: string): Promise<AuthToken> {
  return req<AuthToken>('POST', '/v1/auth/token', { api_key: apiKey });
}

// ─── Health / Status ─────────────────────────────────────────────────────────
export const getHealth  = () => req<{ status: string }>('GET', '/health');
export const getStatus  = () => req<APIStatus>('GET', '/v1/status');
export const getStats   = () => req<APIStats>('GET', '/v1/stats');

// ─── Analysis ────────────────────────────────────────────────────────────────
export function analyzePackage(name: string, registry = 'npm', version?: string): Promise<AnalysisResult> {
  return req<AnalysisResult>('POST', '/v1/analyze', { package_name: name, registry, version });
}

export function analyzeBatch(packages: BatchPackage[]): Promise<BatchResult> {
  return req<BatchResult>('POST', '/v1/analyze/batch', { packages });
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
export const getDashboardMetrics = () => req<DashboardMetrics>('GET', '/v1/dashboard/metrics');
export const getDashboardPerf    = () => req<PerfMetrics>('GET', '/v1/dashboard/performance');

// ─── Scans ───────────────────────────────────────────────────────────────────
export function getScans(limit = 50, offset = 0): Promise<{ scans: ScanRecord[]; total: number }> {
  return req('GET', `/v1/scans?limit=${limit}&offset=${offset}`);
}

// ─── Threats ─────────────────────────────────────────────────────────────────
export function getThreats(limit = 50, offset = 0): Promise<{ threats: Threat[]; total: number; limit: number; offset: number }> {
  return req('GET', `/v1/threats?limit=${limit}&offset=${offset}`);
}

// ─── Reports ─────────────────────────────────────────────────────────────────
export async function generateReport(
  type:   'technical' | 'executive' | 'compliance',
  format: 'pdf' | 'sarif' | 'cyclonedx' | 'spdx' | 'json',
): Promise<{ blob: Blob; filename: string }> {
  const jwt    = auth.getJWT();
  const apiKey = auth.getKey();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (jwt)    headers['Authorization'] = `Bearer ${jwt}`;
  else if (apiKey) headers['X-API-Key'] = apiKey;

  const res = await fetch(`${BASE}/v1/reports/generate`, {
    method:  'POST',
    headers,
    body:    JSON.stringify({ type, format }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}${text ? ': ' + text : ''}`);
  }

  const cd    = res.headers.get('Content-Disposition') ?? '';
  const match = cd.match(/filename="?([^"]+)"?/);
  const ext   = format === 'sarif' ? 'sarif' : format === 'cyclonedx' ? 'cdx.json' : format === 'spdx' ? 'spdx.json' : 'json';
  const filename = match?.[1] ?? `falcn-${type}-${new Date().toISOString().slice(0,10)}.${ext}`;
  const blob  = await res.blob();
  return { blob, filename };
}

// ─── Vulnerabilities ─────────────────────────────────────────────────────────
export function getVulnerabilities(limit = 50) {
  return req<{ vulnerabilities: unknown[]; total: number }>('GET', `/v1/vulnerabilities?limit=${limit}`);
}

// ─── SSE stream ──────────────────────────────────────────────────────────────
export function createEventStream(): EventSource {
  const jwt    = auth.getJWT();
  const apiKey = auth.getKey();
  const param  = jwt ? `token=${jwt}` : apiKey ? `api_key=${apiKey}` : '';
  return new EventSource(`${BASE}/v1/stream${param ? '?' + param : ''}`);
}

// ─── Mock data (for demo when API is unavailable) ────────────────────────────
export const MOCK: DashboardMetrics = {
  total_scans: 1_284,
  total_packages: 48_721,
  total_threats: 342,
  critical_threats: 17,
  high_threats: 58,
  medium_threats: 149,
  low_threats: 118,
  avg_risk_score: 0.23,
  scans_today: 47,
  threats_today: 12,
  top_ecosystems: [
    { ecosystem: 'npm',    count: 22340, threats: 178 },
    { ecosystem: 'PyPI',   count: 12_100, threats: 81 },
    { ecosystem: 'Go',     count: 7_200, threats: 39 },
    { ecosystem: 'Maven',  count: 4_100, threats: 27 },
    { ecosystem: 'Cargo',  count: 2_981, threats: 17 },
  ],
  threat_trend: Array.from({ length: 14 }, (_, i) => ({
    date:    new Date(Date.now() - (13 - i) * 86_400_000).toLocaleDateString('en', { month: 'short', day: 'numeric' }),
    threats: Math.floor(Math.random() * 35) + 5,
    scans:   Math.floor(Math.random() * 100) + 50,
  })),
  recent_threats: [
    { id: 't1', type: 'typosquatting', severity: 'critical', title: 'Typosquatting detected', description: 'Package name closely resembles popular library', package: 'crossenv', registry: 'npm', confidence: 0.97, similar_to: 'cross-env', detected_at: new Date().toISOString() },
    { id: 't2', type: 'malicious_code', severity: 'high', title: 'Obfuscated payload found', description: 'Base64-encoded shell command in install script', package: 'event-stream', registry: 'npm', confidence: 0.91, detected_at: new Date(Date.now() - 300_000).toISOString() },
    { id: 't3', type: 'cve', severity: 'high', title: 'CVE-2023-44487', description: 'HTTP/2 Rapid Reset vulnerability', package: 'grpc', registry: 'PyPI', confidence: 1.0, cve_id: 'CVE-2023-44487', cvss_score: 7.5, detected_at: new Date(Date.now() - 900_000).toISOString() },
    { id: 't4', type: 'dependency_confusion', severity: 'medium', title: 'Dependency confusion risk', description: 'Public package name matches internal namespace', package: 'acme-utils', registry: 'npm', confidence: 0.76, detected_at: new Date(Date.now() - 1_800_000).toISOString() },
    { id: 't5', type: 'secret_leak', severity: 'medium', title: 'Hardcoded credential', description: 'AWS access key pattern found in source', package: 'datadog-agent', registry: 'PyPI', confidence: 0.88, detected_at: new Date(Date.now() - 3_600_000).toISOString() },
  ],
};
