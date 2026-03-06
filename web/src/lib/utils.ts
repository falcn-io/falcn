import { clsx, type ClassValue } from 'clsx';
import type { Severity } from '@/types';

export const cn = (...inputs: ClassValue[]) => clsx(inputs);

// ─── Severity helpers ────────────────────────────────────────────────────────
export const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

export const severityColor = (s: Severity) => ({
  critical: { bg: 'bg-sev-critical-bg', text: 'text-sev-critical', dot: '#f43f5e', border: 'border-sev-critical/30' },
  high:     { bg: 'bg-sev-high-bg',     text: 'text-sev-high',     dot: '#f97316', border: 'border-sev-high/30' },
  medium:   { bg: 'bg-sev-medium-bg',   text: 'text-sev-medium',   dot: '#f59e0b', border: 'border-sev-medium/30' },
  low:      { bg: 'bg-sev-low-bg',      text: 'text-sev-low',      dot: '#22c55e', border: 'border-sev-low/30' },
  none:     { bg: 'bg-surface-3',       text: 'text-ink-faint',    dot: '#475569', border: 'border-border' },
}[s]);

export const riskColor = (score: number) => {
  if (score >= 0.8) return 'text-sev-critical';
  if (score >= 0.6) return 'text-sev-high';
  if (score >= 0.4) return 'text-sev-medium';
  return 'text-sev-low';
};

export const riskLabel = (score: number) => {
  if (score >= 0.8) return 'Critical';
  if (score >= 0.6) return 'High';
  if (score >= 0.4) return 'Medium';
  return 'Low';
};

// ─── Formatting ──────────────────────────────────────────────────────────────
export const fmtNumber = (n: number) =>
  n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M`
  : n >= 1_000   ? `${(n / 1_000).toFixed(1)}K`
  : String(n);

export const fmtPercent = (n: number) => `${(n * 100).toFixed(1)}%`;

export const fmtMs = (ms: number) =>
  ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms}ms`;

export const fmtRelTime = (iso: string) => {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000)   return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
};

export const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

// ─── Registry icons ──────────────────────────────────────────────────────────
export const registryEmoji: Record<string, string> = {
  npm: '⬡', pypi: '🐍', go: '🐹', cargo: '🦀',
  maven: '☕', rubygems: '💎', nuget: '🟣', composer: '🎵',
};

// ─── Threat type labels ──────────────────────────────────────────────────────
export const threatTypeLabel: Record<string, string> = {
  typosquatting:       'Typosquatting',
  malicious_code:      'Malicious Code',
  cve:                 'CVE',
  secret_leak:         'Secret Leak',
  dependency_confusion:'Dep. Confusion',
  supply_chain:        'Supply Chain',
  backdoor:            'Backdoor',
  data_exfiltration:   'Data Exfil.',
};
