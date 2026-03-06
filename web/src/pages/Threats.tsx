import { useState, useEffect, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  ShieldAlert, Filter, Search, RefreshCw, AlertCircle,
  ChevronDown, ChevronUp, Sparkles,
} from 'lucide-react';
import { TopBar }        from '@/components/TopBar';
import { SeverityBadge } from '@/components/SeverityBadge';
import { getThreats }    from '@/lib/api';
import { fmtRelTime, threatTypeLabel, registryEmoji, cn } from '@/lib/utils';
import type { Threat, Severity, ThreatExplanation } from '@/types';

const ALL_SEVS: Severity[] = ['critical', 'high', 'medium', 'low'];

// Fully-spelled-out class names so Tailwind JIT includes them all.
const EXPL_LABEL_CLASSES: Record<string, string> = {
  What:   'text-accent',
  Why:    'text-sev-high',
  Impact: 'text-sev-critical',
  Fix:    'text-sev-low',
};

export function Threats() {
  const [threats,    setThreats]    = useState<Threat[]>([]);
  const [total,      setTotal]      = useState(0);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState<string | null>(null);
  const [search,     setSearch]     = useState('');
  const [sevFilter,  setSevFilter]  = useState<Severity | 'all'>('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [page,       setPage]       = useState(0);
  const limit = 50;

  const load = useCallback(async (p: number) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getThreats(limit, p * limit);
      setThreats(res.threats ?? []);
      setTotal(res.total ?? 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load threats');
      setThreats([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(page); }, [load, page]);

  // Derive unique threat types from loaded data for the type filter dropdown.
  const types = ['all', ...Array.from(new Set(threats.map(t => t.type)))].filter(Boolean);

  // Client-side filter on the current page.
  const filtered = threats.filter(t => {
    const q  = search.toLowerCase();
    const ms = !q || t.package.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
    const mv = sevFilter  === 'all' || t.severity === sevFilter;
    const mt = typeFilter === 'all' || t.type     === typeFilter;
    return ms && mv && mt;
  });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="animate-fade-in">
      <TopBar
        title="Threats"
        subtitle={loading ? 'Loading…' : `${total} threats detected across all scans`}
        actions={
          <button onClick={() => load(page)} disabled={loading} className="btn-ghost">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />

      <div className="p-6 space-y-4">
        {/* Filters */}
        <div className="card p-3 flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-48">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search packages or descriptions…"
              className="input-base pl-8 py-1.5 text-xs"
            />
          </div>

          {/* Severity pills */}
          <div className="flex items-center gap-1">
            <Filter size={12} className="text-ink-faint" />
            {(['all', ...ALL_SEVS] as const).map(s => (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                className={cn(
                  'px-2.5 py-1 rounded-lg text-xs font-medium transition-all',
                  sevFilter === s
                    ? 'bg-accent text-white'
                    : 'text-ink-faint hover:text-ink hover:bg-surface-3',
                )}
              >
                {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>

          {/* Type dropdown */}
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="input-base py-1 text-xs w-44"
          >
            {types.map(t => (
              <option key={t} value={t}>
                {t === 'all' ? 'All types' : (threatTypeLabel[t] ?? t)}
              </option>
            ))}
          </select>
        </div>

        {/* Table */}
        <div className="card overflow-hidden">
          {/* Header row */}
          <div className="grid grid-cols-[2fr_1fr_1fr_1.5fr_1fr_auto] gap-4 px-4 py-2.5
                          border-b border-border bg-surface-1
                          text-2xs font-semibold text-ink-faint uppercase tracking-wider">
            <span>Package</span>
            <span>Severity</span>
            <span>Type</span>
            <span>Description</span>
            <span>Detected</span>
            <span className="w-10 text-center">AI</span>
          </div>

          {loading ? (
            <div className="divide-y divide-border/50">
              {Array.from({ length: 8 }, (_, i) => (
                <div key={i} className="grid grid-cols-[2fr_1fr_1fr_1.5fr_1fr_auto] gap-4 px-4 py-3">
                  <div className="h-4 w-36 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-16 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-20 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-full rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-14 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-8 rounded bg-surface-3 animate-pulse" />
                </div>
              ))}
            </div>
          ) : error ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <div className="text-center space-y-2">
                <AlertCircle size={28} className="mx-auto opacity-40" />
                <p className="text-sm">{error}</p>
                <button onClick={() => load(page)} className="btn-ghost text-xs">Retry</button>
              </div>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-ink-faint">
              <div className="text-center">
                <ShieldAlert size={28} className="mx-auto mb-2 opacity-30" />
                <p className="text-sm">
                  {total === 0 ? 'No threats recorded yet — great news!' : 'No threats match your filters.'}
                </p>
              </div>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {filtered.map(t => (
                <ThreatTableRow key={t.id} threat={t} />
              ))}
            </div>
          )}

          {/* Footer: filter count + pagination */}
          {!loading && !error && total > 0 && (
            <div className="px-4 py-2.5 border-t border-border bg-surface-1
                            flex items-center justify-between text-xs text-ink-faint">
              <span>
                Showing {filtered.length} of {threats.length} on this page
                {search || sevFilter !== 'all' || typeFilter !== 'all' ? ' (filtered)' : ''}
              </span>
              {totalPages > 1 && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(0, p - 1))}
                    disabled={page === 0 || loading}
                    className="btn-ghost text-xs py-1 px-2.5 disabled:opacity-40"
                  >
                    ← Prev
                  </button>
                  <span className="tabular-nums">{page + 1} / {totalPages}</span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1 || loading}
                    className="btn-ghost text-xs py-1 px-2.5 disabled:opacity-40"
                  >
                    Next →
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Expandable threat row ────────────────────────────────────────────────────

function ThreatTableRow({ threat: t }: { threat: Threat }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <div
        className={cn(
          'grid grid-cols-[2fr_1fr_1fr_1.5fr_1fr_auto] gap-4 px-4 py-3',
          'hover:bg-surface-3/50 transition-colors',
          expanded && 'bg-surface-2/60',
          t.explanation ? 'cursor-pointer' : 'cursor-default',
        )}
        onClick={() => t.explanation && setExpanded(v => !v)}
      >
        {/* Package + CVE */}
        <div className="min-w-0">
          <div className="mono text-sm text-ink truncate">
            {registryEmoji[(t.registry ?? '').toLowerCase()] ?? '📦'} {t.package}
          </div>
          {t.cve_id && (
            <span className="text-2xs font-mono text-sev-high">{t.cve_id}</span>
          )}
          {t.similar_to && (
            <span className="text-2xs text-ink-faint"> ≈ {t.similar_to}</span>
          )}
        </div>

        <div><SeverityBadge severity={t.severity as Severity} size="sm" /></div>
        <div className="text-xs text-ink-muted">{threatTypeLabel[t.type] ?? t.type}</div>

        <div className="text-xs text-ink-muted truncate" title={t.description}>
          {t.description}
        </div>

        <div className="text-xs text-ink-faint whitespace-nowrap">
          {fmtRelTime(typeof t.detected_at === 'string' ? t.detected_at : new Date(t.detected_at).toISOString())}
        </div>

        {/* AI toggle / indicator */}
        <div className="w-10 flex items-center justify-center">
          {t.explanation ? (
            <button
              onClick={e => { e.stopPropagation(); setExpanded(v => !v); }}
              className="flex items-center gap-0.5 text-2xs px-1.5 py-0.5 rounded border
                         border-accent/40 bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
              title={expanded ? 'Hide AI explanation' : 'Show AI explanation'}
            >
              <Sparkles size={9} />
              {expanded ? <ChevronUp size={9} /> : <ChevronDown size={9} />}
            </button>
          ) : (
            <span className="text-2xs text-ink-faint/30">—</span>
          )}
        </div>
      </div>

      {/* Animated explanation panel */}
      <AnimatePresence initial={false}>
        {expanded && t.explanation && (
          <motion.div
            key={`expl-${t.id}`}
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.22, ease: 'easeInOut' }}
            className="overflow-hidden border-b border-border/40"
          >
            <InlineExplanation explanation={t.explanation} />
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

// ─── Inline explanation panel ─────────────────────────────────────────────────

function InlineExplanation({ explanation }: { explanation: ThreatExplanation }) {
  return (
    <div className="px-4 pb-4 pt-2 bg-surface-2/60">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <Sparkles size={12} className="text-accent" />
        <span className="text-2xs font-medium text-accent">AI Explanation</span>
        {explanation.generated_by && (
          <span className="ml-auto text-2xs text-ink-faint mono">{explanation.generated_by}</span>
        )}
        {explanation.cache_hit && (
          <span className="text-2xs text-ink-faint px-1.5 py-0.5 rounded bg-surface-3 border border-border/40">
            cached
          </span>
        )}
      </div>

      {/* 2-col grid of sections */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
        {(['What', 'Why', 'Impact', 'Fix'] as const).map(label => {
          const text = label === 'What'   ? explanation.what
                     : label === 'Why'    ? explanation.why
                     : label === 'Impact' ? explanation.impact
                     :                     explanation.remediation;
          const cls  = EXPL_LABEL_CLASSES[label] ?? 'text-ink-muted';
          return (
            <div key={label} className="rounded-lg bg-surface-1/60 border border-border/40 p-3">
              <div className={`text-2xs font-semibold mb-1 uppercase tracking-wider ${cls}`}>
                {label}
              </div>
              <p className="text-xs text-ink-muted leading-relaxed">{text}</p>
            </div>
          );
        })}
      </div>

      {/* Confidence bar */}
      <div className="flex items-center gap-2">
        <span className="text-2xs text-ink-faint w-16">Confidence</span>
        <div className="flex-1 h-1.5 rounded-full bg-surface-3 overflow-hidden">
          <div
            className="h-full rounded-full bg-accent transition-all"
            style={{ width: `${Math.round((explanation.confidence ?? 0) * 100)}%` }}
          />
        </div>
        <span className="text-2xs text-ink-faint mono w-8 text-right">
          {Math.round((explanation.confidence ?? 0) * 100)}%
        </span>
      </div>
    </div>
  );
}
