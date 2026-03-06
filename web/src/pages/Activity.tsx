import { useState, useEffect, useCallback } from 'react';
import { Activity as ActivityIcon, Clock, Package, RefreshCw, AlertCircle } from 'lucide-react';
import { TopBar }      from '@/components/TopBar';
import { SeverityDot } from '@/components/SeverityBadge';
import { getScans }    from '@/lib/api';
import { fmtMs, fmtRelTime, registryEmoji, cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

// Derive a rough risk severity from the number of threats found.
function riskSeverity(threats: number): 'critical' | 'high' | 'medium' | 'low' {
  if (threats >= 5) return 'critical';
  if (threats >= 3) return 'high';
  if (threats >= 1) return 'medium';
  return 'low';
}

export function Activity() {
  const [scans,   setScans]   = useState<ScanRecord[]>([]);
  const [total,   setTotal]   = useState(0);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const [page,    setPage]    = useState(0);
  const limit = 25;

  const load = useCallback(async (p: number) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getScans(limit, p * limit);
      setScans(res.scans ?? []);
      setTotal(res.total ?? 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scan history');
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(page); }, [load, page]);

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="animate-fade-in">
      <TopBar
        title="Activity"
        subtitle={loading ? 'Loading…' : `${total} scans recorded`}
        actions={
          <button onClick={() => load(page)} disabled={loading} className="btn-ghost">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />

      <div className="p-6 space-y-4">
        <div className="card overflow-hidden">
          <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ActivityIcon size={14} className="text-accent" />
              <h2 className="text-sm font-semibold text-ink">Scan History</h2>
            </div>
            {total > 0 && (
              <span className="text-xs text-ink-faint tabular-nums">
                {total} total
              </span>
            )}
          </div>

          {/* Column headers */}
          <div className="grid grid-cols-[2.5fr_1fr_1fr_1fr_1fr] gap-4 px-5 py-2.5 border-b border-border
                          bg-surface-1 text-2xs font-semibold text-ink-faint uppercase tracking-wider">
            <span>Target</span>
            <span>Registry</span>
            <span>Threats</span>
            <span>Duration</span>
            <span>Status</span>
          </div>

          {/* Body */}
          {loading ? (
            <div className="divide-y divide-border/50">
              {Array.from({ length: 8 }, (_, i) => (
                <div key={i} className="grid grid-cols-[2.5fr_1fr_1fr_1fr_1fr] gap-4 px-5 py-3">
                  <div className="h-4 w-40 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-14 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-10 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-16 rounded bg-surface-3 animate-pulse" />
                  <div className="h-4 w-18 rounded bg-surface-3 animate-pulse" />
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
          ) : scans.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <div className="text-center space-y-2">
                <Package size={28} className="mx-auto opacity-30" />
                <p className="text-sm">No scans recorded yet.</p>
                <p className="text-xs">Run <code className="mono bg-surface-3 px-1 rounded">falcn scan</code> or use the Scanner page.</p>
              </div>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {scans.map(s => {
                const sev = riskSeverity(s.threats);
                const reg = (s.registry || '').toLowerCase();
                return (
                  <div
                    key={s.id}
                    className="grid grid-cols-[2.5fr_1fr_1fr_1fr_1fr] gap-4 px-5 py-3
                               hover:bg-surface-3/40 transition-colors cursor-default"
                  >
                    {/* Target */}
                    <div className="flex items-center gap-2 min-w-0">
                      <Package size={12} className="text-ink-faint flex-shrink-0" />
                      <div className="min-w-0">
                        <div className="mono text-sm text-ink truncate">
                          {s.name || s.package}
                        </div>
                        {s.package !== s.name && s.package && (
                          <div className="text-2xs text-ink-faint truncate">{s.package}</div>
                        )}
                      </div>
                    </div>

                    {/* Registry */}
                    <div className="text-sm text-ink-muted">
                      {reg ? `${registryEmoji[reg] ?? '📦'} ${s.registry}` : '—'}
                    </div>

                    {/* Threats */}
                    <div className="flex items-center gap-1.5">
                      {s.threats > 0 && <SeverityDot severity={sev} />}
                      <span className="text-sm tabular-nums text-ink-muted">{s.threats}</span>
                    </div>

                    {/* Duration */}
                    <div className="flex items-center gap-1 text-xs text-ink-faint">
                      <Clock size={10} />
                      {fmtMs(s.duration_ms)}
                    </div>

                    {/* Status + age */}
                    <div className="flex items-center gap-2">
                      <span className={cn(
                        'badge text-2xs',
                        s.status === 'running'
                          ? 'bg-accent-ghost text-accent border border-accent/20'
                          : s.status === 'completed'
                            ? 'bg-sev-low-bg text-sev-low border border-sev-low/20'
                            : 'bg-sev-critical-bg text-sev-critical border border-sev-critical/20',
                      )}>
                        {s.status === 'running' && (
                          <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse-dot inline-block mr-1" />
                        )}
                        {s.status}
                      </span>
                      <span className="text-2xs text-ink-faint hidden xl:block whitespace-nowrap">
                        {fmtRelTime(s.created_at)}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="px-5 py-3 border-t border-border bg-surface-1 flex items-center justify-between">
              <span className="text-xs text-ink-faint">
                Page {page + 1} of {totalPages}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0 || loading}
                  className="btn-ghost text-xs py-1 px-2.5 disabled:opacity-40"
                >
                  ← Prev
                </button>
                <button
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1 || loading}
                  className="btn-ghost text-xs py-1 px-2.5 disabled:opacity-40"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
