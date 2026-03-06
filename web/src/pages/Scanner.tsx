import { useState, useCallback } from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Loader2, Trash2, Wifi, WifiOff } from 'lucide-react';
import { TopBar }        from '@/components/TopBar';
import { ScanForm }      from '@/components/ScanForm';
import { ThreatFeed }    from '@/components/ThreatFeed';
import { RiskGauge }     from '@/components/RiskGauge';

import { useSSE }        from '@/hooks/useSSE';
import { analyzePackage } from '@/lib/api';
import { fmtMs, registryEmoji } from '@/lib/utils';
import type { AnalysisResult }  from '@/types';
import { cn } from '@/lib/utils';

export function Scanner() {
  const [result,  setResult]  = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  const { threats, status, totalSeen, clearThreats, connect, disconnect } = useSSE(100);

  const handleScan = useCallback(async (pkg: string, registry: string, version: string) => {
    setLoading(true);
    setError(null);
    setResult(null);
    clearThreats();
    try {
      const r = await analyzePackage(pkg, registry, version || undefined);
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setLoading(false);
    }
  }, [clearThreats]);

  const riskScore = result?.risk_score ?? 0;
  const hasThreats = (result?.threats?.length ?? 0) > 0 || threats.length > 0;

  return (
    <div className="animate-fade-in">
      <TopBar
        title="Scanner"
        subtitle="Analyze packages for supply chain threats in real time"
        actions={
          <button
            onClick={() => status === 'connected' ? disconnect() : connect()}
            className={cn('btn-ghost text-xs', status === 'connected' ? 'text-sev-low' : 'text-ink-faint')}
          >
            {status === 'connected'
              ? <><Wifi size={12} /> Live</>
              : <><WifiOff size={12} /> Offline</>}
          </button>
        }
      />

      <div className="p-6 grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* ── Left panel: form + gauge ── */}
        <div className="xl:col-span-1 space-y-4">
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
              <Shield size={14} className="text-accent" />
              Package Analysis
            </h2>
            <ScanForm onScan={handleScan} loading={loading} />
          </div>

          {/* Risk gauge */}
          {(result || loading) && (
            <div className="card p-5 flex flex-col items-center gap-4 animate-slide-up">
              {loading ? (
                <div className="flex flex-col items-center gap-3 py-4">
                  <Loader2 size={32} className="animate-spin text-accent opacity-60" />
                  <p className="text-sm text-ink-muted">Scanning…</p>
                </div>
              ) : result ? (
                <>
                  <RiskGauge score={riskScore} size={120} />
                  <div className="text-center">
                    <p className="mono text-sm text-ink">
                      {registryEmoji[result.registry?.toLowerCase()] ?? '📦'} {result.package_name}
                    </p>
                    {result.version && (
                      <p className="text-xs text-ink-faint mt-0.5">{result.registry} · {result.version}</p>
                    )}
                  </div>
                  {result.scan_duration_ms && (
                    <p className="text-xs text-ink-faint">
                      Scanned in {fmtMs(result.scan_duration_ms)}
                    </p>
                  )}
                </>
              ) : null}
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="card border-sev-critical/30 bg-sev-critical-bg p-4 text-sm text-sev-critical flex items-start gap-2 animate-fade-in">
              <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
              {error}
            </div>
          )}
        </div>

        {/* ── Right panel: results ── */}
        <div className="xl:col-span-2 space-y-4">
          {/* Result summary */}
          {result && !loading && (
            <div className="card p-5 animate-slide-in-r">
              <div className="flex items-center gap-3 mb-4">
                {hasThreats
                  ? <ShieldAlert size={18} className="text-sev-critical" />
                  : <ShieldCheck size={18} className="text-sev-low" />}
                <div>
                  <h2 className="text-sm font-semibold text-ink">
                    {hasThreats ? `${result.threats.length} Threat${result.threats.length !== 1 ? 's' : ''} Found` : 'All Clear'}
                  </h2>
                  <p className="text-xs text-ink-faint">
                    {hasThreats ? 'Immediate action recommended' : 'No threats detected in this package'}
                  </p>
                </div>
              </div>

              {/* Warnings */}
              {result.warnings?.length > 0 && (
                <div className="mb-4 space-y-1.5">
                  {result.warnings.map((w, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-sev-medium bg-sev-medium-bg
                                            rounded-lg px-3 py-2 border border-sev-medium/20">
                      <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
                      {w.message}
                    </div>
                  ))}
                </div>
              )}

              {/* Threat list */}
              {result.threats.length > 0 && (
                <ThreatFeed threats={result.threats} />
              )}

              {result.threats.length === 0 && (
                <div className="flex flex-col items-center py-8 text-ink-faint">
                  <ShieldCheck size={28} className="text-sev-low mb-2 opacity-70" />
                  <p className="text-sm">No threats detected</p>
                </div>
              )}
            </div>
          )}

          {/* SSE live feed */}
          <div className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className={cn(
                  'live-dot',
                  status !== 'connected' && 'bg-ink-faint after:bg-ink-faint',
                )} />
                <h2 className="text-sm font-semibold text-ink">Live Threat Stream</h2>
                {totalSeen > 0 && (
                  <span className="badge bg-accent-ghost text-accent border border-accent/20">
                    {totalSeen} total
                  </span>
                )}
              </div>
              {threats.length > 0 && (
                <button onClick={clearThreats} className="btn-ghost text-xs">
                  <Trash2 size={11} /> Clear
                </button>
              )}
            </div>

            {status === 'connecting' && (
              <div className="flex items-center gap-2 text-sm text-ink-muted py-4">
                <Loader2 size={14} className="animate-spin" /> Connecting to event stream…
              </div>
            )}

            <ThreatFeed threats={threats} maxItems={30} />
          </div>
        </div>
      </div>
    </div>
  );
}
