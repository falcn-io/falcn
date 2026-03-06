import { useState, useEffect } from 'react';
import {
  ShieldAlert, Package, Scan,
  AlertTriangle, RefreshCw, Zap
} from 'lucide-react';
import { TopBar }          from '@/components/TopBar';
import { StatCard }        from '@/components/StatCard';
import { ThreatFeed }      from '@/components/ThreatFeed';
import { EcosystemChart }  from '@/components/EcosystemChart';
import { ThreatTimeline }  from '@/components/ThreatTimeline';
import { SeverityBadge }   from '@/components/SeverityBadge';
import { getDashboardMetrics, MOCK } from '@/lib/api';
import { fmtNumber, fmtPercent }     from '@/lib/utils';
import type { DashboardMetrics }     from '@/types';

export function Dashboard() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await getDashboardMetrics();
      setMetrics(data);
    } catch {
      // API not available — use mock data for demo
      setMetrics(MOCK);
    } finally {
      setLoading(false);
      setLastUpdated(new Date());
    }
  };

  useEffect(() => { load(); }, []);

  const m = metrics ?? MOCK;

  return (
    <div className="animate-fade-in">
      <TopBar
        title="Dashboard"
        subtitle={lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Loading…'}
        actions={
          <button onClick={load} className="btn-ghost" disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />

      <div className="p-6 space-y-6">
        {/* ── Stat cards ── */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
          <StatCard
            label="Total Scans"
            value={m.total_scans}
            icon={<Scan size={18} className="text-accent" />}
            iconBg="bg-accent-ghost"
            trend={8}
            loading={loading}
            sub={`${m.scans_today} today`}
          />
          <StatCard
            label="Packages Analyzed"
            value={m.total_packages}
            icon={<Package size={18} className="text-teal" />}
            iconBg="bg-teal-dim"
            loading={loading}
          />
          <StatCard
            label="Threats Detected"
            value={m.total_threats}
            icon={<ShieldAlert size={18} className="text-sev-high" />}
            iconBg="bg-sev-high-bg"
            trend={-12}
            loading={loading}
            sub={`${m.threats_today} today`}
          />
          <StatCard
            label="Critical Threats"
            value={m.critical_threats}
            icon={<AlertTriangle size={18} className="text-sev-critical" />}
            iconBg="bg-sev-critical-bg"
            danger
            loading={loading}
          />
        </div>

        {/* ── Second row: timeline + ecosystems ── */}
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
          {/* Timeline — wider */}
          <div className="card p-5 xl:col-span-3">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-ink">Threat Trend</h2>
                <p className="text-xs text-ink-faint">Last 14 days</p>
              </div>
              <div className="flex items-center gap-4 text-xs text-ink-faint">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-0.5 rounded bg-accent inline-block" /> Threats
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-0.5 rounded bg-teal inline-block" /> Scans
                </span>
              </div>
            </div>
            {loading ? (
              <div className="h-40 rounded-lg bg-surface-3 animate-pulse" />
            ) : (
              <ThreatTimeline data={m.threat_trend} />
            )}
          </div>

          {/* Ecosystems — narrower */}
          <div className="card p-5 xl:col-span-2">
            <div className="mb-4">
              <h2 className="text-sm font-semibold text-ink">Threats by Ecosystem</h2>
              <p className="text-xs text-ink-faint">All time</p>
            </div>
            {loading ? (
              <div className="h-40 rounded-lg bg-surface-3 animate-pulse" />
            ) : (
              <EcosystemChart data={m.top_ecosystems} />
            )}
          </div>
        </div>

        {/* ── Third row: threat feed + severity breakdown ── */}
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
          {/* Live feed */}
          <div className="card p-5 xl:col-span-3">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Zap size={14} className="text-accent" />
                <h2 className="text-sm font-semibold text-ink">Recent Threats</h2>
              </div>
              <a href="/threats" className="text-xs text-accent hover:text-accent-hover transition-colors">
                View all →
              </a>
            </div>
            <ThreatFeed threats={m.recent_threats} maxItems={5} />
          </div>

          {/* Severity breakdown */}
          <div className="card p-5 xl:col-span-2">
            <h2 className="text-sm font-semibold text-ink mb-4">Severity Breakdown</h2>
            <div className="space-y-3">
              {[
                { sev: 'critical' as const, count: m.critical_threats },
                { sev: 'high'     as const, count: m.high_threats     },
                { sev: 'medium'   as const, count: m.medium_threats   },
                { sev: 'low'      as const, count: m.low_threats      },
              ].map(({ sev, count }) => {
                const pct = m.total_threats > 0 ? count / m.total_threats : 0;
                return (
                  <div key={sev}>
                    <div className="flex items-center justify-between mb-1">
                      <SeverityBadge severity={sev} size="sm" />
                      <span className="text-xs text-ink-muted tabular-nums">
                        {fmtNumber(count)} <span className="text-ink-faint">({fmtPercent(pct)})</span>
                      </span>
                    </div>
                    <div className="h-1.5 rounded-full bg-surface-3 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{
                          width: `${pct * 100}%`,
                          background: sev === 'critical' ? '#f43f5e' :
                                      sev === 'high'     ? '#f97316' :
                                      sev === 'medium'   ? '#f59e0b' : '#22c55e',
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Avg risk score */}
            <div className="mt-5 pt-4 border-t border-border">
              <div className="flex items-center justify-between">
                <span className="text-xs text-ink-muted">Avg. Risk Score</span>
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-16 rounded-full bg-surface-3 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-accent transition-all duration-700"
                      style={{ width: `${m.avg_risk_score * 100}%` }}
                    />
                  </div>
                  <span className="text-sm font-semibold text-ink tabular-nums">
                    {(m.avg_risk_score * 100).toFixed(0)}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
