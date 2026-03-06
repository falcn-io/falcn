import { type ReactNode } from 'react';
import { cn, fmtNumber } from '@/lib/utils';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface Props {
  label:    string;
  value:    number | string;
  icon:     ReactNode;
  iconBg?:  string;
  trend?:   number;          // percent change; positive = up, negative = down
  suffix?:  string;
  danger?:  boolean;
  loading?: boolean;
  sub?:     string;
}

export function StatCard({ label, value, icon, iconBg, trend, suffix, danger, loading, sub }: Props) {
  const formatted = typeof value === 'number' ? fmtNumber(value) : value;

  return (
    <div className={cn(
      'card p-5 flex flex-col gap-3 relative overflow-hidden transition-all duration-200',
      'hover:shadow-card-hover hover:border-border-bright',
      danger && 'border-sev-critical/20',
    )}>
      {/* Background glow for danger cards */}
      {danger && (
        <div className="absolute inset-0 bg-gradient-radial from-sev-critical-bg to-transparent opacity-40 pointer-events-none" />
      )}

      <div className="flex items-start justify-between relative">
        <div className={cn(
          'w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0',
          iconBg ?? 'bg-accent-ghost',
        )}>
          {icon}
        </div>

        {trend !== undefined && (
          <div className={cn(
            'flex items-center gap-1 text-xs font-medium',
            trend > 0  ? 'text-sev-critical' :
            trend < 0  ? 'text-sev-low'      :
            'text-ink-faint',
          )}>
            {trend > 0  ? <TrendingUp  size={12} /> :
             trend < 0  ? <TrendingDown size={12} /> :
             <Minus size={12} />}
            {trend !== 0 && `${Math.abs(trend).toFixed(0)}%`}
          </div>
        )}
      </div>

      <div className="relative">
        {loading ? (
          <div className="h-8 w-24 rounded bg-surface-3 animate-pulse" />
        ) : (
          <div className="flex items-baseline gap-1">
            <span className={cn('stat-value', danger && 'text-sev-critical')}>
              {formatted}
            </span>
            {suffix && <span className="text-sm text-ink-muted">{suffix}</span>}
          </div>
        )}
        <p className="text-sm text-ink-muted mt-0.5">{label}</p>
        {sub && <p className="text-xs text-ink-faint mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}
