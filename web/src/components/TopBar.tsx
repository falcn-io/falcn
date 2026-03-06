import { Bell, Shield } from 'lucide-react';
import { useSSE } from '@/hooks/useSSE';
import { cn } from '@/lib/utils';

interface Props {
  title:    string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export function TopBar({ title, subtitle, actions }: Props) {
  const { status, totalSeen } = useSSE(0); // share status without accumulating

  const statusLabel: Record<typeof status, string> = {
    connecting:   'Connecting…',
    connected:    'Live',
    disconnected: 'Offline',
    error:        'Reconnecting…',
  };

  return (
    <header className="h-14 border-b border-border bg-surface-1/60 backdrop-blur-sm
                       flex items-center justify-between px-6 sticky top-0 z-10">
      <div>
        <h1 className="text-sm font-semibold text-ink">{title}</h1>
        {subtitle && <p className="text-xs text-ink-faint">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-3">
        {/* SSE status */}
        <div className={cn(
          'flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-2xs font-medium',
          status === 'connected'
            ? 'bg-sev-low-bg border-sev-low/30 text-sev-low'
            : 'bg-surface-3 border-border text-ink-faint',
        )}>
          <span className={cn(
            'w-1.5 h-1.5 rounded-full',
            status === 'connected'    ? 'bg-sev-low animate-pulse-dot' :
            status === 'connecting'   ? 'bg-sev-medium animate-pulse-dot' :
            'bg-ink-faint',
          )} />
          {statusLabel[status]}
        </div>

        {/* Threat badge */}
        {totalSeen > 0 && (
          <div className="relative">
            <Bell size={16} className="text-ink-muted" />
            <span className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-sev-critical
                             text-white text-2xs rounded-full flex items-center justify-center font-bold">
              {totalSeen > 9 ? '9+' : totalSeen}
            </span>
          </div>
        )}

        {/* Custom actions */}
        {actions}

        {/* Falcn shield */}
        <div className="w-7 h-7 rounded-lg bg-accent-ghost border border-accent/20 flex items-center justify-center">
          <Shield size={14} className="text-accent" />
        </div>
      </div>
    </header>
  );
}
