import { cn, severityColor } from '@/lib/utils';
import type { Severity } from '@/types';

interface Props {
  severity: Severity;
  size?: 'sm' | 'md';
  dot?: boolean;
}

const LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high:     'High',
  medium:   'Medium',
  low:      'Low',
  none:     'None',
};

export function SeverityBadge({ severity, size = 'md', dot = false }: Props) {
  const c = severityColor(severity);
  return (
    <span className={cn(
      'badge border',
      c.bg, c.text, c.border,
      size === 'sm' ? 'text-2xs px-1.5 py-0' : '',
    )}>
      {dot && (
        <span
          className="inline-block w-1.5 h-1.5 rounded-full flex-shrink-0"
          style={{ backgroundColor: c.dot }}
        />
      )}
      {LABELS[severity]}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const c = severityColor(severity);
  return (
    <span
      className="inline-block w-2 h-2 rounded-full flex-shrink-0"
      style={{ backgroundColor: c.dot }}
      title={LABELS[severity]}
    />
  );
}
