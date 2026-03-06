import { riskLabel } from '@/lib/utils';

interface Props { score: number; size?: number; }

export function RiskGauge({ score, size = 100 }: Props) {
  const r     = (size - 12) / 2;
  const cx    = size / 2;
  const cy    = size / 2;
  const circ  = 2 * Math.PI * r;
  // Arc spans 270° (from 135° to 405° = 135° to 45°)
  const arc   = circ * 0.75;
  const fill  = arc * Math.min(1, Math.max(0, score));
  const offset = circ * 0.25; // Start at 135°

  const scoreColor =
    score >= 0.8 ? '#f43f5e' :
    score >= 0.6 ? '#f97316' :
    score >= 0.4 ? '#f59e0b' :
                   '#22c55e';

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-[135deg]">
        {/* Track */}
        <circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke="#1e2a40"
          strokeWidth={8}
          strokeDasharray={`${arc} ${circ - arc}`}
          strokeDashoffset={-offset}
          strokeLinecap="round"
        />
        {/* Fill */}
        <circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={scoreColor}
          strokeWidth={8}
          strokeDasharray={`${fill} ${circ - fill}`}
          strokeDashoffset={-offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.6s ease, stroke 0.4s ease' }}
          filter={`drop-shadow(0 0 6px ${scoreColor}88)`}
        />
      </svg>
      {/* Center text */}
      <div className="absolute flex flex-col items-center leading-tight">
        <span className="text-xl font-bold tabular-nums" style={{ color: scoreColor }}>
          {Math.round(score * 100)}
        </span>
        <span className="text-2xs text-ink-faint uppercase tracking-wider">
          {riskLabel(score)}
        </span>
      </div>
    </div>
  );
}
