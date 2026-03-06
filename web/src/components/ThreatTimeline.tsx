import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts';
import type { TrendPoint } from '@/types';

interface Props { data: TrendPoint[]; }

export function ThreatTimeline({ data }: Props) {
  return (
    <ResponsiveContainer width="100%" height={160}>
      <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#6366f1" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#6366f1" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="scansGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#14b8a6" stopOpacity={0.25} />
            <stop offset="100%" stopColor="#14b8a6" stopOpacity={0.01} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,42,64,0.6)" />
        <XAxis
          dataKey="date"
          tickLine={false}
          axisLine={false}
          tick={{ fontSize: 10, fill: '#475569' }}
          interval="preserveStartEnd"
        />
        <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 10, fill: '#475569' }} />
        <Tooltip
          contentStyle={{
            background: '#111827', border: '1px solid #1e2a40',
            borderRadius: '8px', fontSize: '12px', color: '#e2e8f0',
          }}
        />
        <Area
          type="monotone" dataKey="scans"
          stroke="#14b8a6" strokeWidth={1.5}
          fill="url(#scansGrad)" name="Scans"
        />
        <Area
          type="monotone" dataKey="threats"
          stroke="#6366f1" strokeWidth={1.5}
          fill="url(#threatsGrad)" name="Threats"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
