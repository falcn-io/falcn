import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { registryEmoji } from '@/lib/utils';
import type { EcosystemStat } from '@/types';

const COLORS = ['#6366f1', '#14b8a6', '#f59e0b', '#f43f5e', '#22c55e', '#38bdf8'];

interface Props { data: EcosystemStat[]; }

export function EcosystemChart({ data }: Props) {
  const chartData = data.map(d => ({
    name:    d.ecosystem,
    threats: d.threats,
    scans:   d.count,
  }));

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={chartData} barSize={28} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <XAxis
          dataKey="name"
          tickLine={false}
          axisLine={false}
          tick={{ fontSize: 11, fill: '#475569' }}
          tickFormatter={v => `${registryEmoji[v.toLowerCase()] ?? ''} ${v}`}
        />
        <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 10, fill: '#475569' }} />
        <Tooltip
          cursor={{ fill: 'rgba(99,102,241,0.06)' }}
          contentStyle={{
            background:   '#111827',
            border:       '1px solid #1e2a40',
            borderRadius: '8px',
            fontSize:     '12px',
            color:        '#e2e8f0',
          }}
          labelFormatter={label => `${label} ecosystem`}
        />
        <Bar dataKey="threats" radius={[4, 4, 0, 0]} name="Threats">
          {chartData.map((_, i) => (
            <Cell key={i} fill={COLORS[i % COLORS.length]} fillOpacity={0.85} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
