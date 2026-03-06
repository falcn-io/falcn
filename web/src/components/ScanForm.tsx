import { useState } from 'react';
import { Search, Loader2, Package } from 'lucide-react';
import { cn } from '@/lib/utils';

const REGISTRIES = ['npm', 'PyPI', 'go', 'cargo', 'maven', 'rubygems', 'nuget', 'composer'];

interface Props {
  onScan: (pkg: string, registry: string, version: string) => Promise<void>;
  loading?: boolean;
}

export function ScanForm({ onScan, loading }: Props) {
  const [pkg,      setPkg]      = useState('');
  const [registry, setRegistry] = useState('npm');
  const [version,  setVersion]  = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pkg.trim() || loading) return;
    await onScan(pkg.trim(), registry, version.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Package name */}
      <div>
        <label className="block text-xs font-medium text-ink-muted mb-1.5">Package Name</label>
        <div className="relative">
          <Package size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
          <input
            type="text"
            value={pkg}
            onChange={e => setPkg(e.target.value)}
            placeholder="e.g. lodash, requests, serde"
            className="input-base pl-8"
            disabled={loading}
          />
        </div>
      </div>

      {/* Registry + Version row */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-ink-muted mb-1.5">Registry</label>
          <select
            value={registry}
            onChange={e => setRegistry(e.target.value)}
            className="input-base"
            disabled={loading}
          >
            {REGISTRIES.map(r => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-ink-muted mb-1.5">
            Version <span className="text-ink-faint">(optional)</span>
          </label>
          <input
            type="text"
            value={version}
            onChange={e => setVersion(e.target.value)}
            placeholder="latest"
            className="input-base"
            disabled={loading}
          />
        </div>
      </div>

      {/* Submit */}
      <button
        type="submit"
        disabled={!pkg.trim() || loading}
        className={cn(
          'btn-primary w-full justify-center py-2.5',
          'disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100',
        )}
      >
        {loading ? (
          <><Loader2 size={15} className="animate-spin" /> Analyzing…</>
        ) : (
          <><Search size={15} /> Analyze Package</>
        )}
      </button>
    </form>
  );
}
