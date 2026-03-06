import { useState } from 'react';
import { Settings as SettingsIcon, Key, Shield, Bell, CheckCircle, Eye, EyeOff, Save } from 'lucide-react';
import { TopBar } from '@/components/TopBar';
import { auth, issueToken } from '@/lib/api';
import { cn } from '@/lib/utils';

export function Settings() {
  const [apiKey,   setApiKey]   = useState(auth.getKey());
  const [showKey,  setShowKey]  = useState(false);
  const [saving,   setSaving]   = useState(false);
  const [saved,    setSaved]    = useState(false);
  const [testMsg,  setTestMsg]  = useState<{ ok: boolean; msg: string } | null>(null);

  const saveKey = () => {
    auth.setKey(apiKey);
    setSaving(true);
    setTimeout(() => { setSaving(false); setSaved(true); setTimeout(() => setSaved(false), 3000); }, 600);
  };

  const testConn = async () => {
    setTestMsg(null);
    try {
      const result = await issueToken(apiKey);
      if (result.token) {
        auth.setJWT(result.token);
        setTestMsg({ ok: true, msg: 'Connected — JWT issued successfully.' });
      }
    } catch (e) {
      setTestMsg({ ok: false, msg: e instanceof Error ? e.message : 'Connection failed.' });
    }
  };

  return (
    <div className="animate-fade-in">
      <TopBar title="Settings" subtitle="Configure API connection and preferences" />

      <div className="p-6 max-w-2xl space-y-5">
        {/* API Authentication */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
            <Key size={14} className="text-accent" /> API Authentication
          </h2>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-ink-muted mb-1.5">API Key</label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <input
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    onChange={e => { setApiKey(e.target.value); setSaved(false); }}
                    placeholder="Enter your Falcn API key (32+ chars)"
                    className="input-base pr-10 font-mono text-sm"
                  />
                  <button
                    onClick={() => setShowKey(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-faint hover:text-ink-muted"
                  >
                    {showKey ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
                <button onClick={saveKey} className={cn('btn-primary px-3 gap-1.5', saved && 'bg-sev-low/80 hover:bg-sev-low')}>
                  {saved ? <CheckCircle size={13} /> : saving ? <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" /> : <Save size={13} />}
                  {saved ? 'Saved' : 'Save'}
                </button>
              </div>
              <p className="text-xs text-ink-faint mt-1.5">
                Generate with: <code className="mono bg-surface-1 px-1 rounded">openssl rand -hex 32</code>
              </p>
            </div>

            <button onClick={testConn} className="btn-ghost text-xs">
              <Shield size={12} /> Test Connection
            </button>

            {testMsg && (
              <div className={cn(
                'flex items-center gap-2 text-xs rounded-lg px-3 py-2 border animate-fade-in',
                testMsg.ok
                  ? 'text-sev-low bg-sev-low-bg border-sev-low/20'
                  : 'text-sev-critical bg-sev-critical-bg border-sev-critical/20',
              )}>
                {testMsg.ok ? <CheckCircle size={12} /> : <Shield size={12} />}
                {testMsg.msg}
              </div>
            )}
          </div>
        </div>

        {/* API URL */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
            <SettingsIcon size={14} className="text-teal" /> API Endpoint
          </h2>
          <div>
            <label className="block text-xs font-medium text-ink-muted mb-1.5">Base URL</label>
            <input
              type="url"
              defaultValue={import.meta.env.VITE_API_URL ?? ''}
              className="input-base font-mono text-sm"
              placeholder="(relative — same origin)"
            />
            <p className="text-xs text-ink-faint mt-1.5">
              Override with <code className="mono bg-surface-1 px-1 rounded">VITE_API_URL</code> env variable.
            </p>
          </div>
        </div>

        {/* Alerts */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
            <Bell size={14} className="text-sev-medium" /> Alert Preferences
          </h2>
          <div className="space-y-3">
            {[
              { label: 'Critical threats',  desc: 'Always show immediately', enabled: true  },
              { label: 'High threats',      desc: 'Show in live feed',       enabled: true  },
              { label: 'Medium threats',    desc: 'Batch notifications',     enabled: false },
              { label: 'Low threats',       desc: 'Summary only',            enabled: false },
            ].map(({ label, desc, enabled }) => (
              <div key={label} className="flex items-center justify-between py-2">
                <div>
                  <p className="text-sm text-ink">{label}</p>
                  <p className="text-xs text-ink-faint">{desc}</p>
                </div>
                <button className={cn(
                  'relative w-9 h-5 rounded-full transition-colors duration-200 flex-shrink-0',
                  enabled ? 'bg-accent' : 'bg-surface-4',
                )}>
                  <span className={cn(
                    'absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200',
                    enabled ? 'translate-x-4' : 'translate-x-0.5',
                  )} />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* About */}
        <div className="card p-5 border-accent/10">
          <div className="flex items-start gap-4">
            <div className="relative w-10 h-10 flex-shrink-0">
              <div className="absolute inset-0 rounded-xl bg-accent-gradient rotate-6 opacity-80" />
              <svg viewBox="0 0 40 40" className="relative w-10 h-10">
                <path d="M20 4 L32 14 L26 18 L32 32 L20 24 L8 32 L14 18 L8 14 Z" fill="white" opacity="0.95" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-ink">Falcn v3.0.0</p>
              <p className="text-xs text-ink-faint mt-0.5">Supply Chain Security Platform</p>
              <p className="text-xs text-ink-faint mt-2">
                Protecting 8 ecosystems · ML-powered detection · Air-gap capable
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
