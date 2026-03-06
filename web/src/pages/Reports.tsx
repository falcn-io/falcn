import { useState } from 'react';
import { FileText, Download, Loader2, CheckCircle, AlertCircle, ExternalLink } from 'lucide-react';
import { TopBar }          from '@/components/TopBar';
import { generateReport }  from '@/lib/api';
import { cn }              from '@/lib/utils';

type ReportType = 'technical' | 'executive' | 'compliance';
type Format     = 'json' | 'sarif' | 'cyclonedx' | 'spdx';

const REPORT_TYPES: { id: ReportType; label: string; desc: string; icon: string }[] = [
  { id: 'technical',  label: 'Technical Report',  icon: '🔬', desc: 'Full threat details, confidence scores, package provenance, remediation steps.' },
  { id: 'executive',  label: 'Executive Summary',  icon: '📊', desc: 'High-level risk overview for stakeholders — counts, trend, top exposures.' },
  { id: 'compliance', label: 'Compliance Report',  icon: '✅', desc: 'Regulatory alignment — SOC 2, NIST SSDF, FedRAMP, PCI-DSS.' },
];

const FORMATS: { id: Format; label: string; ext: string; desc: string; color: string }[] = [
  { id: 'json',      label: 'JSON',      ext: '.json',      desc: 'Raw data export', color: 'text-teal' },
  { id: 'sarif',     label: 'SARIF',     ext: '.sarif',     desc: 'GitHub Security tab', color: 'text-accent' },
  { id: 'cyclonedx', label: 'CycloneDX', ext: '.cdx.json',  desc: 'OWASP SBOM standard', color: 'text-sev-medium' },
  { id: 'spdx',      label: 'SPDX',      ext: '.spdx.json', desc: 'Linux Foundation SBOM', color: 'text-sev-low' },
];

type State = 'idle' | 'generating' | 'done' | 'error';

// Helper: trigger a browser file download from a Blob.
function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function Reports() {
  const [reportType,    setReportType]    = useState<ReportType>('technical');
  const [format,        setFormat]        = useState<Format>('json');
  const [state,         setState]         = useState<State>('idle');
  const [errorMsg,      setErrorMsg]      = useState('');
  const [lastFilename,  setLastFilename]  = useState('');

  const generate = async () => {
    setState('generating');
    setErrorMsg('');
    setLastFilename('');
    try {
      const { blob, filename } = await generateReport(reportType, format);
      setLastFilename(filename);
      downloadBlob(blob, filename);
      setState('done');
      setTimeout(() => setState('idle'), 6000);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Generation failed');
      setState('error');
      setTimeout(() => setState('idle'), 8000);
    }
  };

  const selectedFmt = FORMATS.find(f => f.id === format)!;

  return (
    <div className="animate-fade-in">
      <TopBar title="Reports" subtitle="Generate and download security reports" />

      <div className="p-6 grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* ── Left: generator ── */}
        <div className="xl:col-span-1 space-y-4">
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-ink mb-4 flex items-center gap-2">
              <FileText size={14} className="text-accent" /> Generate Report
            </h2>

            {/* Report type */}
            <div className="mb-4">
              <p className="text-xs font-medium text-ink-muted mb-2">Report Type</p>
              <div className="space-y-2">
                {REPORT_TYPES.map(rt => (
                  <button
                    key={rt.id}
                    onClick={() => setReportType(rt.id)}
                    className={cn(
                      'w-full text-left p-3 rounded-lg border transition-all duration-150',
                      reportType === rt.id
                        ? 'border-accent/50 bg-accent-ghost'
                        : 'border-border hover:border-border-bright bg-surface-1',
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <span>{rt.icon}</span>
                      <span className={cn('text-sm font-medium', reportType === rt.id ? 'text-accent' : 'text-ink')}>
                        {rt.label}
                      </span>
                    </div>
                    <p className="text-xs text-ink-faint mt-0.5 ml-6">{rt.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Format */}
            <div className="mb-5">
              <p className="text-xs font-medium text-ink-muted mb-2">Output Format</p>
              <div className="grid grid-cols-2 gap-1.5">
                {FORMATS.map(f => (
                  <button
                    key={f.id}
                    onClick={() => setFormat(f.id)}
                    className={cn(
                      'text-left px-3 py-2 rounded-lg border text-xs transition-all duration-150',
                      format === f.id
                        ? 'border-accent/50 bg-accent-ghost text-accent'
                        : 'border-border hover:border-border-bright text-ink-muted',
                    )}
                  >
                    <div className={cn('font-semibold', format === f.id ? 'text-accent' : f.color)}>{f.label}</div>
                    <div className="text-ink-faint mt-0.5">{f.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Generate button */}
            <button
              onClick={generate}
              disabled={state === 'generating'}
              className={cn(
                'btn-primary w-full justify-center py-2.5',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
            >
              {state === 'generating' ? (
                <><Loader2 size={14} className="animate-spin" /> Generating…</>
              ) : state === 'done' ? (
                <><CheckCircle size={14} /> Downloaded!</>
              ) : (
                <><Download size={14} /> Generate &amp; Download</>
              )}
            </button>

            {/* Status feedback */}
            {state === 'done' && (
              <div className="mt-3 flex items-start gap-2 text-xs text-sev-low bg-sev-low-bg
                              rounded-lg px-3 py-2.5 border border-sev-low/20 animate-fade-in">
                <CheckCircle size={12} className="mt-0.5 flex-shrink-0" />
                <div>
                  <div className="font-medium">Download started</div>
                  <div className="text-ink-faint mono mt-0.5">{lastFilename}</div>
                </div>
              </div>
            )}
            {state === 'error' && (
              <div className="mt-3 flex items-start gap-2 text-xs text-sev-critical bg-sev-critical-bg
                              rounded-lg px-3 py-2.5 border border-sev-critical/20 animate-fade-in">
                <AlertCircle size={12} className="mt-0.5 flex-shrink-0" />
                <div>
                  <div className="font-medium">Generation failed</div>
                  <div className="text-ink-faint mt-0.5">{errorMsg}</div>
                </div>
              </div>
            )}
          </div>

          {/* What you'll get */}
          <div className="card p-4 space-y-2">
            <p className="text-xs font-semibold text-ink-muted uppercase tracking-wide">
              {selectedFmt.label}{selectedFmt.ext} contains
            </p>
            {format === 'sarif' && (
              <ul className="space-y-1 text-xs text-ink-muted">
                <li>• SARIF 2.1.0 schema — imports into GitHub Security tab</li>
                <li>• One result per detected threat with ruleId, level, message</li>
                <li>• PhysicalLocation using <code className="mono">pkg:npm/…</code> PURLs</li>
                <li>• Severity mapped to SARIF levels (error / warning / note)</li>
              </ul>
            )}
            {format === 'cyclonedx' && (
              <ul className="space-y-1 text-xs text-ink-muted">
                <li>• CycloneDX 1.5 BOM — compatible with Dependency-Track</li>
                <li>• Components list with PURLs for each flagged package</li>
                <li>• Vulnerability entries with severity ratings</li>
                <li>• Tool metadata referencing Falcn v3.0.0</li>
              </ul>
            )}
            {format === 'spdx' && (
              <ul className="space-y-1 text-xs text-ink-muted">
                <li>• SPDX 2.3 — Linux Foundation SBOM format</li>
                <li>• Package entries with threat annotations in comments</li>
                <li>• DESCRIBES relationships to document root</li>
                <li>• Compatible with FOSSA, Snyk, OSS Review Toolkit</li>
              </ul>
            )}
            {format === 'json' && (
              <ul className="space-y-1 text-xs text-ink-muted">
                <li>• Full threat list with confidence scores</li>
                <li>• Severity breakdown summary (critical/high/medium/low)</li>
                <li>• Threat type distribution</li>
                <li>• Average confidence and report metadata</li>
              </ul>
            )}
          </div>
        </div>

        {/* ── Right: format cards + integration guide ── */}
        <div className="xl:col-span-2 space-y-4">
          {/* Format overview */}
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-ink mb-4">Export Formats</h2>
            <div className="grid grid-cols-2 gap-3">
              {[
                { fmt: 'SARIF 2.1', icon: '🐙', color: 'text-accent',
                  desc: 'Imports directly into GitHub Security tab, VS Code Problems panel, and CI gates.',
                  link: 'https://docs.github.com/en/code-security/code-scanning' },
                { fmt: 'CycloneDX 1.5', icon: '🔄', color: 'text-sev-medium',
                  desc: 'OWASP SBOM standard — compatible with Dependency-Track and DependencyHub.',
                  link: 'https://cyclonedx.org' },
                { fmt: 'SPDX 2.3', icon: '📜', color: 'text-sev-low',
                  desc: 'Linux Foundation SBOM for license compliance, FOSSA, OSS Review Toolkit.',
                  link: 'https://spdx.dev' },
                { fmt: 'JSON', icon: '📋', color: 'text-teal',
                  desc: 'Structured raw data for custom pipelines, dashboards, and audit trails.',
                  link: '#' },
              ].map(({ fmt, icon, color, desc, link }) => (
                <div key={fmt} className="p-3.5 rounded-lg bg-surface-1 border border-border space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span>{icon}</span>
                      <span className={cn('text-xs font-semibold', color)}>{fmt}</span>
                    </div>
                    {link !== '#' && (
                      <a href={link} target="_blank" rel="noopener noreferrer"
                         className="text-ink-faint hover:text-accent transition-colors">
                        <ExternalLink size={11} />
                      </a>
                    )}
                  </div>
                  <p className="text-xs text-ink-faint">{desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* How threat detection works */}
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-ink mb-4">How Threat Detection Works</h2>
            <div className="space-y-3">
              {[
                { step: '1', title: 'Package ingestion', color: 'bg-accent',
                  desc: 'Each package name, registry, and version is normalized and fed into the detection pipeline.' },
                { step: '2', title: 'Typosquatting detection', color: 'bg-teal',
                  desc: 'Jaro-Winkler + keyboard-distance similarity is computed against a curated list of 50 k+ popular packages. Scores ≥ 0.75 flag a candidate; scores ≥ 0.80 are confirmed typosquats.' },
                { step: '3', title: 'Behavioural analysis', color: 'bg-sev-medium',
                  desc: 'Install scripts, postinstall hooks, and binary references are scanned for obfuscated shells, crypto-miners, network beacons, and clipboard hijackers.' },
                { step: '4', title: 'Dependency confusion', color: 'bg-sev-high',
                  desc: 'Version numbers ≥ 9000 and package names matching internal namespace patterns (e.g. acme-, corp-, internal-) are flagged as potential confusion attacks.' },
                { step: '5', title: 'Secret / CVE detection', color: 'bg-sev-critical',
                  desc: 'Source files are scanned for credential patterns (AWS, GH tokens, private keys). CVE databases (OSV + NVD + GitHub Advisory) are queried for known vulnerabilities.' },
                { step: '6', title: 'ML scoring', color: 'bg-accent',
                  desc: 'A 25-feature ensemble model (RandomForest + GradientBoosting) computes a final risk score 0–1. Confidence ≥ 0.75 is surfaced as a threat.' },
              ].map(({ step, title, color, desc }) => (
                <div key={step} className="flex gap-3">
                  <div className={cn('w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5', color)}>
                    <span className="text-2xs font-bold text-white">{step}</span>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-ink">{title}</p>
                    <p className="text-xs text-ink-faint mt-0.5">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
