import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Shield, AlertTriangle, Zap, Lock, GitBranch, Bug,
  ChevronDown, ChevronUp, Sparkles, Loader2,
} from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';
import { fmtRelTime, threatTypeLabel, registryEmoji } from '@/lib/utils';
import type { Threat, ThreatExplanation } from '@/types';

const THREAT_ICONS: Record<string, React.ElementType> = {
  typosquatting:        AlertTriangle,
  malicious_code:       Zap,
  cve:                  Bug,
  secret_leak:          Lock,
  dependency_confusion: GitBranch,
  default:              Shield,
};

interface Props {
  threats:   Threat[];
  maxItems?: number;
  compact?:  boolean;
}

export function ThreatFeed({ threats, maxItems = 20, compact = false }: Props) {
  const visible = threats.slice(0, maxItems);

  if (visible.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-ink-faint">
        <Shield size={32} className="mb-3 opacity-30" />
        <p className="text-sm">No threats detected</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <AnimatePresence initial={false}>
        {visible.map((t) => (
          <ThreatRow key={t.id} threat={t} compact={compact} />
        ))}
      </AnimatePresence>
    </div>
  );
}

// ─── Individual row ───────────────────────────────────────────────────────────

function ThreatRow({ threat, compact }: { threat: Threat; compact: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = THREAT_ICONS[threat.type] ?? THREAT_ICONS.default;
  const registry = (threat.registry ?? '').toLowerCase();
  const hasExplanation = !!threat.explanation;
  // Show a "pending" spinner only when the threat was detected very recently
  // (within the last 60 s) and no explanation has arrived yet. This avoids a
  // permanent spinner when no LLM provider is configured.
  const isRecent = !threat.detected_at ||
    (Date.now() - new Date(threat.detected_at).getTime()) < 60_000;
  const pendingExplanation = !hasExplanation && !compact && isRecent;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: -8, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, scale: 0.96 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      className="threat-row group flex-col !items-start gap-2"
    >
      {/* ── Top row ─────────────────────────────────────────────────────── */}
      <div className="flex w-full items-start gap-3">
        {/* Icon */}
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-surface-2 flex items-center justify-center border border-border/50">
          <Icon size={14} className="text-ink-muted group-hover:text-ink transition-colors" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm text-ink truncate mono">
              {registryEmoji[registry] ?? '📦'} {threat.package}
            </span>
            <SeverityBadge severity={threat.severity} size="sm" />
            <span className="text-2xs text-ink-faint">
              {threatTypeLabel[threat.type] ?? threat.type}
            </span>
          </div>

          {!compact && (
            <p className="text-xs text-ink-muted mt-0.5 line-clamp-2">
              {threat.description}
            </p>
          )}

          {threat.similar_to && (
            <p className="text-2xs text-ink-faint mt-0.5">
              Similar to <span className="mono text-accent">{threat.similar_to}</span>
            </p>
          )}

          {threat.cve_id && (
            <p className="text-2xs text-sev-high mt-0.5 font-mono">
              {threat.cve_id}
              {threat.cvss_score !== undefined && ` · CVSS ${threat.cvss_score.toFixed(1)}`}
            </p>
          )}
        </div>

        {/* Right side: time + AI toggle */}
        <div className="flex-shrink-0 flex flex-col items-end gap-1.5 self-start">
          <span className="text-2xs text-ink-faint whitespace-nowrap">
            {fmtRelTime(threat.detected_at)}
          </span>

          {!compact && (
            <ExplanationToggle
              hasExplanation={hasExplanation}
              pending={pendingExplanation}
              expanded={expanded}
              onToggle={() => hasExplanation && setExpanded(v => !v)}
            />
          )}
        </div>
      </div>

      {/* ── Explanation panel ────────────────────────────────────────────── */}
      {!compact && (
        <AnimatePresence initial={false}>
          {expanded && hasExplanation && (
            <motion.div
              key="explanation"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.22, ease: 'easeInOut' }}
              className="overflow-hidden w-full"
            >
              <ExplanationPanel explanation={threat.explanation!} />
            </motion.div>
          )}
        </AnimatePresence>
      )}
    </motion.div>
  );
}

// ─── AI toggle button ─────────────────────────────────────────────────────────

function ExplanationToggle({
  hasExplanation,
  pending,
  expanded,
  onToggle,
}: {
  hasExplanation: boolean;
  pending: boolean;
  expanded: boolean;
  onToggle: () => void;
}) {
  if (pending) {
    return (
      <div className="flex items-center gap-1 text-2xs text-ink-faint px-1.5 py-0.5 rounded border border-border/40 bg-surface-2/60">
        <Loader2 size={10} className="animate-spin opacity-60" />
        <span>AI</span>
      </div>
    );
  }

  if (!hasExplanation) return null;

  return (
    <button
      onClick={onToggle}
      className="flex items-center gap-1 text-2xs px-1.5 py-0.5 rounded border
                 border-accent/40 bg-accent/10 text-accent hover:bg-accent/20
                 transition-colors cursor-pointer"
      title={expanded ? 'Hide AI explanation' : 'Show AI explanation'}
    >
      <Sparkles size={10} />
      <span>AI</span>
      {expanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
    </button>
  );
}

// ─── Expanded explanation panel ───────────────────────────────────────────────

// Fully-spelled-out class names so Tailwind JIT includes them all.
const SECTION_LABEL_CLASSES: Record<string, string> = {
  What:   'text-accent',
  Why:    'text-sev-high',
  Impact: 'text-sev-critical',
  Fix:    'text-sev-low',
};

function ExplanationPanel({ explanation }: { explanation: ThreatExplanation }) {
  return (
    <div className="ml-11 mt-1 rounded-lg border border-border/60 bg-surface-2/80 overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border/40 bg-surface-2">
        <Sparkles size={12} className="text-accent" />
        <span className="text-2xs font-medium text-accent">AI Explanation</span>
        {explanation.generated_by && (
          <span className="ml-auto text-2xs text-ink-faint mono">
            {explanation.generated_by}
          </span>
        )}
        {explanation.cache_hit && (
          <span className="text-2xs text-ink-faint px-1.5 py-0.5 rounded bg-surface-3 border border-border/40">
            cached
          </span>
        )}
      </div>

      {/* Four sections in a 2-column grid on sm+ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-border/30">
        <ExplSection label="What"   text={explanation.what}        />
        <ExplSection label="Why"    text={explanation.why}         />
        <ExplSection label="Impact" text={explanation.impact}      />
        <ExplSection label="Fix"    text={explanation.remediation} />
      </div>

      {/* Confidence bar */}
      <div className="flex items-center gap-2 px-3 py-2 border-t border-border/40">
        <span className="text-2xs text-ink-faint w-16">Confidence</span>
        <div className="flex-1 h-1.5 rounded-full bg-surface-3 overflow-hidden">
          <div
            className="h-full rounded-full bg-accent transition-all"
            style={{ width: `${Math.round((explanation.confidence ?? 0) * 100)}%` }}
          />
        </div>
        <span className="text-2xs text-ink-faint mono w-8 text-right">
          {Math.round((explanation.confidence ?? 0) * 100)}%
        </span>
      </div>
    </div>
  );
}

function ExplSection({ label, text }: { label: string; text: string }) {
  const labelClass = SECTION_LABEL_CLASSES[label] ?? 'text-ink-muted';
  return (
    <div className="bg-surface-2/40 p-3">
      <div className={`text-2xs font-semibold mb-1 uppercase tracking-wider ${labelClass}`}>
        {label}
      </div>
      <p className="text-xs text-ink-muted leading-relaxed">
        {text}
      </p>
    </div>
  );
}
