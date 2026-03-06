/**
 * hoverProvider.ts — HoverProvider for package manifest files
 *
 * When the user hovers over a package name in a supported manifest file,
 * this provider shows a rich Markdown card with:
 *   - Risk score (with a visual bar)
 *   - Detected threat types
 *   - LLM explanation (if available)
 *   - Safe version suggestion
 *   - Link to Falcn dashboard
 */

import * as vscode from 'vscode';
import { parseManifest, PackageEntry, detectRegistry } from './manifestParser';
import { getResultForPackage, resultCache } from './diagnostics';
import { analyzePackage, AnalyzeResult } from './api';
import { outputChannel } from './extension';

// ---------------------------------------------------------------------------
// Cache for on-demand hover analysis (packages not yet in the diagnostics cache)
// ---------------------------------------------------------------------------

const hoverAnalysisCache = new Map<
  string,
  { result: AnalyzeResult; timestamp: number }
>();

const HOVER_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ---------------------------------------------------------------------------
// HoverProvider
// ---------------------------------------------------------------------------

export class FalcnHoverProvider implements vscode.HoverProvider {
  async provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    token: vscode.CancellationToken
  ): Promise<vscode.Hover | null> {
    const cfg = vscode.workspace.getConfiguration('falcn');
    if (!cfg.get<boolean>('enableHoverProvider', true)) {
      return null;
    }

    const registry = detectRegistry(document);
    if (!registry) {
      return null;
    }

    // Find which package entry the cursor is over
    const entries = parseManifest(document);
    const entry = findEntryAtPosition(entries, position);
    if (!entry) {
      return null;
    }

    // Try diagnostics cache first
    let result = getResultForPackage(entry.registry, entry.name);

    // Then hover-specific cache
    if (!result) {
      const cacheKey = `${entry.registry}:${entry.name}`;
      const cached = hoverAnalysisCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < HOVER_CACHE_TTL_MS) {
        result = cached.result;
      }
    }

    // On-demand fetch if not cached
    if (!result) {
      const fetched = await fetchOnDemand(entry, token);
      result = fetched ?? undefined;
    }

    if (token.isCancellationRequested) {
      return null;
    }

    const range = new vscode.Range(
      entry.line, entry.nameStart,
      entry.line, entry.nameEnd
    );

    if (!result) {
      // Return a lightweight "unknown" hover
      const md = new vscode.MarkdownString(
        `**$(shield) Falcn Security**\n\n` +
        `Package: \`${entry.name}@${entry.version}\`\n\n` +
        `_Scan in progress or API unavailable. Run **Falcn: Scan Project** to analyze._`
      );
      md.isTrusted = true;
      md.supportThemeIcons = true;
      return new vscode.Hover(md, range);
    }

    return new vscode.Hover(buildHoverMarkdown(result, entry), range);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findEntryAtPosition(
  entries: PackageEntry[],
  position: vscode.Position
): PackageEntry | null {
  for (const entry of entries) {
    if (entry.line !== position.line) {
      continue;
    }
    if (position.character >= entry.nameStart && position.character <= entry.nameEnd) {
      return entry;
    }
  }
  return null;
}

async function fetchOnDemand(
  entry: PackageEntry,
  token: vscode.CancellationToken
): Promise<AnalyzeResult | null> {
  outputChannel.appendLine(
    `[Hover] On-demand analysis: ${entry.registry}:${entry.name}@${entry.version}`
  );

  const result = await analyzePackage(
    { package_name: entry.name, version: entry.version, registry: entry.registry },
    token
  );

  if (result) {
    const cacheKey = `${entry.registry}:${entry.name}`;
    hoverAnalysisCache.set(cacheKey, { result, timestamp: Date.now() });
    // Also populate the main cache
    resultCache.set(cacheKey, result);
  }

  return result;
}

function buildHoverMarkdown(result: AnalyzeResult, entry: PackageEntry): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = true;
  md.supportThemeIcons = true;
  md.supportHtml = false;

  // Header
  const riskIcon = riskScoreIcon(result.risk_score);
  md.appendMarkdown(`## ${riskIcon} Falcn Security — \`${entry.name}\`\n\n`);

  // Registry badge
  md.appendMarkdown(
    `**Registry:** ${registryLabel(entry.registry)} | ` +
    `**Version:** \`${result.version || entry.version}\`\n\n`
  );

  // Risk score bar
  const scorePercent = Math.round(result.risk_score * 100);
  const bar = buildRiskBar(result.risk_score);
  const severityLabel = getSeverityLabel(result.risk_score);
  md.appendMarkdown(
    `**Risk Score:** ${bar} **${scorePercent}%** — ${severityLabel}\n\n`
  );

  // Malicious flag
  if (result.is_malicious) {
    md.appendMarkdown(`> $(error) **This package has been flagged as malicious.**\n\n`);
  }

  // Threat breakdown
  if (result.threats && result.threats.length > 0) {
    md.appendMarkdown(`**Detected Threats:**\n\n`);
    for (const threat of result.threats.slice(0, 5)) {
      const icon = severityIcon(threat.severity);
      const confidence = Math.round(threat.confidence * 100);
      md.appendMarkdown(
        `- ${icon} **${threat.type}** ` +
        `(confidence: ${confidence}%): ${truncate(threat.description, 120)}\n`
      );
    }
    md.appendMarkdown('\n');
  } else {
    md.appendMarkdown(`$(check) No threats detected above threshold.\n\n`);
  }

  // Safe version
  if (result.safe_version) {
    md.appendMarkdown(
      `**$(arrow-up) Recommended Safe Version:** \`${result.safe_version}\`\n\n`
    );
  }

  // LLM explanation
  if (result.explanation) {
    md.appendMarkdown(`**Analysis:**\n\n${truncate(result.explanation, 400)}\n\n`);
  }

  // Scan metadata
  md.appendMarkdown(`---\n`);
  md.appendMarkdown(
    `_Scanned in ${result.scan_duration_ms}ms${result.cached ? ' (cached)' : ''} · ` +
    `[View on Falcn Dashboard](https://falcn.io/packages/${entry.registry}/${entry.name})_\n`
  );

  return md;
}

// ---------------------------------------------------------------------------
// Visual helpers
// ---------------------------------------------------------------------------

function riskScoreIcon(score: number): string {
  if (score >= 0.9) return '$(error)';
  if (score >= 0.7) return '$(warning)';
  if (score >= 0.5) return '$(info)';
  return '$(check)';
}

function buildRiskBar(score: number): string {
  const filled = Math.round(score * 10);
  const empty = 10 - filled;
  const filledChar = '█';
  const emptyChar = '░';
  return '`' + filledChar.repeat(filled) + emptyChar.repeat(empty) + '`';
}

function getSeverityLabel(score: number): string {
  if (score >= 0.9) return '🔴 CRITICAL';
  if (score >= 0.7) return '🟠 HIGH';
  if (score >= 0.5) return '🟡 MEDIUM';
  if (score >= 0.3) return '🔵 LOW';
  return '🟢 SAFE';
}

function severityIcon(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL': return '$(error)';
    case 'HIGH': return '$(warning)';
    case 'MEDIUM': return '$(info)';
    default: return '$(dash)';
  }
}

function registryLabel(registry: string): string {
  const labels: Record<string, string> = {
    npm: 'npm',
    go: 'Go Modules',
    pypi: 'PyPI',
    cargo: 'Cargo (Rust)',
    composer: 'Composer (PHP)',
    rubygems: 'RubyGems',
    maven: 'Maven',
    nuget: 'NuGet',
  };
  return labels[registry] || registry;
}

function truncate(str: string, max: number): string {
  if (str.length <= max) {
    return str;
  }
  return str.slice(0, max - 1) + '…';
}
