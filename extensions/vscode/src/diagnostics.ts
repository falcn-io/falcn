/**
 * diagnostics.ts — DiagnosticCollection manager
 *
 * Orchestrates manifest parsing → API calls → VS Code diagnostics.
 * Features:
 *   - Per-document debouncing (configurable, default 1500 ms)
 *   - CancellationToken per document to abort in-flight scans
 *   - Progress notification via status bar
 *   - Caches results for hover / quick-fix providers
 */

import * as vscode from 'vscode';
import { parseManifest, PackageEntry, Registry } from './manifestParser';
import { analyzePackagesBatch, AnalyzeResult, checkApiHealth, scanWithCLI } from './api';
import { statusBar } from './extension';

// ---------------------------------------------------------------------------
// Shared result cache (used by hover and quick-fix providers)
// ---------------------------------------------------------------------------

export const resultCache = new Map<
  string,   // `registry:packageName`
  AnalyzeResult
>();

// ---------------------------------------------------------------------------
// Diagnostic collection singleton (created in extension.ts)
// ---------------------------------------------------------------------------

let diagnosticCollection: vscode.DiagnosticCollection;

export function setDiagnosticCollection(col: vscode.DiagnosticCollection): void {
  diagnosticCollection = col;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

function toVSCodeSeverity(falcnSeverity: string): vscode.DiagnosticSeverity {
  const cfg = vscode.workspace.getConfiguration('falcn');
  const global = cfg.get<string>('severityLevel', 'warning');

  // Per-severity override
  switch (falcnSeverity.toUpperCase()) {
    case 'CRITICAL':
      return vscode.DiagnosticSeverity.Error;
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return global === 'error'
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;
    case 'LOW':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function riskToFalcnSeverity(score: number): string {
  if (score >= 0.9) return 'CRITICAL';
  if (score >= 0.7) return 'HIGH';
  if (score >= 0.5) return 'MEDIUM';
  if (score >= 0.3) return 'LOW';
  return 'INFO';
}

// ---------------------------------------------------------------------------
// Debounce map — one timer per document URI
// ---------------------------------------------------------------------------

const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
const cancellationTokenSources = new Map<string, vscode.CancellationTokenSource>();

export function scheduleScan(document: vscode.TextDocument): void {
  const uri = document.uri.toString();
  const cfg = vscode.workspace.getConfiguration('falcn');
  const delayMs = cfg.get<number>('debounceMs', 1500);

  // Cancel any existing timer for this document
  const existingTimer = debounceTimers.get(uri);
  if (existingTimer) {
    clearTimeout(existingTimer);
  }

  const timer = setTimeout(() => {
    debounceTimers.delete(uri);
    void runScan(document);
  }, delayMs);

  debounceTimers.set(uri, timer);
}

export function cancelScan(uri: string): void {
  const timer = debounceTimers.get(uri);
  if (timer) {
    clearTimeout(timer);
    debounceTimers.delete(uri);
  }

  const cts = cancellationTokenSources.get(uri);
  if (cts) {
    cts.cancel();
    cts.dispose();
    cancellationTokenSources.delete(uri);
  }
}

// ---------------------------------------------------------------------------
// Core scan routine
// ---------------------------------------------------------------------------

export async function runScan(
  document: vscode.TextDocument,
  forceImmediate = false
): Promise<void> {
  const uri = document.uri.toString();

  // Cancel any in-flight scan for this document
  const existing = cancellationTokenSources.get(uri);
  if (existing) {
    existing.cancel();
    existing.dispose();
  }

  const cts = new vscode.CancellationTokenSource();
  cancellationTokenSources.set(uri, cts);

  try {
    await _doScan(document, cts.token, forceImmediate);
  } finally {
    // Only clean up if this CTS is still the current one
    if (cancellationTokenSources.get(uri) === cts) {
      cancellationTokenSources.delete(uri);
      cts.dispose();
    }
  }
}

async function _doScan(
  document: vscode.TextDocument,
  token: vscode.CancellationToken,
  _forceImmediate: boolean
): Promise<void> {
  const uri = document.uri.toString();
  const cfg = vscode.workspace.getConfiguration('falcn');
  const riskThreshold = cfg.get<number>('riskThreshold', 0.5);

  // Parse the manifest
  const entries = parseManifest(document);
  if (entries.length === 0) {
    diagnosticCollection?.set(document.uri, []);
    statusBar.update('idle', 0);
    return;
  }

  statusBar.update('scanning', 0);

  let results: Map<string, AnalyzeResult>;
  const apiOk = await checkApiHealth();

  if (apiOk && !token.isCancellationRequested) {
    // Use the REST API
    const requests = entries.map((e) => ({
      package_name: e.name,
      version: e.version,
      registry: e.registry,
    }));

    results = await analyzePackagesBatch(
      requests,
      token,
      (done, total) => {
        statusBar.update('scanning', 0, `${done}/${total}`);
      }
    );
  } else if (!token.isCancellationRequested) {
    // CLI fallback — run one scan per workspace folder
    results = new Map();
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (workspaceFolder) {
      const cliResult = await scanWithCLI(workspaceFolder.uri.fsPath, token);
      if (cliResult) {
        for (const threat of cliResult.threats) {
          const key = `${threat.registry}:${threat.package}`;
          results.set(key, {
            package_name: threat.package,
            version: threat.version,
            registry: threat.registry as Registry,
            risk_score: threat.risk_score,
            is_malicious: threat.risk_score > riskThreshold,
            threats: [
              {
                type: 'UNKNOWN',
                severity: threat.severity,
                description: threat.description,
                confidence: threat.risk_score,
              },
            ],
            safe_version: threat.safe_version,
            cached: false,
            scan_duration_ms: 0,
          });
        }
      }
    }
  } else {
    return;
  }

  if (token.isCancellationRequested) {
    return;
  }

  // Merge into cache
  for (const [key, result] of results) {
    resultCache.set(key, result);
  }

  // Build diagnostics
  const diagnostics: vscode.Diagnostic[] = [];

  for (const entry of entries) {
    const key = `${entry.registry}:${entry.name}`;
    const result = results.get(key);

    if (!result) {
      continue;
    }

    if (result.risk_score < riskThreshold && !result.is_malicious) {
      continue;
    }

    const severity = riskToFalcnSeverity(result.risk_score);
    const vsSeverity = toVSCodeSeverity(severity);

    // Build diagnostic message
    const scorePercent = Math.round(result.risk_score * 100);
    const threatSummary = result.threats
      .slice(0, 3)
      .map((t) => t.type)
      .join(', ');

    let message = `[Falcn] ${entry.name}@${result.version} — Risk: ${scorePercent}%`;
    if (threatSummary) {
      message += ` (${threatSummary})`;
    }
    if (result.safe_version) {
      message += ` — Safe version: ${result.safe_version}`;
    }

    // Range: highlight the package name
    const range = new vscode.Range(
      entry.line, entry.nameStart,
      entry.line, entry.nameEnd
    );

    const diag = new vscode.Diagnostic(range, message, vsSeverity);
    diag.source = 'Falcn';
    diag.code = {
      value: severity,
      target: vscode.Uri.parse(`https://falcn.io/packages/${entry.registry}/${entry.name}`),
    };

    // Attach related information (individual threats)
    if (result.threats.length > 0) {
      diag.relatedInformation = result.threats.slice(0, 5).map((t) =>
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(document.uri, range),
          `${t.type}: ${t.description} (confidence: ${Math.round(t.confidence * 100)}%)`
        )
      );
    }

    // Attach tags
    diag.tags = result.is_malicious ? [vscode.DiagnosticTag.Deprecated] : undefined;

    diagnostics.push(diag);
  }

  diagnosticCollection?.set(document.uri, diagnostics);

  const threatCount = diagnostics.filter(
    (d) => d.severity === vscode.DiagnosticSeverity.Error
  ).length;
  statusBar.update('done', threatCount);
}

// ---------------------------------------------------------------------------
// Project-wide scan (all manifest files in workspace)
// ---------------------------------------------------------------------------

export async function scanProject(token: vscode.CancellationToken): Promise<void> {
  const manifests = await vscode.workspace.findFiles(
    '{**/package.json,**/go.mod,**/requirements.txt,**/Cargo.toml,**/composer.json,**/Gemfile}',
    '{**/node_modules/**,**/.git/**,**/vendor/**,**/target/**}'
  );

  statusBar.update('scanning', 0, `0/${manifests.length} files`);

  let scanned = 0;
  for (const uri of manifests) {
    if (token.isCancellationRequested) {
      break;
    }
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      await runScan(doc, true);
    } catch {
      // Ignore documents that fail to open
    }
    scanned++;
    statusBar.update('scanning', 0, `${scanned}/${manifests.length} files`);
  }

  statusBar.update('done', getTotalThreatCount());
}

function getTotalThreatCount(): number {
  let count = 0;
  for (const [, result] of resultCache) {
    if (result.is_malicious) {
      count++;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Exports for other providers
// ---------------------------------------------------------------------------

export function getResultForPackage(registry: string, packageName: string): AnalyzeResult | undefined {
  return resultCache.get(`${registry}:${packageName}`);
}
