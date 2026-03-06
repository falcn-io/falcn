"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.resultCache = void 0;
exports.setDiagnosticCollection = setDiagnosticCollection;
exports.scheduleScan = scheduleScan;
exports.cancelScan = cancelScan;
exports.runScan = runScan;
exports.scanProject = scanProject;
exports.getResultForPackage = getResultForPackage;
const vscode = __importStar(require("vscode"));
const manifestParser_1 = require("./manifestParser");
const api_1 = require("./api");
const extension_1 = require("./extension");
// ---------------------------------------------------------------------------
// Shared result cache (used by hover and quick-fix providers)
// ---------------------------------------------------------------------------
exports.resultCache = new Map();
// ---------------------------------------------------------------------------
// Diagnostic collection singleton (created in extension.ts)
// ---------------------------------------------------------------------------
let diagnosticCollection;
function setDiagnosticCollection(col) {
    diagnosticCollection = col;
}
// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------
function toVSCodeSeverity(falcnSeverity) {
    const cfg = vscode.workspace.getConfiguration('falcn');
    const global = cfg.get('severityLevel', 'warning');
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
function riskToFalcnSeverity(score) {
    if (score >= 0.9)
        return 'CRITICAL';
    if (score >= 0.7)
        return 'HIGH';
    if (score >= 0.5)
        return 'MEDIUM';
    if (score >= 0.3)
        return 'LOW';
    return 'INFO';
}
// ---------------------------------------------------------------------------
// Debounce map — one timer per document URI
// ---------------------------------------------------------------------------
const debounceTimers = new Map();
const cancellationTokenSources = new Map();
function scheduleScan(document) {
    const uri = document.uri.toString();
    const cfg = vscode.workspace.getConfiguration('falcn');
    const delayMs = cfg.get('debounceMs', 1500);
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
function cancelScan(uri) {
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
async function runScan(document, forceImmediate = false) {
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
    }
    finally {
        // Only clean up if this CTS is still the current one
        if (cancellationTokenSources.get(uri) === cts) {
            cancellationTokenSources.delete(uri);
            cts.dispose();
        }
    }
}
async function _doScan(document, token, _forceImmediate) {
    const uri = document.uri.toString();
    const cfg = vscode.workspace.getConfiguration('falcn');
    const riskThreshold = cfg.get('riskThreshold', 0.5);
    // Parse the manifest
    const entries = (0, manifestParser_1.parseManifest)(document);
    if (entries.length === 0) {
        diagnosticCollection?.set(document.uri, []);
        extension_1.statusBar.update('idle', 0);
        return;
    }
    extension_1.statusBar.update('scanning', 0);
    let results;
    const apiOk = await (0, api_1.checkApiHealth)();
    if (apiOk && !token.isCancellationRequested) {
        // Use the REST API
        const requests = entries.map((e) => ({
            package_name: e.name,
            version: e.version,
            registry: e.registry,
        }));
        results = await (0, api_1.analyzePackagesBatch)(requests, token, (done, total) => {
            extension_1.statusBar.update('scanning', 0, `${done}/${total}`);
        });
    }
    else if (!token.isCancellationRequested) {
        // CLI fallback — run one scan per workspace folder
        results = new Map();
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
        if (workspaceFolder) {
            const cliResult = await (0, api_1.scanWithCLI)(workspaceFolder.uri.fsPath, token);
            if (cliResult) {
                for (const threat of cliResult.threats) {
                    const key = `${threat.registry}:${threat.package}`;
                    results.set(key, {
                        package_name: threat.package,
                        version: threat.version,
                        registry: threat.registry,
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
    }
    else {
        return;
    }
    if (token.isCancellationRequested) {
        return;
    }
    // Merge into cache
    for (const [key, result] of results) {
        exports.resultCache.set(key, result);
    }
    // Build diagnostics
    const diagnostics = [];
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
        const range = new vscode.Range(entry.line, entry.nameStart, entry.line, entry.nameEnd);
        const diag = new vscode.Diagnostic(range, message, vsSeverity);
        diag.source = 'Falcn';
        diag.code = {
            value: severity,
            target: vscode.Uri.parse(`https://falcn.io/packages/${entry.registry}/${entry.name}`),
        };
        // Attach related information (individual threats)
        if (result.threats.length > 0) {
            diag.relatedInformation = result.threats.slice(0, 5).map((t) => new vscode.DiagnosticRelatedInformation(new vscode.Location(document.uri, range), `${t.type}: ${t.description} (confidence: ${Math.round(t.confidence * 100)}%)`));
        }
        // Attach tags
        diag.tags = result.is_malicious ? [vscode.DiagnosticTag.Deprecated] : undefined;
        diagnostics.push(diag);
    }
    diagnosticCollection?.set(document.uri, diagnostics);
    const threatCount = diagnostics.filter((d) => d.severity === vscode.DiagnosticSeverity.Error).length;
    extension_1.statusBar.update('done', threatCount);
}
// ---------------------------------------------------------------------------
// Project-wide scan (all manifest files in workspace)
// ---------------------------------------------------------------------------
async function scanProject(token) {
    const manifests = await vscode.workspace.findFiles('{**/package.json,**/go.mod,**/requirements.txt,**/Cargo.toml,**/composer.json,**/Gemfile}', '{**/node_modules/**,**/.git/**,**/vendor/**,**/target/**}');
    extension_1.statusBar.update('scanning', 0, `0/${manifests.length} files`);
    let scanned = 0;
    for (const uri of manifests) {
        if (token.isCancellationRequested) {
            break;
        }
        try {
            const doc = await vscode.workspace.openTextDocument(uri);
            await runScan(doc, true);
        }
        catch {
            // Ignore documents that fail to open
        }
        scanned++;
        extension_1.statusBar.update('scanning', 0, `${scanned}/${manifests.length} files`);
    }
    extension_1.statusBar.update('done', getTotalThreatCount());
}
function getTotalThreatCount() {
    let count = 0;
    for (const [, result] of exports.resultCache) {
        if (result.is_malicious) {
            count++;
        }
    }
    return count;
}
// ---------------------------------------------------------------------------
// Exports for other providers
// ---------------------------------------------------------------------------
function getResultForPackage(registry, packageName) {
    return exports.resultCache.get(`${registry}:${packageName}`);
}
//# sourceMappingURL=diagnostics.js.map