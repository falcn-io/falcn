"use strict";
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
exports.FalcnHoverProvider = void 0;
const vscode = __importStar(require("vscode"));
const manifestParser_1 = require("./manifestParser");
const diagnostics_1 = require("./diagnostics");
const api_1 = require("./api");
const extension_1 = require("./extension");
// ---------------------------------------------------------------------------
// Cache for on-demand hover analysis (packages not yet in the diagnostics cache)
// ---------------------------------------------------------------------------
const hoverAnalysisCache = new Map();
const HOVER_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
// ---------------------------------------------------------------------------
// HoverProvider
// ---------------------------------------------------------------------------
class FalcnHoverProvider {
    async provideHover(document, position, token) {
        const cfg = vscode.workspace.getConfiguration('falcn');
        if (!cfg.get('enableHoverProvider', true)) {
            return null;
        }
        const registry = (0, manifestParser_1.detectRegistry)(document);
        if (!registry) {
            return null;
        }
        // Find which package entry the cursor is over
        const entries = (0, manifestParser_1.parseManifest)(document);
        const entry = findEntryAtPosition(entries, position);
        if (!entry) {
            return null;
        }
        // Try diagnostics cache first
        let result = (0, diagnostics_1.getResultForPackage)(entry.registry, entry.name);
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
        const range = new vscode.Range(entry.line, entry.nameStart, entry.line, entry.nameEnd);
        if (!result) {
            // Return a lightweight "unknown" hover
            const md = new vscode.MarkdownString(`**$(shield) Falcn Security**\n\n` +
                `Package: \`${entry.name}@${entry.version}\`\n\n` +
                `_Scan in progress or API unavailable. Run **Falcn: Scan Project** to analyze._`);
            md.isTrusted = true;
            md.supportThemeIcons = true;
            return new vscode.Hover(md, range);
        }
        return new vscode.Hover(buildHoverMarkdown(result, entry), range);
    }
}
exports.FalcnHoverProvider = FalcnHoverProvider;
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function findEntryAtPosition(entries, position) {
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
async function fetchOnDemand(entry, token) {
    extension_1.outputChannel.appendLine(`[Hover] On-demand analysis: ${entry.registry}:${entry.name}@${entry.version}`);
    const result = await (0, api_1.analyzePackage)({ package_name: entry.name, version: entry.version, registry: entry.registry }, token);
    if (result) {
        const cacheKey = `${entry.registry}:${entry.name}`;
        hoverAnalysisCache.set(cacheKey, { result, timestamp: Date.now() });
        // Also populate the main cache
        diagnostics_1.resultCache.set(cacheKey, result);
    }
    return result;
}
function buildHoverMarkdown(result, entry) {
    const md = new vscode.MarkdownString();
    md.isTrusted = true;
    md.supportThemeIcons = true;
    md.supportHtml = false;
    // Header
    const riskIcon = riskScoreIcon(result.risk_score);
    md.appendMarkdown(`## ${riskIcon} Falcn Security — \`${entry.name}\`\n\n`);
    // Registry badge
    md.appendMarkdown(`**Registry:** ${registryLabel(entry.registry)} | ` +
        `**Version:** \`${result.version || entry.version}\`\n\n`);
    // Risk score bar
    const scorePercent = Math.round(result.risk_score * 100);
    const bar = buildRiskBar(result.risk_score);
    const severityLabel = getSeverityLabel(result.risk_score);
    md.appendMarkdown(`**Risk Score:** ${bar} **${scorePercent}%** — ${severityLabel}\n\n`);
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
            md.appendMarkdown(`- ${icon} **${threat.type}** ` +
                `(confidence: ${confidence}%): ${truncate(threat.description, 120)}\n`);
        }
        md.appendMarkdown('\n');
    }
    else {
        md.appendMarkdown(`$(check) No threats detected above threshold.\n\n`);
    }
    // Safe version
    if (result.safe_version) {
        md.appendMarkdown(`**$(arrow-up) Recommended Safe Version:** \`${result.safe_version}\`\n\n`);
    }
    // LLM explanation
    if (result.explanation) {
        md.appendMarkdown(`**Analysis:**\n\n${truncate(result.explanation, 400)}\n\n`);
    }
    // Scan metadata
    md.appendMarkdown(`---\n`);
    md.appendMarkdown(`_Scanned in ${result.scan_duration_ms}ms${result.cached ? ' (cached)' : ''} · ` +
        `[View on Falcn Dashboard](https://falcn.io/packages/${entry.registry}/${entry.name})_\n`);
    return md;
}
// ---------------------------------------------------------------------------
// Visual helpers
// ---------------------------------------------------------------------------
function riskScoreIcon(score) {
    if (score >= 0.9)
        return '$(error)';
    if (score >= 0.7)
        return '$(warning)';
    if (score >= 0.5)
        return '$(info)';
    return '$(check)';
}
function buildRiskBar(score) {
    const filled = Math.round(score * 10);
    const empty = 10 - filled;
    const filledChar = '█';
    const emptyChar = '░';
    return '`' + filledChar.repeat(filled) + emptyChar.repeat(empty) + '`';
}
function getSeverityLabel(score) {
    if (score >= 0.9)
        return '🔴 CRITICAL';
    if (score >= 0.7)
        return '🟠 HIGH';
    if (score >= 0.5)
        return '🟡 MEDIUM';
    if (score >= 0.3)
        return '🔵 LOW';
    return '🟢 SAFE';
}
function severityIcon(severity) {
    switch (severity.toUpperCase()) {
        case 'CRITICAL': return '$(error)';
        case 'HIGH': return '$(warning)';
        case 'MEDIUM': return '$(info)';
        default: return '$(dash)';
    }
}
function registryLabel(registry) {
    const labels = {
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
function truncate(str, max) {
    if (str.length <= max) {
        return str;
    }
    return str.slice(0, max - 1) + '…';
}
//# sourceMappingURL=hoverProvider.js.map