"use strict";
/**
 * api.ts — Falcn REST API client
 *
 * Handles all HTTP communication with the Falcn API server.
 * Falls back to CLI subprocess when the API is unreachable.
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
exports.Semaphore = void 0;
exports.checkApiHealth = checkApiHealth;
exports.resetApiHealthCache = resetApiHealthCache;
exports.analyzePackage = analyzePackage;
exports.analyzePackagesBatch = analyzePackagesBatch;
exports.scanWithCLI = scanWithCLI;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const extension_1 = require("./extension");
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getConfig() {
    return vscode.workspace.getConfiguration('falcn');
}
function getBaseUrl() {
    const endpoint = getConfig().get('apiEndpoint', 'http://localhost:8082');
    return endpoint.replace(/\/$/, '');
}
function getApiKey() {
    return getConfig().get('apiKey', '');
}
function buildHeaders() {
    const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'falcn-vscode/1.0.0',
    };
    const key = getApiKey();
    if (key) {
        headers['X-API-Key'] = key;
        headers['Authorization'] = `Bearer ${key}`;
    }
    return headers;
}
// ---------------------------------------------------------------------------
// Concurrency limiter
// ---------------------------------------------------------------------------
class Semaphore {
    constructor(permits) {
        this.queue = [];
        this.permits = permits;
    }
    async acquire() {
        if (this.permits > 0) {
            this.permits--;
            return;
        }
        return new Promise((resolve) => {
            this.queue.push(resolve);
        });
    }
    release() {
        if (this.queue.length > 0) {
            const next = this.queue.shift();
            next?.();
        }
        else {
            this.permits++;
        }
    }
    async run(fn) {
        await this.acquire();
        try {
            return await fn();
        }
        finally {
            this.release();
        }
    }
}
exports.Semaphore = Semaphore;
// ---------------------------------------------------------------------------
// API health check
// ---------------------------------------------------------------------------
let apiAvailable = null;
let lastHealthCheck = 0;
const HEALTH_CHECK_TTL_MS = 30000;
async function checkApiHealth() {
    const now = Date.now();
    if (apiAvailable !== null && now - lastHealthCheck < HEALTH_CHECK_TTL_MS) {
        return apiAvailable;
    }
    const baseUrl = getBaseUrl();
    if (!baseUrl) {
        apiAvailable = false;
        lastHealthCheck = now;
        return false;
    }
    try {
        // Dynamic import so the extension works even if node-fetch fails to load
        const fetch = (await Promise.resolve().then(() => __importStar(require('node-fetch')))).default;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        try {
            const resp = await fetch(`${baseUrl}/health`, {
                method: 'GET',
                headers: buildHeaders(),
                signal: controller.signal,
            });
            apiAvailable = resp.ok;
        }
        finally {
            clearTimeout(timer);
        }
    }
    catch {
        apiAvailable = false;
    }
    lastHealthCheck = now;
    extension_1.outputChannel.appendLine(`[API] Health check: ${apiAvailable ? 'OK' : 'UNAVAILABLE'} (${baseUrl})`);
    return apiAvailable;
}
function resetApiHealthCache() {
    apiAvailable = null;
    lastHealthCheck = 0;
}
// ---------------------------------------------------------------------------
// Analyze a single package via REST API
// ---------------------------------------------------------------------------
async function analyzePackage(req, token) {
    const baseUrl = getBaseUrl();
    if (!baseUrl) {
        return null;
    }
    try {
        const fetch = (await Promise.resolve().then(() => __importStar(require('node-fetch')))).default;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        // Wire VS Code cancellation to the fetch abort controller
        const tokenDispose = token?.onCancellationRequested(() => controller.abort());
        try {
            if (token?.isCancellationRequested) {
                return null;
            }
            const resp = await fetch(`${baseUrl}/v1/analyze`, {
                method: 'POST',
                headers: buildHeaders(),
                body: JSON.stringify(req),
                signal: controller.signal,
            });
            if (!resp.ok) {
                extension_1.outputChannel.appendLine(`[API] analyzePackage failed: HTTP ${resp.status} for ${req.package_name}`);
                return null;
            }
            const data = await resp.json();
            return data;
        }
        finally {
            clearTimeout(timer);
            tokenDispose?.dispose();
        }
    }
    catch (err) {
        if (isAbortError(err)) {
            extension_1.outputChannel.appendLine(`[API] Request cancelled for ${req.package_name}`);
        }
        else {
            extension_1.outputChannel.appendLine(`[API] Error analyzing ${req.package_name}: ${String(err)}`);
        }
        return null;
    }
}
// ---------------------------------------------------------------------------
// Analyze packages in batch with concurrency control
// ---------------------------------------------------------------------------
async function analyzePackagesBatch(requests, token, onProgress) {
    const maxConcurrent = getConfig().get('maxConcurrentRequests', 5);
    const semaphore = new Semaphore(maxConcurrent);
    const results = new Map();
    let completed = 0;
    const tasks = requests.map((req) => semaphore.run(async () => {
        if (token?.isCancellationRequested) {
            return;
        }
        const result = await analyzePackage(req, token);
        if (result) {
            results.set(`${req.registry}:${req.package_name}`, result);
        }
        completed++;
        onProgress?.(completed, requests.length);
    }));
    await Promise.allSettled(tasks);
    return results;
}
// ---------------------------------------------------------------------------
// CLI subprocess fallback
// ---------------------------------------------------------------------------
async function scanWithCLI(projectPath, token) {
    const cliPath = getConfig().get('cliPath', 'falcn');
    return new Promise((resolve) => {
        extension_1.outputChannel.appendLine(`[CLI] Running: ${cliPath} scan ${projectPath} --output json`);
        let stdout = '';
        let stderr = '';
        const proc = (0, child_process_1.spawn)(cliPath, ['scan', projectPath, '--output', 'json'], {
            cwd: projectPath,
            timeout: 120000,
        });
        const tokenDispose = token?.onCancellationRequested(() => {
            proc.kill('SIGTERM');
            resolve(null);
        });
        proc.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });
        proc.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });
        proc.on('close', (code) => {
            tokenDispose?.dispose();
            if (code !== 0) {
                extension_1.outputChannel.appendLine(`[CLI] Exit code ${code}. stderr: ${stderr.slice(0, 500)}`);
                resolve(null);
                return;
            }
            try {
                const data = JSON.parse(stdout);
                resolve(data);
            }
            catch (err) {
                extension_1.outputChannel.appendLine(`[CLI] Failed to parse JSON output: ${String(err)}`);
                resolve(null);
            }
        });
        proc.on('error', (err) => {
            tokenDispose?.dispose();
            extension_1.outputChannel.appendLine(`[CLI] Spawn error: ${err.message}`);
            resolve(null);
        });
    });
}
// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
function isAbortError(err) {
    if (err instanceof Error) {
        return err.name === 'AbortError' || err.message.includes('abort');
    }
    return false;
}
//# sourceMappingURL=api.js.map