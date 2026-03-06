/**
 * api.ts — Falcn REST API client
 *
 * Handles all HTTP communication with the Falcn API server.
 * Falls back to CLI subprocess when the API is unreachable.
 */

import * as vscode from 'vscode';
import { spawn } from 'child_process';
import { outputChannel } from './extension';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AnalyzeRequest {
  package_name: string;
  version?: string;
  registry: string;
}

export interface ThreatInfo {
  type: string;
  severity: string;         // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  description: string;
  confidence: number;       // 0–1
}

export interface AnalyzeResult {
  package_name: string;
  version: string;
  registry: string;
  risk_score: number;       // 0–1
  is_malicious: boolean;
  threats: ThreatInfo[];
  safe_version?: string;    // suggested replacement
  explanation?: string;     // LLM-generated explanation
  cached: boolean;
  scan_duration_ms: number;
}

export interface ScanResult {
  threats: Array<{
    package: string;
    version: string;
    registry: string;
    risk_score: number;
    severity: string;
    description: string;
    safe_version?: string;
  }>;
  total_packages: number;
  total_threats: number;
  scan_duration_ms: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getConfig(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('falcn');
}

function getBaseUrl(): string {
  const endpoint = getConfig().get<string>('apiEndpoint', 'http://localhost:8082');
  return endpoint.replace(/\/$/, '');
}

function getApiKey(): string {
  return getConfig().get<string>('apiKey', '');
}

function buildHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
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

export class Semaphore {
  private permits: number;
  private queue: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return;
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    if (this.queue.length > 0) {
      const next = this.queue.shift();
      next?.();
    } else {
      this.permits++;
    }
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

// ---------------------------------------------------------------------------
// API health check
// ---------------------------------------------------------------------------

let apiAvailable: boolean | null = null;
let lastHealthCheck = 0;
const HEALTH_CHECK_TTL_MS = 30_000;

export async function checkApiHealth(): Promise<boolean> {
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
    const fetch = (await import('node-fetch')).default;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      const resp = await fetch(`${baseUrl}/health`, {
        method: 'GET',
        headers: buildHeaders(),
        signal: controller.signal,
      });
      apiAvailable = resp.ok;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    apiAvailable = false;
  }

  lastHealthCheck = now;
  outputChannel.appendLine(
    `[API] Health check: ${apiAvailable ? 'OK' : 'UNAVAILABLE'} (${baseUrl})`
  );
  return apiAvailable;
}

export function resetApiHealthCache(): void {
  apiAvailable = null;
  lastHealthCheck = 0;
}

// ---------------------------------------------------------------------------
// Analyze a single package via REST API
// ---------------------------------------------------------------------------

export async function analyzePackage(
  req: AnalyzeRequest,
  token?: vscode.CancellationToken
): Promise<AnalyzeResult | null> {
  const baseUrl = getBaseUrl();
  if (!baseUrl) {
    return null;
  }

  try {
    const fetch = (await import('node-fetch')).default;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);

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
        outputChannel.appendLine(
          `[API] analyzePackage failed: HTTP ${resp.status} for ${req.package_name}`
        );
        return null;
      }

      const data = await resp.json() as AnalyzeResult;
      return data;
    } finally {
      clearTimeout(timer);
      tokenDispose?.dispose();
    }
  } catch (err: unknown) {
    if (isAbortError(err)) {
      outputChannel.appendLine(`[API] Request cancelled for ${req.package_name}`);
    } else {
      outputChannel.appendLine(`[API] Error analyzing ${req.package_name}: ${String(err)}`);
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Analyze packages in batch with concurrency control
// ---------------------------------------------------------------------------

export async function analyzePackagesBatch(
  requests: AnalyzeRequest[],
  token?: vscode.CancellationToken,
  onProgress?: (completed: number, total: number) => void
): Promise<Map<string, AnalyzeResult>> {
  const maxConcurrent = getConfig().get<number>('maxConcurrentRequests', 5);
  const semaphore = new Semaphore(maxConcurrent);
  const results = new Map<string, AnalyzeResult>();
  let completed = 0;

  const tasks = requests.map((req) =>
    semaphore.run(async () => {
      if (token?.isCancellationRequested) {
        return;
      }
      const result = await analyzePackage(req, token);
      if (result) {
        results.set(`${req.registry}:${req.package_name}`, result);
      }
      completed++;
      onProgress?.(completed, requests.length);
    })
  );

  await Promise.allSettled(tasks);
  return results;
}

// ---------------------------------------------------------------------------
// CLI subprocess fallback
// ---------------------------------------------------------------------------

export async function scanWithCLI(
  projectPath: string,
  token?: vscode.CancellationToken
): Promise<ScanResult | null> {
  const cliPath = getConfig().get<string>('cliPath', 'falcn');

  return new Promise<ScanResult | null>((resolve) => {
    outputChannel.appendLine(`[CLI] Running: ${cliPath} scan ${projectPath} --output json`);

    let stdout = '';
    let stderr = '';

    const proc = spawn(cliPath, ['scan', projectPath, '--output', 'json'], {
      cwd: projectPath,
      timeout: 120_000,
    });

    const tokenDispose = token?.onCancellationRequested(() => {
      proc.kill('SIGTERM');
      resolve(null);
    });

    proc.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    proc.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on('close', (code) => {
      tokenDispose?.dispose();
      if (code !== 0) {
        outputChannel.appendLine(`[CLI] Exit code ${code}. stderr: ${stderr.slice(0, 500)}`);
        resolve(null);
        return;
      }
      try {
        const data = JSON.parse(stdout) as ScanResult;
        resolve(data);
      } catch (err) {
        outputChannel.appendLine(`[CLI] Failed to parse JSON output: ${String(err)}`);
        resolve(null);
      }
    });

    proc.on('error', (err) => {
      tokenDispose?.dispose();
      outputChannel.appendLine(`[CLI] Spawn error: ${err.message}`);
      resolve(null);
    });
  });
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function isAbortError(err: unknown): boolean {
  if (err instanceof Error) {
    return err.name === 'AbortError' || err.message.includes('abort');
  }
  return false;
}
