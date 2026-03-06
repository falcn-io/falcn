/**
 * quickfix.ts — CodeActionProvider for Falcn diagnostics
 *
 * Provides two types of code actions:
 *   1. "Update to safe version" — replaces the current version in the manifest
 *   2. "View on Falcn Dashboard" — opens the web dashboard
 *   3. "Ignore this package" — adds a falcn-ignore comment
 */

import * as vscode from 'vscode';
import { parseManifest, PackageEntry } from './manifestParser';
import { getResultForPackage } from './diagnostics';

// ---------------------------------------------------------------------------
// CodeActionProvider
// ---------------------------------------------------------------------------

export class FalcnCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
    vscode.CodeActionKind.RefactorRewrite,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const cfg = vscode.workspace.getConfiguration('falcn');
    if (!cfg.get<boolean>('enableQuickFix', true)) {
      return [];
    }

    // Only act on Falcn diagnostics
    const falcnDiagnostics = context.diagnostics.filter(
      (d) => d.source === 'Falcn'
    );
    if (falcnDiagnostics.length === 0) {
      return [];
    }

    const entries = parseManifest(document);
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of falcnDiagnostics) {
      const entry = findEntryForDiagnostic(entries, diagnostic);
      if (!entry) {
        continue;
      }

      const result = getResultForPackage(entry.registry, entry.name);

      // Action 1: Update to safe version
      if (result?.safe_version) {
        const updateAction = buildUpdateAction(document, entry, result.safe_version, diagnostic);
        if (updateAction) {
          actions.push(updateAction);
        }
      }

      // Action 2: Open Falcn dashboard
      actions.push(buildViewDashboardAction(entry));

      // Action 3: Ignore this package
      actions.push(buildIgnoreAction(document, entry, diagnostic));
    }

    return actions;
  }
}

// ---------------------------------------------------------------------------
// Action builders
// ---------------------------------------------------------------------------

function buildUpdateAction(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  diagnostic: vscode.Diagnostic
): vscode.CodeAction | null {
  const filename = document.fileName.split('/').pop() || '';
  const edit = buildVersionEdit(document, entry, safeVersion, filename);
  if (!edit) {
    return null;
  }

  const action = new vscode.CodeAction(
    `$(arrow-up) Update ${entry.name} to safe version ${safeVersion}`,
    vscode.CodeActionKind.QuickFix
  );
  action.edit = edit;
  action.diagnostics = [diagnostic];
  action.isPreferred = true;
  action.command = {
    command: 'falcn.scanCurrentFile',
    title: 'Re-scan after update',
  };
  return action;
}

function buildVersionEdit(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  filename: string
): vscode.WorkspaceEdit | null {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(entry.line).text;

  if (filename === 'package.json' || filename === 'composer.json') {
    return buildJsonVersionEdit(document, entry, safeVersion, lineText, edit);
  } else if (filename === 'go.mod') {
    return buildGoModVersionEdit(document, entry, safeVersion, lineText, edit);
  } else if (filename === 'requirements.txt') {
    return buildRequirementsVersionEdit(document, entry, safeVersion, lineText, edit);
  } else if (filename === 'Cargo.toml') {
    return buildCargoVersionEdit(document, entry, safeVersion, lineText, edit);
  } else if (filename === 'Gemfile') {
    return buildGemfileVersionEdit(document, entry, safeVersion, lineText, edit);
  }

  return null;
}

function buildJsonVersionEdit(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  lineText: string,
  edit: vscode.WorkspaceEdit
): vscode.WorkspaceEdit | null {
  // Match: "package-name": "^1.2.3" or "package-name": "~1.2.3"
  const re = new RegExp(`("${escapeRegex(entry.name)}"\\s*:\\s*")([^"]+)(")`);
  const m = lineText.match(re);
  if (!m) {
    return null;
  }

  const prefix = m[1];
  const suffix = m[3];
  // Preserve the range specifier (^ or ~) if present
  const oldVersion = m[2];
  const rangePrefix = oldVersion.match(/^([\^~>=<]+)/u)?.[1] || '^';
  const newValue = `${prefix}${rangePrefix}${safeVersion}${suffix}`;

  const matchStart = lineText.indexOf(m[0]);
  const range = new vscode.Range(
    entry.line, matchStart,
    entry.line, matchStart + m[0].length
  );
  edit.replace(document.uri, range, newValue);
  return edit;
}

function buildGoModVersionEdit(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  lineText: string,
  edit: vscode.WorkspaceEdit
): vscode.WorkspaceEdit | null {
  // Match: github.com/foo/bar v1.2.3
  const re = new RegExp(`(${escapeRegex(entry.name)}\\s+)(v[\\w.\\-+]+)`);
  const m = lineText.match(re);
  if (!m) {
    return null;
  }

  const matchStart = lineText.indexOf(m[0]);
  const versionStart = matchStart + m[1].length;
  const range = new vscode.Range(
    entry.line, versionStart,
    entry.line, versionStart + m[2].length
  );
  edit.replace(document.uri, range, `v${safeVersion}`);
  return edit;
}

function buildRequirementsVersionEdit(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  lineText: string,
  edit: vscode.WorkspaceEdit
): vscode.WorkspaceEdit | null {
  // Match: package==1.0.0 or package>=1.0.0
  const re = new RegExp(`(${escapeRegex(entry.name)}\\s*[=~<>!]+)([\\w.\\-+]+)`);
  const m = lineText.match(re);
  if (!m) {
    return null;
  }

  const matchStart = lineText.indexOf(m[0]);
  const versionStart = matchStart + m[1].length;
  const range = new vscode.Range(
    entry.line, versionStart,
    entry.line, versionStart + m[2].length
  );
  edit.replace(document.uri, range, safeVersion);
  return edit;
}

function buildCargoVersionEdit(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  lineText: string,
  edit: vscode.WorkspaceEdit
): vscode.WorkspaceEdit | null {
  // Match: crate = "1.0.0" or crate = { version = "1.0.0", ... }
  const simple = new RegExp(`(${escapeRegex(entry.name)}\\s*=\\s*")([^"]+)(")`);
  const table = new RegExp(`(${escapeRegex(entry.name)}\\s*=\\s*\\{[^}]*version\\s*=\\s*")([^"]+)(")`);

  let m = lineText.match(table) || lineText.match(simple);
  if (!m) {
    return null;
  }

  const prefix = m[1];
  const suffix = m[3];
  const oldVersion = m[2];
  const rangePrefix = oldVersion.match(/^([\^~>=<]+)/u)?.[1] || '^';
  const newValue = `${prefix}${rangePrefix}${safeVersion}${suffix}`;

  const matchStart = lineText.indexOf(m[0]);
  const range = new vscode.Range(
    entry.line, matchStart,
    entry.line, matchStart + m[0].length
  );
  edit.replace(document.uri, range, newValue);
  return edit;
}

function buildGemfileVersionEdit(
  document: vscode.TextDocument,
  entry: PackageEntry,
  safeVersion: string,
  lineText: string,
  edit: vscode.WorkspaceEdit
): vscode.WorkspaceEdit | null {
  // Match: gem 'name', '~> 1.0'
  const re = new RegExp(`(gem\\s+['"]${escapeRegex(entry.name)}['"]\\s*,\\s*['"])([^'"]+)(['"])`);
  const m = lineText.match(re);
  if (!m) {
    return null;
  }

  const prefix = m[1];
  const suffix = m[3];
  const oldVersion = m[2];
  const rangePrefix = oldVersion.match(/^([~><=!]+\s*)/u)?.[1] || '~> ';
  const newValue = `${prefix}${rangePrefix}${safeVersion}${suffix}`;

  const matchStart = lineText.indexOf(m[0]);
  const range = new vscode.Range(
    entry.line, matchStart,
    entry.line, matchStart + m[0].length
  );
  edit.replace(document.uri, range, newValue);
  return edit;
}

function buildViewDashboardAction(entry: PackageEntry): vscode.CodeAction {
  const action = new vscode.CodeAction(
    `$(link-external) View ${entry.name} on Falcn Dashboard`,
    vscode.CodeActionKind.Empty
  );
  action.command = {
    command: 'vscode.open',
    title: 'Open Falcn Dashboard',
    arguments: [
      vscode.Uri.parse(
        `https://falcn.io/packages/${entry.registry}/${encodeURIComponent(entry.name)}`
      ),
    ],
  };
  return action;
}

function buildIgnoreAction(
  document: vscode.TextDocument,
  entry: PackageEntry,
  diagnostic: vscode.Diagnostic
): vscode.CodeAction {
  const action = new vscode.CodeAction(
    `$(mute) Ignore ${entry.name} (add falcn-ignore comment)`,
    vscode.CodeActionKind.QuickFix
  );
  action.diagnostics = [diagnostic];

  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(entry.line);
  const lineText = line.text;

  // Determine comment syntax based on file type
  const filename = document.fileName.split('/').pop() || '';
  let commentPrefix = '# ';
  if (filename === 'package.json' || filename === 'composer.json') {
    // JSON doesn't support comments; insert a special key on the next line approach
    // Instead, add a companion .falcnignore approach — just show a message
    action.command = {
      command: 'falcn.showIgnoreInstructions',
      title: 'Show ignore instructions',
      arguments: [entry.name, entry.registry],
    };
    return action;
  } else if (filename === 'Cargo.toml') {
    commentPrefix = '# ';
  } else if (filename === 'go.mod') {
    commentPrefix = '// ';
  }

  // Append falcn-ignore comment to the line
  const existingComment = lineText.includes('#') || lineText.includes('//');
  let newLineText: string;
  if (existingComment) {
    // Insert before existing comment
    newLineText = lineText + ` ${commentPrefix.trim()} falcn-ignore`;
  } else {
    newLineText = lineText + `  ${commentPrefix}falcn-ignore`;
  }

  const range = new vscode.Range(entry.line, 0, entry.line, lineText.length);
  edit.replace(document.uri, range, newLineText);
  action.edit = edit;

  return action;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function findEntryForDiagnostic(
  entries: PackageEntry[],
  diagnostic: vscode.Diagnostic
): PackageEntry | null {
  for (const entry of entries) {
    if (
      entry.line === diagnostic.range.start.line &&
      entry.nameStart <= diagnostic.range.start.character &&
      entry.nameEnd >= diagnostic.range.end.character
    ) {
      return entry;
    }
  }
  return null;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
