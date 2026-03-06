"use strict";
/**
 * extension.ts — VS Code extension entry point
 *
 * Registers all providers, commands, and lifecycle hooks for
 * the Falcn Supply Chain Security extension.
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
exports.statusBar = exports.FalcnStatusBar = exports.outputChannel = void 0;
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const diagnostics_1 = require("./diagnostics");
const hoverProvider_1 = require("./hoverProvider");
const quickfix_1 = require("./quickfix");
const api_1 = require("./api");
// ---------------------------------------------------------------------------
// Output channel (shared across modules)
// ---------------------------------------------------------------------------
exports.outputChannel = vscode.window.createOutputChannel('Falcn Security');
// ---------------------------------------------------------------------------
// Status bar item (shared across modules)
// ---------------------------------------------------------------------------
class FalcnStatusBar {
    constructor() {
        this.scanCts = null;
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.item.command = 'falcn.scanProject';
        this.item.tooltip = 'Falcn Supply Chain Security — click to scan';
        this.item.show();
        this.update('idle', 0);
    }
    update(state, threats, detail) {
        switch (state) {
            case 'idle':
                this.item.text = '$(shield) Falcn';
                this.item.color = undefined;
                this.item.backgroundColor = undefined;
                break;
            case 'scanning':
                this.item.text = `$(sync~spin) Falcn: scanning${detail ? ` ${detail}` : ''}`;
                this.item.color = new vscode.ThemeColor('statusBarItem.warningForeground');
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                break;
            case 'done':
                if (threats === 0) {
                    this.item.text = '$(shield-check) Falcn: clean';
                    this.item.color = undefined;
                    this.item.backgroundColor = undefined;
                }
                else {
                    this.item.text = `$(shield-x) Falcn: ${threats} threat${threats !== 1 ? 's' : ''}`;
                    this.item.color = new vscode.ThemeColor('statusBarItem.errorForeground');
                    this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                }
                break;
            case 'error':
                this.item.text = '$(error) Falcn: error';
                this.item.color = new vscode.ThemeColor('statusBarItem.errorForeground');
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                break;
        }
    }
    setScanCts(cts) {
        this.scanCts = cts;
    }
    getScanCts() {
        return this.scanCts;
    }
    dispose() {
        this.item.dispose();
    }
}
exports.FalcnStatusBar = FalcnStatusBar;
exports.statusBar = new FalcnStatusBar();
// ---------------------------------------------------------------------------
// Supported manifest file patterns
// ---------------------------------------------------------------------------
const MANIFEST_DOCUMENT_SELECTORS = [
    { scheme: 'file', pattern: '**/package.json' },
    { scheme: 'file', pattern: '**/go.mod' },
    { scheme: 'file', pattern: '**/requirements.txt' },
    { scheme: 'file', pattern: '**/requirements-dev.txt' },
    { scheme: 'file', pattern: '**/requirements-test.txt' },
    { scheme: 'file', pattern: '**/Cargo.toml' },
    { scheme: 'file', pattern: '**/composer.json' },
    { scheme: 'file', pattern: '**/Gemfile' },
];
function isManifestFile(document) {
    const filename = path.basename(document.fileName);
    const MANIFESTS = new Set([
        'package.json',
        'go.mod',
        'requirements.txt',
        'requirements-dev.txt',
        'requirements-test.txt',
        'Cargo.toml',
        'composer.json',
        'Gemfile',
    ]);
    return MANIFESTS.has(filename) && document.uri.scheme === 'file';
}
// ---------------------------------------------------------------------------
// Extension activation
// ---------------------------------------------------------------------------
async function activate(context) {
    exports.outputChannel.appendLine('Falcn Security extension activated.');
    // -------------------------------------------------------------------
    // Diagnostic collection
    // -------------------------------------------------------------------
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('falcn');
    context.subscriptions.push(diagnosticCollection);
    (0, diagnostics_1.setDiagnosticCollection)(diagnosticCollection);
    // -------------------------------------------------------------------
    // Providers
    // -------------------------------------------------------------------
    const hoverProvider = new hoverProvider_1.FalcnHoverProvider();
    const codeActionProvider = new quickfix_1.FalcnCodeActionProvider();
    context.subscriptions.push(vscode.languages.registerHoverProvider(MANIFEST_DOCUMENT_SELECTORS, hoverProvider), vscode.languages.registerCodeActionsProvider(MANIFEST_DOCUMENT_SELECTORS, codeActionProvider, {
        providedCodeActionKinds: quickfix_1.FalcnCodeActionProvider.providedCodeActionKinds,
    }));
    // -------------------------------------------------------------------
    // Commands
    // -------------------------------------------------------------------
    // Scan project
    context.subscriptions.push(vscode.commands.registerCommand('falcn.scanProject', async () => {
        // Cancel any existing project scan
        const existing = exports.statusBar.getScanCts();
        if (existing) {
            existing.cancel();
            existing.dispose();
        }
        const cts = new vscode.CancellationTokenSource();
        exports.statusBar.setScanCts(cts);
        try {
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Falcn: Scanning project for supply chain threats...',
                cancellable: true,
            }, async (progress, progressToken) => {
                // Wire VS Code progress cancellation
                progressToken.onCancellationRequested(() => {
                    cts.cancel();
                });
                progress.report({ message: 'Discovering manifest files...' });
                await (0, diagnostics_1.scanProject)(cts.token);
                progress.report({ message: 'Done.' });
            });
        }
        finally {
            cts.dispose();
            exports.statusBar.setScanCts(null);
        }
    }));
    // Scan current file
    context.subscriptions.push(vscode.commands.registerCommand('falcn.scanCurrentFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showInformationMessage('Falcn: No active file to scan.');
            return;
        }
        if (!isManifestFile(editor.document)) {
            vscode.window.showInformationMessage('Falcn: The current file is not a recognized manifest. ' +
                'Open a package.json, go.mod, requirements.txt, Cargo.toml, etc.');
            return;
        }
        await (0, diagnostics_1.runScan)(editor.document, true);
    }));
    // Clear diagnostics
    context.subscriptions.push(vscode.commands.registerCommand('falcn.clearDiagnostics', () => {
        diagnosticCollection.clear();
        exports.statusBar.update('idle', 0);
        exports.outputChannel.appendLine('[Command] Diagnostics cleared.');
    }));
    // Show output log
    context.subscriptions.push(vscode.commands.registerCommand('falcn.showOutput', () => {
        exports.outputChannel.show();
    }));
    // Open settings
    context.subscriptions.push(vscode.commands.registerCommand('falcn.openSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', '@ext:falcn-io.falcn-security');
    }));
    // Show ignore instructions (for JSON files that don't support comments)
    context.subscriptions.push(vscode.commands.registerCommand('falcn.showIgnoreInstructions', (packageName, registry) => {
        const msg = `To ignore ${packageName} (${registry}), ` +
            'create a .falcnignore file in your project root and add the package name on a new line.';
        vscode.window.showInformationMessage(msg, 'Create .falcnignore').then((choice) => {
            if (choice === 'Create .falcnignore') {
                void createFalcnIgnoreFile(packageName);
            }
        });
    }));
    // -------------------------------------------------------------------
    // Document event listeners
    // -------------------------------------------------------------------
    const cfg = vscode.workspace.getConfiguration('falcn');
    // Auto-scan on open
    if (cfg.get('autoScanOnOpen', true)) {
        context.subscriptions.push(vscode.workspace.onDidOpenTextDocument((doc) => {
            if (isManifestFile(doc)) {
                (0, diagnostics_1.scheduleScan)(doc);
            }
        }));
    }
    // Auto-scan on save
    if (cfg.get('autoScanOnSave', true)) {
        context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
            if (isManifestFile(doc)) {
                // Immediate scan on save (bypass debounce)
                void (0, diagnostics_1.runScan)(doc, true);
            }
        }));
    }
    // Re-scan (debounced) on document changes
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        if (isManifestFile(event.document)) {
            (0, diagnostics_1.scheduleScan)(event.document);
        }
    }));
    // Clean up diagnostics when a document is closed
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument((doc) => {
        (0, diagnostics_1.cancelScan)(doc.uri.toString());
        diagnosticCollection.delete(doc.uri);
    }));
    // React to configuration changes
    context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('falcn')) {
            (0, api_1.resetApiHealthCache)();
            exports.outputChannel.appendLine('[Config] Settings changed — API health cache reset.');
            // Re-scan all open manifest editors
            for (const editor of vscode.window.visibleTextEditors) {
                if (isManifestFile(editor.document)) {
                    (0, diagnostics_1.scheduleScan)(editor.document);
                }
            }
        }
    }));
    // -------------------------------------------------------------------
    // Initial scan of already-open editors
    // -------------------------------------------------------------------
    for (const editor of vscode.window.visibleTextEditors) {
        if (isManifestFile(editor.document)) {
            (0, diagnostics_1.scheduleScan)(editor.document);
        }
    }
    // -------------------------------------------------------------------
    // API health notification
    // -------------------------------------------------------------------
    void (async () => {
        const apiOk = await (0, api_1.checkApiHealth)();
        if (!apiOk) {
            const apiEndpoint = vscode.workspace.getConfiguration('falcn')
                .get('apiEndpoint', 'http://localhost:8082');
            if (apiEndpoint) {
                const choice = await vscode.window.showWarningMessage(`Falcn: API at ${apiEndpoint} is not reachable. ` +
                    'Will fall back to the falcn CLI. Start the API or update settings.', 'Open Settings', 'Dismiss');
                if (choice === 'Open Settings') {
                    vscode.commands.executeCommand('falcn.openSettings');
                }
            }
        }
        else {
            exports.outputChannel.appendLine(`[Init] Falcn API is reachable.`);
        }
    })();
    // -------------------------------------------------------------------
    // Status bar disposable
    // -------------------------------------------------------------------
    context.subscriptions.push(exports.statusBar);
    context.subscriptions.push(exports.outputChannel);
    exports.outputChannel.appendLine('[Init] Falcn extension ready.');
}
// ---------------------------------------------------------------------------
// Extension deactivation
// ---------------------------------------------------------------------------
function deactivate() {
    exports.outputChannel.appendLine('Falcn Security extension deactivated.');
}
// ---------------------------------------------------------------------------
// Helper: create .falcnignore file
// ---------------------------------------------------------------------------
async function createFalcnIgnoreFile(initialPackage) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showErrorMessage('Falcn: No workspace folder found.');
        return;
    }
    const rootUri = workspaceFolders[0].uri;
    const ignoreUri = vscode.Uri.joinPath(rootUri, '.falcnignore');
    let existing = '';
    try {
        const bytes = await vscode.workspace.fs.readFile(ignoreUri);
        existing = Buffer.from(bytes).toString('utf8');
    }
    catch {
        // File doesn't exist yet
    }
    if (!existing.includes(initialPackage)) {
        const content = existing
            ? existing.trimEnd() + '\n' + initialPackage + '\n'
            : `# Falcn ignore list\n# Add one package name per line\n${initialPackage}\n`;
        await vscode.workspace.fs.writeFile(ignoreUri, Buffer.from(content, 'utf8'));
        const doc = await vscode.workspace.openTextDocument(ignoreUri);
        await vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage(`Added ${initialPackage} to .falcnignore`);
    }
}
//# sourceMappingURL=extension.js.map