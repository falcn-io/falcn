"use strict";
/**
 * manifestParser.ts — Parse dependency manifest files
 *
 * Extracts (package, version, line) tuples from:
 *   - package.json (npm / yarn)
 *   - go.mod (Go modules)
 *   - requirements.txt (PyPI / pip)
 *   - Cargo.toml (Rust / crates.io)
 *   - composer.json (PHP Composer)
 *   - Gemfile (Ruby)
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
exports.detectRegistry = detectRegistry;
exports.parseManifest = parseManifest;
const path = __importStar(require("path"));
// ---------------------------------------------------------------------------
// Registry detection
// ---------------------------------------------------------------------------
function detectRegistry(document) {
    const filename = path.basename(document.fileName);
    switch (filename) {
        case 'package.json':
            return 'npm';
        case 'go.mod':
            return 'go';
        case 'requirements.txt':
        case 'requirements-dev.txt':
        case 'requirements-test.txt':
        case 'Pipfile':
            return 'pypi';
        case 'Cargo.toml':
            return 'cargo';
        case 'composer.json':
            return 'composer';
        case 'Gemfile':
            return 'rubygems';
        default:
            if (filename.endsWith('.csproj') || filename.endsWith('.fsproj')) {
                return 'nuget';
            }
            if (filename === 'pom.xml' || filename === 'build.gradle') {
                return 'maven';
            }
            return null;
    }
}
// ---------------------------------------------------------------------------
// Main parser dispatcher
// ---------------------------------------------------------------------------
function parseManifest(document) {
    const registry = detectRegistry(document);
    if (!registry) {
        return [];
    }
    const text = document.getText();
    switch (registry) {
        case 'npm':
            return parsePackageJson(document, text);
        case 'go':
            return parseGoMod(document, text);
        case 'pypi':
            return parseRequirementsTxt(document, text);
        case 'cargo':
            return parseCargoToml(document, text);
        case 'composer':
            return parseComposerJson(document, text);
        case 'rubygems':
            return parseGemfile(document, text);
        default:
            return [];
    }
}
// ---------------------------------------------------------------------------
// package.json parser
// ---------------------------------------------------------------------------
function parsePackageJson(doc, text) {
    const entries = [];
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return entries;
    }
    const depSections = [
        { key: 'dependencies', isDev: false },
        { key: 'devDependencies', isDev: true },
        { key: 'peerDependencies', isDev: false },
        { key: 'optionalDependencies', isDev: false },
    ];
    for (const { key, isDev } of depSections) {
        const section = parsed[key];
        if (!section || typeof section !== 'object') {
            continue;
        }
        for (const [pkgName, version] of Object.entries(section)) {
            if (typeof version !== 'string') {
                continue;
            }
            const location = findStringInDocument(doc, pkgName, `"${pkgName}"`);
            if (!location) {
                continue;
            }
            entries.push({
                name: pkgName,
                version: version.replace(/^[\^~>=<]*/u, '').trim(),
                registry: 'npm',
                line: location.line,
                nameStart: location.nameStart,
                nameEnd: location.nameEnd,
                lineText: doc.lineAt(location.line).text,
                isDev,
            });
        }
    }
    return entries;
}
// ---------------------------------------------------------------------------
// go.mod parser
// ---------------------------------------------------------------------------
function parseGoMod(doc, text) {
    const entries = [];
    const lines = text.split('\n');
    // Match: require github.com/foo/bar v1.2.3
    // Or lines inside a require ( ... ) block
    const singleRe = /^\s*require\s+(\S+)\s+(v[\w.\-+]+)/u;
    const blockLineRe = /^\s+(\S+)\s+(v[\w.\-+]+)/u;
    const blockStart = /^\s*require\s*\(/u;
    const blockEnd = /^\s*\)/u;
    let inBlock = false;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (blockStart.test(line)) {
            inBlock = true;
            continue;
        }
        if (inBlock && blockEnd.test(line)) {
            inBlock = false;
            continue;
        }
        let m = null;
        if (inBlock) {
            m = line.match(blockLineRe);
        }
        else {
            m = line.match(singleRe);
        }
        if (!m) {
            continue;
        }
        const pkgName = m[1];
        const version = m[2].replace(/^v/u, '');
        // Skip indirect/test deps that start with //
        if (line.trim().startsWith('//')) {
            continue;
        }
        const nameStart = line.indexOf(pkgName);
        entries.push({
            name: pkgName,
            version,
            registry: 'go',
            line: i,
            nameStart,
            nameEnd: nameStart + pkgName.length,
            lineText: line,
            isDev: line.includes('// indirect'),
        });
    }
    return entries;
}
// ---------------------------------------------------------------------------
// requirements.txt parser
// ---------------------------------------------------------------------------
function parseRequirementsTxt(doc, text) {
    const entries = [];
    const lines = text.split('\n');
    // Patterns: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg[extras]>=1.0
    const re = /^([A-Za-z0-9_.\-]+)(?:\[[\w,\s]+\])?(?:[=~<>!]+)([\w.\-+]+)/u;
    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i].trim();
        // Skip comments, blank lines, flags (-r, -e, --index-url, etc.)
        if (!raw || raw.startsWith('#') || raw.startsWith('-')) {
            continue;
        }
        // Strip inline comment
        const line = raw.split('#')[0].trim();
        const m = line.match(re);
        if (!m) {
            // Package without pinned version — still record it
            const nameOnly = line.match(/^([A-Za-z0-9_.\-]+)/u);
            if (nameOnly) {
                const nameStart = lines[i].indexOf(nameOnly[1]);
                entries.push({
                    name: nameOnly[1],
                    version: '*',
                    registry: 'pypi',
                    line: i,
                    nameStart,
                    nameEnd: nameStart + nameOnly[1].length,
                    lineText: lines[i],
                    isDev: false,
                });
            }
            continue;
        }
        const pkgName = m[1];
        const version = m[2];
        const nameStart = lines[i].indexOf(pkgName);
        entries.push({
            name: pkgName,
            version,
            registry: 'pypi',
            line: i,
            nameStart,
            nameEnd: nameStart + pkgName.length,
            lineText: lines[i],
            isDev: false,
        });
    }
    return entries;
}
// ---------------------------------------------------------------------------
// Cargo.toml parser
// ---------------------------------------------------------------------------
function parseCargoToml(doc, text) {
    const entries = [];
    const lines = text.split('\n');
    let inDepsSection = false;
    let isDev = false;
    const sectionRe = /^\s*\[([^\]]+)\]/u;
    // Simple: serde = "1.0"
    const simpleDep = /^\s*([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"/u;
    // Table: serde = { version = "1.0", features = [...] }
    const tableDep = /^\s*([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/u;
    const DEP_SECTIONS = new Set([
        'dependencies',
        'dev-dependencies',
        'build-dependencies',
        'workspace.dependencies',
    ]);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const sectionMatch = line.match(sectionRe);
        if (sectionMatch) {
            const section = sectionMatch[1].trim().toLowerCase();
            inDepsSection = DEP_SECTIONS.has(section);
            isDev = section === 'dev-dependencies';
            continue;
        }
        if (!inDepsSection) {
            continue;
        }
        // Skip comments
        if (line.trim().startsWith('#')) {
            continue;
        }
        const m = line.match(tableDep) || line.match(simpleDep);
        if (!m) {
            continue;
        }
        const pkgName = m[1];
        const version = m[2].replace(/^[\^~>=<]*/u, '').trim();
        const nameStart = line.indexOf(pkgName);
        entries.push({
            name: pkgName,
            version,
            registry: 'cargo',
            line: i,
            nameStart,
            nameEnd: nameStart + pkgName.length,
            lineText: line,
            isDev,
        });
    }
    return entries;
}
// ---------------------------------------------------------------------------
// composer.json parser
// ---------------------------------------------------------------------------
function parseComposerJson(doc, text) {
    const entries = [];
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return entries;
    }
    const sections = [
        { key: 'require', isDev: false },
        { key: 'require-dev', isDev: true },
    ];
    for (const { key, isDev } of sections) {
        const section = parsed[key];
        if (!section || typeof section !== 'object') {
            continue;
        }
        for (const [pkgName, version] of Object.entries(section)) {
            if (pkgName === 'php' || pkgName.startsWith('ext-')) {
                continue; // Skip PHP itself and extensions
            }
            if (typeof version !== 'string') {
                continue;
            }
            const location = findStringInDocument(doc, pkgName, `"${pkgName}"`);
            if (!location) {
                continue;
            }
            entries.push({
                name: pkgName,
                version: version.replace(/^[\^~>=<v]*/u, '').trim(),
                registry: 'composer',
                line: location.line,
                nameStart: location.nameStart,
                nameEnd: location.nameEnd,
                lineText: doc.lineAt(location.line).text,
                isDev,
            });
        }
    }
    return entries;
}
// ---------------------------------------------------------------------------
// Gemfile parser
// ---------------------------------------------------------------------------
function parseGemfile(doc, text) {
    const entries = [];
    const lines = text.split('\n');
    // gem 'rails', '~> 7.0'  or  gem "rails"
    const gemRe = /^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/u;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith('#')) {
            continue;
        }
        const m = line.match(gemRe);
        if (!m) {
            continue;
        }
        const pkgName = m[1];
        const version = m[2] ? m[2].replace(/^[\^~>=<]*/u, '').trim() : '*';
        const nameStart = line.indexOf(pkgName);
        entries.push({
            name: pkgName,
            version,
            registry: 'rubygems',
            line: i,
            nameStart,
            nameEnd: nameStart + pkgName.length,
            lineText: line,
            isDev: false,
        });
    }
    return entries;
}
function findStringInDocument(doc, name, pattern) {
    const lineCount = doc.lineCount;
    for (let i = 0; i < lineCount; i++) {
        const lineText = doc.lineAt(i).text;
        const idx = lineText.indexOf(pattern);
        if (idx !== -1) {
            // Position inside the quotes
            const nameStart = idx + 1; // skip the opening quote
            return { line: i, nameStart, nameEnd: nameStart + name.length };
        }
    }
    return null;
}
//# sourceMappingURL=manifestParser.js.map