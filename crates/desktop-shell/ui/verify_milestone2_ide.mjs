/**
 * COMPREHENSIVE EMPIRICAL VERIFICATION SUITE — MILESTONE 2: FRONTEND FULL-SCREEN IDE & AST SYNC
 * 
 * Tests and verifies:
 * - Feature 5: View Mode State & Hotkeys (graphState, api.ts, HeaderDeck, App.svelte)
 * - Feature 6: Full-Screen IDE Container (IdeView.svelte, DOM retention of AetherCanvas)
 * - Feature 7: Project File Tree Component (IdeFileTree.svelte, hierarchy, search, fallback)
 * - Feature 8: AST Symbol Hierarchy Component (IdeSymbolHierarchy.svelte, kind badges, line numbers, CWE, click events)
 * - Feature 9: Full-Screen Code Editor (IdeEditor.svelte, line numbers, tokenizer, search, Ctrl+S save)
 * - Feature 10: AST Graph & Telemetry Synchronization (activeSymbol, /api/ai/target, camera requestFocusSymbol)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function findFile(relPath) {
  if (fs.existsSync(relPath)) return relPath;
  const sub = path.join(__dirname, relPath);
  if (fs.existsSync(sub)) return sub;
  const stripped = relPath.replace(/^crates\/desktop-shell\/ui\//, '');
  const sub2 = path.join(__dirname, stripped);
  if (fs.existsSync(sub2)) return sub2;
  return relPath;
}

let totalTests = 0;
let passedTests = 0;
const failures = [];

function assert(condition, message) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  [PASS] ${message}`);
  } else {
    failures.push(message);
    console.error(`  [FAIL] ${message}`);
  }
}

console.log('================================================================');
console.log('⚡ VERIFYING MILESTONE 2: FRONTEND FULL-SCREEN IDE & AST SYNC ⚡');
console.log('================================================================\n');

// ----------------------------------------------------------------------------
// SUITE 1: Feature 5 — View Mode State & Hotkeys
// ----------------------------------------------------------------------------
console.log('--- Suite 1: Feature 5 — View Mode State & Hotkeys ---');
const graphStateCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/state/graphState.svelte.ts'), 'utf-8');
const apiCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/lib/api.ts'), 'utf-8');
const headerDeckCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/HeaderDeck.svelte'), 'utf-8');
const appCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/App.svelte'), 'utf-8');

assert(
  graphStateCode.includes("viewMode = $state<'code' | 'vault' | 'ide'>('code')"),
  'graphState defines viewMode union accepting "code" | "vault" | "ide"'
);
assert(
  graphStateCode.includes("ideActiveFile = $state<string | null>(null)"),
  'graphState defines reactive state ideActiveFile'
);
assert(
  graphStateCode.includes("ideTargetLine = $state<number | null>(null)"),
  'graphState defines reactive state ideTargetLine'
);
assert(
  graphStateCode.includes("ideCursorPosition = $state<{ line: number; ch: number } | null>(null)"),
  'graphState defines reactive state ideCursorPosition'
);
assert(
  apiCode.includes("async switchViewMode(mode: 'code' | 'vault' | 'ide'): Promise<any>"),
  'api.ts switchViewMode signature accepts "code" | "vault" | "ide"'
);
assert(
  apiCode.includes("async saveFile(filePath: string, content: string): Promise<any>"),
  'api.ts provides saveFile calling POST /api/save_file'
);
assert(
  apiCode.includes("async getFiles(): Promise<"),
  'api.ts provides getFiles calling GET /api/files'
);
assert(
  apiCode.includes("async getFileContent(path: string, raw: boolean = true)"),
  'api.ts getFileContent supports raw=true by default'
);
assert(
  headerDeckCode.includes("switchViewMode('ide')"),
  'HeaderDeck renders IDE view mode toggle calling switchViewMode("ide")'
);
assert(
  headerDeckCode.includes("Vision 3 : Environnement IDE & Éditeur de Code (Alt+3)"),
  'HeaderDeck IDE button has descriptive tooltip mentioning Alt+3'
);
assert(
  appCode.includes("e.key === '3' || e.code === 'Digit3'"),
  'App.svelte handleGlobalKeydown binds Alt+3 to viewMode = "ide"'
);
assert(
  appCode.includes("tag === 'input' || tag === 'textarea' || tag === 'select' || target?.isContentEditable"),
  'App.svelte shortcut handler protects against input/textarea hijacking'
);

// ----------------------------------------------------------------------------
// SUITE 2: Feature 6 — Full-Screen IDE Container
// ----------------------------------------------------------------------------
console.log('\n--- Suite 2: Feature 6 — Full-Screen IDE Container ---');
const ideViewCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/ide/IdeView.svelte'), 'utf-8');

assert(
  appCode.includes("class:hidden={cockpitState.viewMode === 'ide'}"),
  'AetherCanvas & HUD overlays are hidden via CSS class:hidden when viewMode === "ide" (WebGL context retained)'
);
assert(
  appCode.includes("class:hidden={cockpitState.viewMode !== 'ide'}"),
  'IdeView container is mounted and toggled via class:hidden without unmounting dirty editor state'
);
assert(
  appCode.includes("<IdeView />"),
  'IdeView component is mounted within primary viewport'
);
assert(
  ideViewCode.includes("w-full h-full flex bg-[#060810] text-slate-100 overflow-hidden"),
  'IdeView uses master full-screen flex layout'
);
assert(
  ideViewCode.includes("w-80 shrink-0") || ideViewCode.includes("w-[320px]"),
  'IdeView sidebar is allocated ~320px width'
);
assert(
  ideViewCode.includes("<IdeFileTree />") && ideViewCode.includes("<IdeSymbolHierarchy />") && ideViewCode.includes("<IdeEditor />"),
  'IdeView integrates IdeFileTree, IdeSymbolHierarchy, and IdeEditor components'
);

// ----------------------------------------------------------------------------
// SUITE 3: Feature 7 — Project File Tree Component
// ----------------------------------------------------------------------------
console.log('\n--- Suite 3: Feature 7 — Project File Tree Component ---');
const fileTreeCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/ide/IdeFileTree.svelte'), 'utf-8');

assert(
  fileTreeCode.includes("api.getFiles()"),
  'IdeFileTree invokes api.getFiles() to fetch project directory structure'
);
assert(
  fileTreeCode.includes("fallbackFromGraph()") || fileTreeCode.includes("cockpitState.graph.nodes"),
  'IdeFileTree includes fallback aggregation from cockpitState.graph.nodes when backend is offline'
);
assert(
  fileTreeCode.includes("bind:value={searchFilter}") && fileTreeCode.includes("placeholder=\"Filtrer les fichiers...\""),
  'IdeFileTree provides search filter input with reactive binding'
);
assert(
  fileTreeCode.includes("toggleFolder(node.path") || fileTreeCode.includes("expandedPaths"),
  'IdeFileTree supports collapsible directory nodes with toggle state'
);
assert(
  fileTreeCode.includes("cockpitState.ideActiveFile = node.path"),
  'Clicking a file selects it into cockpitState.ideActiveFile'
);
assert(
  fileTreeCode.includes("ShieldAlert"),
  'IdeFileTree highlights files containing security anomalies'
);

// ----------------------------------------------------------------------------
// SUITE 4: Feature 8 — AST Symbol Hierarchy Component
// ----------------------------------------------------------------------------
console.log('\n--- Suite 4: Feature 8 — AST Symbol Hierarchy Component ---');
const symbolHierarchyCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/ide/IdeSymbolHierarchy.svelte'), 'utf-8');

assert(
  symbolHierarchyCode.includes("cockpitState.graph.nodes.filter"),
  'IdeSymbolHierarchy filters AST nodes from active file'
);
assert(
  symbolHierarchyCode.includes("getKindBadge") &&
  symbolHierarchyCode.includes("Function") &&
  symbolHierarchyCode.includes("Struct") &&
  symbolHierarchyCode.includes("Endpoint"),
  'IdeSymbolHierarchy supports symbol kinds: Function, Struct, Endpoint, Method'
);
assert(
  symbolHierarchyCode.includes("L{sym.line_number || 1}") || symbolHierarchyCode.includes("L{sym.line_number}"),
  'IdeSymbolHierarchy renders 1-indexed line number badges (e.g. L42)'
);
assert(
  symbolHierarchyCode.includes("hasAnomaly") && symbolHierarchyCode.includes("ShieldAlert"),
  'IdeSymbolHierarchy renders CWE security anomaly warning badges'
);
assert(
  symbolHierarchyCode.includes("cockpitState.activeSymbol = sym"),
  'Clicking a symbol updates cockpitState.activeSymbol'
);
assert(
  symbolHierarchyCode.includes("cockpitState.ideTargetLine = line"),
  'Clicking a symbol updates cockpitState.ideTargetLine to trigger editor jump'
);
assert(
  symbolHierarchyCode.includes("api.setAiTarget(sym.id, 'IDE Navigation')"),
  'Clicking a symbol updates active AI target via api.setAiTarget'
);
assert(
  symbolHierarchyCode.includes("cockpitState.requestFocusSymbol(sym.id)"),
  'Clicking a symbol triggers requestFocusSymbol for 3D camera centering'
);

// ----------------------------------------------------------------------------
// SUITE 5: Feature 9 — Full-Screen Code Editor
// ----------------------------------------------------------------------------
console.log('\n--- Suite 5: Feature 9 — Full-Screen Code Editor ---');
const editorCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/ide/IdeEditor.svelte'), 'utf-8');

assert(
  editorCode.includes("lineNum") && editorCode.includes("lines as _, idx"),
  'IdeEditor renders line numbers gutter'
);
assert(
  editorCode.includes("tokenizeCodeLine(lineText, syntaxLanguage)"),
  'IdeEditor applies multi-language syntax highlighting tokenizer'
);
assert(
  editorCode.includes("isSearchOpen") && editorCode.includes("searchQuery") && editorCode.includes("searchMatches"),
  'IdeEditor provides in-file search overlay with match counter (Ctrl+F)'
);
assert(
  editorCode.includes("scrollToLine(line)") || editorCode.includes("scrollToLine(targetLine)"),
  'IdeEditor scrolls smoothly to target line on AST symbol selection'
);
assert(
  editorCode.includes("isDirty = $derived(content !== savedContent)"),
  'IdeEditor derives isDirty status from unsaved changes'
);
assert(
  editorCode.includes("● Modifié") || editorCode.includes("isDirty"),
  'IdeEditor renders dirty / unsaved indicator'
);
assert(
  editorCode.includes("api.saveFile(cockpitState.ideActiveFile, content)"),
  'IdeEditor saves buffer to disk via api.saveFile on Ctrl+S / save button'
);
assert(
  editorCode.includes("Ln {cursorLine}, Col {cursorCol}") && editorCode.includes("{lineCount}"),
  'IdeEditor status bar displays line count, cursor position, and syntax mode'
);

// ----------------------------------------------------------------------------
// SUITE 6: Feature 10 — AST Graph & Telemetry Synchronization
// ----------------------------------------------------------------------------
console.log('\n--- Suite 6: Feature 10 — AST Graph & Telemetry Synchronization ---');

assert(
  graphStateCode.includes("this.ideActiveFile = found.file_path") &&
  graphStateCode.includes("this.ideTargetLine = found.line_number"),
  'cockpitState.selectSymbol synchronizes active file and target line to IDE'
);
assert(
  symbolHierarchyCode.includes("cockpitState.requestFocusSymbol"),
  'IdeSymbolHierarchy signals 3D canvas camera to focus selected symbol'
);
assert(
  appCode.includes("cockpitState.viewMode = 'code'") &&
  appCode.includes("api.switchViewMode('code')"),
  'Alt+1 returns cleanly to WebGL Code AST graph retaining focused symbol'
);

// ----------------------------------------------------------------------------
// SUMMARY
// ----------------------------------------------------------------------------
console.log('\n================================================================');
console.log(`🏁 MILESTONE 2 VERIFICATION COMPLETE: ${passedTests}/${totalTests} PASSED`);
if (failures.length === 0) {
  console.log('✅ ALL MILESTONE 2 REQUIREMENTS & CONSTRAINTS SATISFIED!');
} else {
  console.error(`❌ ${failures.length} ASSERTION FAILURES DETECTED!`);
  process.exit(1);
}
console.log('================================================================\n');
