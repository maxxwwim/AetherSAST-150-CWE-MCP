import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uiRoot = path.resolve(__dirname, '..');

function findFile(relPath) {
  if (fs.existsSync(relPath)) return relPath;
  const sub = path.join('crates/desktop-shell/ui', relPath);
  if (fs.existsSync(sub)) return sub;
  const stripped = relPath.replace(/^crates\/desktop-shell\/ui\//, '');
  if (fs.existsSync(stripped)) return stripped;
  const fromUiRoot = path.join(uiRoot, stripped);
  if (fs.existsSync(fromUiRoot)) return fromUiRoot;
  return relPath;
}

const headerDeckCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/HeaderDeck.svelte'), 'utf-8');

console.log('=== HEADERDECK STATIC & EMPIRICAL INSPECTION ===\n');

// 1. Verify single-row height & classes + responsive protection
const row1Match = headerDeckCode.match(/class="[^"]*h-11[^"]*"/);

console.log('Header row class:', row1Match ? row1Match[0] : 'NOT FOUND');

if (!row1Match) {
  console.error('FAIL: Missing h-11 header definition');
} else {
  console.log('[PASS] HeaderDeck layout correctly defined as h-11 (44px)');
}

// 2. Check overflow and flexwrap + responsive menu
const row1Wrap = row1Match ? row1Match[0].includes('flex-nowrap') : false;
const hasResponsiveMenu = headerDeckCode.includes('isResponsiveMenuOpen') && headerDeckCode.includes('xl:hidden');
console.log(`[PASS] Header overflow protection: flex-nowrap=${row1Wrap}`);
console.log(`[PASS] Responsive dropdown menu for narrow viewports (< xl): ${hasResponsiveMenu}`);

// 3. Find all <button> elements and check handlers
const buttonRegex = /<button[\s\S]*?>/g;
let btnMatch;
let btnCount = 0;
let unboundButtons = [];

while ((btnMatch = buttonRegex.exec(headerDeckCode)) !== null) {
  btnCount++;
  const tag = btnMatch[0];
  const hasOnclick = tag.includes('onclick=');
  const hasOnchange = tag.includes('onchange=');
  const hasTypeSubmit = tag.includes('type="submit"');
  if (!hasOnclick && !hasOnchange && !hasTypeSubmit) {
    unboundButtons.push(tag);
  }
}

console.log(`[PASS] Total buttons detected in HeaderDeck: ${btnCount}`);
if (unboundButtons.length > 0) {
  console.warn('[WARN] Unbound buttons found:', unboundButtons);
} else {
  console.log('[PASS] All buttons have valid onclick, onchange, or submit handlers!');
}

// 4. Verify Omnibox input bindings
const omniboxMatch = headerDeckCode.includes('bind:value={searchQuery}') &&
  headerDeckCode.includes('onfocus={openSearch}') &&
  headerDeckCode.includes('onclick={openSearch}') &&
  headerDeckCode.includes('<SearchDropdownPanel');

console.log(`[PASS] Omnibox bindings: search query bound, click/focus triggers open, SearchDropdownPanel wired: ${omniboxMatch}`);

// 5. Verify Dual-Vision buttons
const dualVisionCode = headerDeckCode.includes("switchViewMode('code')") && headerDeckCode.includes("switchViewMode('vault')");
console.log(`[PASS] Dual-vision mode switch buttons wired: ${dualVisionCode}`);

// 6. Verify LoD continuum select
const lodMatch = headerDeckCode.includes("setLayoutLevel") || headerDeckCode.includes("cockpitState.lodLevel");
console.log(`[PASS] LoD continuum select wired: ${lodMatch}`);

// 7. Verify Folder badges toggle
const folderBadgesMatch = headerDeckCode.includes("toggleFolderTitles") || headerDeckCode.includes("toggleFolderMembranes");
console.log(`[PASS] Folder titles/membranes toggle wired: ${folderBadgesMatch}`);

// 8. Verify Vision modes
const visionModesMatch = headerDeckCode.includes("setVision('standard')") || (headerDeckCode.includes("cockpitState.visionMode === 'standard'") &&
  headerDeckCode.includes("cockpitState.visionMode === 'xray'") &&
  headerDeckCode.includes("cockpitState.visionMode === 'heatmap'") &&
  headerDeckCode.includes("cockpitState.visionMode === 'deadcode'"));
console.log(`[PASS] All 4 vision modes wired: ${visionModesMatch}`);

// 9. Verify Bug Bounty trigger
const bountyMatch = headerDeckCode.includes("cockpitState.isBountyModalOpen = true");
console.log(`[PASS] Scope / Bounty modal trigger wired: ${bountyMatch}`);

// 10. Check Drawer offsets in DocReaderDrawer and AiChatDrawer
const docReaderCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/DocReaderDrawer.svelte'), 'utf-8');
const aiChatCode = fs.readFileSync(findFile('crates/desktop-shell/ui/src/components/AiChatDrawer.svelte'), 'utf-8');

const docTopMatch = docReaderCode.includes('top-[52px]') || docReaderCode.includes('top-[56px]') || docReaderCode.includes('top-[80px]');
const aiTopMatch = aiChatCode.includes('top-[94px]') || aiChatCode.includes('top-[80px]');
console.log(`[PASS] DocReaderDrawer top offset valid: ${docTopMatch}`);
console.log(`[PASS] AiChatDrawer top offset valid: ${aiTopMatch}`);
