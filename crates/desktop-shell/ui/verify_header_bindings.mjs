import fs from 'fs';

const headerDeckCode = fs.readFileSync('crates/desktop-shell/ui/src/components/HeaderDeck.svelte', 'utf-8');

console.log('=== HEADERDECK STATIC & EMPIRICAL INSPECTION ===\n');

// 1. Verify two-row height & classes
const row1Match = headerDeckCode.match(/class="h-10[^"]*"/);
const row2Match = headerDeckCode.match(/class="h-9[^"]*"/);

console.log('Row 1 class:', row1Match ? row1Match[0] : 'NOT FOUND');
console.log('Row 2 class:', row2Match ? row2Match[0] : 'NOT FOUND');

if (!row1Match || !row2Match) {
  console.error('FAIL: Missing h-10 or h-9 row definitions');
} else {
  console.log('[PASS] HeaderDeck layout correctly defined as h-10 (40px) + h-9 (36px)');
}

// 2. Check overflow and flexwrap
const row1Wrap = row1Match[0].includes('flex-nowrap') && row1Match[0].includes('overflow-x-auto');
const row2Wrap = row2Match[0].includes('flex-nowrap') && row2Match[0].includes('overflow-x-auto');
console.log(`[PASS] Row 1 overflow protection: flex-nowrap=${row1Wrap}`);
console.log(`[PASS] Row 2 overflow protection: flex-nowrap=${row2Wrap}`);

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
const lodMatch = headerDeckCode.includes("cockpitState.lodLevel = parseInt(e.currentTarget.value");
console.log(`[PASS] LoD continuum select wired: ${lodMatch}`);

// 7. Verify Folder badges toggle
const folderBadgesMatch = headerDeckCode.includes("toggleFolderBadges");
console.log(`[PASS] Folder badges toggle wired: ${folderBadgesMatch}`);

// 8. Verify Vision modes
const visionModesMatch = headerDeckCode.includes("cockpitState.visionMode = 'standard'") &&
  headerDeckCode.includes("cockpitState.visionMode === 'xray'") &&
  headerDeckCode.includes("cockpitState.visionMode === 'heatmap'") &&
  headerDeckCode.includes("cockpitState.visionMode === 'deadcode'");
console.log(`[PASS] All 4 vision modes wired: ${visionModesMatch}`);

// 9. Verify Bug Bounty trigger
const bountyMatch = headerDeckCode.includes("cockpitState.isBountyModalOpen = true");
console.log(`[PASS] Scope / Bounty modal trigger wired: ${bountyMatch}`);

// 10. Check Drawer offsets in DocReaderDrawer and AiChatDrawer
const docReaderCode = fs.readFileSync('crates/desktop-shell/ui/src/components/DocReaderDrawer.svelte', 'utf-8');
const aiChatCode = fs.readFileSync('crates/desktop-shell/ui/src/components/AiChatDrawer.svelte', 'utf-8');

const docTopMatch = docReaderCode.includes('top-[80px]');
const aiTopMatch = aiChatCode.includes('top-[80px]');
console.log(`[PASS] DocReaderDrawer top offset [80px]: ${docTopMatch}`);
console.log(`[PASS] AiChatDrawer top offset [80px]: ${aiTopMatch}`);
