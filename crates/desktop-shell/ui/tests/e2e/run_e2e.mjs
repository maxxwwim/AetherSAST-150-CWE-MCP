import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { spec } from 'node:test/reporters';
import { installBrowserStubs, closeViteServer } from './harness.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function parseTiers(argv) {
  const selected = new Set();
  for (const arg of argv) {
    if (arg.startsWith('--tier=')) {
      const raw = arg.slice('--tier='.length).trim();
      for (const part of raw.split(',')) {
        const n = Number(part.trim());
        if (![1, 2, 3, 4].includes(n)) {
          console.error(`Invalid --tier value "${part}". Expected 1, 2, 3, or 4.`);
          process.exit(2);
        }
        selected.add(n);
      }
    }
  }
  if (selected.size === 0) {
    selected.add(1);
    selected.add(2);
    selected.add(3);
    selected.add(4);
  }
  return selected;
}

function classifyTier(testName) {
  if (testName.startsWith('tier1_')) return 1;
  if (testName.startsWith('tier2_')) return 2;
  if (testName.startsWith('tier3_')) return 3;
  if (testName.startsWith('tier4_')) return 4;
  return null;
}

async function main() {
  installBrowserStubs();
  const tiers = parseTiers(process.argv.slice(2));

  const files = [];
  if (tiers.has(1)) files.push(path.join(__dirname, 'tier1_ui_features.mjs'));
  if (tiers.has(2)) files.push(path.join(__dirname, 'tier2_ui_boundaries.mjs'));
  if (tiers.has(3) || tiers.has(4)) files.push(path.join(__dirname, 'tier3_tier4_ui_scenarios.mjs'));

  const patterns = [];
  if (tiers.has(1)) patterns.push(/^Tier 1|^F\d+:|^tier1_/);
  if (tiers.has(2)) patterns.push(/^Tier 2|^F\d+ Boundaries:|^tier2_/);
  if (tiers.has(3)) patterns.push(/^Tier 3|^tier3_/);
  if (tiers.has(4)) patterns.push(/^Tier 4|^tier4_/);

  const stats = {
    1: { passed: 0, failed: 0, failures: [] },
    2: { passed: 0, failed: 0, failures: [] },
    3: { passed: 0, failed: 0, failures: [] },
    4: { passed: 0, failed: 0, failures: [] },
  };

  let suiteErrors = 0;

  try {
    const stream = run({
      files,
      isolation: 'none',
      testNamePatterns: patterns,
    });

    stream.on('test:pass', (ev) => {
      if (ev.details?.type === 'suite') return;
      const tier = classifyTier(ev.name);
      if (tier) stats[tier].passed += 1;
    });

    stream.on('test:fail', (ev) => {
      if (ev.details?.type === 'suite') {
        if (!ev.name.startsWith('Tier ') && !ev.name.startsWith('F')) {
          suiteErrors += 1;
        }
        return;
      }
      const tier = classifyTier(ev.name);
      if (tier) {
        stats[tier].failed += 1;
        stats[tier].failures.push({
          name: ev.name,
          reason: ev.details?.error?.cause?.message || ev.details?.error?.message || 'Assertion failed',
        });
      } else {
        suiteErrors += 1;
      }
    });

    stream.compose(spec).pipe(process.stdout);

    await new Promise((resolve, reject) => {
      stream.on('end', resolve);
      stream.on('error', reject);
    });
  } finally {
    await closeViteServer();
  }

  let totalPassed = 0;
  let totalFailed = suiteErrors;

  console.log('\n================ E2E-M2 UI/IDE SUMMARY ================');
  for (const t of [1, 2, 3, 4]) {
    if (!tiers.has(t)) continue;
    const s = stats[t];
    totalPassed += s.passed;
    totalFailed += s.failed;
    console.log(`Tier ${t}: ${s.passed} passed, ${s.failed} failed (${s.passed + s.failed} total)`);
  }
  console.log(`TOTAL : ${totalPassed} passed, ${totalFailed} failed (${totalPassed + totalFailed} total)`);
  console.log('=======================================================');

  if (totalFailed > 0) {
    process.exitCode = 1;
  }
}

main().catch(async (err) => {
  console.error(err);
  await closeViteServer();
  process.exit(1);
});
