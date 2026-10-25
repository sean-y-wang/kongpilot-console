#!/usr/bin/env node
// Merge sharded ci-quality summaries. Coverage is conserved only if every
// shard 1..n is present exactly once, each shard passed every stage, and the
// summed executed test count equals the unsharded `vitest list` inventory.
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fail = code => { throw new Error(code); };
const int = v => Number.isSafeInteger(v) && v >= 0 ? v : fail('CI_MERGE_COUNT_INVALID');

export function mergeShardSummaries(summaries, inventory) {
  if (!Array.isArray(summaries) || summaries.length === 0) fail('CI_MERGE_NO_SHARDS');
  const count = summaries[0]?.testShard?.count;
  if (!Number.isInteger(count) || summaries.length !== count) fail('CI_MERGE_SHARD_SET_INCOMPLETE');
  const seen = new Set(), files = new Set();
  const totals = { total: 0, passed: 0, failed: 0, skipped: 0, todo: 0, failedSuites: 0, totalSuites: 0 };
  for (const s of summaries) {
    const shard = s?.testShard;
    if (!shard || shard.count !== count || !Number.isInteger(shard.index) || shard.index < 1 || shard.index > count || seen.has(shard.index)) fail('CI_MERGE_SHARD_SET_INCOMPLETE');
    seen.add(shard.index);
    if (s.completed !== true || s.allPassed !== true) fail('CI_MERGE_SHARD_FAILED');
    const t = s.stages?.find(x => x.id === 'tests')?.tests;
    if (!t || t.passedWithoutSkippedTests !== true) fail('CI_MERGE_SHARD_TESTS_FAILED');
    for (const k of Object.keys(totals)) totals[k] += int(t[k]);
    const list = s.stages.find(x => x.id === 'tests').testFiles;
    if (!Array.isArray(list)) fail('CI_MERGE_SHARD_FILES_MISSING');
    for (const f of list) { if (files.has(f)) fail('CI_MERGE_FILE_DUPLICATED'); files.add(f); }
  }
  if (!Array.isArray(inventory) || inventory.length === 0) fail('CI_MERGE_LIST_INVALID');
  const expected = new Set(inventory), missing = inventory.filter(f => !files.has(f)), extra = [...files].filter(f => !expected.has(f));
  const conserved = expected.size === inventory.length && missing.length === 0 && extra.length === 0 && totals.total === totals.passed;
  return { schemaVersion: 1, shards: count, inventoryFiles: inventory.length, executedFiles: files.size, missingFiles: missing.slice(0, 20), extraFiles: extra.slice(0, 20), totals, coverageConserved: conserved,
    allPassed: conserved && totals.failed === 0 && totals.skipped === 0 && totals.todo === 0 && totals.failedSuites === 0 };
}

export function listedTestFiles(repo) {
  const r = spawnSync('npx', ['vitest', 'list', '--filesOnly', '--json'], { cwd: repo, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 20 * 60 * 1000 });
  if (r.status !== 0) fail('CI_MERGE_LIST_FAILED');
  const rows = JSON.parse(r.stdout.slice(r.stdout.indexOf('[')));
  if (!Array.isArray(rows) || rows.length === 0) fail('CI_MERGE_LIST_INVALID');
  const root = resolve(repo) + '/';
  return rows.map(r => { const f = String(r?.file ?? ''); if (!f.startsWith(root)) fail('CI_MERGE_LIST_INVALID'); return f.slice(root.length); }).sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const input = process.env.KONGPILOT_SHARD_SUMMARIES ?? fail('CI_MERGE_INPUT_REQUIRED');
  const out = process.env.KONGPILOT_MERGED_REPORT ?? join(process.env.RUNNER_TEMP ?? '/tmp', 'kongpilot-quality-merged');
  let result;
  try {
    const summaries = readdirSync(input).map(d => join(input, d, 'summary.json')).filter(existsSync).map(f => JSON.parse(readFileSync(f, 'utf8')));
    result = mergeShardSummaries(summaries, listedTestFiles(process.cwd()));
  } catch (e) { result = { allPassed: false, failureCode: /^CI_MERGE_[A-Z_]+$/.test(e?.message) ? e.message : 'CI_MERGE_PRIVATE_FAILURE' }; }
  mkdirSync(out, { recursive: true }); writeFileSync(join(out, 'summary.json'), JSON.stringify(result, null, 2) + '\n');
  process.stdout.write(JSON.stringify(result) + '\n'); if (!result.allPassed) process.exitCode = 1;
}
