import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, chmodSync, statSync, symlinkSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createMetricsMaterial } from './metrics-material.mjs';
import { captureTestMaterial, readTestReference } from './metrics-test-reference.mjs';

const checks = [];
function check(name, callback) { try { callback(); checks.push({ name, passed: true }); } catch { checks.push({ name, passed: false }); } }
function run(args) { return spawnSync('node', ['deploy/scripts/stage-deploy.mjs', ...args], { encoding: 'utf8' }); }
check('test flag requires observability', () => { assert.equal(run(['M5', '--capture-metrics-test-tokens', '--dry-run']).status, 2); });
check('test flag requires M5', () => { assert.equal(run(['M4', '--observability', '--capture-metrics-test-tokens', '--dry-run']).status, 2); });
check('test flag disallowed in verify-only', () => { assert.equal(run(['M5', '--observability', '--capture-metrics-test-tokens', '--verify-only']).status, 2); });
check('explicit test dry-run plans capture without keys', () => { const result = run(['M5', '--observability', '--capture-metrics-test-tokens', '--dry-run']); assert.equal(result.status, 0); const data = JSON.parse(result.stdout); assert.equal(data.deploymentPerformed, false); assert(data.commands.find(row => row.name === 'enroll-metrics').args.includes('--test-private-reference')); });
check('default production plan never captures reference', () => { const result = run(['M5', '--observability', '--dry-run']); assert.equal(result.status, 0); assert(!result.stdout.includes('--test-private-reference')); assert(!result.stdout.includes('runtime-secrets')); });
const directory = mkdtempSync(resolve(tmpdir(), 'kongos-metrics-reference-test-'));
chmodSync(directory, 0o700);
const file = resolve(directory, 'private.json');
const material = createMetricsMaterial(randomUUID(), 1);
try {
  check('capture file created0600', () => { captureTestMaterial(material, file); assert.equal(statSync(file).mode & 0o777, 0o600); });
  check('all four token purposes retained before enrollment', () => { const value = readTestReference(file); assert.equal(value.tokens.length, 4); assert(material.enrollment.credentials.every(row => value.tokens.some(token => token.token === row.token && token.purpose === row.purpose))); });
  check('existing private history survives capture', () => { const next = createMetricsMaterial(material.enrollment.clusterId, 2); captureTestMaterial(next, file); assert.equal(readTestReference(file).tokens.length, 8); });
  check('world-readable reference rejected', () => { chmodSync(file, 0o644); assert.throws(() => readTestReference(file)); chmodSync(file, 0o600); });
  check('symlink reference rejected', () => { const link = resolve(directory, 'link.json'); symlinkSync(file, link); assert.throws(() => readTestReference(link)); });
  check('oversized reference rejected', () => { const large = resolve(directory, 'large.json'); writeFileSync(large, 'x'.repeat(513 * 1024), { mode: 0o600 }); assert.throws(() => readTestReference(large)); });
} finally { rmSync(directory, { recursive: true, force: true }); }
const result = { stage: 'M5', observedAt: new Date().toISOString(), kind: 'offline explicit capture flags and private-file controls; no enrollment/runtime changes', checks, allPassed: checks.every(row => row.passed), temporarySecretFilesRemoved: true, secretsPrinted: false };
mkdirSync('artifacts/M5', { recursive: true }); writeFileSync('artifacts/M5/metrics-test-reference-verification.json', JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(row => row.passed).length}/${checks.length} test-reference controls passed; temporary private references removed.`);
if (!result.allPassed) process.exitCode = 1;
