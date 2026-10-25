import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensurePortalEnvironment } from '../../deploy/scripts/portal-environment.mjs';
import { validateCaptureAck, validateCaptureBundle } from '../../deploy/scripts/capture-existing-metrics-test-reference.mjs';
import { stagePlan } from '../../deploy/scripts/stage-plan.mjs';

const directories: string[] = [], secret = 'a1'.repeat(32), app = 'b2'.repeat(32), encryption = 'c3'.repeat(32);
function environment(text: string, mode = 0o600) {
  const directory = mkdtempSync(join(tmpdir(), 'kongos-m6-helper-test-')); directories.push(directory);
  const filename = join(directory, 'isolated-test-env'); writeFileSync(filename, text, { mode }); chmodSync(filename, mode); return { directory, filename };
}
const cid = '10000000-0000-4000-8000-000000000001', cid2 = '10000000-0000-4000-8000-000000000002';
const ack = () => ({ captureId: '10000000-0000-4000-8000-000000000003', path: '/dev/shm/kongos-metrics-capture-aA12bB/capture.json', clusterIds: [cid], generations: { [cid]: 7 }, count: 4 });
const purposes = [['native_scrape', 'bff'], ['collector_scrape', 'collector'], ['collector_catalog', 'bff'], ['collector_ingest', 'collector']];
function bundle() {
  const tokens = purposes.map(([purpose, audience], index) => ({ clusterId: cid, generation: 7, purpose, audience, token: String.fromCharCode(65 + index).repeat(43) }));
  return { tokens, secrets: tokens.map(row => row.token), users: [] };
}
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

describe('M6 offline Portal secret environment helper', () => {
  it('adds only missing Portal values, preserves existing bytes and leaves a private0600 regular file', () => {
    const original = `APP_SECRET=${app}\nCONSOLE_ENCRYPTION_KEY=${encryption}\nCUSTOM_VALUE=keep=literal\n`;
    const f = environment(original), result = ensurePortalEnvironment(f.filename, { random: () => secret });
    const value = readFileSync(f.filename, 'utf8');
    expect(value.startsWith(original)).toBe(true); expect(value).toContain(`PORTAL_SECRET=${secret}\n`);
    expect(value).toContain('PORTAL_WEB_PORT=8082\n'); expect(lstatSync(f.filename).mode & 0o777).toBe(0o600);
    expect(result).toEqual({ createdPortalSecret: true, existingValuesPreserved: true, privateMode0600: true });
    expect(readdirSync(f.directory)).toEqual(['isolated-test-env']);
  });
  it('never rotates an existing Portal key or overwrites production TLS/origin/port settings', () => {
    const original = `APP_SECRET=${app}\nCONSOLE_ENCRYPTION_KEY=${encryption}\nPORTAL_SECRET=${secret}\nPORTAL_PUBLIC_ORIGINS=https://developer.example.test\nPORTAL_COOKIE_SECURE=true\nCOOKIE_SECURE=true\nDEVELOPMENT_MODE=false\nPORTAL_WEB_PORT=8443\n`;
    const f = environment(original); const random = () => { throw new Error('existing secret must not be regenerated'); };
    expect(ensurePortalEnvironment(f.filename, { random }).createdPortalSecret).toBe(false);
    expect(ensurePortalEnvironment(f.filename, { random }).createdPortalSecret).toBe(false);
    expect(readFileSync(f.filename, 'utf8')).toBe(original);
  });
  it.each([0o644, 0o640, 0o660, 0o700])('refuses non-private mode %s without modifying the original', mode => {
    const f = environment('CUSTOM_VALUE=untouched\n', mode); expect(() => ensurePortalEnvironment(f.filename)).toThrow('PORTAL_ENV_PRIVATE_FILE_REQUIRED');
    expect(readFileSync(f.filename, 'utf8')).toBe('CUSTOM_VALUE=untouched\n');
  });
  it('refuses symlinks/directories/oversize files and leaves their contents untouched', () => {
    const f = environment('CUSTOM_VALUE=untouched\n'), alias = join(f.directory, 'symbolic'); symlinkSync(f.filename, alias);
    expect(() => ensurePortalEnvironment(alias)).toThrow('PORTAL_ENV_PRIVATE_FILE_REQUIRED');
    expect(() => ensurePortalEnvironment(f.directory)).toThrow('PORTAL_ENV_PRIVATE_FILE_REQUIRED');
    const large = environment('x'.repeat(131073)); expect(() => ensurePortalEnvironment(large.filename)).toThrow('PORTAL_ENV_PRIVATE_FILE_REQUIRED');
    expect(readFileSync(f.filename, 'utf8')).toBe('CUSTOM_VALUE=untouched\n');
  });
  it.each([app, encryption, 'short', 'A'.repeat(64), `${secret}\nEVIL_VALUE=1`])('rejects weak/duplicate/injected generated keys before any append', generated => {
    const original = `APP_SECRET=${app}\nCONSOLE_ENCRYPTION_KEY=${encryption}\n`, f = environment(original);
    expect(() => ensurePortalEnvironment(f.filename, { random: () => generated })).toThrow('PORTAL_ENV_SECRET_INVALID');
    expect(readFileSync(f.filename, 'utf8')).toBe(original); expect(readdirSync(f.directory)).toEqual(['isolated-test-env']);
  });
  it('rejects duplicate existing keys and preserves even a file without a final newline', () => {
    const bad = environment(`PORTAL_SECRET=${secret}\nPORTAL_SECRET=${secret}\n`);
    expect(() => ensurePortalEnvironment(bad.filename)).toThrow('PORTAL_ENV_DUPLICATE_KEY');
    const good = environment(`APP_SECRET=${app}`); ensurePortalEnvironment(good.filename, { random: () => secret });
    expect(readFileSync(good.filename, 'utf8').startsWith(`APP_SECRET=${app}\nPORTAL_SECRET=`)).toBe(true);
  });
});

describe('M6 offline metrics continuity capture validation', () => {
  it('accepts the exact four-purpose same-generation family and ignores cluster ordering only', () => {
    const reference = ack(), value = bundle(); expect(validateCaptureAck(reference, [cid])).toBe(reference); expect(validateCaptureBundle(value, reference)).toBe(value);
    const two = { ...reference, clusterIds: [cid2, cid], generations: { [cid]: 7, [cid2]: 8 }, count: 8 };
    expect(validateCaptureAck(two, [cid, cid2])).toBe(two);
  });
  it.each(['/tmp/capture.json', '/dev/shm/kongos-metrics-capture-abcdef/../capture.json', '/dev/shm/kongos-metrics-capture-abcdef/capture.json/extra', '/dev/shm/kongos-metrics-capture-ab/capture.json', '/dev/shm/kongos-metrics-capture-abcdef/capture.json\n'])('rejects unsafe capture path %s', path => {
    expect(() => validateCaptureAck({ ...ack(), path }, [cid])).toThrow('METRICS_CAPTURE_ACK_INVALID');
  });
  it.each(['foreign-cluster', 'bad-uuid', 'wrong-count', 'extra-field', 'missing-generation', 'zero-generation', 'fraction-generation'])('rejects malformed acknowledgement %s', kind => {
    const value: any = ack();
    if (kind === 'foreign-cluster') value.clusterIds = [cid2];
    if (kind === 'bad-uuid') value.captureId = 'capture-id';
    if (kind === 'wrong-count') value.count = 3;
    if (kind === 'extra-field') value.command = 'arbitrary-runtime-command';
    if (kind === 'missing-generation') value.generations = {};
    if (kind === 'zero-generation') value.generations[cid] = 0;
    if (kind === 'fraction-generation') value.generations[cid] = 1.5;
    expect(() => validateCaptureAck(value, [cid])).toThrow('METRICS_CAPTURE_ACK_INVALID');
  });
  it.each(['foreign-cluster', 'generation', 'audience', 'duplicate-purpose', 'duplicate-token', 'prototype-purpose', 'extra-field', 'missing-token', 'weak-token', 'too-long-token', 'users', 'secret-mismatch'])('rejects malformed token family %s without accepting a partial reference', kind => {
    const value: any = bundle();
    if (kind === 'foreign-cluster') value.tokens[0].clusterId = cid2;
    if (kind === 'generation') value.tokens[0].generation = 8;
    if (kind === 'audience') value.tokens[0].audience = 'collector';
    if (kind === 'duplicate-purpose') value.tokens[1].purpose = value.tokens[0].purpose;
    if (kind === 'duplicate-token') value.tokens[1].token = value.tokens[0].token;
    if (kind === 'prototype-purpose') { value.tokens[0].purpose = '__proto__'; value.tokens[0].audience = Object.prototype; }
    if (kind === 'extra-field') value.tokens[0].url = 'http://arbitrary-destination';
    if (kind === 'missing-token') value.tokens.pop();
    if (kind === 'weak-token') value.tokens[0].token = 'x'.repeat(42);
    if (kind === 'too-long-token') value.tokens[0].token = 'x'.repeat(129);
    if (kind === 'users') value.users.push({ username: 'must-not-be-in-reference' });
    if (kind === 'secret-mismatch') value.secrets[0] = 'unregistered-extra-canary';
    expect(() => validateCaptureBundle(value, ack())).toThrow('METRICS_CAPTURE_BUNDLE_INVALID');
  });
});

describe('M6 pure stage plan preserves existing monitoring', () => {
  const compose = ['compose', '--env-file', 'isolated-test-env', '-f', 'docker-compose.yml'];
  it('does not enroll/rotate/restart monitoring services during M6 and preserves explicit readonly capture sequencing', () => {
    const steps = stagePlan({ stage: 'M6', compose, portal: true, observability: true, multicluster: true, captureExistingMetrics: true });
    expect(steps[0][0]).toBe('continuity-before');
    expect(steps.filter(([name]: any) => /enroll|metrics-storage|prometheus-reload|apply-metrics-services/.test(name))).toHaveLength(0);
    const dockerCommands = steps.filter((row: any) => row[1] === 'docker').map((row: any) => row[2]);
    expect(dockerCommands.every((args: string[]) => !args.includes('down') && !args.includes('--volumes') && !args.includes('-v'))).toBe(true);
    expect(dockerCommands.filter((args: string[]) => args.includes('restart')).flat()).not.toContain('telemetry-collector');
    expect(steps.find(([name]: any) => name === 'capture-existing-metrics-test-reference')?.[2]).toContain('--test-only');
    expect(steps.findIndex(([name]: any) => name === 'continuity-after')).toBeLessThan(steps.findIndex(([name]: any) => name === 'capture-existing-metrics-test-reference'));
  });
  it('keeps initial M5 enrollment explicit and later Portal-enabled stages do not invent new enrollment', () => {
    const initial = stagePlan({ stage: 'M5', compose, observability: true, captureMetricsTokens: true });
    expect(initial.find(([name]: any) => name === 'enroll-metrics')?.[2]).toContain('--test-private-reference');
    for (const stage of ['M6', 'M7', 'M11']) {
      const later = stagePlan({ stage, compose, portal: true, observability: true });
      expect(later.some(([name]: any) => name === 'enroll-metrics')).toBe(false);
    }
  });
});
