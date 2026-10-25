// @ts-nocheck -- actual policy/finalizer functions; synthetic RAM only.
import { describe, expect, it } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { m8CapturedSecrets, m8PublicJwtIssuer, m8SecretForms, M8_LOG_SERVICES } from './lib/m8-secret-scan-policy.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
function fixture() {
  const area = { cid: randomUUID(), wid: randomUUID() }, consumer = { id: randomUUID() }, admin = { user: { id: randomUUID() }, sid: randomUUID() }, key = randomUUID();
  const inputs = { jwt: { key: 'synthetic-independent-m8-jwt', secret: 'SyntheticIndependentSigningSecret!47' } };
  const jwt = { id: randomUUID(), consumer, key: '[REDACTED:0000000000000000]', secret: '[REDACTED:1111111111111111]' }, body = { ...inputs.jwt, tags: ['synthetic-independent-m8'] };
  const packet = { index: 0, method: 'POST', path: `/api/v1/clusters/${area.cid}/consumers/${consumer.id}/credentials/jwt`, query: `?workspaceId=${area.wid}`,
    clusterId: area.cid, workspaceId: area.wid, actorId: admin.user.id, sessionId: admin.sid, key, body, bodySha256: sha(JSON.stringify(body)),
    headers: { Cookie: 'kongos_access=SyntheticIndependentAccess!47', 'X-Idempotency-Key': key, 'X-CSRF-Token': 'SyntheticIndependentCsrf!47', 'Content-Type': 'application/json' },
    state: 'response_observed', status: 201, responseData: { entity: jwt }, requestId: randomUUID() };
  return { version: 1, milestone: 'M8', testTag: 'synthetic-independent-m8', secrets: [inputs.jwt.key, inputs.jwt.secret, 'SyntheticIndependentAccess!47', 'SyntheticIndependentCsrf!47'],
    requests: [packet], sessions: { admin }, nativeFixture: { area, consumer, inputs, credentials: { jwt } }, proxyChecks: [], cliIntents: [], configurationOperations: [] };
}
function download(r) {
  const text = '_format_version: "1.1"\nconsumers:\n- basicauth_credentials:\n  - password: SyntheticOriginalBcryptHash!47\n  keyauth_credentials:\n  - key: SyntheticYamlApiKey!47\nplugins:\n- name: oauth2\n  config:\n    provision_key: SyntheticYamlProvisionKey!47\n    redis_password: SyntheticYamlRedisPassword!47\n    keys: [SyntheticYamlArrayKey!47]\n';
  const p = { ...structuredClone(r.requests[0]), index: r.requests.length, key: randomUUID(), path: `/api/v1/clusters/${r.nativeFixture.area.cid}/configuration/exports/${randomUUID()}/download`, body: { revision: 1 },
    rawResponseText: text, responseSha256: sha(text), responseByteCount: Buffer.byteLength(text), raw: true };
  p.headers['X-Idempotency-Key'] = p.key; p.bodySha256 = sha(JSON.stringify(p.body)); r.requests.push(p); return p;
}
function addPacket(r, body, responseData) {
  const p = { ...structuredClone(r.requests[0]), index: r.requests.length, key: randomUUID(), body, responseData, path: `/api/v1/clusters/${r.nativeFixture.area.cid}/entities/services`, requestId: randomUUID() };
  p.headers['X-Idempotency-Key'] = p.key; p.bodySha256 = sha(JSON.stringify(p.body)); r.requests.push(p); return p;
}
function chain(n, tail = { terminal: true }) { for (let i = 0; i < n; i++) tail = { next: tail }; return tail; }

describe('independent SOURCE M8 exact secret provenance and unchanged budgets', () => {
  it('exempts only an exact actual typed public issuer while retaining signing, cookie and CSRF material', () => {
    const r = fixture(), result = m8CapturedSecrets(r);
    expect(m8PublicJwtIssuer(r, r.nativeFixture.inputs.jwt.key)).toBe(true);
    expect(result.values).not.toContain(r.nativeFixture.inputs.jwt.key); expect(result.values).not.toContain(r.requests[0].key);
    expect(result.values).toEqual(expect.arrayContaining(r.secrets.slice(1)));
    expect(result.classifiedPublic).toEqual([{ kind: 'exact-created-jwt-issuer', sha256: sha(r.nativeFixture.inputs.jwt.key) }]);
  });
  it('requires the actual admin SID, UUID transport/request IDs and complete original headers before a public issuer exception', () => {
    for (const change of ['foreignSid', 'missingSid', 'transportKey', 'requestId', 'emptyCookie', 'missingCsrf', 'foreignCredential', 'wrongParent']) {
      const r = fixture(), p = r.requests[0];
      if (change === 'foreignSid') p.sessionId = randomUUID();
      if (change === 'missingSid') delete p.sessionId;
      if (change === 'transportKey') p.key = p.headers['X-Idempotency-Key'] = 'synthetic-not-a-uuid';
      if (change === 'requestId') delete p.requestId;
      if (change === 'emptyCookie') p.headers.Cookie = '';
      if (change === 'missingCsrf') delete p.headers['X-CSRF-Token'];
      if (change === 'foreignCredential') p.responseData = { entity: { ...p.responseData.entity, id: randomUUID() } };
      if (change === 'wrongParent') p.responseData = { entity: { ...p.responseData.entity, consumer: { id: randomUUID() } } };
      expect(m8PublicJwtIssuer(r, r.nativeFixture.inputs.jwt.key), change).toBe(false);
      expect(m8CapturedSecrets(r).values, change).toContain(r.nativeFixture.inputs.jwt.key);
    }
  });
  it('same-value password in any retained context overrides the exact public issuer exception', () => {
    const r = fixture(), h = structuredClone(r); h.extra = { password: r.nativeFixture.inputs.jwt.key };
    expect(m8CapturedSecrets(r, [h]).values).toContain(r.nativeFixture.inputs.jwt.key);
  });
  it('accepts a complete metadata packet copy, but a body or response copy keeps every key confidential', () => {
    for (const place of ['metadata', 'body', 'response']) {
      const r = fixture(), copy = structuredClone(r.requests[0]), h = structuredClone(r);
      h.originalHttpRequests = [copy];
      if (place === 'body') addPacket(r, { inner: { originalHttpRequests: [copy] } }, { ok: true });
      if (place === 'response') addPacket(r, { harmless: true }, { originalHttpRequests: [copy] });
      const result = m8CapturedSecrets(r, [h]);
      if (place === 'metadata') expect(result.values).not.toContain(copy.key);
      else expect(result.values, place).toContain(copy.key);
    }
  });
  it('shared body/response redaction subtrees retain different effective secret contexts', () => {
    const r = fixture(), shared = { secret: '[REDACTED:abcdef0123456789]' };
    addPacket(r, { nested: shared }, { nested: shared });
    expect(m8CapturedSecrets(r).values).toContain(shared.secret);
  });
  it('changed or differently ordered historical packets lose exact metadata-key provenance', () => {
    for (const change of ['sid', 'missingHeaders', 'propertyOrder']) {
      const r = fixture(), h = structuredClone(r);
      if (change === 'sid') h.requests[0].sessionId = randomUUID();
      if (change === 'missingHeaders') delete h.requests[0].headers;
      if (change === 'propertyOrder') h.requests[0] = Object.fromEntries(Object.entries(h.requests[0]).reverse());
      expect(m8CapturedSecrets(r, [h]).values, change).toContain(r.requests[0].key);
    }
  });
  it('harvests native bcrypt/API keys and plugin provision/Redis/array secrets from a hash-bound original YAML', () => {
    const r = fixture(); download(r);
    expect(m8CapturedSecrets(r).values).toEqual(expect.arrayContaining(['SyntheticOriginalBcryptHash!47', 'SyntheticYamlApiKey!47', 'SyntheticYamlProvisionKey!47', 'SyntheticYamlRedisPassword!47', 'SyntheticYamlArrayKey!47']));
  });
  it('fails closed for missing or mismatched raw YAML digest/byte proof and malformed decK YAML', () => {
    for (const change of ['missingSha', 'wrongSha', 'missingBytes', 'wrongBytes', 'wrongFormat', 'duplicateYamlKey']) {
      const r = fixture(), p = download(r);
      if (change === 'missingSha') delete p.responseSha256;
      if (change === 'wrongSha') p.responseSha256 = '0'.repeat(64);
      if (change === 'missingBytes') delete p.responseByteCount;
      if (change === 'wrongBytes') p.responseByteCount++;
      if (change === 'wrongFormat') p.rawResponseText = '_format_version: "3.0"\n';
      if (change === 'duplicateYamlKey') p.rawResponseText = '_format_version: "1.1"\nkey: first\nkey: second\n';
      if (['wrongFormat', 'duplicateYamlKey'].includes(change)) { p.responseSha256 = sha(p.rawResponseText); p.responseByteCount = Buffer.byteLength(p.rawResponseText); }
      expect(() => m8CapturedSecrets(r), change).toThrow();
    }
  });
  it('validates history count and cumulative original registry without accepting omitted or invalid strings', () => {
    const r = fixture(), h = structuredClone(r); h.secrets.push('SyntheticHistoricalOnlySecret!47');
    expect(() => m8CapturedSecrets(r, [h])).toThrow('REGISTRY_INCOMPLETE');
    expect(() => m8CapturedSecrets(r, Array(33).fill(r))).toThrow('REGISTRY_HISTORY_INVALID');
    for (const bad of ['', {}, 7]) { const q = fixture(); q.secrets.push(bad); expect(() => m8CapturedSecrets(q)).toThrow('REGISTRY_HISTORY_INVALID'); }
  });
  it('allows cloned histories over 200000 physical leaves without increasing the 200000 unique structure limit', () => {
    const r = fixture(); r.neutral = Array.from({ length: 12500 }, (_, ordinal) => ({ ordinal }));
    expect(m8CapturedSecrets(r, Array.from({ length: 16 }, () => structuredClone(r))).uniqueStructures).toBeLessThan(200000);
    const q = fixture(); q.neutral = Array.from({ length: 200001 }, (_, ordinal) => ({ ordinal }));
    expect(() => m8CapturedSecrets(q)).toThrow('UNIQUE_BUDGET');
  }, 20000);
  it('rejects cycles and deep aliases even when a shared subtree has already been hashed at a shallow path', () => {
    const r = fixture(); r.cycle = r; expect(() => m8CapturedSecrets(r)).toThrow('DEPTH_CYCLE');
    const q = fixture(), shared = chain(30); q.shallow = shared;
    const h = { version: 1, milestone: 'M8', testTag: q.testTag, secrets: [...q.secrets], deep: chain(40, shared), shallow: shared };
    expect(() => m8CapturedSecrets(q, [h])).toThrow('DEPTH_CYCLE');
  });
});

// Execute the unchanged scanner/finalizer source with a completely synthetic
// filesystem, process and child-process transport. No host env is consulted.
function finalizerFixture(encodedLeak = '') {
  const r = fixture(), scanSecret = 'Synthetic Scan+/\nSecret!47'; r.secrets.push(scanSecret);
  r.phase = 'cleanup-complete'; r.inFlight = null; r.httpAcceptanceComplete = true; r.deckAcceptance = { complete: true }; r.rbacAcceptance = { complete: true };
  r.cleanup = { businessCompleted: true }; r.requests[0].startedAt = '2026-01-02T03:04:05.000Z'; r.pemDirectory = '/tmp/kongos-m8-pem-synthetic';
  r.manualUiJournal = { phase: 'complete', attempts: Array.from({ length: 12 }, () => ({ state: 'succeeded' })) };
  const reports = { http: { actualM8Complete: true }, manual: { plannedActions: Array(12).fill({ synthetic: true }), successfulUiWrites: 12, unknownUiWrites: 0 },
    cleanup: { auditWriteCoverage: { allCovered: true, coveredWrites: 4, successfulWrites: 3, recoveredSuccessfulCommits: 1 } } };
  const files = new Map(), operations = [], descriptors = new Map(); let descriptor = 100;
  r.finalScanHandoff = { version: 1, phase: 'ready', testTag: r.testTag, evidence: {} };
  for (const [name, report] of Object.entries(reports)) {
    const path = `artifacts/M8/synthetic-${name}.json`, bytes = Buffer.from(JSON.stringify({ ...report, allPassed: true, failed: 0, testTag: r.testTag }));
    files.set(path, bytes); r.finalScanHandoff.evidence[name] = { path, sha256: sha(bytes) };
  }
  files.set('synthetic-source-candidate.txt', Buffer.from(encodedLeak));
  const constants = { O_RDONLY: 0, O_NOFOLLOW: 131072, O_NONBLOCK: 2048 }, uid = 123;
  const stat = directory => ({ isFile: () => !directory, isDirectory: () => directory, isSymbolicLink: () => false, uid, mode: directory ? 0o700 : 0o600, nlink: 1, size: 0 });
  const fs = { constants, existsSync: path => files.has(path),
    openSync(path, flags) { expect(files.has(path)).toBe(true); expect(flags & constants.O_NOFOLLOW).toBe(constants.O_NOFOLLOW); const fd = descriptor++; descriptors.set(fd, path); return fd; },
    fstatSync(fd) { return { ...stat(false), size: files.get(descriptors.get(fd)).length }; },
    readFileSync(path) { const key = typeof path === 'number' ? descriptors.get(path) : path; expect(files.has(key)).toBe(true); return files.get(key); }, closeSync: fd => descriptors.delete(fd),
    readdirSync: () => [], lstatSync: path => { expect(path).toBe(r.pemDirectory); return stat(true); },
    rmSync(path) { operations.push({ op: 'delete', path }); files.delete(path); }, rmdirSync: path => operations.push({ op: 'rmdir', path }) };
  const execFileSync = (command, args) => {
    operations.push({ op: 'command', command, args });
    if (command === 'git') return 'synthetic-source-candidate.txt\0';
    expect(command).toBe('docker'); expect(args[0]).toBe('--host=unix:///var/run/docker.sock');
    if (args.includes('inspect')) return 'synthetic_project\n';
    if (args.includes('compose')) return 'a'.repeat(64) + '\n';
    if (args.at(-1) === '{{.Label "com.docker.compose.service"}}') return M8_LOG_SERVICES.join('\n') + '\n';
    return 'b'.repeat(12) + '\n';
  };
  const scannerSource = readFileSync(new URL('./check-artifacts.mjs', import.meta.url), 'utf8').replace(/^import[^\n]+;\n/gm, '').split('if (process.argv[1]')[0].replace(/export /g, '');
  const scan = runInNewContext(scannerSource + '\nfindSecretArtifacts;', { ...fs, execFileSync, Buffer });
  const processMock = { env: { M8_FINAL_SCAN_READY: 'true', DOCKER_HOST: 'synthetic-foreign-daemon', DOCKER_CONTEXT: 'synthetic-foreign-context' }, argv: ['node', 'synthetic-finalizer', '--evidence-complete'], getuid: () => uid, exitCode: undefined };
  const source = readFileSync(new URL('./finalize-m8-secret-scan.mjs', import.meta.url), 'utf8').replace(/^import[^\n]+;\n/gm, '');
  runInNewContext(source, { ...fs, Buffer, process: processMock, console: { log: () => {} }, join: (...values) => values.join('/'), parseEnv: () => ({}),
    execFileSync, spawnSync(command, args, options) { expect(command).toBe('docker'); expect(args[0]).toBe('--host=unix:///var/run/docker.sock');
      expect(options.env.DOCKER_HOST).toBeUndefined(); expect(options.env.DOCKER_CONTEXT).toBeUndefined(); operations.push({ op: 'logs', args }); return { status: 0, stdout: '', stderr: '' }; },
    collectEnvironmentSecrets: () => [], findSecretArtifacts: scan, M8_REFERENCE: '/synthetic-private-reference.json', M8_HISTORY_DIRECTORY: '/synthetic-history', M8_COMPOSE: ['compose'],
    readM8Reference: () => r, readM8PrivateHistories: () => { operations.push({ op: 'validated-history' }); return []; }, sha256: sha,
    durableJson(path, value) { operations.push({ op: 'durable', path, passed: value.allPassed }); files.set(path, Buffer.from(JSON.stringify(value))); },
    m8CapturedSecrets, m8SecretForms, M8_LOG_SERVICES });
  return { operations, report: JSON.parse(files.get('artifacts/M8/runtime-secret-artifact-scan.json')), exitCode: processMock.exitCode, scanSecret, descriptors };
}

describe('independent unchanged M8 finalizer and actual artifact scanner with RAM files only', () => {
  it('collects every required log stream and durably writes a green scan before any private removal', () => {
    const { operations, report, exitCode, descriptors } = finalizerFixture();
    expect(exitCode).toBe(0); expect(report.allPassed).toBe(true); expect(report.runtimeLogs).toHaveLength(9); expect(descriptors.size).toBe(0);
    const durable = operations.findIndex(item => item.op === 'durable' && item.path === 'artifacts/M8/runtime-secret-artifact-scan.json');
    const firstDelete = operations.findIndex(item => item.op === 'delete'); expect(durable).toBeGreaterThan(-1); expect(firstDelete).toBeGreaterThan(durable);
    expect(operations.slice(0, firstDelete).filter(item => item.op === 'logs')).toHaveLength(9);
    expect(operations.slice(0, firstDelete).filter(item => item.op === 'validated-history')).toHaveLength(2);
  });
  it('actual artifact scanning catches raw, JSON escaped, URI and base64 forms and removes nothing on any leak', () => {
    const value = 'Synthetic Scan+/\nSecret!47', forms = [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString('base64')];
    expect(m8SecretForms([value])).toEqual(expect.arrayContaining(forms));
    for (const form of forms) {
      const { operations, report, exitCode } = finalizerFixture(form);
      expect(exitCode).toBe(1); expect(report.allPassed).toBe(false); expect(report.leaks).toContain('synthetic-source-candidate.txt');
      expect(operations.some(item => ['delete', 'rmdir'].includes(item.op))).toBe(false); expect(report.privateReferenceRemoved).toBe(false);
    }
  });
});
