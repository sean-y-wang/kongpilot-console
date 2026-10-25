// @ts-nocheck -- exact helper source in an isolated VM with synthetic env/RAM.
// No process.env, private reference, child process, network or Docker access.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { parse, stringify } from 'yaml';
import { M8_COMPOSE, M8Harness, entity, scope, sha256 } from './lib/m8-harness.mjs';
import { assertConfigurationReceipt } from './lib/m8-configuration-acceptance.mjs';

const toolHash = '642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed';
const check = (value, label) => { if (!value) throw Error(label); };
function fixture() {
  const area = { cid: randomUUID(), wid: randomUUID() }, actor = { user: { id: randomUUID() }, sid: randomUUID() };
  const h = { state: { phase: 'synthetic-ready', inFlight: null, requests: [], proxyChecks: [], cliIntents: [], configurationOperations: [] },
    remember: vi.fn(), snapshots: [], data: value => value.payload.data, check,
    save(extra = {}) { Object.assign(h.state, extra); h.snapshots.push(structuredClone(h.state)); },
    assertWritable() { return M8Harness.prototype.assertWritable.call(h); } };
  const input = { command: 'sync', sessionId: randomUUID(), tokenSecret: 'S'.repeat(43), stateYaml: '_format_version: "1.1"\nservices: []\n' };
  return { area, actor, h, input };
}
function runtime(spawn) {
  const source = readFileSync(new URL('./lib/m8-deck-acceptance.mjs', import.meta.url), 'utf8')
    .replace(/^import[^\n]*\n/gm, '').replace(/\bexport\s+(?=(?:async\s+)?function)/g, '');
  return runInNewContext(`${source}\n({ runM8FixedDeck, submitM8DeckApply })`, {
    spawn, randomUUID, parse, stringify, M8_COMPOSE, entity, scope, sha256, assertConfigurationReceipt,
    configurationRead: async (h, actor, area, path) => h.data(await h.request(actor, scope(area.cid, area.wid, path))),
    process: { env: { DOCKER_HOST: 'tcp://synthetic.invalid', DOCKER_CONTEXT: 'synthetic-remote', DOCKER_TLS: '1', DOCKER_TLS_VERIFY: '1', DOCKER_CERT_PATH: '/synthetic/certs', SYNTHETIC_ALLOWED: 'only-synthetic' } },
    Buffer, Date, URL, URLSearchParams, Object, Promise, Error,
    setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay), clearTimeout: timer => globalThis.clearTimeout(timer),
  });
}
function child() {
  const value = new EventEmitter(); value.stdout = new EventEmitter(); value.stderr = new EventEmitter(); value.stdin = new EventEmitter();
  value.kill = vi.fn(); value.stdin.end = vi.fn(); return value;
}
function success(command) {
  return { command, toolBinarySha256: toolHash, toolVersion: '1.2.4', toolCommit: '8e68931', exitCode: 0,
    timedOut: false, outputLimitReached: false, possibleUnknown: false, consoleJobSuccessProved: false };
}
afterEach(() => vi.useRealTimers());

describe('independent fixed decK transport and immutable input contracts', () => {
  it('fsyncs original actor/SID/input before fixed local Docker spawn and sends exactly that private stdin once', async () => {
    const f = fixture(), c = child(); let atTransport;
    const spawn = vi.fn(() => { atTransport = structuredClone(f.h.snapshots.at(-1)); return c; });
    c.stdin.end.mockImplementation(bytes => queueMicrotask(() => { c.stdout.emit('data', Buffer.from(JSON.stringify(success(JSON.parse(bytes).command)))); c.emit('close', 0, null); }));
    await expect(runtime(spawn).runM8FixedDeck(f.h, f.actor, f.area, f.input, { jobId: randomUUID() })).resolves.toMatchObject({ command: 'sync', consoleJobSuccessProved: false });
    const [program, argv, options] = spawn.mock.calls[0];
    expect(program).toBe('docker'); expect(argv[0]).toBe('--host=unix:///var/run/docker.sock'); expect(argv).toContain('--no-deps'); expect(argv).not.toContain('--build');
    expect(options.shell).toBe(false); expect(options.env).toEqual({ SYNTHETIC_ALLOWED: 'only-synthetic' });
    expect(atTransport.cliIntents[0]).toMatchObject({ state: 'prepared', actorId: f.actor.user.id, sessionId: f.actor.sid, clusterId: f.area.cid, workspaceId: f.area.wid,
      input: f.input, inputSha256: sha256(JSON.stringify(f.input)) });
    expect(c.stdin.end).toHaveBeenCalledExactlyOnceWith(JSON.stringify(f.input));
    expect(f.h.state.cliIntents[0].state).toBe('response_observed');
  });
  it('does not authorize a result for caller-mutated command instead of the original frozen sync input', async () => {
    const f = fixture(), original = structuredClone(f.input), c = child(), spawn = vi.fn(() => c);
    c.stdin.end.mockImplementation(() => queueMicrotask(() => { f.input.command = 'validate'; c.stdout.emit('data', Buffer.from(JSON.stringify(success('validate')))); c.emit('close', 0, null); }));
    await expect(runtime(spawn).runM8FixedDeck(f.h, f.actor, f.area, f.input)).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');
    expect(f.h.state.cliIntents[0]).toMatchObject({ state: 'response_unknown', input: original, inputSha256: sha256(JSON.stringify(original)) });
    expect(f.h.state.phase).toBe('stopped-cli-unknown');
  });
  it('rejects an old official 1.1.0 tool result as unknown and never replays its sync intent', async () => {
    const f = fixture(), c = child(), spawn = vi.fn(() => c), real = runtime(spawn);
    const legacy = { ...success('sync'), toolBinarySha256: '61394e30ebc92599fbccc9807e558cec018ab407d78e644c0bff5bcb0011554b', toolVersion: '1.1.0', toolCommit: 'acdb161' };
    c.stdin.end.mockImplementation(() => queueMicrotask(() => { c.stdout.emit('data', Buffer.from(JSON.stringify(legacy))); c.emit('close', 0, null); }));
    await expect(real.runM8FixedDeck(f.h, f.actor, f.area, f.input)).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');
    expect(f.h.state.cliIntents[0]).toMatchObject({ state: 'response_unknown', input: f.input, inputSha256: sha256(JSON.stringify(f.input)) });
    expect(f.h.state.phase).toBe('stopped-cli-unknown');
    await expect(real.runM8FixedDeck(f.h, f.actor, f.area, f.input)).rejects.toThrow('M8_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');
    expect(spawn).toHaveBeenCalledTimes(1); expect(f.h.state.cliIntents).toHaveLength(1);
  });
  it('durably marks synchronous spawn failure unknown and refuses to replay the original sync intent', async () => {
    const f = fixture(), spawn = vi.fn(() => { throw Error('synthetic spawn failure'); }), real = runtime(spawn);
    await expect(real.runM8FixedDeck(f.h, f.actor, f.area, f.input)).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');
    expect(f.h.state.cliIntents[0].state).toBe('response_unknown');
    await expect(real.runM8FixedDeck(f.h, f.actor, f.area, f.input)).rejects.toThrow('M8_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');
    expect(spawn).toHaveBeenCalledTimes(1); expect(f.h.state.cliIntents).toHaveLength(1);
  });
  it('bounds shutdown when a sync child exceeds stdout budget and ignores SIGTERM', async () => {
    vi.useFakeTimers(); const f = fixture(), c = child(), spawn = vi.fn(() => c), real = runtime(spawn); let outcome;
    c.stdin.end.mockImplementation(() => queueMicrotask(() => c.stdout.emit('data', Buffer.alloc(65537))));
    const pending = real.runM8FixedDeck(f.h, f.actor, f.area, f.input).then(value => { outcome = { value }; }, error => { outcome = { error }; });
    await vi.advanceTimersByTimeAsync(160000);
    expect(c.kill.mock.calls.flat()).toContain('SIGTERM'); expect(c.kill.mock.calls.flat()).toContain('SIGKILL');
    expect(outcome?.error?.message).toBe('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');
    expect(f.h.state.cliIntents[0].state).toBe('response_unknown'); await pending;
    await expect(real.runM8FixedDeck(f.h, f.actor, f.area, f.input)).rejects.toThrow('M8_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');
    expect(spawn).toHaveBeenCalledTimes(1);
  });
  it('rejects a running receipt from a different plan without polling terminal state or attempting CLI', async () => {
    const f = fixture(), planId = randomUUID(), jobId = randomUUID(), plan = { id: planId, planHash: 'a'.repeat(64), planRevision: 1, revision: 1, name: 'Synthetic plan', deleteCount: 0, executionMode: 'direct', capabilities: { apply: true } };
    f.h.request = vi.fn(async (_actor, _path, method = 'GET', _body, options) => ({ payload: { data: method === 'GET' ? { entity: plan } : {
      domain: 'configuration', durable: true, id: jobId, jobId, idempotencyKey: options.key, actorId: f.actor.user.id, clusterId: f.area.cid, workspaceId: f.area.wid,
      originalScope: { clusterId: f.area.cid, workspaceId: f.area.wid }, kind: 'apply', state: 'running', driver: 'deck', planId: randomUUID(), executionId: randomUUID(), executionCompleted: false } } }));
    const spawn = vi.fn();
    await expect(runtime(spawn).submitM8DeckApply(f.h, f.actor, f.area, { planId, planHash: plan.planHash, planRevision: 1 })).rejects.toThrow();
    expect(f.h.request).toHaveBeenCalledTimes(2); expect(f.h.request.mock.calls.filter(value => value[2] === 'POST')).toHaveLength(1); expect(spawn).not.toHaveBeenCalled();
  });
});
