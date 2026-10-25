import { afterEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { M6Harness, cookieMerge, portalScope, privateReference, releasedReservation } from './lib/m6-harness.mjs';

const directories: string[] = [];
function fixture(liveEnabled = false) {
  const directory = mkdtempSync(join(tmpdir(), 'kongos-m6-harness-unit-')); directories.push(directory);
  const referencePath = join(directory, 'reference.json');
  return { referencePath, harness: new M6Harness({ referencePath, liveEnabled }) };
}
afterEach(() => { vi.unstubAllGlobals(); for (const directory of directories.splice(0)) rmSync(directory, { force: true, recursive: true }); });

describe('M6 runner safety and lost-response evidence (offline harness tests)', () => {
  it('blocks HTTP before the explicit unified deployment handoff', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    const { harness } = fixture();
    await expect(harness.portal(null, '/tenants')).rejects.toThrow('exclusive live handoff');
    await expect(harness.request(null, '/clusters')).rejects.toThrow('exclusive live handoff');
    expect(fetch).not.toHaveBeenCalled();
  });
  it('journals the original key, exact tenant and request BEFORE the first wire call', async () => {
    const { harness, referencePath } = fixture(true);
    const key = randomUUID(), password = `Aa7!${randomUUID()}`;
    vi.stubGlobal('fetch', vi.fn(async () => {
      const saved = JSON.parse(readFileSync(referencePath, 'utf8'));
      expect(saved.writeAttempts).toHaveLength(1);
      expect(saved.writeAttempts[0]).toMatchObject({ key, path: '/api/v1/portal/auth/register', state: 'not_observed', clusterId: 'c1', workspaceId: 'w1' });
      expect(saved.writeAttempts[0].body.password).toBe(password);
      expect(saved.secrets).toContain(password);
      return new Response(JSON.stringify({ data: { status: 'pending' }, meta: { requestId: randomUUID() } }), { status: 202 });
    }));
    await harness.portal(null, '/auth/register', 'POST', { clusterId: 'c1', workspaceId: 'w1', password }, { key });
    expect(JSON.parse(readFileSync(referencePath, 'utf8')).writeAttempts[0].httpStatus).toBe(202);
  });
  it('retains unknown write evidence and never automatically replays a POST', async () => {
    const { harness, referencePath } = fixture(true), key = randomUUID();
    const fetch = vi.fn(async () => { throw new TypeError('synthetic connection closed'); }); vi.stubGlobal('fetch', fetch);
    await expect(harness.portal(null, '/requests', 'POST', { clusterId: 'c1', workspaceId: 'w1', applicationId: randomUUID() }, { key })).rejects.toThrow(TypeError);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(JSON.parse(readFileSync(referencePath, 'utf8')).writeAttempts[0]).toMatchObject({ key, state: 'response_unknown' });
  });
  it('preserves trusted telemetry material and prior manual secrets when saving a checkpoint', () => {
    const { harness, referencePath } = fixture();
    const token = randomUUID();
    writeFileSync(referencePath, JSON.stringify({ tokens: [{ purpose: 'collector_ingest', token }], secrets: [token], manualMarker: { unchanged: true } }), { mode: 0o600 });
    harness.saveReference({ checkpoint: { phase: 'before-fixtures' } });
    const saved = privateReference(referencePath);
    expect(saved.tokens[0].token).toBe(token); expect(saved.manualMarker.unchanged).toBe(true); expect(saved.secrets).toContain(token);
  });
  it('rejects a world-readable reference and symlink before reading credentials', () => {
    const { referencePath } = fixture();
    writeFileSync(referencePath, '{}', { mode: 0o600 }); chmodSync(referencePath, 0o644);
    expect(() => privateReference(referencePath)).toThrow('ownership, mode or size');
    chmodSync(referencePath, 0o600); symlinkSync(referencePath, `${referencePath}.link`);
    expect(() => privateReference(`${referencePath}.link`)).toThrow('ownership, mode or size');
  });
  it('separates portal tenant scope and cookie names without exposing secret values', () => {
    expect(portalScope('/auth/me?clusterId=wrong&workspaceId=wrong', { clusterId: 'c1', workspaceId: 'w1' })).toBe('/auth/me?clusterId=c1&workspaceId=w1');
    const old = randomUUID(), next = randomUUID();
    const jar = cookieMerge(`kongos_portal_access=${old}; kongos_access=console`, [`kongos_portal_access=${next}; Path=/api/v1/portal; HttpOnly; SameSite=Strict`]);
    expect(jar).toBe(`kongos_portal_access=${next}; kongos_access=console`);
  });
  it('rejects native Admin fixture access and write SQL in the evidence helper', () => {
    const { harness } = fixture(true);
    expect(() => harness.native({}, '/consumers', 'POST', {})).toThrow('no native Admin fixture escape');
    expect(() => harness.consoleRead('DELETE FROM portal_credentials')).toThrow('read-only');
    expect(() => harness.consoleRead('SELECT 1; DELETE FROM portal_credentials')).toThrow('read-only');
  });
  it('pins direct-create responses to the actual portal object and terminal receipt', () => {
    const { harness } = fixture();
    const actual = { id: randomUUID(), name: 'scoped publication', revision: 2 };
    expect(harness.metadataEntity({ entity: actual, workflowId: randomUUID(), receipt: { state: 'succeeded' } }, 'Source/Contract', 'publication')).toBe(actual);
  });
  it('rejects a workflow summary or incomplete receipt before using its UUID as a portal object', () => {
    const { harness } = fixture();
    const workflowId = randomUUID();
    expect(() => harness.metadataEntity({ entity: { id: workflowId, kind: 'portal-metadata' }, workflowId, receipt: { state: 'succeeded' } }, 'Source/Contract', 'publication')).toThrow();
    expect(() => harness.metadataEntity({ entity: { id: randomUUID() }, workflowId, receipt: { state: 'running' } }, 'Source/Contract', 'settings')).toThrow();
  });
  it('retains a returned key before releasing the response and preserves unknown server state for receipt recovery', async () => {
    const { harness, referencePath } = fixture(true);
    const returnedKey = randomUUID();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { key: returnedKey }, meta: { requestId: randomUUID() } }), { status: 201 })));
    await harness.portal(null, '/applications/example/reveal', 'POST', { clusterId: 'c1', workspaceId: 'w1' });
    const saved = privateReference(referencePath);
    expect(saved.secrets).toContain(returnedKey);
    expect(saved.writeAttempts[0].responseData.key).toBe(returnedKey);
    harness.observed(saved.writeAttempts[0], { status: 503, payload: { error: { code: 'WRITE_RESULT_UNKNOWN', details: { state: 'uncertain' } } } });
    expect(saved.writeAttempts[0]).toMatchObject({ state: 'response_observed', serverState: 'uncertain', errorCode: 'WRITE_RESULT_UNKNOWN' });
  });
  it('recognizes only a terminal unused reservation whose independent facts are all complete', () => {
    const facts = { reservation_released_at: new Date().toISOString(), state: 'disabled', workflow_state: 'cancelled', current_generation: 0, current_credential_id: null, acl_credential_ref_id: null, no_live_workflows: true, no_executions: true, no_bound_native_steps: true, no_issued_credentials: true, no_mutation_receipts: true, no_native_operations: true, no_credential_refs: true };
    expect(releasedReservation(facts)).toBe(true);
    expect(releasedReservation({ ...facts, workflow_state: 'rejected' })).toBe(true);
    expect(releasedReservation({ ...facts, no_executions: false })).toBe(false);
    expect(releasedReservation({ ...facts, no_bound_native_steps: false })).toBe(false);
    expect(releasedReservation({ ...facts, no_issued_credentials: false })).toBe(false);
    expect(releasedReservation({ ...facts, no_mutation_receipts: false })).toBe(false);
    expect(releasedReservation({ ...facts, no_credential_refs: false })).toBe(false);
    expect(releasedReservation({ ...facts, no_live_workflows: false })).toBe(false);
    expect(releasedReservation({ ...facts, no_native_operations: false })).toBe(false);
  });
  it('never treats disabled, uncertain, issued or omitted reservation facts as a cleanup permission', () => {
    const facts = { reservation_released_at: new Date().toISOString(), state: 'disabled', workflow_state: 'cancelled', current_generation: 0, no_live_workflows: true, no_executions: true, no_bound_native_steps: true, no_issued_credentials: true, no_mutation_receipts: true, no_native_operations: true, no_credential_refs: true };
    expect(releasedReservation({ ...facts, reservation_released_at: null })).toBe(false);
    expect(releasedReservation({ ...facts, workflow_state: 'uncertain' })).toBe(false);
    expect(releasedReservation({ ...facts, current_generation: 1 })).toBe(false);
    expect(releasedReservation({ ...facts, current_credential_id: randomUUID() })).toBe(false);
    expect(releasedReservation({ ...facts, no_issued_credentials: undefined })).toBe(false);
    expect(releasedReservation(undefined)).toBe(false);
  });
});
