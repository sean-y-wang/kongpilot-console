import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearConfigurationWorkflowAttempt, configurationCanCreateWorkflow, configurationWorkflowAttempt, configurationWorkflowConfirmation, configurationWorkflowSourceMatches,
  readConfigurationWorkflowAttempt, storeConfigurationWorkflowAttempt, validConfigurationWorkflowIdentity } from '../../apps/console-web/src/features/configuration-workflow.model';

const id = (n: number) => `7e000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const identity = { actor: id(1), cid: id(2), wid: id(3), version: 'current-PV-1' };
function plan(): any { return { id: id(4), jobId: id(5), name: `配置计划 ${id(4)}`, clusterId: identity.cid, workspaceId: identity.wid,
  revision: 2, planRevision: 1, planHash: 'a'.repeat(64), mode: 'merge', state: 'ready', expiresAt: '2099-01-01T00:00:00.000Z',
  executionMode: 'approval', approvalRequired: true, authorityDomain: 'legacy-http-v1', durableIssueId: null, workflowId: null,
  capabilities: { apply: true, durableSubmit: true }, recoveryComplete: true, blockers: [], deleteCount: 0, deleteConfirmName: null }; }
function storage() {
  const data = new Map<string, string>();
  vi.stubGlobal('sessionStorage', { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) });
  return data;
}
afterEach(() => vi.unstubAllGlobals());
describe('configuration workflow source and original-key journal', () => {
  it('offers only the actual server-authorized unconsumed approval source', () => { expect(configurationCanCreateWorkflow(plan(), identity)).toBe(true); });
  it.each([
    { capabilities: { apply: true } }, { capabilities: { durableSubmit: false } }, { authorityDomain: undefined }, { authorityDomain: 'durable-configuration-v1' },
    { durableIssueId: id(6) }, { workflowId: id(7) }, { sourcePlanId: id(8) }, { state: 'uncertain' }, { state: 'failed' }, { state: 'expired' },
    { state: 'pending_approval' }, { expiresAt: '2020-01-01T00:00:00.000Z' }, { expiresAt: 'invalid' }, { executionMode: 'direct' }, { approvalRequired: false },
    { mode: 'promote' }, { recoveryComplete: false }, { blockers: ['CURRENT_REFERENCE_INVALID'] }, { workspaceId: id(9) }, { clusterId: id(9) },
    { name: 'caller-created-name' }, { planHash: 'invalid' }, { id: undefined }, { jobId: undefined }, { deleteCount: -1 },
  ])('does not convert an unavailable or foreign source %j', change => { expect(configurationCanCreateWorkflow({ ...plan(), ...change }, identity)).toBe(false); });
  it('requires complete current actor/scope/permission identity', () => {
    for (const change of [{ actor: undefined }, { cid: undefined }, { wid: undefined }, { actor: 'invalid' }, { version: '' }]) {
      expect(validConfigurationWorkflowIdentity({ ...identity, ...change })).toBe(false);
      expect(configurationCanCreateWorkflow(plan(), { ...identity, ...change })).toBe(false);
    }
  });
  it('reuses exact plan and delete confirmation without a client-chosen TTL or secret body', () => {
    const source = { ...plan(), deleteCount: 2, deleteConfirmName: 'DELETE 2' };
    expect(configurationWorkflowConfirmation(source, identity, source.name, 'DELETE 2')).toEqual({ planRevision: 1, planHash: source.planHash, confirmed: true, confirm_name: source.name, confirm_deletes: true });
    for (const [name, deletion] of [['wrong-name', 'DELETE 2'], [source.name, undefined], [source.name, 'DELETE 1']]) expect(() => configurationWorkflowConfirmation(source, identity, name!, deletion)).toThrow();
    expect(configurationWorkflowConfirmation(plan(), identity, plan().name)).not.toHaveProperty('ttlHours');
  });
  it('captures the original source and refuses a changed plan before a fresh command', () => {
    const original = configurationWorkflowAttempt(identity, plan(), id(10));
    expect(configurationWorkflowSourceMatches(original, plan())).toBe(true);
    for (const change of [{ id: id(11) }, { jobId: id(11) }, { revision: 3 }, { planRevision: 2 }, { planHash: 'b'.repeat(64) }, { clusterId: id(11) }, { workspaceId: id(11) }]) expect(configurationWorkflowSourceMatches(original, { ...plan(), ...change })).toBe(false);
  });
  it('retains the exact original request across permission changes and allows only its state to become unknown', () => {
    storage(); const original = configurationWorkflowAttempt(identity, plan(), id(10));
    storeConfigurationWorkflowAttempt(original); storeConfigurationWorkflowAttempt({ ...original, state: 'unknown' });
    expect(readConfigurationWorkflowAttempt({ ...identity, version: 'current-PV-2' })).toEqual({ ...original, state: 'unknown' });
    expect(() => storeConfigurationWorkflowAttempt(original)).toThrow();
    for (const change of [{ key: id(11) }, { sourcePlanId: id(11) }, { sourcePlanHash: 'b'.repeat(64) }, { sourcePlanRevision: 2 }, { version: 'current-PV-2' }]) expect(() => storeConfigurationWorkflowAttempt({ ...original, ...change })).toThrow();
  });
  it('isolates actors/clusters/workspaces and blocks a replacement source in the same original scope', () => {
    storage(); const original = configurationWorkflowAttempt(identity, plan(), id(10)); storeConfigurationWorkflowAttempt(original);
    for (const changedIdentity of [{ ...identity, actor: id(11) }, { ...identity, cid: id(11) }, { ...identity, wid: id(11) }]) expect(readConfigurationWorkflowAttempt(changedIdentity)).toBeUndefined();
    expect(() => storeConfigurationWorkflowAttempt({ ...original, sourcePlanId: id(11) })).toThrow();
  });
  it('stores no secret payload, YAML, CSRF or returned private material', () => {
    const data = storage(), original = configurationWorkflowAttempt(identity, plan(), id(10));
    storeConfigurationWorkflowAttempt({ ...original, yaml: 'private-only-RAM', csrf: 'private-only-RAM', body: { key: 'private-only-RAM' }, result: { ciphertext: 'private-only-RAM' } } as any);
    expect([...data.values()].join('')).not.toContain('private-only-RAM'); expect(Object.keys(readConfigurationWorkflowAttempt(identity)!)).toHaveLength(11);
  });
  it('preserves malformed storage as a blocking error rather than silently issuing another key', () => {
    const data = storage(), original = configurationWorkflowAttempt(identity, plan(), id(10)); storeConfigurationWorkflowAttempt(original);
    const key = [...data.keys()][0]; data.set(key, '{broken'); expect(() => readConfigurationWorkflowAttempt(identity)).toThrow(); expect(() => storeConfigurationWorkflowAttempt(original)).toThrow(); expect(data.get(key)).toBe('{broken');
  });
  it('rejects omitted journal IDs instead of equating absent UUIDs', () => {
    const data = storage(), original = configurationWorkflowAttempt(identity, plan(), id(10)); storeConfigurationWorkflowAttempt(original); const key = [...data.keys()][0];
    for (const field of ['actor', 'cid', 'wid', 'key', 'sourcePlanId', 'sourceJobId']) { const damaged: any = { ...original }; delete damaged[field]; data.set(key, JSON.stringify(damaged)); expect(() => readConfigurationWorkflowAttempt(identity)).toThrow(); }
  });
  it('clears only the original verified-command anchor, never a foreign key or changed plan', () => {
    storage(); const original = configurationWorkflowAttempt(identity, plan(), id(10)); storeConfigurationWorkflowAttempt({ ...original, state: 'unknown' });
    expect(() => clearConfigurationWorkflowAttempt({ ...original, key: id(11) })).toThrow(); expect(() => clearConfigurationWorkflowAttempt({ ...original, sourcePlanHash: 'b'.repeat(64) })).toThrow();
    clearConfigurationWorkflowAttempt(original); expect(readConfigurationWorkflowAttempt(identity)).toBeUndefined();
  });
  it('never matches malformed source pointers through equal undefined IDs', () => {
    expect(configurationWorkflowSourceMatches({} as any, {} as any)).toBe(false);
    const original = configurationWorkflowAttempt(identity, plan(), id(10));
    expect(configurationWorkflowSourceMatches({ ...original, key: undefined } as any, plan())).toBe(false);
  });
});
