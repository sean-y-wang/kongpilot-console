import { afterEach, describe, expect, it, vi } from 'vitest';
import { canInScope, canManageRegistry, grantMatches, hasModule, logicalGrantTag } from '../../apps/console-web/src/api/permissions';
import { newIdempotencyKey } from '../../apps/console-web/src/api/idempotency';
import { safeRecoveryReferences } from '../../apps/console-web/src/api/workspace-scope';
import type { Capabilities, EffectiveGrant } from '../../apps/console-web/src/api/types';

const cid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', wid = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', actor = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', entityId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const grant: EffectiveGrant = { cluster_id: cid, workspace_id: wid, module: 'services', action: 'write', scope_type: 'tag_group', scope_values: ['kos-tag-dGVhbTpwYXk'] };
function capabilities(grants: EffectiveGrant[]): Capabilities { return { grants, modules: {}, clusters: [cid], platformAdmin: false }; }
afterEach(() => vi.unstubAllGlobals());

describe('M4 frontend authorization contracts', () => {
  it('does not combine module, action or scope from independent grant rows', () => {
    const caps = capabilities([{ ...grant, action: 'read' }, { ...grant, module: 'routes' }, { ...grant, workspace_id: null, scope_type: 'workspace', scope_values: ['eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'] }]);
    expect(canInScope(caps, 'services', 'write', { clusterId: cid, workspaceId: wid, entity: { id: entityId, tags: ['team:pay'] } })).toBe(false);
  });
  it('requires cluster and workspace and business-tag intersection to match together', () => {
    const scope = { clusterId: cid, workspaceId: wid, entity: { id: entityId, tags: ['team:pay'] } };
    expect(grantMatches(grant, 'services', 'write', scope)).toBe(true);
    expect(grantMatches(grant, 'services', 'write', { ...scope, clusterId: entityId })).toBe(false);
    expect(grantMatches(grant, 'services', 'write', { ...scope, workspaceId: entityId })).toBe(false);
    expect(grantMatches(grant, 'services', 'write', { ...scope, entity: { id: entityId, tags: ['team:other'] } })).toBe(false);
    expect(grantMatches(grant, 'services', 'write', { clusterId: cid, workspaceId: wid })).toBe(false);
  });
  it('distinguishes potential creation from existing-entity authorization', () => {
    expect(grantMatches(grant, 'services', 'write', { clusterId: cid, workspaceId: wid, potential: true })).toBe(true);
    expect(grantMatches({ ...grant, scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: entityId }] }, 'services', 'write', { clusterId: cid, workspaceId: wid, potential: true })).toBe(false);
  });
  it('entity whitelist matches both the exact type and ID', () => {
    const row: EffectiveGrant = { ...grant, scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: entityId }] };
    const scope = { clusterId: cid, workspaceId: wid, entityType: 'services', entity: { id: entityId } };
    expect(grantMatches(row, 'services', 'write', scope)).toBe(true);
    expect(grantMatches(row, 'services', 'write', { ...scope, entityType: 'routes' })).toBe(false);
    expect(grantMatches(row, 'services', 'write', { ...scope, entity: { id: actor } })).toBe(false);
  });
  it('workspace scope uses its own authorized values rather than broad module aggregation', () => {
    const row = { ...grant, scope_type: 'workspace' as const, scope_values: [wid], workspace_id: null };
    expect(grantMatches(row, 'services', 'write', { clusterId: cid, workspaceId: wid })).toBe(true);
    expect(grantMatches(row, 'services', 'write', { clusterId: cid, workspaceId: entityId })).toBe(false);
  });
  it('does not infer secret access from native write/delete grants', () => {
    const caps = capabilities([{ ...grant, scope_type: 'global', scope_values: [] }]);
    expect(canInScope(caps, 'secrets', 'read', { clusterId: cid, workspaceId: wid, entity: { id: entityId } })).toBe(false);
    expect(hasModule(undefined, 'services')).toBe(false);
    expect(canInScope(undefined, 'services', 'delete')).toBe(false);
  });
  it('normalizes target/credential module ownership without inventing inheritance', () => {
    expect(grantMatches({ ...grant, module: 'upstreams', scope_type: 'global' }, 'targets', 'write', { clusterId: cid, workspaceId: wid })).toBe(true);
    expect(grantMatches({ ...grant, module: 'consumers', scope_type: 'global' }, 'key-auth', 'write', { clusterId: cid, workspaceId: wid })).toBe(true);
    expect(grantMatches(grant, 'plugins', 'write', { clusterId: cid, workspaceId: wid })).toBe(false);
  });
  it('decodes encoded UTF-8 business labels and handles malformed labels safely', () => {
    expect(logicalGrantTag('kos-tag-dGVhbTpwYXk')).toBe('team:pay');
    expect(logicalGrantTag('kos-ws-pay')).toBe('workspace:pay');
    expect(logicalGrantTag('kos-tag-!')).toBe('kos-tag-!');
  });
  it('requires global registry authority for Admin destinations, and whole-cluster authority for shared data sources', () => {
    const row = { ...grant, module: 'clusters', scope_type: 'global' as const, scope_values: [], workspace_id: null };
    expect(canManageRegistry(capabilities([row]), 'clusters', 'write', cid)).toBe(false);
    expect(canManageRegistry(capabilities([{ ...row, cluster_id: null }]), 'clusters', 'write')).toBe(true);
    expect(canManageRegistry(capabilities([{ ...row, module: 'data-sources' }]), 'data-sources', 'write', cid)).toBe(true);
    expect(canManageRegistry(capabilities([{ ...row, module: 'data-sources' }]), 'data-sources', 'write', actor)).toBe(false);
    expect(canManageRegistry(capabilities([{ ...row, module: 'data-sources', workspace_id: wid }]), 'data-sources', 'write', cid)).toBe(false);
    expect(canManageRegistry(capabilities([{ ...row, module: 'data-sources', scope_type: 'workspace', scope_values: [wid] }]), 'data-sources', 'write', cid)).toBe(false);
  });
});
describe('M4 IAM recovery and HTTP LAN operation identity', () => {
  it('IAM references preserve identifiers and actor but strip fake gateway scope and payload', () => {
    const now = Date.now(), rows = safeRecoveryReferences([{ actor_id: actor, domain: 'iam', cid, wid, idempotencyKey: entityId, state: 'uncertain', created_at: new Date(now).toISOString(), payload: { password: 'must-not-persist' } }], actor, now);
    expect(rows).toEqual([{ actor_id: actor, domain: 'iam', idempotencyKey: entityId, state: 'uncertain', created_at: new Date(now).toISOString() }]);
    expect(safeRecoveryReferences(rows, cid, now)).toEqual([]);
    expect(safeRecoveryReferences(rows, actor, now + 86_400_001)).toEqual([]);
  });
  it('rejects invented recovery domains rather than treating them as global IAM', () => {
    expect(safeRecoveryReferences([{ actor_id: actor, domain: 'other', cid, wid, idempotencyKey: entityId, created_at: new Date().toISOString() }], actor)).toEqual([]);
  });
  it('generates a v4 UUID with cryptographic bytes when randomUUID is unavailable on LAN HTTP', () => {
    const random = vi.fn((bytes: Uint8Array) => { bytes.fill(255); return bytes; });
    vi.stubGlobal('crypto', { getRandomValues: random });
    const key = newIdempotencyKey();
    expect(key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(random).toHaveBeenCalledTimes(1);
  });
});
