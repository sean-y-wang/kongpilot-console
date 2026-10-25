import { describe, expect, it, vi } from 'vitest';
import { canInScope, grantMatches, hasModule, logicalGrantTag, permissionModule } from '../../apps/console-web/src/api/permissions';
import { newIdempotencyKey } from '../../apps/console-web/src/api/idempotency';
import type { Capabilities, EffectiveGrant } from '../../apps/console-web/src/api/types';

const c1 = 'c1', c2 = 'c2', pay = 'pay', ops = 'ops';
const scope = { clusterId: c1, workspaceId: pay, entityType: 'services', entity: { id: 'shared-id', tags: ['team:pay'] } };
const grant = (overrides: Partial<EffectiveGrant> = {}): EffectiveGrant => ({ module: 'services', action: 'read', scope_type: 'workspace', cluster_id: c1, workspace_id: pay, scope_values: [pay], ...overrides });
const caps = (grants: EffectiveGrant[]): Capabilities => ({ platformAdmin: false, clusters: [c1], grants, modules: { services: { read: true, write: true, delete: true, approve: false } } });
const physicalTag = (logical: string) => `kos-tag-${Buffer.from(logical).toString('base64url')}`;

describe('M4 independent frontend permission projection', () => {
  it('fails closed when capabilities are absent and never substitutes a coarse module flag for entity scope', () => {
    expect(canInScope(undefined, 'services', 'read', scope)).toBe(false);
    expect(hasModule(undefined, 'services')).toBe(false);
    expect(hasModule(caps([]), 'services', 'write')).toBe(true);
    expect(canInScope(caps([]), 'services', 'write', scope)).toBe(false);
  });
  it('evaluates complete grant rows and does not union module/action/workspace dimensions', () => {
    const capability = caps([grant(), grant({ module: 'routes', action: 'write', workspace_id: ops, scope_values: [ops] })]);
    expect(canInScope(capability, 'services', 'read', scope)).toBe(true);
    expect(canInScope(capability, 'services', 'write', scope)).toBe(false);
    expect(canInScope(capability, 'routes', 'write', scope)).toBe(false);
  });
  it('keeps write, delete, approve and secret reveal independent', () => {
    const capability = caps([grant({ action: 'write' })]);
    expect(canInScope(capability, 'services', 'write', scope)).toBe(true);
    for (const action of ['read', 'delete', 'approve'] as const) expect(canInScope(capability, 'services', action, scope)).toBe(false);
    expect(canInScope(capability, 'secrets', 'read', scope)).toBe(false);
  });
  it('keeps global grant binding cluster/workspace ceilings even though scope_type stays global', () => {
    const global = grant({ scope_type: 'global', scope_values: [] });
    expect(grantMatches(global, 'services', 'read', scope)).toBe(true);
    expect(grantMatches(global, 'services', 'read', { ...scope, clusterId: c2 })).toBe(false);
    expect(grantMatches(global, 'services', 'read', { ...scope, workspaceId: ops })).toBe(false);
    expect(grantMatches(global, 'services', 'read', { ...scope, workspaceId: undefined })).toBe(false);
  });
  it('allows an unbounded global module grant without treating it as platform-super for unrelated modules', () => {
    const capability = caps([grant({ scope_type: 'global', cluster_id: null, workspace_id: null, scope_values: [] })]);
    expect(canInScope(capability, 'services', 'read', { ...scope, clusterId: c2, workspaceId: ops })).toBe(true);
    expect(canInScope(capability, 'users', 'write')).toBe(false);
    expect(capability.platformAdmin).toBe(false);
  });
  it('requires the actual workspace value and rejects an empty workspace scope', () => {
    expect(grantMatches(grant(), 'services', 'read', { ...scope, workspaceId: ops })).toBe(false);
    expect(grantMatches(grant({ scope_values: [] }), 'services', 'read', scope)).toBe(false);
  });
  it('implements business tag OR inside mandatory cluster/workspace AND', () => {
    const tag = grant({ scope_type: 'tag_group', scope_values: [physicalTag('team:pay'), physicalTag('team:shared')] });
    for (const tags of [['team:pay'], ['team:shared'], [physicalTag('team:pay')]]) expect(grantMatches(tag, 'services', 'read', { ...scope, entity: { id: 's', tags } })).toBe(true);
    expect(grantMatches(tag, 'services', 'read', { ...scope, entity: { id: 's', tags: ['team:ops'] } })).toBe(false);
    expect(grantMatches(tag, 'services', 'read', { ...scope, workspaceId: ops, entity: { id: 's', tags: ['team:pay'] } })).toBe(false);
    expect(grantMatches(tag, 'services', 'read', { ...scope, entity: undefined })).toBe(false);
  });
  it('uses potential tag scope only for creation visibility and keeps its ceilings', () => {
    const tag = grant({ scope_type: 'tag_group', action: 'write', scope_values: [physicalTag('team:pay')] });
    expect(grantMatches(tag, 'services', 'write', { clusterId: c1, workspaceId: pay, potential: true })).toBe(true);
    expect(grantMatches(tag, 'services', 'write', { clusterId: c2, workspaceId: pay, potential: true })).toBe(false);
    expect(grantMatches(tag, 'services', 'write', { clusterId: c1, workspaceId: ops, potential: true })).toBe(false);
  });
  it('requires cluster, actual entity type and ID for entity grants', () => {
    const typed = grant({ scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: 'shared-id' }] });
    expect(grantMatches(typed, 'services', 'read', scope)).toBe(true);
    expect(grantMatches(typed, 'services', 'read', { ...scope, clusterId: c2 })).toBe(false);
    expect(grantMatches(typed, 'services', 'read', { ...scope, entityType: 'consumers' })).toBe(false);
    expect(grantMatches(typed, 'services', 'read', { ...scope, entity: { id: 'sibling-id' } })).toBe(false);
    expect(grantMatches(typed, 'services', 'read', { ...scope, entity: undefined })).toBe(false);
  });
  it('canonicalizes child module aliases while preserving the actual typed child', () => {
    expect(permissionModule('targets')).toBe('upstreams');
    expect(permissionModule('workspace-migrations')).toBe('workspaces');
    for (const kind of ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']) {
      expect(permissionModule(kind)).toBe('consumers');
      const typed = grant({ module: 'consumers', scope_type: 'entity', scope_values: [{ entity_type: kind, entity_id: 'credential-id' }] });
      expect(grantMatches(typed, kind, 'read', { ...scope, entityType: kind, entity: { id: 'credential-id' } })).toBe(true);
      expect(grantMatches(typed, kind, 'read', { ...scope, entityType: 'consumers', entity: { id: 'credential-id' } })).toBe(false);
    }
  });
  it('roundtrips non-ASCII logical tags and preserves invalid encodings safely', () => {
    expect(logicalGrantTag(physicalTag('team:支付'))).toBe('team:支付');
    expect(logicalGrantTag('kos-tag-%invalid')).toBe('kos-tag-%invalid');
  });
});

describe('M4 per-write secure idempotency IDs', () => {
  it('uses independent native UUIDs', () => {
    const first = newIdempotencyKey(), second = newIdempotencyKey();
    expect(first).toMatch(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i);
    expect(first).not.toBe(second);
  });
  it('uses cryptographic fallback with UUID version and variant bits', () => {
    const getRandomValues = vi.fn((bytes: Uint8Array) => { bytes.fill(0xff); return bytes; });
    vi.stubGlobal('crypto', { getRandomValues });
    try {
      expect(newIdempotencyKey()).toBe('ffffffff-ffff-4fff-bfff-ffffffffffff');
      expect(getRandomValues).toHaveBeenCalledTimes(1);
    } finally { vi.unstubAllGlobals(); }
  });
});
