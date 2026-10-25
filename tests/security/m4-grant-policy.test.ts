import { describe, expect, it } from 'vitest';
import { coarseGrantMatches, grantContains, grantMatchesEntity, inheritedTagMatches, validGrant } from '../../apps/console-api/src/modules/authorization/grant-policy';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';

const c1 = '7530297b-364c-41d9-aeb5-9e2d119843b4', c2 = '9486f880-ecbe-4a04-a765-e1be2d2b75d9';
const pay = 'ed35bc52-0eea-4c4e-894d-265c8165d00c', ops = '1b963e31-527b-4b2a-ac29-19b6d7e03e09';
const id = '9d0043e1-576e-4ad2-a397-2b9da0e6ce11';
const target = { clusterId: c1, workspaceId: pay, entityType: 'services', entity: { id, tags: [encodeTag('team:pay')] } };
const grant = (changes: Partial<EffectiveGrant> = {}): EffectiveGrant => ({ cluster_id: c1, workspace_id: pay, module: 'services', action: 'read', scope_type: 'workspace', scope_values: [pay], ...changes });

describe('M4 independent complete-grant actual-object authorization', () => {
  it.each(['global', 'workspace', 'tag_group', 'entity'] as const)('requires resolved actual CID/WID for %s while coarse discovery stays separate', kind => {
    const value = grant({ scope_type: kind, scope_values: kind === 'global' ? [] : kind === 'tag_group' ? [encodeTag('team:pay')] : kind === 'entity' ? [{ entity_type: 'services', entity_id: id }] : [pay] });
    expect(grantMatchesEntity(value, 'services', 'read', target)).toBe(true);
    for (const changes of [{ clusterId: undefined }, { workspaceId: undefined }, { clusterId: 'invalid' }, { workspaceId: 'invalid' }]) expect(grantMatchesEntity(value, 'services', 'read', { ...target, ...changes })).toBe(false);
    expect(coarseGrantMatches(value, 'services', 'read', {})).toBe(true);
  });
  it('requires an actual resolved object scope even for a platform-wide module grant', () => {
    const global = grant({ scope_type: 'global', cluster_id: null, workspace_id: null, scope_values: [] });
    expect(grantMatchesEntity(global, 'services', 'read', target)).toBe(true);
    expect(grantMatchesEntity(global, 'services', 'read', {})).toBe(false);
    expect(coarseGrantMatches(global, 'services', 'read', {})).toBe(true);
  });
  it('does not union module, action or scope across independent rows', () => {
    const rows = [grant(), grant({ module: 'routes', action: 'write', workspace_id: ops, scope_values: [ops] })];
    expect(rows.some(value => grantMatchesEntity(value, 'services', 'write', target))).toBe(false);
    expect(rows.some(value => grantMatchesEntity(value, 'routes', 'write', target))).toBe(false);
  });
  it('preserves mandatory ceilings for narrowed global bindings', () => {
    const global = grant({ scope_type: 'global', scope_values: [] });
    expect(grantMatchesEntity(global, 'services', 'read', { ...target, clusterId: c2 })).toBe(false);
    expect(grantMatchesEntity(global, 'services', 'read', { ...target, workspaceId: ops })).toBe(false);
  });
  it('rejects empty workspace/tag/entity values instead of inventing a default', () => {
    for (const scope_type of ['workspace', 'tag_group', 'entity'] as const) {
      const empty = grant({ scope_type, scope_values: [] });
      expect(validGrant(empty)).toBe(false); expect(grantMatchesEntity(empty, 'services', 'read', target)).toBe(false);
    }
  });
  it('implements encoded tag OR inside cluster/workspace AND and requires child tags for inheritance', () => {
    const value = grant({ scope_type: 'tag_group', scope_values: [encodeTag('team:pay'), encodeTag('team:shared')] });
    for (const tag of ['team:pay', 'team:shared']) expect(grantMatchesEntity(value, 'services', 'read', { ...target, entity: { id, tags: [encodeTag(tag)] } })).toBe(true);
    expect(grantMatchesEntity(value, 'services', 'read', { ...target, workspaceId: ops })).toBe(false);
    expect(inheritedTagMatches(value, { tags: [] })).toBe(false);
    expect(inheritedTagMatches(value, { tags: [encodeTag('team:ops')] })).toBe(false);
    expect(inheritedTagMatches(value, target.entity)).toBe(true);
  });
  it('matches entity grants by exact cluster, actual type and ID', () => {
    const value = grant({ scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: id }] });
    expect(grantMatchesEntity(value, 'services', 'read', target)).toBe(true);
    expect(grantMatchesEntity(value, 'services', 'read', { ...target, clusterId: c2 })).toBe(false);
    expect(grantMatchesEntity(value, 'services', 'read', { ...target, entityType: 'consumers' })).toBe(false);
    expect(grantMatchesEntity(value, 'services', 'read', { ...target, entity: { id: c2 } })).toBe(false);
  });
  it('keeps canonical child module aliases and actual child type independent', () => {
    const value = grant({ module: 'consumers', scope_type: 'entity', scope_values: [{ entity_type: 'key-auth', entity_id: id }] });
    expect(grantMatchesEntity(value, 'key-auth', 'read', { ...target, entityType: 'key-auth' })).toBe(true);
    expect(grantMatchesEntity(value, 'jwt', 'read', { ...target, entityType: 'jwt' })).toBe(false);
    expect(grantMatchesEntity(value, 'consumers', 'read', { ...target, entityType: 'consumers' })).toBe(false);
  });
  it('delegates only scopes contained by one complete existing grant', () => {
    const existing = grant({ scope_type: 'tag_group', scope_values: [encodeTag('team:pay')] });
    expect(grantContains(existing, existing)).toBe(true);
    expect(grantContains(existing, { ...existing, scope_values: [encodeTag('team:pay'), encodeTag('team:ops')] })).toBe(false);
    expect(grantContains(existing, { ...existing, action: 'write' })).toBe(false);
    expect(grantContains(existing, { ...existing, workspace_id: null })).toBe(false);
    expect(grantContains(existing, grant({ scope_type: 'global', scope_values: [] }))).toBe(false);
  });
});
