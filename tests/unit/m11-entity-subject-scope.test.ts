import {describe, expect, it} from 'vitest';
import type {EffectiveGrant} from '../../apps/console-api/src/common/authorization.types';
import type {PreparedEntityChange} from '../../apps/console-api/src/modules/entities/entity-change.types';
import {assertFrozenChangeGrants} from '../../apps/console-api/src/modules/entities/entity-change-subject-policy';

const cid = '11111111-1111-4111-8111-111111111111', wid = '22222222-2222-4222-8222-222222222222';
const serviceId = '33333333-3333-4333-8333-333333333333', otherId = '44444444-4444-4444-8444-444444444444';
const pluginId = '55555555-5555-4555-8555-555555555555';
const grant = (module: string, action: EffectiveGrant['action'], scope_type: EffectiveGrant['scope_type'] = 'workspace', scope_values: any[] = [wid]): EffectiveGrant =>
  ({module, action, cluster_id: cid, workspace_id: wid, scope_type, scope_values});
const material = (type = 'services', body: any = {name: 'after'}): PreparedEntityChange => {
  const before = {id: serviceId, name: 'before', tags: ['kos-ws-own', 'team-a']};
  return {version: 1, clusterId: cid, workspaceId: wid, requesterId: otherId, prerequisites: [], metadataObligations: [],
    packets: [{nativeType: type, nativeId: serviceId, method: 'PATCH', before, body, permissionAction: 'write'}]} as any;
};
describe('M11 frozen entity subject scope', () => {
  it('denies an entity-ID-only writer reviewing another service', () => {
    const grants = [grant('workflows', 'write'), grant('services', 'write', 'entity', [{entity_type: 'services', entity_id: otherId}])];
    expect(() => assertFrozenChangeGrants(material(), grants, false, 'write', true)).toThrow();
  });
  it('checks both old and proposed tags without merging unrelated scope dimensions', () => {
    const grants = [grant('workflows', 'write'), grant('services', 'write', 'tag_group', ['team-a'])];
    expect(() => assertFrozenChangeGrants(material('services', {tags: ['kos-ws-own', 'team-b']}), grants, false, 'write', true)).toThrow();
    expect(() => assertFrozenChangeGrants(material('services', {tags: ['kos-ws-own', 'team-a']}), grants, false, 'write', true)).not.toThrow();
  });
  it('permits approval-only reviewers with the exact read and approve scopes, without writer grants', () => {
    const grants = [grant('workflows', 'approve'), grant('services', 'read')];
    expect(() => assertFrozenChangeGrants(material(), grants, false, 'approve', false)).not.toThrow();
    expect(() => assertFrozenChangeGrants(material(), grants, false, 'write', false)).toThrow();
  });
  it('inherits string-bound plugin scope from the captured service while preserving entity and tag ceilings', () => {
    const m = material('plugins', {config: {status_code: 418}});
    m.packets[0].nativeId = pluginId;
    m.packets[0].before = {id: pluginId, name: 'request-termination', service: serviceId, tags: ['kos-ws-own', 'team-a']};
    m.prerequisites = [{type: 'services', nativeId: serviceId, before: {id: serviceId, tags: ['kos-ws-own', 'team-a']}, absent: false, permissionAction: 'read'}] as any;
    const entity = [{entity_type: 'services', entity_id: serviceId}];
    const grants = [grant('workflows', 'write', 'entity', entity), grant('services', 'write', 'entity', entity), grant('services', 'read', 'entity', entity)];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).not.toThrow();
    m.packets[0].body = {service: otherId};
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
  it('rejects missing captured parents and ordinary global-plugin writes', () => {
    const m = material('plugins'); m.packets[0].before = {id: serviceId, service: otherId};
    const grants = [grant('workflows', 'write'), grant('plugins', 'write'), grant('services', 'write')];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
    m.packets[0].before = {id: serviceId, name: 'cors'};
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
  it('allows historical read under current grants and denies a foreign cluster grant', () => {
    const grants = [grant('workflows', 'read'), grant('services', 'read')];
    expect(() => assertFrozenChangeGrants(material(), grants, false, 'read', false)).not.toThrow();
    expect(() => assertFrozenChangeGrants(material(), grants.map(g => ({...g, cluster_id: otherId})), false, 'read', false)).toThrow();
  });
  it('allows an exact credential whitelist without granting public parent read/write', () => {
    const m = material('key-auth', {key: 'new-value'});
    m.packets[0].parentId = otherId;
    m.packets[0].before = {id: serviceId, consumer: {id: otherId}, tags: ['kos-ws-own']};
    m.prerequisites = [{type: 'consumers', nativeId: otherId, before: {id: otherId, tags: ['kos-ws-own']}, absent: false,
      permissionAction: 'write', purpose: 'private-parent'}] as any;
    const entity = [{entity_type: 'key-auth', entity_id: serviceId}];
    const grants = [grant('workflows', 'write', 'entity', entity), grant('consumers', 'write', 'entity', entity)];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).not.toThrow();
    m.packets[0].parentId = pluginId;
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
  it('keeps a Target weight scope on the exact original logical record and refuses arbitrary ID remapping', () => {
    const m = material('targets', {id: pluginId, target: 'backend.invalid:8080', weight: 30});
    m.packets[0] = {...m.packets[0], nativeId: pluginId, originalNativeId: serviceId, parentId: otherId, method: 'POST', mutationAction: 'update',
      before: {id: serviceId, upstream: {id: otherId}, target: 'backend.invalid:8080', weight: 100, tags: ['kos-ws-own']}};
    m.prerequisites = [{type: 'upstreams', nativeId: otherId, before: {id: otherId, tags: ['kos-ws-own']}, absent: false,
      permissionAction: 'write', purpose: 'private-parent'}] as any;
    const entity = [{entity_type: 'targets', entity_id: serviceId}];
    const grants = [grant('workflows', 'write', 'entity', entity), grant('upstreams', 'write', 'entity', entity)];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).not.toThrow();
    m.packets[0].originalNativeId = otherId;
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
  it('permits only the certificate relation change caused by its explicit preceding SNI deletes', () => {
    const cert = {id: serviceId, cert: 'public-cert', key: 'private-key', snis: ['m11.test'], tags: ['kos-ws-own']};
    const sni = {id: otherId, name: 'm11.test', certificate: {id: serviceId}, tags: ['kos-ws-own']};
    const m = material('certificates');
    m.packets = [
      {key: 'sni-delete', order: 1, nativeType: 'snis', nativeId: otherId, method: 'DELETE', mutationAction: 'delete', permissionAction: 'delete', dependencies: [], before: sni},
      {key: 'cert-delete', order: 2, nativeType: 'certificates', nativeId: serviceId, method: 'DELETE', mutationAction: 'delete', permissionAction: 'delete', dependencies: ['sni-delete'], before: {...cert, snis: []}}
    ] as any;
    m.metadataObligations = [{kind: 'recycle-archive', packetKeys: ['sni-delete', 'cert-delete'], graph: {complete: true, nodes: [
      {type: 'certificates', id: serviceId, data: cert, affected: true}, {type: 'snis', id: otherId, data: sni, affected: true}
    ]}}] as any;
    const grants = [grant('workflows', 'write'), grant('certificates', 'delete'), grant('snis', 'delete')];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).not.toThrow();
    (m.packets[1].before as any).key = 'different-key';
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
    m.packets[1].before = {...cert, snis: []}; m.packets[1].dependencies = [];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
  it('keeps actual restored timestamps separate and rejects unexpected certificate SNI bindings', () => {
    const cert = {id: serviceId, cert: 'public-cert', key: 'private-key', created_at: 1, snis: ['m11.test'], tags: ['kos-ws-own']};
    const sni = {id: otherId, name: 'm11.test', certificate: {id: serviceId}, tags: ['kos-ws-own']};
    const m = material('snis', sni);
    m.packets[0] = {...m.packets[0], key: 'sni-restore', nativeId: otherId, method: 'POST', before: null, body: sni, mutationAction: 'restore'};
    m.prerequisites = [{type: 'certificates', nativeId: serviceId, before: {...cert, created_at: 2, snis: []}, absent: false, permissionAction: 'read'}] as any;
    m.metadataObligations = [{kind: 'recycle-restore', entryId: pluginId, packetKeys: ['sni-restore'], sealedEntry: {clusterId: cid, workspaceId: wid, entryId: pluginId}, graph: {complete: true, nodes: [
      {type: 'certificates', id: serviceId, data: cert, affected: true}, {type: 'snis', id: otherId, data: sni, affected: true}
    ]}}] as any;
    const grants = [grant('workflows', 'write'), grant('snis', 'write'), grant('certificates', 'read')];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).not.toThrow();
    (m.prerequisites[0].before as any).snis = ['foreign.test'];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
  it('limits single Target restoration to the exact archived address and original entity grant', () => {
    const original = {id: serviceId, upstream: {id: otherId}, target: 'backend.invalid:8080', weight: 100, tags: ['kos-ws-own']};
    const m = material('targets');
    m.packets[0] = {...m.packets[0], key: 'target-restore', nativeId: pluginId, originalNativeId: serviceId, parentId: otherId,
      method: 'POST', mutationAction: 'restore', before: null, body: {...original, id: pluginId}};
    m.metadataObligations = [{kind: 'recycle-restore', entryId: cid, packetKeys: ['target-restore'], sealedEntry: {clusterId: cid, workspaceId: wid, entryId: cid}, graph: {complete: true, nodes: [
      {type: 'targets', id: serviceId, data: original, affected: true}, {type: 'upstreams', id: otherId, data: {id: otherId, tags: ['kos-ws-own']}, affected: false}
    ]}}] as any;
    const entity = [{entity_type: 'targets', entity_id: serviceId}];
    const grants = [grant('workflows', 'write', 'entity', entity), grant('upstreams', 'write', 'entity', entity)];
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).not.toThrow();
    m.packets[0].body!.target = 'different.invalid:8080';
    expect(() => assertFrozenChangeGrants(m, grants, false, 'write', true)).toThrow();
  });
});
