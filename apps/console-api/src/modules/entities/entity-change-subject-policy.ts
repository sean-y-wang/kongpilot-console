import {ForbiddenException} from '@nestjs/common';
import {permissionModule, type EffectiveGrant, type PermissionAction} from '../../common/authorization.types';
import {canonicalJson} from '../../infrastructure/secret.service';
import {grantMatchesEntity, inheritedTagMatches} from '../authorization/grant-policy';
import {entityReferenceId} from './entity-reference';
import {CREDENTIAL_KINDS} from './entities.types';
import type {PreparedEntityChange} from './entity-change.types';

const core = new Set(['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis']);
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const denied = () => new ForbiddenException({code: 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED'});
export interface FrozenChangeObject {type: string; data: Record<string, any>}
export interface FrozenChangeSubject {before: ReadonlyMap<string, FrozenChangeObject>; after: ReadonlyMap<string, FrozenChangeObject>}
const key = (type: string, id: string) => `${type}:${id}`;
const parentType = (type: string) => type === 'targets' ? 'upstreams' : CREDENTIAL_KINDS.includes(type as any) ? 'consumers' : undefined;
const parentId = (type: string, data: any) => entityReferenceId(type === 'targets' ? data?.upstream : data?.consumer);
function object(type: string, data: any, id?: string, parent?: string): FrozenChangeObject {
  if (!core.has(type) && type !== 'targets' && !CREDENTIAL_KINDS.includes(type as any) || !data || typeof data !== 'object' || Array.isArray(data)) throw denied();
  if (id !== undefined && data.id !== undefined && data.id !== id) throw denied();
  if (parent !== undefined && parentId(type, data) !== undefined && parentId(type, data) !== parent) throw denied();
  const copy = {...data, ...(id ? {id} : {}), ...(parent ? {[type === 'targets' ? 'upstream' : 'consumer']: {id: parent}} : {})};
  if (typeof copy.id !== 'string' || !uuid.test(copy.id)) throw denied();
  return {type, data: copy};
}

/** SQL/HMAC-authenticated compiler material only. A frozen parent supplies
 * historical identity, never a live native permit or a network read. */
export function frozenChangeSubject(material: PreparedEntityChange): FrozenChangeSubject {
  const before = new Map<string, FrozenChangeObject>();
  const add = (node: FrozenChangeObject) => {
    const identity = key(node.type, node.data.id), prior = before.get(identity);
    if (prior && canonicalJson(prior.data) !== canonicalJson(node.data)) throw denied();
    before.set(identity, node);
  };
  for (const p of material.prerequisites) if (!p.absent && p.before) add(object(p.type, p.before, p.nativeId, p.parentId));
  for (const obligation of material.metadataObligations) if (obligation.kind === 'recycle-archive' || obligation.kind === 'recycle-restore') {
    if (obligation.kind === 'recycle-restore' && (obligation.sealedEntry.clusterId !== material.clusterId
      || obligation.sealedEntry.workspaceId !== material.workspaceId || obligation.sealedEntry.entryId !== obligation.entryId)) throw denied();
    for (const node of obligation.graph.nodes) {
      const value = object(node.type, node.data, node.id), current = before.get(key(node.type, node.id));
      if (obligation.kind === 'recycle-restore' && current && canonicalJson(current.data) !== canonicalJson(value.data)) {
        const business = (data: Record<string, any>) => Object.fromEntries(Object.entries(data).filter(([field]) => !['created_at', 'updated_at', 'ttl'].includes(field)
          && !(node.type === 'certificates' && field === 'snis')));
        if (canonicalJson(business(current.data)) !== canonicalJson(business(value.data))) throw denied();
        if (node.type === 'certificates') {
          const names = new Set(obligation.graph.nodes.filter(child => child.type === 'snis' && entityReferenceId(child.data.certificate) === node.id).map(child => child.data.name));
          for (const data of [current.data, value.data]) if (!Array.isArray(data.snis) || data.snis.some((name: unknown) => typeof name !== 'string' || !names.has(name))) throw denied();
        }
        // Actual GET prerequisites remain the observed before. The immutable
        // archive separately retains original restoration identity/material.
        continue;
      }
      add(value);
    }
  }
  for (const p of material.packets) if (p.before) {
    const value = object(p.nativeType, p.before, (p.before as any).id ?? p.originalNativeId ?? p.nativeId, p.parentId);
    const prior = before.get(key(value.type, value.data.id));
    if (prior && canonicalJson(prior.data) !== canonicalJson(value.data)) {
      if (p.nativeType !== 'certificates' || p.method !== 'DELETE' || p.mutationAction !== 'delete') throw denied();
      const archive = material.metadataObligations.find(o => o.kind === 'recycle-archive' && o.packetKeys.includes(p.key));
      if (!archive || archive.kind !== 'recycle-archive' || !archive.graph.nodes.some(n => n.affected && n.type === 'certificates' && n.id === p.nativeId)) throw denied();
      const children = material.packets.filter(child => archive.packetKeys.includes(child.key) && child.nativeType === 'snis' && child.method === 'DELETE'
        && entityReferenceId((child.before as any)?.certificate) === p.nativeId);
      if (!children.length || children.some(child => child.order >= p.order || !p.dependencies.includes(child.key))) throw denied();
      if (children.some(child => !archive.graph.nodes.some(node => node.affected && node.type === 'snis' && node.id === child.nativeId
        && canonicalJson(node.data) === canonicalJson(child.before)))) throw denied();
      const removed = new Set(children.map(child => (child.before as any)?.name));
      if ([...removed].some(name => typeof name !== 'string') || !Array.isArray(prior.data.snis)) throw denied();
      const expected = {...prior.data, snis: prior.data.snis.filter((name: unknown) => !removed.has(name))};
      if (canonicalJson(expected) !== canonicalJson(value.data)) throw denied();
      // Keep initial certificate identity for historical authorization. The
      // separate send-time projection is exact and has explicit SNI steps.
      continue;
    }
    add(value);
  }
  const after = new Map(before);
  for (const p of material.packets) {
    if (p.method === 'DELETE') {after.delete(key(p.nativeType, p.nativeId)); continue;}
    const value = object(p.nativeType, {...(p.before as any), ...p.body}, p.nativeId, p.parentId);
    after.set(key(p.nativeType, p.nativeId), value);
  }
  return {before, after};
}

/** One complete grant is evaluated at each identity. Parent inheritance uses
 * the same grant's tag intersection; scopes from different grants never fuse. */
export function frozenChangePermits(grants: readonly EffectiveGrant[], material: PreparedEntityChange,
  graph: ReadonlyMap<string, FrozenChangeObject>, node: FrozenChangeObject, module: 'native' | 'workflows', action: PermissionAction): boolean {
  const cid = material.clusterId, wid = material.workspaceId;
  const direct = (g: EffectiveGrant, current: FrozenChangeObject, operation = action) => grantMatchesEntity(g,
    module === 'native' ? permissionModule(current.type) : 'workflows', operation,
    {clusterId: cid, workspaceId: wid, entityType: current.type, entity: current.data});
  const parent = (type: string, id: string | undefined) => id ? graph.get(key(type, id)) : undefined;
  const inherited = (current: FrozenChangeObject, child: FrozenChangeObject, depth = 0): boolean => {
    if (depth > 8) return false;
    if (grants.some(g => direct(g, current) && inheritedTagMatches(g, child.data))) return true;
    if (current.type === 'routes' && (module === 'workflows' || action === 'write' || action === 'delete')) {
      const service = parent('services', entityReferenceId(current.data.service));
      if (service) return grants.some(g => direct(g, service) && inheritedTagMatches(g, current.data) && inheritedTagMatches(g, child.data));
    }
    return false;
  };
  if (node.type === 'plugins') {
    const bindings: FrozenChangeObject[] = [];
    for (const [field, type] of [['service', 'services'], ['route', 'routes'], ['consumer', 'consumers']]) {
      const id = entityReferenceId(node.data[field]);
      if (id) {const value = parent(type, id); if (!value) return false; bindings.push(value);}
    }
    // Ordinary global plugin writes require the separate platform boundary.
    if (!bindings.length) return action === 'read' && grants.some(g => direct(g, node));
    return bindings.every(binding => inherited(binding, node));
  }
  if (grants.some(g => direct(g, node))) return true;
  const inheritedParent = parentType(node.type);
  if (inheritedParent) {const value = parent(inheritedParent, parentId(node.type, node.data)); return !!value && inherited(value, node);}
  if (node.type === 'routes' && (module === 'workflows' || action === 'write' || action === 'delete')) {
    const value = parent('services', entityReferenceId(node.data.service)); return !!value && inherited(value, node);
  }
  if (node.type === 'services' && action === 'read') return [...graph.values()].some(route => route.type === 'routes'
    && entityReferenceId(route.data.service) === node.data.id && grants.some(g => grantMatchesEntity(g, module === 'native' ? 'routes' : 'workflows',
      module === 'native' ? g.action : action, {clusterId: cid, workspaceId: wid, entityType: 'routes', entity: route.data})));
  return false;
}

export function assertFrozenChangeGrants(material: PreparedEntityChange, grants: readonly EffectiveGrant[], platformAdmin: boolean,
  action: 'read' | 'write' | 'approve', requester: boolean): FrozenChangeSubject {
  const subject = frozenChangeSubject(material);
  if (platformAdmin) return subject;
  const require = (graph: ReadonlyMap<string, FrozenChangeObject>, node: FrozenChangeObject, operation: PermissionAction) => {
    if (!frozenChangePermits(grants, material, graph, node, 'workflows', action)) throw denied();
    const nativeAction = action === 'write' ? operation : 'read';
    if (!frozenChangePermits(grants, material, graph, node, 'native', nativeAction)
      && !(requester && action === 'read' && frozenChangePermits(grants, material, graph, node, 'native', operation))) throw denied();
  };
  for (const packet of material.packets) {
    if (packet.before) {
      const id = (packet.before as any).id ?? packet.originalNativeId ?? packet.nativeId;
      const value = subject.before.get(key(packet.nativeType, id)); if (!value) throw denied();
      require(subject.before, value, packet.permissionAction);
    }
    if (packet.method !== 'DELETE') {
      const value = subject.after.get(key(packet.nativeType, packet.nativeId)); if (!value) throw denied();
      if (packet.originalNativeId !== undefined) {
        // Kong appends a physical Target history UUID for a logical weight
        // update. This scope view never grants the new UUID as an ordinary
        // entity; Gate3's genuine source must separately prove this tuple.
        if (packet.nativeType !== 'targets' || packet.method !== 'POST' || !packet.parentId) throw denied();
        if (packet.mutationAction === 'update') {
          if ((packet.before as any)?.id !== packet.originalNativeId || entityReferenceId((packet.before as any)?.upstream) !== packet.parentId) throw denied();
        } else if (packet.mutationAction === 'restore') {
          const restoration = material.metadataObligations.find(o => o.kind === 'recycle-restore' && o.packetKeys.includes(packet.key));
          if (!restoration || restoration.kind !== 'recycle-restore' || packet.before !== null) throw denied();
          const original = restoration.graph.nodes.find(n => n.affected && n.type === 'targets' && n.id === packet.originalNativeId);
          if (!original || entityReferenceId(original.data.upstream) !== packet.parentId || original.data.target !== packet.body?.target) throw denied();
          require(subject.before, object('targets', original.data, original.id, packet.parentId), packet.permissionAction);
        } else throw denied();
        require(subject.after, {type: value.type, data: {...value.data, id: packet.originalNativeId}}, packet.permissionAction);
      } else require(subject.after, value, packet.permissionAction);
    }
  }
  for (const p of material.prerequisites) if (!p.absent && p.before) {
    const value = subject.before.get(key(p.type, p.nativeId ?? (p.before as any).id)); if (!value) throw denied();
    if (p.purpose === 'private-parent') {
      // The child's exact before/after permissions were checked above. This
      // private identity does not grant access to the parent's configuration.
      if (!['consumers', 'upstreams'].includes(p.type) || !material.packets.some(packet => packet.parentId === value.data.id
        && parentType(packet.nativeType) === p.type)) throw denied();
      continue;
    }
    const operation = action === 'write' ? p.permissionAction : 'read';
    if (!frozenChangePermits(grants, material, subject.before, value, 'native', operation)
      && !(requester && action === 'read' && frozenChangePermits(grants, material, subject.before, value, 'native', p.permissionAction))) throw denied();
  }
  return subject;
}
