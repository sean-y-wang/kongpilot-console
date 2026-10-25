import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { assertControlMetadataPlan, controlOperationMatches, normalizeControlChangeRequest } from '../../apps/console-api/src/modules/control-plane/control-metadata-plan';
import { CONTROL_CHANGE_OPERATIONS, CONTROL_CHANGE_RESOURCES, type ControlChangeOperation, type ControlChangeResource } from '../../apps/console-api/src/modules/control-plane/control-metadata.types';

// Pure protocol/source validation only. Digests in these plans are synthetic;
// their authenticity and live SQL/private execution proofs belong to the fixed
// production intent verifier, not this shape validator.
const supported: Record<ControlChangeResource, readonly ControlChangeOperation[]> = {
  clusters: ['update', 'deactivate'],
  'data-sources': ['create', 'update', 'deactivate'],
  workspaces: ['create', 'update', 'archive', 'restore'],
  'recycle-bin': ['purge'],
};
const matrix = CONTROL_CHANGE_RESOURCES.flatMap(resource => CONTROL_CHANGE_OPERATIONS.map(operation => [resource, operation] as const));
const valid = matrix.filter(([resource, operation]) => supported[resource].includes(operation));
const invalid = matrix.filter(([resource, operation]) => !supported[resource].includes(operation));

function request(resource: ControlChangeResource = 'clusters', operation: ControlChangeOperation = 'update'): any {
  return { resource, operation, ...(operation === 'create' ? {} : { resourceId: randomUUID() }), input: resource === 'recycle-bin' ? {revision:2,workspaceId:randomUUID(),confirmed:true,confirm_name:'Production'} : { revision: 2, name: 'Production' } };
}

function plan(resource: ControlChangeResource = 'clusters', operation: ControlChangeOperation = 'update'): any {
  const intentId = randomUUID();
  return {
    version: 1, clusterId: randomUUID(), workspaceId: randomUUID(), workflowId: randomUUID(), planRevision: 1,
    kind: 'control-metadata', executionMode: 'approval', approvalRequired: true,
    subject: { type: 'control_metadata_requests', id: intentId }, requester: { type: 'console', id: randomUUID() },
    definition: { id: randomUUID(), version: 1, policyHash: 'a'.repeat(64) },
    issuedAt: '2026-10-14T00:00:00.000Z', expiresAt: '2026-10-14T00:30:00.000Z',
    scope: { transportScope: 'b'.repeat(64), clusterRevision: 2, workspaceRevision: 3 }, prerequisites: [],
    steps: [{ id: randomUUID(), key: 'control.metadata', handler: 'control.metadata', order: 1, kind: 'metadata',
      entityType: 'control_metadata_requests', entityId: intentId,
      permissionAction: ['archive', 'deactivate', 'purge'].includes(operation) ? 'delete' : 'write', dependencies: [], nativeRequests: [],
      before: { id: randomUUID(), revision: 2, name: 'Production' },
      metadata: { intentId, resource, operation, materialHmac: 'c'.repeat(64) },
      metadataRevision: 2, metadataBeforeHmac: 'd'.repeat(64), metadataPayloadHmac: 'e'.repeat(64) }],
  };
}

describe('M11 control metadata: strict typed change selectors', () => {
  it.each(matrix)('matches exactly the enumerated %s / %s selector', (resource, operation) => {
    expect(controlOperationMatches(resource, operation)).toBe(supported[resource].includes(operation));
  });

  it.each(valid)('normalizes supported %s / %s without introducing execution capability', (resource, operation) => {
    const raw = request(resource, operation), normalized = normalizeControlChangeRequest(raw);
    expect(normalized).toEqual(raw); expect(normalized).not.toBe(raw); expect(normalized.input).not.toBe(raw.input);
    expect(Object.isFrozen(normalized)).toBe(true); expect(Object.isFrozen(normalized.input)).toBe(true);
    expect(Object.keys(normalized).sort()).toEqual(operation === 'create' ? ['input', 'operation', 'resource'] : ['input', 'operation', 'resource', 'resourceId']);
  });

  it.each(invalid)('refuses unsupported %s / %s selectors', (resource, operation) => {
    expect(() => normalizeControlChangeRequest(request(resource, operation))).toThrow();
  });

  it.each([undefined, null, true, false, 0, 1, '', 'clusters', [], ['clusters']])('refuses non-object top-level selector %#', value => {
    expect(() => normalizeControlChangeRequest(value)).toThrow();
  });

  it.each(['users', 'roles', 'services', 'vaults', 'workspaces/', '/clusters', '../clusters', 'clusters;DROP TABLE users', 'Clusters', ''])
    ('refuses unknown resource %s', resource => {
      expect(() => normalizeControlChangeRequest({ ...request(), resource })).toThrow();
      expect(controlOperationMatches(resource, 'update')).toBe(false);
    });

  it.each(['delete', 'probe', 'purge', 'restore-all', 'migrate', 'binding.grant', 'permissions', 'reset-password', '/update', 'Update', ''])
    ('refuses unknown operation %s', operation => {
      expect(() => normalizeControlChangeRequest({ ...request(), operation })).toThrow();
      expect(controlOperationMatches('clusters', operation)).toBe(false);
    });

  it.each(['clusterId', 'workspaceId', 'actorId', 'sessionId', 'handler', 'nativeRequests', 'workflowId', 'workflowKind', 'kind', 'transaction', 'approved', 'originalHandle', 'relatedId', 'transportScope', 'executionMode', 'idempotencyKey', 'metadata'])
    ('refuses a caller-controlled top-level %s field', key => {
      expect(() => normalizeControlChangeRequest({ ...request(), [key]: randomUUID() })).toThrow();
    });

  it.each(valid.filter(([, operation]) => operation !== 'create'))('requires a UUID for non-create %s / %s', (resource, operation) => {
    for (const value of [undefined, null, '', 'not-a-uuid', '../foreign', {}, [], 12, false, '00000000-0000-0000-0000-000000000000', '61000000-0000-9000-8000-000000000001', '61000000-0000-4000-0000-000000000001']) {
      expect(() => normalizeControlChangeRequest({ ...request(resource, operation), resourceId: value })).toThrow();
    }
  });

  it.each(valid.filter(([, operation]) => operation === 'create'))('refuses caller-allocated IDs for %s / %s', (resource, operation) => {
    for (const resourceId of [randomUUID(), null, '', [], 1]) expect(() => normalizeControlChangeRequest({ ...request(resource, operation), resourceId })).toThrow();
  });

  it('canonicalizes UUID case to the same PostgreSQL identity without changing the target', () => {
    const value = { ...request(), resourceId: '610000AA-0000-4000-8000-000000000001' };
    expect(normalizeControlChangeRequest(value).resourceId).toBe(value.resourceId.toLowerCase());
  });

  it.each([undefined, null, '', 'input', 1, false, [], [{}]])('requires an object input rather than scalar or array %#', input => {
    expect(() => normalizeControlChangeRequest({ ...request(), input })).toThrow();
  });

  it('retains arbitrary JSON business input keys for the original service validator without lifting them to execution selectors', () => {
    const input = { revision: 2, execution_mode: 'direct', labels: ['prod'], connection_auth: { type: 'bearer', token: 'Synthetic-input-secret' }, nested: { enabled: true, nullable: null, records: [{ key: 'name', value: 'kept' }] } };
    const normalized = normalizeControlChangeRequest({ ...request(), input });
    expect(normalized.input).toEqual(input); expect(Object.keys(normalized)).not.toContain('executionMode');
  });

  it('clones and deeply freezes nested records and arrays against caller mutation after normalization', () => {
    const raw = request('data-sources', 'update');
    raw.input = { revision: 2, labels: ['prod'], auth: { type: 'basic', username: 'reader', password: 'Synthetic-key' }, nested: [{ entries: [{ name: 'kept' }] }] };
    const before = structuredClone(raw), normalized = normalizeControlChangeRequest(raw), nested: any = normalized.input;
    for (const value of [normalized, nested, nested.labels, nested.auth, nested.nested, nested.nested[0], nested.nested[0].entries, nested.nested[0].entries[0]]) expect(Object.isFrozen(value)).toBe(true);
    raw.input.auth.username = 'changed'; raw.input.nested[0].entries[0].name = 'changed'; raw.input.labels.push('foreign');
    expect(normalized).toEqual(before);
    try { nested.auth.username = 'changed'; } catch { /* frozen object */ }
    try { nested.nested.push({ entries: [] }); } catch { /* frozen array */ }
    expect(normalized).toEqual(before);
  });

  for (const key of ['__proto__', 'prototype', 'constructor']) {
    it(`refuses reserved object key ${key} anywhere including nested array records`, () => {
      const poison = JSON.parse(`{"${key}":{"injected":true}}`);
      for (const input of [poison, { nested: poison }, { nested: [poison] }]) expect(() => normalizeControlChangeRequest({ ...request(), input })).toThrow();
      const array: any[] = []; Object.defineProperty(array, key, { enumerable: true, value: { injected: true } });
      expect(() => normalizeControlChangeRequest({ ...request(), input: { nested: array } })).toThrow();
    });
  }

  it('does not adopt selectors inherited through a custom prototype', () => {
    const raw = Object.create(request()); raw.input = {};
    expect(() => normalizeControlChangeRequest(raw)).toThrow();
  });

  it('normalizes JSON-compatible null-prototype input into an ordinary deeply frozen JSON object', () => {
    const input = Object.assign(Object.create(null), { revision: 2, name: 'kept' });
    const normalized = normalizeControlChangeRequest({ ...request(), input });
    expect(normalized.input).toEqual({ revision: 2, name: 'kept' }); expect(Object.getPrototypeOf(normalized.input)).toBe(Object.prototype); expect(Object.isFrozen(normalized.input)).toBe(true);
  });

  it.each([new Date('2026-10-14T00:00:00Z'), /not-json/, new Map([['name', 'injected']]), new Set(['name'])])
    ('refuses non-JSON object input whose serialization would change its object meaning %#', input => {
      expect(() => normalizeControlChangeRequest({ ...request(), input })).toThrow();
    });

  it.each([undefined, Symbol('input'), 4n, NaN, Infinity, -Infinity, () => undefined])('refuses non-JSON nested primitive %# rather than silently dropping or converting it', value => {
    expect(() => normalizeControlChangeRequest({ ...request(), input: { value } })).toThrow();
  });

  it('refuses accessor input without evaluating caller-provided getter code', () => {
    const getter = vi.fn(() => 'injected'), input: any = {};
    Object.defineProperty(input, 'name', { enumerable: true, get: getter });
    expect(() => normalizeControlChangeRequest({ ...request(), input })).toThrow(); expect(getter).not.toHaveBeenCalled();
  });

  it('refuses inherited array serialization hooks before they can alter sealed approval input', () => {
    const hook = vi.fn(() => [{ name: 'injected' }]), nested: any[] = [{ name: 'original' }];
    Object.setPrototypeOf(nested, { toJSON: hook });
    expect(() => normalizeControlChangeRequest({ ...request(), input: { nested } })).toThrow(); expect(hook).not.toHaveBeenCalled();
  });

  it('refuses nested array custom own fields instead of silently dropping them', () => {
    const nested: any = [{ name: 'kept' }]; nested.extra = 'hidden-selector';
    expect(() => normalizeControlChangeRequest({ ...request(), input: { nested } })).toThrow();
  });

  it('permits shared acyclic JSON objects and freezes independent copies instead of confusing them with real cycles', () => {
    const shared = { name: 'same' }, normalized: any = normalizeControlChangeRequest({ ...request(), input: { first: shared, second: shared } });
    expect(normalized.input).toEqual({ first: { name: 'same' }, second: { name: 'same' } });
    expect(Object.isFrozen(normalized.input.first)).toBe(true); expect(Object.isFrozen(normalized.input.second)).toBe(true);
    expect(normalized.input.first).not.toBe(normalized.input.second);
  });

  it('refuses nonserializable graphs, cycles, excessive depth and oversized input before persistence', () => {
    const circular: any = {}; circular.parent = circular;
    const nested: any = {}; let node = nested; for (let index = 0; index < 52; index++) node = node.child = {};
    for (const input of [circular, { revision: 2n }, { callback: () => undefined }, nested, { name: 'x'.repeat(2 * 1024 * 1024) }]) expect(() => normalizeControlChangeRequest({ ...request(), input })).toThrow();
  });
});

describe('M11 control metadata: one fixed Native 0 approval step', () => {
  it.each(valid)('accepts %s / %s with the exact action and leaves the plan unchanged', (resource, operation) => {
    const value = plan(resource, operation), before = structuredClone(value);
    expect(assertControlMetadataPlan(value)).toBe(value.steps[0]); expect(value).toEqual(before); expect(value.steps[0].nativeRequests).toEqual([]);
  });

  it.each(invalid)('refuses unsupported %s / %s in the sealed plan too', (resource, operation) => {
    expect(() => assertControlMetadataPlan(plan(resource, operation))).toThrow();
  });

  it.each(['kind', 'subject-type', 'subject-id', 'requester', 'direct', 'missing-approval', 'steps-empty', 'second-step', 'prerequisite', 'generated', 'migration'])
    ('refuses %s plan capability substitution', variant => {
      const value = plan();
      if (variant === 'kind') value.kind = 'iam-metadata';
      if (variant === 'subject-type') value.subject.type = 'iam_metadata_requests';
      if (variant === 'subject-id') value.subject.id = randomUUID();
      if (variant === 'requester') value.requester.type = 'developer';
      if (variant === 'direct') value.executionMode = 'direct';
      if (variant === 'missing-approval') value.approvalRequired = false;
      if (variant === 'steps-empty') value.steps = [];
      if (variant === 'second-step') value.steps.push({ ...value.steps[0], id: randomUUID(), order: 2 });
      if (variant === 'prerequisite') value.prerequisites.push({ type: 'services', id: randomUUID(), path: '/services', fingerprint: 'f'.repeat(64), before: {} });
      if (variant === 'generated') value.generated = { consumerId: randomUUID(), aclId: randomUUID(), credentialId: randomUUID(), key: 'Synthetic-native-key' };
      if (variant === 'migration') value.migration = { sourceWorkspaceId: randomUUID(), targetWorkspaceId: randomUUID(), materialHmac: 'f'.repeat(64) };
      expect(() => assertControlMetadataPlan(value)).toThrow();
    });

  it.each([undefined, null, false, 'true', 1, {}, []])('requires literal approvalRequired true rather than coercible value %#', approvalRequired => {
    const value = plan(); value.approvalRequired = approvalRequired; expect(() => assertControlMetadataPlan(value)).toThrow();
  });

  for (const field of ['steps', 'prerequisites', 'nativeRequests', 'dependencies']) {
    it.each([undefined, null, '', '[]', { length: 0 }, { length: 1 }, false])(`requires an actual ${field} array rather than a length-like value %#`, replacement => {
      const value = plan();
      if (field === 'steps' || field === 'prerequisites') value[field] = replacement; else value.steps[0][field] = replacement;
      expect(() => assertControlMetadataPlan(value)).toThrow();
    });
  }

  it('rejects an array-like single metadata step even when its indexed object and length look correct', () => {
    const value = plan(); value.steps = { 0: value.steps[0], length: 1 }; expect(() => assertControlMetadataPlan(value)).toThrow();
  });

  it.each(['native-kind', 'wrong-handler', 'fake-handler', 'wrong-key', 'wrong-entity-type', 'wrong-entity-id', 'dependencies', 'native-request'])
    ('refuses %s within the one-step boundary', variant => {
      const value = plan(), step = value.steps[0];
      if (variant === 'native-kind') step.kind = 'native';
      if (variant === 'wrong-handler') step.handler = 'iam.metadata';
      if (variant === 'fake-handler') step.handler = 'control.metadata.execute-arbitrary';
      if (variant === 'wrong-key') step.key = 'entity.change';
      if (variant === 'wrong-entity-type') step.entityType = 'clusters';
      if (variant === 'wrong-entity-id') step.entityId = randomUUID();
      if (variant === 'dependencies') step.dependencies = [randomUUID()];
      if (variant === 'native-request') step.nativeRequests = [{ method: 'DELETE', canonicalPath: '/services', nativeType: 'services', nativeId: randomUUID(), bodyHmac: 'f'.repeat(64) }];
      expect(() => assertControlMetadataPlan(value)).toThrow();
    });

  for (const field of ['mutationAction', 'mutationPayload', 'mutationPayloadHmac', 'beforeFingerprint', 'mutationIdempotencyKey']) {
    it.each([null, false, '', {}, [], 'injected'])(`rejects forbidden ${field} presence even for a falsy value %#`, value => {
      const body = plan(); body.steps[0][field] = value; expect(() => assertControlMetadataPlan(body)).toThrow();
    });
  }

  it.each(['parentId', 'credentialKind'])('rejects a native relationship capability in %s', field => {
    for (const input of ['', false, 0, {}, [], randomUUID()]) { const value = plan(); value.steps[0][field] = input; expect(() => assertControlMetadataPlan(value)).toThrow(); }
  });

  it.each([0, 2, -1, 1.5, '1', undefined, null, NaN, Infinity])('requires exact metadata order 1 and rejects %#', order => {
    const value = plan(); value.steps[0].order = order; expect(() => assertControlMetadataPlan(value)).toThrow();
  });

  it.each(valid)('rejects action widening for %s / %s', (resource, operation) => {
    for (const permissionAction of ['read', 'approve', '', null, undefined, ['archive', 'deactivate', 'purge'].includes(operation) ? 'write' : 'delete']) {
      const value = plan(resource, operation); value.steps[0].permissionAction = permissionAction; expect(() => assertControlMetadataPlan(value)).toThrow();
    }
  });

  it.each(['missing', 'null', 'array', 'string', 'extra-body', 'extra-handler', 'missing-key', 'foreign-intent', 'invalid-intent', 'resource', 'operation'])
    ('requires exactly the fixed four own metadata fields and rejects %s', variant => {
      const value = plan(), step = value.steps[0];
      if (variant === 'missing') delete step.metadata;
      if (variant === 'null') step.metadata = null;
      if (variant === 'array') step.metadata = [];
      if (variant === 'string') step.metadata = 'control-metadata';
      if (variant === 'extra-body') step.metadata.body = { nativeRequest: true };
      if (variant === 'extra-handler') step.metadata.handler = 'entity.change';
      if (variant === 'missing-key') delete step.metadata.materialHmac;
      if (variant === 'foreign-intent') step.metadata.intentId = randomUUID();
      if (variant === 'invalid-intent') value.subject.id = step.entityId = step.metadata.intentId = 'not-a-uuid';
      if (variant === 'resource') step.metadata.resource = 'users';
      if (variant === 'operation') step.metadata.operation = 'probe';
      expect(() => assertControlMetadataPlan(value)).toThrow();
    });

  it('rejects a metadata key inherited from a prototype even when four other own keys exist', () => {
    const value = plan(), metadata = value.steps[0].metadata;
    value.steps[0].metadata = Object.assign(Object.create({ materialHmac: metadata.materialHmac }), { intentId: metadata.intentId, resource: metadata.resource, operation: metadata.operation, extra: true });
    expect(() => assertControlMetadataPlan(value)).toThrow();
  });

  for (const field of ['materialHmac', 'metadataBeforeHmac', 'metadataPayloadHmac']) {
    it.each([undefined, null, '', 'f'.repeat(63), 'f'.repeat(65), 'z'.repeat(64), 'F'.repeat(64), 1, true, {}, ['f'.repeat(64)], [['f'.repeat(64)]]])
      (`requires an actual bounded lowercase hex string for ${field} and rejects %#`, hmac => {
        const value = plan(); if (field === 'materialHmac') value.steps[0].metadata[field] = hmac; else value.steps[0][field] = hmac;
        expect(() => assertControlMetadataPlan(value)).toThrow();
      });
  }

  it.each([-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, '2', undefined, null, false, {}, []])('rejects invalid metadataRevision %#', revision => {
    const value = plan(); value.steps[0].metadataRevision = revision; expect(() => assertControlMetadataPlan(value)).toThrow();
  });

  it.each([0, 1, Number.MAX_SAFE_INTEGER])('accepts a nonnegative safe-integer metadata revision %s as shape only', revision => {
    const value = plan(); value.steps[0].metadataRevision = revision; expect(assertControlMetadataPlan(value)).toBe(value.steps[0]);
  });
});
