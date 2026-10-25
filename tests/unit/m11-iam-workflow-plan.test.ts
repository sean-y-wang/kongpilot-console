import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { assertIamMetadataPlan, normalizeIamChangeRequest } from '../../apps/console-api/src/modules/iam/iam-workflow-plan';
import type { IamChangeOperation, IamChangeResource } from '../../apps/console-api/src/modules/iam/iam-workflow.types';

const ordinaryOperations: IamChangeOperation[] = ['create', 'update', 'status', 'archive', 'restore'];
const validOperations: Array<[IamChangeResource, IamChangeOperation]> = [
  ...(['users', 'teams', 'roles'] as const).flatMap(resource => ordinaryOperations.map(operation => [resource, operation] as [IamChangeResource, IamChangeOperation])),
  ['roles', 'permissions'], ['roles', 'clone'],
  ...(['users', 'teams'] as const).flatMap(resource => (['binding.grant', 'binding.revoke', 'binding.restore'] as const).map(operation => [resource, operation] as [IamChangeResource, IamChangeOperation])),
  ['teams', 'member.add'], ['teams', 'member.revoke'], ['teams', 'member.restore'],
];

function request(resource: IamChangeResource = 'roles', operation: IamChangeOperation = 'update'): any {
  return { resource, operation, ...(operation === 'create' ? {} : { resourceId: randomUUID() }),
    ...(['binding.revoke', 'binding.restore', 'member.revoke', 'member.restore'].includes(operation) ? { relatedId: randomUUID() } : {}),
    input: { revision: 4, name: 'payments operators' } };
}

/** Fixed plan structure only. HMAC authenticity and current SQL authorization
 * belong to the production intent verifier, not this pure shape validator. */
function plan(resource: IamChangeResource = 'roles', operation: IamChangeOperation = 'update'): any {
  const intentId = randomUUID();
  return { version: 1, clusterId: randomUUID(), workspaceId: randomUUID(), workflowId: randomUUID(), planRevision: 1,
    kind: 'iam-metadata', executionMode: 'approval', approvalRequired: true,
    subject: { type: 'iam_metadata_requests', id: intentId }, requester: { type: 'console', id: randomUUID() },
    definition: { id: randomUUID(), version: 1, policyHash: 'a'.repeat(64) },
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(),
    scope: { transportScope: 'b'.repeat(64), clusterRevision: 2, workspaceRevision: 3 }, prerequisites: [],
    steps: [{ id: randomUUID(), key: 'iam.metadata', handler: 'iam.metadata', order: 1, kind: 'metadata',
      entityType: 'iam_metadata_requests', entityId: intentId,
      permissionAction: ['archive', 'binding.revoke', 'member.revoke'].includes(operation) ? 'delete' : 'write',
      dependencies: [], nativeRequests: [], before: { revision: 4 },
      metadata: { intentId, resource, operation, materialHmac: 'c'.repeat(64) },
      metadataRevision: 4, metadataBeforeHmac: 'd'.repeat(64), metadataPayloadHmac: 'e'.repeat(64) }] };
}

describe('M11 IAM request selector boundary', () => {
  it.each(validOperations)('accepts the supported %s / %s selector without adding execution capability', (resource, operation) => {
    const input = request(resource, operation), normalized = normalizeIamChangeRequest(input);
    expect(normalized).toEqual(input);
    expect(normalized).not.toBe(input);
    expect(normalized.input).not.toBe(input.input);
    expect(Object.isFrozen(normalized)).toBe(true);
  });

  it.each([
    null, undefined, 'roles', [], 4,
    { resource: 'permissions', operation: 'create', input: {} },
    { resource: 'roles', operation: 'delete', resourceId: randomUUID(), input: {} },
    { resource: 'roles', operation: 'reset-password', resourceId: randomUUID(), input: {} },
    { resource: 'roles', operation: 'update', resourceId: randomUUID() },
    { resource: 'roles', operation: 'update', resourceId: randomUUID(), input: null },
    { resource: 'roles', operation: 'update', resourceId: randomUUID(), input: [] },
    { resource: 'roles', operation: 'update', resourceId: randomUUID(), input: 'injected' },
  ])('refuses malformed or unsupported selector %#', input => {
    expect(() => normalizeIamChangeRequest(input)).toThrow();
  });

  it.each(['clusterId', 'workspaceId', 'actorId', 'handler', 'nativeRequests', 'workflowKind', 'approved', 'originalHandle'])
    ('refuses caller-supplied %s execution selectors', field => {
      expect(() => normalizeIamChangeRequest({ ...request(), [field]: randomUUID() })).toThrow();
    });

  it.each(['services', '/roles', '../users', 'roles;DROP TABLE users', 'Roles'])('refuses non-enumerated resource %s', resource => {
    expect(() => normalizeIamChangeRequest({ ...request(), resource })).toThrow();
  });

  it.each(['resourceId', 'relatedId'])('requires actual UUID syntax for %s', field => {
    for (const value of ['', 'not-a-uuid', '../other', '00000000-0000-0000-0000-000000000000', {}, [], 12, null]) {
      const input = request('users', 'binding.revoke');
      input[field] = value;
      expect(() => normalizeIamChangeRequest(input)).toThrow();
    }
  });

  it('rejects a caller-allocated create ID and every mutation missing its resource ID', () => {
    expect(() => normalizeIamChangeRequest({ ...request('users', 'create'), resourceId: randomUUID() })).toThrow();
    for (const [resource, operation] of validOperations.filter(([, operation]) => operation !== 'create')) {
      const input = request(resource, operation); delete input.resourceId;
      expect(() => normalizeIamChangeRequest(input)).toThrow();
    }
  });

  it.each([
    ['users', 'permissions'], ['teams', 'permissions'], ['users', 'clone'], ['teams', 'clone'],
    ['roles', 'binding.grant'], ['roles', 'binding.revoke'], ['roles', 'binding.restore'],
    ['users', 'member.add'], ['users', 'member.revoke'], ['users', 'member.restore'],
    ['roles', 'member.add'], ['roles', 'member.revoke'], ['roles', 'member.restore'],
  ] as Array<[IamChangeResource, IamChangeOperation]>)('refuses impossible %s / %s relationship', (resource, operation) => {
    expect(() => normalizeIamChangeRequest(request(resource, operation))).toThrow();
  });

  it('requires exactly the relationship selector appropriate to each operation', () => {
    for (const [resource, operation] of validOperations) {
      const input = request(resource, operation);
      if (input.relatedId) delete input.relatedId; else input.relatedId = randomUUID();
      expect(() => normalizeIamChangeRequest(input)).toThrow();
    }
  });

  it('clones input so a submitted caller object cannot later change the intended permissions', () => {
    const input = request('roles', 'permissions');
    input.input = { permissions: [{ module: 'services', scope_values: [{ entity_type: 'services', entity_id: randomUUID() }] }] };
    const before = structuredClone(input), normalized = normalizeIamChangeRequest(input);
    input.input.permissions[0].module = 'users';
    input.input.permissions[0].scope_values[0].entity_id = randomUUID();
    input.input.permissions.push({ module: 'roles', scope_values: [] });
    expect(normalized).toEqual(before);
  });

  it('deep-freezes the normalized permission graph to prevent internal selector mutation after validation', () => {
    const input = request('roles', 'permissions');
    input.input = { permissions: [{ module: 'services', scope_values: [{ entity_type: 'services', entity_id: randomUUID() }] }] };
    const normalized = normalizeIamChangeRequest(input), before = structuredClone(normalized), nested: any = normalized.input;
    for (const value of [nested, nested.permissions, nested.permissions[0], nested.permissions[0].scope_values, nested.permissions[0].scope_values[0]]) {
      expect(Object.isFrozen(value)).toBe(true);
    }
    try { nested.permissions[0].module = 'users'; } catch { /* frozen object */ }
    try { nested.permissions.push({ module: 'users' }); } catch { /* frozen array */ }
    expect(normalized).toEqual(before);
  });

  it('rejects a non-serializable request graph before it can become persisted approval material', () => {
    const circular = request(); circular.input.parent = circular.input;
    expect(() => normalizeIamChangeRequest(circular)).toThrow();
    const bigint = request(); bigint.input.revision = 4n;
    expect(() => normalizeIamChangeRequest(bigint)).toThrow();
  });
});

describe('M11 IAM fixed zero-Native approval plan boundary', () => {
  it.each(validOperations)('allows one fixed metadata step for %s / %s with its exact permission action', (resource, operation) => {
    const value = plan(resource, operation), before = structuredClone(value);
    expect(assertIamMetadataPlan(value)).toBe(value.steps[0]);
    expect(value).toEqual(before);
    expect(value.steps[0].nativeRequests).toEqual([]);
  });

  it.each(['kind', 'subject-type', 'subject-id', 'requester', 'direct', 'approval-disabled', 'empty-steps', 'second-step', 'prerequisite', 'generated', 'migration'])
    ('refuses %s plan capability substitution', variant => {
      const value = plan();
      if (variant === 'kind') value.kind = 'configuration_v2';
      if (variant === 'subject-type') value.subject.type = 'entity_change_intents';
      if (variant === 'subject-id') value.subject.id = randomUUID();
      if (variant === 'requester') value.requester.type = 'developer';
      if (variant === 'direct') value.executionMode = 'direct';
      if (variant === 'approval-disabled') value.approvalRequired = false;
      if (variant === 'empty-steps') value.steps = [];
      if (variant === 'second-step') value.steps.push({ ...value.steps[0], id: randomUUID(), order: 2 });
      if (variant === 'prerequisite') value.prerequisites.push({ type: 'services', id: randomUUID(), path: '/services', before: {}, fingerprint: 'a'.repeat(64) });
      if (variant === 'generated') value.generated = { consumerId: randomUUID(), aclId: randomUUID(), credentialId: randomUUID(), key: 'Synthetic-secret' };
      if (variant === 'migration') value.migration = { sourceWorkspaceId: randomUUID(), targetWorkspaceId: randomUUID(), materialHmac: 'a'.repeat(64) };
      expect(() => assertIamMetadataPlan(value)).toThrow();
    });

  it.each([undefined, null, false, 'true', 1])('requires a literal approval-required boolean %s', approvalRequired => {
    const value = plan(); value.approvalRequired = approvalRequired;
    expect(() => assertIamMetadataPlan(value)).toThrow();
  });

  it.each(['array-like-steps', 'array-like-prerequisites', 'string-prerequisites', 'array-like-native', 'string-native', 'array-like-dependencies', 'string-dependencies'])
    ('does not accept %s in place of the fixed zero-Native array structure', variant => {
      const value = plan(), step = value.steps[0];
      if (variant === 'array-like-steps') value.steps = { 0: step, length: 1 };
      if (variant === 'array-like-prerequisites') value.prerequisites = { length: 0 };
      if (variant === 'string-prerequisites') value.prerequisites = '';
      if (variant === 'array-like-native') step.nativeRequests = { length: 0 };
      if (variant === 'string-native') step.nativeRequests = '';
      if (variant === 'array-like-dependencies') step.dependencies = { length: 0 };
      if (variant === 'string-dependencies') step.dependencies = '';
      expect(() => assertIamMetadataPlan(value)).toThrow();
    });

  it.each(['native-kind', 'handler', 'key', 'entity-type', 'entity-id', 'dependency', 'native-packet', 'parentId', 'credentialKind', 'mutationAction', 'mutationPayload', 'mutationPayloadHmac', 'beforeFingerprint', 'mutationIdempotencyKey'])
    ('refuses %s step capability substitution', variant => {
      const value = plan(), step = value.steps[0];
      if (variant === 'native-kind') step.kind = 'native';
      if (variant === 'handler') step.handler = 'entity.change';
      if (variant === 'key') step.key = 'execute.caller';
      if (variant === 'entity-type') step.entityType = 'users';
      if (variant === 'entity-id') step.entityId = randomUUID();
      if (variant === 'dependency') step.dependencies.push(randomUUID());
      if (variant === 'native-packet') step.nativeRequests.push({ method: 'POST', canonicalPath: '/consumers', nativeType: 'consumers', nativeId: randomUUID(), body: { username: 'injected' }, bodyHmac: 'f'.repeat(64) });
      if (['parentId', 'credentialKind', 'mutationAction', 'mutationPayload', 'mutationPayloadHmac', 'beforeFingerprint', 'mutationIdempotencyKey'].includes(variant)) {
        const values: any = { parentId: randomUUID(), credentialKind: 'key-auth', mutationAction: 'create', mutationPayload: { username: 'injected' }, mutationPayloadHmac: 'f'.repeat(64), beforeFingerprint: 'f'.repeat(64), mutationIdempotencyKey: 'injected-operation' };
        step[variant] = values[variant];
      }
      expect(() => assertIamMetadataPlan(value)).toThrow();
    });

  it.each(['missing', 'array', 'extra-body', 'extra-handler', 'missing-field', 'foreign-intent', 'invalid-intent', 'resource', 'operation', 'material-hmac'])
    ('refuses %s metadata payload substitution', variant => {
      const value = plan(), step = value.steps[0];
      if (variant === 'missing') delete step.metadata;
      if (variant === 'array') step.metadata = [];
      if (variant === 'extra-body') step.metadata.body = { password: 'Synthetic-injected' };
      if (variant === 'extra-handler') step.metadata.handler = 'entity.change';
      if (variant === 'missing-field') delete step.metadata.materialHmac;
      if (variant === 'foreign-intent') step.metadata.intentId = randomUUID();
      if (variant === 'invalid-intent') step.metadata.intentId = value.subject.id = step.entityId = 'not-a-uuid';
      if (variant === 'resource') step.metadata.resource = 'permissions';
      if (variant === 'operation') step.metadata.operation = 'reset-password';
      if (variant === 'material-hmac') step.metadata.materialHmac = 'A'.repeat(64);
      expect(() => assertIamMetadataPlan(value)).toThrow();
    });

  it.each([
    ['users', 'permissions'], ['teams', 'clone'], ['roles', 'binding.grant'], ['roles', 'member.add'], ['users', 'member.revoke'],
  ] as Array<[IamChangeResource, IamChangeOperation]>)('does not admit impossible %s / %s through a metadata plan', (resource, operation) => {
    expect(() => assertIamMetadataPlan(plan(resource, operation))).toThrow();
  });

  it.each(validOperations)('prevents permission-action widening for %s / %s', (resource, operation) => {
    const value = plan(resource, operation);
    value.steps[0].permissionAction = value.steps[0].permissionAction === 'delete' ? 'write' : 'delete';
    expect(() => assertIamMetadataPlan(value)).toThrow();
  });

  it.each(['metadataBeforeHmac', 'metadataPayloadHmac'])('requires a bounded lowercase HMAC for %s', field => {
    for (const hmac of [undefined, null, '', 'f'.repeat(63), 'f'.repeat(65), 'z'.repeat(64), 'F'.repeat(64)]) {
      const value = plan(); value.steps[0][field] = hmac;
      expect(() => assertIamMetadataPlan(value)).toThrow();
    }
  });

  it.each([-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '4', undefined, null])('rejects an invalid metadata revision %s', revision => {
    const value = plan(); value.steps[0].metadataRevision = revision;
    expect(() => assertIamMetadataPlan(value)).toThrow();
  });
});
