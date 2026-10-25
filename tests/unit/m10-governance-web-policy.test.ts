import { describe, expect, it } from 'vitest';
import { governanceCan, governanceCredentialKinds, governanceCredentialSelection, governanceEnvironment, governanceIdentityKey, governanceObjectLink, governancePair, governancePairCan, governancePath, governancePlanLink, governanceReceiptPath, governanceReceiptResult, governanceReconcileConfirmation, governanceRecoveryReference, governanceRuleDocument, governanceSafeValue, governanceSourceObjectKey, governanceTypedConfirmation, sameGovernanceIdentity, sameGovernancePair } from '../../apps/console-web/src/features/governance.model';
import type { Capabilities, EffectiveGrant } from '../../apps/console-web/src/api/types';

const actor = '11111111-1111-4111-8111-111111111111', cid = '22222222-2222-4222-8222-222222222222', wid = '33333333-3333-4333-8333-333333333333', other = '44444444-4444-4444-8444-444444444444', target = '55555555-5555-4555-8555-555555555555';
const sourceEnv = { clusterId: cid, workspaceId: wid, scope: 'workspace' as const, serviceIds: [] }, targetEnv = { clusterId: other, workspaceId: target, scope: 'workspace' as const, serviceIds: [] }, identity = { actor, version: 'epoch-1', cid, wid };
const grants = (rows: EffectiveGrant[]): Capabilities => ({ platformAdmin: false, modules: {}, clusters: [], grants: rows });
const grant = (cluster: string, workspace: string, action: EffectiveGrant['action']): EffectiveGrant => ({ module: 'promote', action, cluster_id: cluster, workspace_id: workspace, scope_type: 'workspace', scope_values: [workspace] });

describe('M10 frontend scope, confirmation and projection boundaries', () => {
  it('ties cached material to actor, permission epoch and both local scope dimensions', () => {
    expect(sameGovernanceIdentity(identity, { ...identity })).toBe(true);
    for (const change of [{ actor: other }, { version: 'epoch-2' }, { cid: other }, { wid: other }]) {
      expect(sameGovernanceIdentity(identity, { ...identity, ...change })).toBe(false);
      expect(governanceIdentityKey(identity, 'reports')).not.toBe(governanceIdentityKey({ ...identity, ...change }, 'reports'));
    }
  });
  it('normalizes the exact authorized selection and rejects mismatched service scopes', () => {
    expect(governanceEnvironment(sourceEnv)).toEqual(sourceEnv);
    expect(governanceEnvironment({ ...sourceEnv, scope: 'services', serviceIds: [other, actor, other] }).serviceIds).toEqual([actor, other]);
    for (const input of [{ ...sourceEnv, workspaceId: undefined }, { ...sourceEnv, scope: 'cluster' }, { ...sourceEnv, serviceIds: [actor] }, { ...sourceEnv, scope: 'services' }, { ...sourceEnv, scope: 'services', serviceIds: ['../services'] }, { ...sourceEnv, scope: 'services', serviceIds: Array(101).fill(actor) }]) expect(() => governanceEnvironment(input)).toThrow();
  });
  it('invalidates old compare/promote material when either environment or permissions changes', () => {
    const pair = governancePair(sourceEnv, targetEnv, actor, 'epoch-1');
    expect(sameGovernancePair(pair, governancePair(sourceEnv, targetEnv, actor, 'epoch-1'))).toBe(true);
    for (const changed of [{ ...pair, actor: other }, { ...pair, version: 'epoch-2' }, { ...pair, source: { ...sourceEnv, workspaceId: other } }, { ...pair, target: { ...targetEnv, workspaceId: wid } }, { ...pair, target: { ...targetEnv, scope: 'services' as const, serviceIds: [actor] } }]) expect(sameGovernancePair(pair, changed)).toBe(false);
    expect(() => governancePair(sourceEnv, sourceEnv, actor, 'epoch-1')).toThrow();
    expect(() => governancePair(sourceEnv, targetEnv, undefined, 'epoch-1')).toThrow();
  });
  it('requires source read and target write independently, never trusting a module flag', () => {
    const pair = governancePair(sourceEnv, targetEnv, actor, 'epoch-1');
    expect(governancePairCan(grants([grant(cid, wid, 'read'), grant(other, target, 'write')]), 'promote', 'write', pair)).toBe(true);
    for (const rows of [[grant(cid, wid, 'read')], [grant(other, target, 'write')], [grant(cid, target, 'read'), grant(other, target, 'write')], [grant(cid, wid, 'read'), grant(other, wid, 'write')]]) expect(governancePairCan(grants(rows), 'promote', 'write', pair)).toBe(false);
    expect(governancePairCan({ ...grants([]), modules: { promote: { read: true, write: true, delete: true, approve: true } } }, 'promote', 'write', pair)).toBe(false);
  });
  it('never turns projection grants into shared rule or schedule management permissions', () => {
    const cap = grants([{ ...grant(cid, wid, 'write'), module: 'lint', scope_type: 'tag_group', scope_values: ['team:pay'] }]);
    expect(governanceCan(cap, 'lint', 'write', sourceEnv)).toBe(true);
    expect(governanceCan(cap, 'lint', 'write', sourceEnv, true)).toBe(false);
  });
  it('generates only BFF scoped paths and escapes filter material', () => {
    expect(governancePath(identity, 'reports', { cursor: 'x&workspaceId=foreign' })).toBe(`/clusters/${cid}/governance/reports?cursor=x%26workspaceId%3Dforeign&workspaceId=${wid}`);
    for (const path of ['https://kong:8001/services', '../services', 'reports//other', 'reports?approved=true', '/cache']) expect(() => governancePath(identity, path)).toThrow();
    expect(() => governancePath({ ...identity, wid: undefined }, 'reports')).toThrow();
  });
  it('uses exact typed confirmations without DTO authorization flags', () => {
    expect(governanceTypedConfirmation('publish-prod', 'publish-prod')).toEqual({ confirmed: true, confirm_name: 'publish-prod' });
    for (const input of ['publish-prod ', 'PUBLISH-PROD', true, undefined]) expect(() => governanceTypedConfirmation('publish-prod', input)).toThrow();
    expect(() => governanceTypedConfirmation('', '')).toThrow();
  });
  it('links only real known entity paths and target parents', () => {
    expect(governanceObjectLink('services', actor)).toBe(`/entities/services/${actor}`);
    expect(governanceObjectLink('targets', actor, other)).toBe(`/entities/upstreams/${other}`);
    expect(governanceObjectLink('targets', actor)).toBeUndefined();
    expect(governanceObjectLink('vaults', actor)).toBeUndefined();
    expect(governanceObjectLink('services', 'javascript:alert(1)')).toBeUndefined();
  });
  it('does not reflect secret values, capabilities or PEM into public evidence', () => {
    const input = { name: 'safe', password: 'do-not-display', config: { authorization: 'Bearer do-not-display', url: 'https://user:do-not-display@private/path' }, payloadHmac: 'do-not-display', sourceProof: { approved: true }, evidence: '-----BEGIN PRIVATE KEY-----\ndo-not-display', nested: { key: 'do-not-display' }, constructor: 'do-not-display' };
    const output = governanceSafeValue(input);
    expect(output).toMatchObject({ name: 'safe', password: '[已隐藏]', evidence: '[已隐藏]' });
    expect(JSON.stringify(output)).not.toContain('do-not-display');
    expect(JSON.stringify(output)).not.toContain('sourceProof');
    expect(JSON.stringify(output)).not.toContain('payloadHmac');
  });
  it('requires real original operation identity, never a standalone report entity', () => {
    const reference = { actorId: actor, clusterId: cid, workspaceId: wid, idempotencyKey: other };
    const receipt = { id: target, ...reference, domain: 'governance', kind: 'inspection', state: 'succeeded', registrationCompleted: true, submissionCompleted: false, executionCompleted: true, nativeExecutionRequested: false, entity: { id: target } };
    expect(governanceReceiptResult(receipt, reference)).toMatchObject({ complete: true, success: true });
    expect(() => governanceReceiptResult({ entity: { id: target } }, reference)).toThrow();
    for (const change of [{ actorId: other }, { clusterId: other }, { workspaceId: other }, { idempotencyKey: target }, { kind: 'arbitrary-proxy' }, { nativeExecutionRequested: true }, { id: 'not-an-id' }]) expect(() => governanceReceiptResult({ ...receipt, ...change }, reference)).toThrow();
    for (const state of ['pending', 'running', 'uncertain', 'partial', 'planning']) expect(governanceReceiptResult({ ...receipt, state }, reference).complete).toBe(false);
  });
  it('distinguishes real metadata commit, workflow submission and unexecuted M8 plan registration', () => {
    const reference = { actorId: actor, clusterId: cid, workspaceId: wid, idempotencyKey: other }, common = { id: target, ...reference, registrationCompleted: true, nativeExecutionRequested: false };
    expect(governanceReceiptResult({ ...common, domain: 'iam', kind: 'rule-change', state: 'succeeded', configurationCommitted: false, executionCompleted: false }, reference).complete).toBe(false);
    expect(governanceReceiptResult({ ...common, domain: 'iam', kind: 'rule-change', state: 'succeeded', configurationCommitted: true, executionCompleted: true }, reference)).toMatchObject({ complete: true, label: '治理配置已保存' });
    const workflow = { ...common, domain: 'workflow', kind: 'schedule-change', state: 'pending_approval', submissionCompleted: true, executionCompleted: false, workflowId: target };
    expect(governanceReceiptResult(workflow, reference)).toMatchObject({ complete: true, success: true, label: '已提交审批' });
    expect(governanceReceiptResult({ ...workflow, state: 'pending' }, reference)).toMatchObject({ complete: true, success: true, label: '已提交审批' });
    expect(governanceReceiptResult({ ...workflow, workflowId: undefined }, reference).complete).toBe(false);
    const plan = { ...common, domain: 'governance', kind: 'promotion-plan', state: 'ready', executionCompleted: false, jobId: target };
    expect(governanceReceiptResult(plan, reference)).toMatchObject({ complete: true, success: true, label: '变更预览已生成，尚未执行网关变更' });
    expect(governanceReceiptResult({ ...plan, jobId: undefined }, reference).complete).toBe(false);
  });
  it('reads original governance recovery using its own source scope after selectors change', () => {
    const reference = governanceRecoveryReference({ kind: 'governance', clusterId: cid, workspaceId: wid, idempotencyKey: other }, actor);
    expect(governanceReceiptPath(reference)).toBe(`/clusters/${cid}/governance/operations/by-key/${other}?workspaceId=${wid}`);
    for (const invalid of [{ domain: 'iam' }, { kind: 'configuration' }, { workspaceId: undefined }, { idempotencyKey: '../again' }]) expect(() => governanceRecoveryReference({ kind: 'governance', clusterId: cid, workspaceId: wid, idempotencyKey: other, ...invalid }, actor)).toThrow();
  });
  it('bounds typed JSON and rejects prototype paths/network refs without reflecting input', () => {
    expect(governanceRuleDocument('{"field":"enabled","equals":false}')).toEqual({ field: 'enabled', equals: false });
    for (const input of ['[]', 'null', '{"constructor":1}', '{"__proto__":{}}', '{"$ref":"https://private"}', '{"x":'.repeat(18) + '0' + '}'.repeat(18), 'x'.repeat(17000), 'not-valid-password']) {
      expect(() => governanceRuleDocument(input)).toThrow();
      try { governanceRuleDocument(input); } catch (error) { expect((error as Error).message).not.toContain('not-valid-password'); }
    }
  });
  it('links a target M8 plan only from the actual verified origin receipt and exact chosen target', () => {
    const receipt = { id: actor, actorId: actor, clusterId: cid, workspaceId: wid, idempotencyKey: other, domain: 'governance' as const, kind: 'promotion-plan' as const, state: 'ready', registrationCompleted: true, submissionCompleted: false, executionCompleted: false, nativeExecutionRequested: false as const, jobId: actor, planId: cid, targetClusterId: other, targetWorkspaceId: target };
    expect(governancePlanLink(receipt, targetEnv)).toEqual({ jobId: actor, planId: cid, state: 'ready', targetClusterId: other, targetWorkspaceId: target });
    expect(() => governancePlanLink({ ...receipt, targetWorkspaceId: wid }, targetEnv)).toThrow();
    expect(() => governancePlanLink({ ...receipt, planId: '../foreign' }, targetEnv)).toThrow();
    expect(governancePlanLink({ ...receipt, jobId: undefined }, targetEnv)).toBeUndefined();
    expect(governancePlanLink({ ...receipt, kind: 'rule-change' }, targetEnv)).toBeUndefined();
  });
  it('closes annotation metadata fixes only after the exact real child is sealed into its parent', () => {
    const reference = { actorId: actor, clusterId: cid, workspaceId: wid, idempotencyKey: other };
    const receipt = { id: target, ...reference, domain: 'iam', kind: 'fix-plan', state: 'succeeded', registrationCompleted: true, submissionCompleted: false, executionCompleted: true, nativeExecutionRequested: false, configurationCommitted: true, governanceRequestId: target, governanceState: 'ready', metadataOnlyResult: true, metadataOperationId: actor, metadataChildKey: `governance-fix-${target}`, metadataReconciliationPending: false };
    expect(governanceReceiptResult(receipt, reference)).toMatchObject({ complete: true, success: true });
    for (const changed of [{ governanceState: 'uncertain' }, { governanceRequestId: actor }, { metadataOperationId: undefined }, { metadataChildKey: `governance-fix-${actor}` }, { metadataReconciliationPending: true }, { metadataOnlyResult: false }]) expect(governanceReceiptResult({ ...receipt, ...changed }, reference).complete).toBe(false);
    const nativeChild = { ...receipt, domain: 'governance', state: 'ready', jobId: actor, metadataReconciliationPending: true };
    expect(governanceReceiptResult(nativeChild, reference).complete).toBe(false);
  });
  it('permits only typed metadata reconciliation of the exact existing child under the original key', () => {
    const reference = { actorId: actor, clusterId: cid, workspaceId: wid, idempotencyKey: other };
    const receipt = { id: target, ...reference, domain: 'governance' as const, kind: 'fix-plan' as const, state: 'uncertain', registrationCompleted: true, submissionCompleted: false, executionCompleted: false, nativeExecutionRequested: false as const, governanceRequestId: target, governanceState: 'uncertain', jobId: actor, metadataReconciliationPending: true };
    expect(governanceReconcileConfirmation(receipt, reference, `reconcile:${other}`)).toEqual({ confirmed: true, confirm_name: `reconcile:${other}` });
    for (const changed of [{ jobId: undefined }, { governanceRequestId: actor }, { metadataReconciliationPending: false }, { kind: 'promotion-plan' as const }, { actorId: other }]) expect(() => governanceReconcileConfirmation({ ...receipt, ...changed }, reference, `reconcile:${other}`)).toThrow();
    expect(() => governanceReconcileConfirmation(receipt, reference, `reconcile:${actor}`)).toThrow();
  });
  it('keeps credential inclusion explicit and accepts only the six native credential kinds', () => {
    expect(governanceCredentialSelection(false, ['key-auth'])).toBeUndefined();
    expect(governanceCredentialSelection(true, [])).toBeUndefined();
    expect(governanceCredentialSelection(true, ['key-auth', 'jwt', 'acls'])).toEqual(['key-auth', 'jwt', 'acls']);
    expect(governanceCredentialSelection(true, [...governanceCredentialKinds])).toEqual(governanceCredentialKinds);
    for (const input of [['vaults'], ['keys'], ['key-auth', 'key-auth'], { approved: true }, ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls', 'key-auth']]) expect(() => governanceCredentialSelection(true, input)).toThrow();
  });
  it('selects an unchanged source Consumer by its exact server descriptor without exposing raw config', () => {
    const object = { objectKey: `consumers:${actor}`, entityType: 'consumers', nativeId: actor, name: 'developer', objectWorkspaceId: wid, referenceOnly: false, eligible: true };
    expect(governanceSourceObjectKey(object)).toBe(`consumers:${actor}`);
    for (const change of [{ eligible: false }, { referenceOnly: true }, { objectKey: `consumers:${other}` }, { nativeId: '../entities' }, { objectWorkspaceId: 'foreign' }, { entityType: 'credentials' }]) expect(governanceSourceObjectKey({ ...object, ...change })).toBeUndefined();
    const target = { ...object, entityType: 'targets', parentId: cid, objectKey: `targets:${cid}:${actor}` };
    expect(governanceSourceObjectKey(target)).toBe(target.objectKey); expect(governanceSourceObjectKey({ ...target, parentId: undefined })).toBeUndefined();
  });
});
