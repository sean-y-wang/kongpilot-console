import { describe, expect, it } from 'vitest';
import { configurationDetailEntity } from '../../apps/console-web/src/features/m8.model';
import { configurationCanCreateWorkflow, configurationWorkflowAttempt, configurationWorkflowReceiptPointer, configurationWorkflowRegisteredPlanMatches } from '../../apps/console-web/src/features/configuration-workflow.model';
import { expiry, id, identity, publishedPlan, receipt, requestKey, sourcePlan } from './helpers/configuration-workflow-web.fixture';
const original = () => configurationWorkflowAttempt(identity, sourcePlan(), requestKey);
describe('new configuration workflow publication receipts prove only registration', () => {
  it('binds the original key/author/source and the actual independently published plan', () => {
    const proof = configurationWorkflowReceiptPointer(receipt(), original());
    expect(proof).toEqual({ actorId: identity.actor, clusterId: identity.cid, workspaceId: identity.wid, sourcePlanId: id(4), jobId: id(6), planId: id(7), workflowId: id(8), issueId: id(9), expiresAt: expiry, state: 'waiting_approval', registrationOnly: true });
    expect(configurationWorkflowRegisteredPlanMatches(proof, publishedPlan())).toBe(true);
    expect(configurationCanCreateWorkflow(publishedPlan(), identity)).toBe(false);
  });
  it.each(['running', 'succeeded', 'failed', 'partial', 'uncertain', 'cancelled'])('keeps later %s execution as its actual state without claiming native success', state => {
    const proof = configurationWorkflowReceiptPointer(receipt(state), original()); expect(proof.state).toBe(state); expect(proof.registrationOnly).toBe(true);
    expect(proof).not.toHaveProperty('success'); expect(proof).not.toHaveProperty('executionCompleted');
  });
  it.each([
    ['domain', 'workflow'], ['durable', false], ['registrationCompleted', false], ['submissionCompleted', false], ['idempotencyKey', id(99)],
    ['actorId', id(99)], ['clusterId', id(99)], ['workspaceId', id(99)], ['id', id(99)], ['jobId', id(99)], ['planId', id(99)], ['workflowId', id(99)],
    ['authorityDomain', 'legacy-http-v1'], ['durableIssueId', id(99)], ['sourcePlanId', id(99)], ['expiresAt', 'not-a-deadline'], ['executionMode', 'direct'], ['approvalRequired', false], ['state', 'succeeded'],
  ])('rejects a mismatched top-level receipt %s', (field, value) => { expect(() => configurationWorkflowReceiptPointer({ ...receipt(), [field]: value }, original())).toThrow(); });
  it.each([
    ['actorId', id(99)], ['clusterId', id(99)], ['workspaceId', id(99)], ['planId', id(4)], ['workflowId', undefined], ['kind', 'import'],
    ['authorityDomain', 'legacy-http-v1'], ['durableIssueId', undefined], ['sourcePlanId', undefined], ['expiresAt', '2099-01-01T00:00:01.000Z'],
  ])('rejects mismatched actual job %s', (field, value) => { const raw = receipt(); raw.job[field] = value; expect(() => configurationWorkflowReceiptPointer(raw, original())).toThrow(); });
  it.each(['authorityDomain', 'durableIssueId', 'sourcePlanId', 'expiresAt'])('rejects a missing persisted safeProgress marker %s', field => { const raw = receipt(); delete raw.job.safeProgress[field]; expect(() => configurationWorkflowReceiptPointer(raw, original())).toThrow(); });
  it('rejects a receipt whose original scope differs even if its outer IDs appear valid', () => { const raw = receipt(); raw.originalScope.workspaceId = id(99); expect(() => configurationWorkflowReceiptPointer(raw, original())).toThrow(); });
  it.each([
    { id: id(4) }, { jobId: id(5) }, { workflowId: id(99) }, { clusterId: id(99) }, { workspaceId: id(99) }, { authorityDomain: 'legacy-http-v1' },
    { durableIssueId: id(99) }, { expiresAt: '2099-01-01T00:00:01.000Z' }, { capabilities: { apply: true, durableSubmit: false } }, { capabilities: { apply: false, durableSubmit: true } },
    { planHash: 'invalid' }, { planRevision: 0 },
  ])('requires the new Diff to match its actual publication markers %j', change => {
    const proof = configurationWorkflowReceiptPointer(receipt(), original()); expect(configurationWorkflowRegisteredPlanMatches(proof, { ...publishedPlan(), ...change } as any)).toBe(false);
  });
  it('retains only the actual paired Target unsupported reason while filtering arbitrary string capabilities', () => {
    const entity = sourcePlan(), capabilities = { apply: true, durableSubmit: false, durableSubmitBlockerCode: 'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED', durableSubmitReason: '当前配置的 Target 权重变更封存包不完整，暂不能创建配置工单', privateMaterial: 'must-never-render', download: 'yes' };
    const actual = configurationDetailEntity<any>({ entity, capabilities }, identity, entity.id);
    expect(actual.capabilities).toEqual({ apply: true, durableSubmit: false, durableSubmitBlockerCode: capabilities.durableSubmitBlockerCode, durableSubmitReason: capabilities.durableSubmitReason });
    expect(JSON.stringify(actual.capabilities)).not.toContain('must-never-render');
    for (const change of [{ durableSubmit: true }, { durableSubmitBlockerCode: 'UNKNOWN_REASON' }, { durableSubmitReason: 'x'.repeat(257) }]) expect(configurationDetailEntity<any>({ entity, capabilities: { ...capabilities, ...change } }, identity, entity.id).capabilities).not.toHaveProperty('durableSubmitReason');
  });
});
