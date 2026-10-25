import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { assertWorkflowCandidateFeasibility, normalizeWorkflowApprovalPolicy } from '../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import type { WorkflowCandidateManifest } from '../../apps/console-api/src/modules/workflows/workflow-approval.types';

const candidate = (userId: string) => ({ userId, credentialEpoch: '1', provenance: [{ kind: 'user' as const, selectorId: userId }] });
const stage = (level: number, users: string[], threshold = 1): WorkflowCandidateManifest['stages'][number] => ({ level, mode: 'quorum', threshold, candidates: users.map(candidate) });
const policy = (users: string[]) => ({ version: 2, kind: 'portal-publication', allowSelfApproval: false, stages: [{ level: 1, name: '安全审核', mode: 'any', threshold: 1, selector: { users } }] });
describe('M11 bounded approval policy and actual candidate matching', () => {
  it('normalizes selectors and freezes defaults without extending the plan envelope', () => {
    const id = randomUUID(), value = normalizeWorkflowApprovalPolicy(policy([id, id]));
    expect(value.intentTtlHours).toBe(24); expect(value.distinctAcrossStages).toBe(true); expect(value.stages[0].selector.users).toEqual([id]); expect(Object.isFrozen(value.stages)).toBe(true);
  });
  it('rejects self approval and client authority fields', () => {
    expect(() => normalizeWorkflowApprovalPolicy({ ...policy([randomUUID()]), allowSelfApproval: true })).toThrow();
    expect(() => normalizeWorkflowApprovalPolicy({ ...policy([randomUUID()]), actorId: randomUUID() })).toThrow();
  });
  it('requires contiguous stages and a real all threshold derived from frozen candidates', () => {
    const value = policy([randomUUID()]);
    expect(() => normalizeWorkflowApprovalPolicy({ ...value, stages: [{ ...value.stages[0], level: 2 }] })).toThrow();
    expect(() => normalizeWorkflowApprovalPolicy({ ...value, stages: [{ ...value.stages[0], mode: 'all', threshold: 1 }] })).toThrow();
    expect(normalizeWorkflowApprovalPolicy({ ...value, stages: [{ ...value.stages[0], mode: 'all', threshold: null }] }).stages[0].threshold).toBeNull();
  });
  it('accepts overlapping pools when a distinct assignment exists', () => {
    const a = randomUUID(), b = randomUUID(); expect(() => assertWorkflowCandidateFeasibility([stage(1, [a, b]), stage(2, [b])], true)).not.toThrow();
  });
  it('rejects a globally impossible pool despite each stage being individually sufficient', () => {
    const a = randomUUID(), b = randomUUID(); expect(() => assertWorkflowCandidateFeasibility([stage(1, [a, b], 2), stage(2, [b])], true)).toThrow();
  });
  it('allows explicit cross-stage reuse and checks remaining distinct capacity', () => {
    const a = randomUUID(), b = randomUUID(); expect(() => assertWorkflowCandidateFeasibility([stage(1, [a]), stage(2, [a])], false, new Set([a]))).not.toThrow();
    expect(() => assertWorkflowCandidateFeasibility([stage(2, [a, b], 2)], true, new Set([a]))).toThrow();
  });
});
