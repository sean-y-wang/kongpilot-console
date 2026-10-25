import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ApiError } from '../../apps/console-web/src/api/client';
import { workflowRejectionIsDefinitive as definitive } from '../../apps/console-web/src/features/workflow-entity-change.model';

// Browser E2E matrix: an execute answered with a definitive 409 kept the
// "请求未完成…核验" banner and a retained attempt that blocked the page.
describe('workflow action definitive rejection', () => {
  it('explicit 4xx rejections are definitive', () => {
    for (const [status, code] of [[409, 'ENTITY_RECYCLE_FACT_INVALID'], [409, 'WORKFLOW_REVISION_CONFLICT'], [403, 'PERMISSION_DENIED'], [400, undefined], [404, 'WORKFLOW_NOT_FOUND'], [422, 'X']] as const)
      expect(definitive(new ApiError('x', status, code))).toBe(true);
  });
  it('true unknown outcomes stay unknown', () => {
    expect(definitive(new ApiError('x', 502, 'WRITE_RESULT_UNKNOWN'))).toBe(false);
    expect(definitive(new ApiError('x', 500))).toBe(false);
    expect(definitive(new ApiError('x', 0, 'NETWORK'))).toBe(false);
    expect(definitive(new ApiError('x', 408))).toBe(false);
    expect(definitive(new ApiError('x', 429))).toBe(false);
    expect(definitive(new ApiError('x', 409, 'IDEMPOTENCY_CONFLICT'))).toBe(false);
    expect(definitive(new ApiError('x', 409, 'EXECUTION_IN_PROGRESS'))).toBe(false);
    expect(definitive(new ApiError('x', 409, 'WORKFLOW_RESULT_UNCERTAIN'))).toBe(false);
    expect(definitive(new ApiError('x', 401, 'SESSION_CHANGED'))).toBe(false);
    expect(definitive(new ApiError('x', 409, 'C', undefined, undefined, { kind: 'workflow', state: 'partial' } as any))).toBe(false);
    expect(definitive(new ApiError('x', 409, 'C', undefined, undefined, { kind: 'workflow', state: 'uncertain' } as any))).toBe(false);
    expect(definitive(new Error('请求已返回，原回执仍未证明完成'))).toBe(false);
    expect(definitive(undefined)).toBe(false);
  });
  it('WorkflowsPage releases the attempt only for a definitive rejection of the action POST itself', () => {
    const src = readFileSync('apps/console-web/src/features/WorkflowsPage.tsx', 'utf8');
    expect(src).toMatch(/catch \(rejected\) \{ if \(workflowRejectionIsDefinitive\(rejected\)\) \{ releaseAttempt\(reference\); throw Object\.assign\(rejected as object, \{ definitiveRejection: true, recovery: undefined \}\); \} throw rejected; \}/);
    // Receipt gaps after a 2xx and non-definitive failures still retain the key.
    expect(src).toMatch(/if \(\(cause as \{ definitiveRejection\?: boolean \}\)\?\.definitiveRejection\) throw cause; const retained = \{ \.\.\.reference, state:/);
    const shared = readFileSync('apps/console-web/src/components/Shared.tsx', 'utf8');
    expect(shared).toContain("definitiveRejection === true ? '请求已被服务端明确拒绝（无需核验原请求）' : '请求未完成'");
  });
});
