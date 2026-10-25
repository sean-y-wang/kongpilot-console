import { describe, expect, it } from 'vitest';
import { workflowBoardColumn, workflowOverdue } from '../../apps/console-web/src/features/workflow-board.model';

describe('workflow board preserves server states', () => {
  it('keeps pending and approved separate from in-flight and unknown outcomes', () => {
    expect(['pending', 'approved', 'executing'].map(workflowBoardColumn)).toEqual(['pending', 'approved', 'executing']);
    expect(['partial', 'uncertain', 'failed', 'expired', 'future-state'].map(workflowBoardColumn)).toEqual(Array(5).fill('closed'));
  });
  it('reminds only expired pending or approved orders, without relabelling active or uncertain work', () => {
    const expiresAt = '2026-10-13T20:00:00.000Z', now = Date.parse(expiresAt);
    expect(workflowOverdue({ state: 'pending', expiresAt }, now)).toBe(true);
    expect(workflowOverdue({ state: 'approved', expiresAt }, now - 1)).toBe(false);
    for (const state of ['executing', 'uncertain', 'succeeded', 'partial', 'failed', 'cancelled', 'expired']) {
      expect(workflowOverdue({ state, expiresAt }, now + 1)).toBe(false);
    }
    expect(workflowOverdue({ state: 'pending', expiresAt: 'invalid' }, now)).toBe(false);
  });
});
