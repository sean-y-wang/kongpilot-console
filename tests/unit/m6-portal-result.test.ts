import { describe, expect, it } from 'vitest';
import { portalWorkflowNotice } from '../../apps/console-web/src/features/portal-result';

const businessId = '1240998d-bb26-462f-a5e1-d80e265d28d1';
const workflowId = 'b11b98ad-a82c-4c0d-a0e7-b1d26a63b04b';

describe('M6 actual compound portal-result projection', () => {
  it('uses the top-level parent identity and terminal receipt while the returned publication has a different ID', () => {
    const notice = portalWorkflowNotice({ entity: { id: businessId, status: 'published' }, workflowId, receipt: { workflowId, state: 'succeeded' } }, true);
    expect(notice).toEqual({ workflowId, href: `/workflows/${workflowId}`, type: 'success', message: '变更执行完成，配置生效中' });
    expect(notice?.href).not.toContain(businessId);
  });

  it('shows a safe identifier without an unauthorized details link for a Portal-only role', () => {
    expect(portalWorkflowNotice({ entity: { id: businessId }, workflowId, receipt: { state: 'pending' } }, false)).toEqual({ workflowId, type: 'info', message: '变更已提交，等待审批' });
  });

  it('keeps partial and uncertain parent results visible rather than accepting nested entity success', () => {
    for (const state of ['partial', 'uncertain']) {
      const notice = portalWorkflowNotice({ entity: { id: businessId, state: 'succeeded' }, workflowId, receipt: { state } }, true);
      expect(notice?.type).toBe('warning');
      expect(notice?.message).not.toContain('执行完成');
    }
  });

  it('accepts an actual approval summary while rejecting a business ID or unsafe path pretending to be a workflow ID', () => {
    expect(portalWorkflowNotice({ entity: { id: workflowId, kind: 'portal-publication', state: 'approved' } }, true)?.href).toBe(`/workflows/${workflowId}`);
    expect(portalWorkflowNotice({ entity: { id: businessId, state: 'published' } }, true)).toBeUndefined();
    expect(portalWorkflowNotice({ entity: { id: businessId }, workflowId: '../audit' }, true)).toBeUndefined();
  });

  it('never claims a terminal outcome from an unknown server state', () => {
    const notice = portalWorkflowNotice({ workflowId, entity: { id: businessId, state: 'succeeded' }, receipt: { state: 'future-state' } }, true);
    expect(notice?.type).toBe('info');
    expect(notice?.message).toBe('变更已登记，请核验执行状态');
  });
});
