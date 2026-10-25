import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { App } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setApiActorId } from '../../apps/console-web/src/api/client';
import { configurationWorkflowAttempt, settleConfigurationWorkflowRejection, storeConfigurationWorkflowAttempt } from '../../apps/console-web/src/features/configuration-workflow.model';
import { id, identity, publishedPlan, rejectedReceipt, requestKey, sourcePlan } from './helpers/configuration-workflow-web.fixture';
const current = vi.hoisted(() => ({ plan: undefined as any, scope: undefined as any }));
vi.mock('../../apps/console-web/src/features/m8.hooks', () => ({
  useM8Scope: () => current.scope,
  useM8Detail: () => ({ data: current.plan, isFetching: false, refetch: vi.fn() }),
  useM8Page: () => ({ data: { items: [], nextCursor: null }, isFetching: false, page: 1 }),
  useM8Mutation: () => ({ blocked: false, busy: false, mutate: vi.fn(), result: undefined }),
  M8Pager: () => null, M8MutationNotice: () => null,
}));
vi.mock('../../apps/console-web/src/components/Shared', () => ({
  QueryError: ({ error }: any) => createElement('span', { 'data-testid': 'safe-error' }, error instanceof Error ? error.message : '请求未完成'),
  PageHeading: ({ title }: any) => createElement('h1', null, title),
  formatTime: (value: string) => value,
}));
import { ConfigurationPlanPage } from '../../apps/console-web/src/features/ConfigurationPlanPage';

let data: Map<string, string>, fetcher: ReturnType<typeof vi.fn>;
beforeEach(() => {
  data = new Map(); vi.stubGlobal('sessionStorage', { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) });
  fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher); setApiActorId(identity.actor);
  current.scope = { identity, cid: identity.cid, wid: identity.wid, writable: true, workspace: { writeBlocked: false }, permission: { has: () => true }, assertCurrent: vi.fn() };
});
afterEach(() => { setApiActorId(undefined); vi.unstubAllGlobals(); });
function render(plan: any = sourcePlan()) {
  current.plan = plan; const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return renderToStaticMarkup(createElement(QueryClientProvider, { client }, createElement(App, null,
    createElement(MemoryRouter, { initialEntries: [`/configuration/plans/${plan?.id ?? id(4)}`] }, createElement(Routes, null,
      createElement(Route, { path: '/configuration/plans/:id', element: createElement(ConfigurationPlanPage) }))))));
}
// Static rendering checks the real component decisions with controlled public
// query data. It does not claim browser or actual workflow acceptance.
describe('configuration workflow UI preserves the existing review page', () => {
  it('shows an explicit create action for the genuine server capability while preserving the existing Diff', () => {
    const html = render(); expect(html).toContain('创建配置工单'); expect(html).toContain('逐对象 Diff / 依赖'); expect(html).not.toContain('审阅并提交审批'); expect(fetcher).not.toHaveBeenCalled();
  });
  it('keeps the legacy flow when the new server capability is absent instead of inventing a route', () => {
    const source = sourcePlan(); source.capabilities = { apply: true }; const html = render(source);
    expect(html).not.toContain('创建配置工单'); expect(html).toContain('审阅并提交审批'); expect(fetcher).not.toHaveBeenCalled();
  });
  it('a published workflow plan exposes its actual expiry and Diff plus workflow link, with no apply or create action', () => {
    const html = render(publishedPlan()); expect(html).toContain('工单有效期'); expect(html).toContain('2099-01-01T00:00:00.000Z'); expect(html).toContain('逐对象 Diff / 依赖');
    expect(html).toContain(`/workflows/${id(8)}`); expect(html).toContain('查看工单'); expect(html).not.toContain('审阅并提交审批'); expect(html).not.toContain('审阅并执行'); expect(html).not.toContain('>创建配置工单<');
    expect(html).not.toContain('durable-configuration-v1'); expect(fetcher).not.toHaveBeenCalled();
  });
  it('shows the actual Target unsupported reason without claiming the append flow is supported', () => {
    const source = sourcePlan(); source.capabilities = { apply: true, durableSubmit: false, durableSubmitBlockerCode: 'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED', durableSubmitReason: '当前配置的 Target 权重变更封存包不完整，暂不能创建配置工单' };
    const html = render(source); expect(html).toContain(source.capabilities.durableSubmitReason!); expect(html).not.toContain('>创建配置工单<'); expect(fetcher).not.toHaveBeenCalled();
  });
  it('retains readonly original-key verification even when the source plan is no longer readable', () => {
    const original = configurationWorkflowAttempt(identity, sourcePlan(), requestKey); storeConfigurationWorkflowAttempt({ ...original, state: 'unknown' });
    const html = render(null); expect(html).toContain('原配置工单请求尚未核验'); expect(html).toContain(requestKey); expect(html).toContain('核验原请求'); expect(html).not.toContain('>创建配置工单<'); expect(fetcher).not.toHaveBeenCalled();
  });
  it('an unknown original request disables creation rather than substituting a new key', () => {
    storeConfigurationWorkflowAttempt({ ...configurationWorkflowAttempt(identity, sourcePlan(), requestKey), state: 'unknown' });
    const html = render(); expect(html).toContain('核验原请求'); expect(html).toMatch(/<button[^>]*disabled=""[^>]*><span>创建配置工单<\/span><\/button>/); expect(fetcher).not.toHaveBeenCalled();
  });
  it('read-only workspace keeps the create action disabled despite stale displayed capabilities', () => {
    current.scope.writable = false; const html = render(); expect(html).toMatch(/<button[^>]*disabled=""[^>]*><span>创建配置工单<\/span><\/button>/); expect(fetcher).not.toHaveBeenCalled();
  });
  it('corrupt journal blocks creation and never echoes private storage content', () => {
    storeConfigurationWorkflowAttempt(configurationWorkflowAttempt(identity, sourcePlan(), requestKey)); data.set([...data.keys()][0], '{private-never-render');
    const html = render(); expect(html).toContain('原配置工单请求记录或范围无效'); expect(html).not.toContain('private-never-render'); expect(html).toMatch(/<button[^>]*disabled=""[^>]*><span>创建配置工单<\/span><\/button>/); expect(fetcher).not.toHaveBeenCalled();
  });
  it('shows a retained rejection and explicit fresh-preview entry after reload without exposing native success or retrying the old plan', () => {
    const original = configurationWorkflowAttempt(identity, sourcePlan(), requestKey); storeConfigurationWorkflowAttempt({ ...original, state: 'unknown' });
    settleConfigurationWorkflowRejection(original, rejectedReceipt()); const html = render();
    expect(html).toContain('当前配置已变化，请重新预览后创建配置工单'); expect(html).toContain('原拒绝回执已保留'); expect(html).toContain('重新预览配置'); expect(html).toContain(requestKey);
    expect(html).not.toContain('>创建配置工单<'); expect(html).not.toContain('审阅并提交审批'); expect(html).not.toContain('durable-registration'); expect(html).not.toContain('配置已执行');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('does not expose the legacy submission fallback for the same archived rejected source, even with stale server capabilities', () => {
    const original = configurationWorkflowAttempt(identity, sourcePlan(), requestKey); storeConfigurationWorkflowAttempt({ ...original, state: 'unknown' }); settleConfigurationWorkflowRejection(original, rejectedReceipt());
    const stale = sourcePlan(); stale.capabilities = { apply: true, durableSubmit: false };
    const html = render(stale); expect(html).toContain('重新预览配置'); expect(html).not.toContain('审阅并提交审批'); expect(html).not.toContain('>创建配置工单<'); expect(fetcher).not.toHaveBeenCalled();
  });
});
