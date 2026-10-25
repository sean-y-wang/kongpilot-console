import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {App} from 'antd';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {MemoryRouter,Route,Routes} from 'react-router-dom';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {setApiActorId} from '../../apps/console-web/src/api/client';
import {configurationDetailEntity,configurationDurableSourceBlocked,configurationDurableSubmitBlocker} from '../../apps/console-web/src/features/m8.model';
import {configurationWorkflowAttempt,settleConfigurationWorkflowRejection,storeConfigurationWorkflowAttempt} from '../../apps/console-web/src/features/configuration-workflow.model';
import {id,identity,rejectedReceipt,requestKey,sourcePlan} from './helpers/configuration-workflow-web.fixture';

const current=vi.hoisted(()=>({plan:undefined as any,scope:undefined as any}));
vi.mock('../../apps/console-web/src/features/m8.hooks',()=>({
 useM8Scope:()=>current.scope,useM8Detail:()=>({data:current.plan,isFetching:false,refetch:vi.fn()}),
 useM8Page:()=>({data:{items:[],nextCursor:null},isFetching:false,page:1}),useM8Mutation:()=>({blocked:false,busy:false,mutate:vi.fn(),result:undefined}),
 M8Pager:()=>null,M8MutationNotice:()=>null,
}));
vi.mock('../../apps/console-web/src/components/Shared',()=>({
 QueryError:({error}:any)=>createElement('span',{'data-testid':'safe-error'},error instanceof Error?error.message:'请求未完成'),
 PageHeading:({title}:any)=>createElement('h1',null,title),formatTime:(value:string)=>value,
}));
import {ConfigurationPlanPage} from '../../apps/console-web/src/features/ConfigurationPlanPage';

const rejected={code:'CONFIGURATION_DURABLE_SOURCE_REJECTED',reason:'当前配置已变化，原计划已拒绝，请重新预览后创建配置工单'};
const registered={code:'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED',reason:'原计划已创建配置工单，请核验原请求并查看对应工单'};
const target={code:'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED',reason:'当前配置的 Target 权重变更封存包不完整，暂不能创建配置工单'};
let storage:Map<string,string>,fetcher:ReturnType<typeof vi.fn>;
beforeEach(()=>{
 storage=new Map();vi.stubGlobal('sessionStorage',{getItem:(key:string)=>storage.get(key)??null,setItem:(key:string,value:string)=>storage.set(key,value),removeItem:(key:string)=>storage.delete(key)});
 fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);setApiActorId(identity.actor);
 current.scope={identity,cid:identity.cid,wid:identity.wid,writable:true,workspace:{writeBlocked:false},permission:{has:()=>true},assertCurrent:vi.fn()};
});
afterEach(()=>{setApiActorId(undefined);vi.unstubAllGlobals();});
function caps(blocker:{code:string;reason:unknown},apply=false){return{apply,durableSubmit:false,durableSubmitBlockerCode:blocker.code,durableSubmitReason:blocker.reason};}
function project(capabilities:unknown,flat=false):any{
 const plan=sourcePlan();return configurationDetailEntity(flat?{...plan,capabilities}:{entity:plan,capabilities},identity,plan.id);
}
function render(plan:any){
 current.plan=plan;const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
 return renderToStaticMarkup(createElement(QueryClientProvider,{client},createElement(App,null,
  createElement(MemoryRouter,{initialEntries:[`/configuration/plans/${plan?.id??id(4)}`]},createElement(Routes,null,
   createElement(Route,{path:'/configuration/plans/:id',element:createElement(ConfigurationPlanPage)}))))));
}
describe('source-disposition fixed public capability reasons and fresh-tab static UI',()=>{
 it.each([rejected,registered])('shows safe $code in a fresh tab without local archive or legacy fallback',blocker=>{
  const plan=project(caps(blocker));expect(storage.size).toBe(0);const html=render(plan);
  expect(html).toContain(blocker.reason);expect(html).toContain('逐对象 Diff / 依赖');expect(html).not.toContain('审阅并提交审批');expect(html).not.toContain('审阅并执行');
  expect(html).not.toContain('>创建配置工单<');expect(html).not.toContain('原拒绝回执已保留');expect(storage.size).toBe(0);expect(fetcher).not.toHaveBeenCalled();
 });
 it.each([rejected,registered])('retains known $code as a deny-only hint if apply is stale true',blocker=>{
  const plan=project(caps(blocker,true)),html=render(plan);expect(configurationDurableSourceBlocked(plan.capabilities)).toBe(true);
  expect(html).toContain(blocker.reason);expect(html).not.toContain('审阅并提交审批');expect(html).not.toContain('审阅并执行');expect(fetcher).not.toHaveBeenCalled();
 });
 it('does not turn Target append refusal into a source disposition or remove its existing legacy flow',()=>{
  const plan=project(caps(target,true)),html=render(plan);expect(html).toContain(target.reason);expect(html).toContain('审阅并提交审批');
  expect(html).not.toContain('>创建配置工单<');expect(configurationDurableSourceBlocked(plan.capabilities)).toBe(false);expect(fetcher).not.toHaveBeenCalled();
 });
 it('does not render unknown code or raw server reason or disable the ordinary legacy capability',()=>{
  const plan=project(caps({code:'PRIVATE_UNKNOWN_BLOCKER',reason:'private-response-never-render'},true)),html=render(plan);
  expect(plan.capabilities).toEqual({apply:true,durableSubmit:false});expect(html).not.toContain('PRIVATE_UNKNOWN_BLOCKER');expect(html).not.toContain('private-response-never-render');
  expect(html).toContain('审阅并提交审批');expect(fetcher).not.toHaveBeenCalled();
 });
 it('uses canonical static text even when a recognized code is paired with a different bounded private string',()=>{
  const raw='secret-reference-never-render';const plan=project(caps({...rejected,reason:raw})),html=render(plan);
  expect(plan.capabilities.durableSubmitReason).toBe(rejected.reason);expect(html).toContain(rejected.reason);expect(html).not.toContain(raw);
 });
 it('also protects direct component props from raw reason rendering',()=>{
  const plan=sourcePlan();plan.capabilities=caps({...registered,reason:'private-direct-prop'});const html=render(plan);
  expect(html).toContain(registered.reason);expect(html).not.toContain('private-direct-prop');expect(html).not.toContain('审阅并提交审批');
 });
 it.each([undefined,null,42,true,false,{},[],['private'], '', '   ', 'x'.repeat(257)])('drops invalid public reason shape %j without raw UI output',reason=>{
  const plan=project(caps({...rejected,reason}));expect(plan.capabilities).toEqual({apply:false,durableSubmit:false});
  expect(configurationDurableSubmitBlocker(caps({...rejected,reason}))).toBeUndefined();
 });
 it.each([rejected,registered,target])('projects $code safely for both wrapped and flat public DTOs',blocker=>{
  for(const flat of [false,true])expect(project(caps(blocker),flat).capabilities).toEqual(caps(blocker));
 });
 it('requires durableSubmit=false rather than accepting an absent or truthy flag for reason projection',()=>{
  for(const flag of [undefined,true,'false',0]){
   const plan=project({...caps(rejected),durableSubmit:flag});expect(plan.capabilities.durableSubmitReason).toBeUndefined();expect(plan.capabilities.durableSubmitBlockerCode).toBeUndefined();
  }
 });
 it('does not accept arbitrary capability objects as a source deny or public reason',()=>{
  for(const value of [undefined,null,[],false,'CONFIGURATION_DURABLE_SOURCE_REJECTED']){
   expect(configurationDurableSourceBlocked(value)).toBe(false);expect(configurationDurableSubmitBlocker(value)).toBeUndefined();
  }
 });
 it('keeps the previously archived local rejection deny even with a stale ordinary server capability',()=>{
  const attempt=configurationWorkflowAttempt(identity,sourcePlan(),requestKey);storeConfigurationWorkflowAttempt({...attempt,state:'unknown'});settleConfigurationWorkflowRejection(attempt,rejectedReceipt());
  const plan=sourcePlan();plan.capabilities={apply:true,durableSubmit:false};const html=render(plan);
  expect(html).toContain('原拒绝回执已保留');expect(html).not.toContain('审阅并提交审批');expect(html).not.toContain('>创建配置工单<');expect(fetcher).not.toHaveBeenCalled();
 });
 it('keeps unknown original-key verification when source disposition is closed',()=>{
  const attempt=configurationWorkflowAttempt(identity,sourcePlan(),requestKey);storeConfigurationWorkflowAttempt({...attempt,state:'unknown'});
  const html=render(project(caps(registered)));expect(html).toContain('原配置工单请求尚未核验');expect(html).toContain('核验原请求');expect(html).toContain(requestKey);
  expect(html).toContain(registered.reason);expect(html).not.toContain('审阅并提交审批');expect(html).not.toContain('>创建配置工单<');expect(fetcher).not.toHaveBeenCalled();
 });
});
