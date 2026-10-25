import 'reflect-metadata';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {App} from 'antd';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {WorkflowBusinessSchedulesPanel} from '../../apps/console-web/src/pages/WorkflowBusinessSchedulesPanel';
import {setApiActorId} from '../../apps/console-web/src/api/client';
import {storeBusinessAttempt} from '../../apps/console-web/src/api/workflow-business-schedules.model';
const id=(n:number)=>`7b000000-0000-4000-8000-${String(n).padStart(12,'0')}`,identity={actor:id(1),cid:id(2),wid:id(3),version:'controlled-PV'};
const row={id:id(4),revision:1,state:'pending-approval',kind:'configuration_v2',workflowId:id(5),workflowPlanRevision:2,workflowPlanHash:'b'.repeat(64),requesterType:'console',requesterId:id(1),executorId:id(1),notBefore:'2099-01-01T00:10:00.000Z',windowStart:'2099-01-01T00:09:00.000Z',windowEnd:'2099-01-01T00:15:00.000Z',claimId:null,reasonCode:null,nativeAuthority:false};
function setup(action='write'){
 const values=new Map<string,string>();vi.stubGlobal('sessionStorage',{getItem:(k:string)=>values.get(k)??null,setItem:(k:string,v:string)=>values.set(k,v),removeItem:(k:string)=>values.delete(k)});setApiActorId(identity.actor);const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);
 const actor:any={id:identity.actor,username:'current-user',permissionsVersion:identity.version,forcePasswordChange:false,capabilities:{platformAdmin:false,grants:[{module:'workflows',action,cluster_id:identity.cid,workspace_id:identity.wid,scope_type:'workspace',scope_values:[identity.wid]}]}};
 const workflow:any={id:id(5),kind:'configuration_v2',clusterId:identity.cid,workspaceId:identity.wid,revision:2,planRevision:1,planHash:'a'.repeat(64),state:'pending',approvalRequired:true,executionMode:'approval',expiresAt:'2099-01-01T00:20:00.000Z',approval:{format:2,stages:[{votes:0,state:'active'}]},decisions:[],steps:[{state:'pending'}]};
 const client=new QueryClient({defaultOptions:{queries:{retry:false}}});client.setQueryData(['business-workflow-schedules',identity.actor,identity.cid,identity.wid,identity.version,undefined],{items:[row],size:20,total:null,nextCursor:null});
 const render=(extra:any={})=>renderToStaticMarkup(createElement(QueryClientProvider,{client},createElement(App,null,createElement(WorkflowBusinessSchedulesPanel,{clusterId:identity.cid,workspaceId:identity.wid,actor,workflowDetail:workflow,...extra}))));
 return{render,fetcher,workflow};
}
afterEach(()=>{setApiActorId(undefined);vi.unstubAllGlobals();});
// Static component rendering and controlled query-cache fixtures exercise UI
// policy only, not a fake backend browser, real grant or scheduled execution.
describe('business scheduling panel preserves ordinary commercial controls',()=>{
 it('renders author time fields, real metadata columns and cursor previous/next without any POST',()=>{const f=setup(),html=f.render();for(const label of ['登记排程','执行时间（本地）','窗口开始（含）','窗口结束（不含）','配置变更','执行人','状态原因','上一页','下一页'])expect(html).toContain(label);expect(html).not.toContain('ownerId');expect(html).not.toContain('executorId');expect(f.fetcher).not.toHaveBeenCalled();});
 it('shows the server deadline and bounds every local time input without inventing a fresh expiry',()=>{const f=setup(),html=f.render();expect(html).toContain('窗口结束上限');const fields=html.match(/<input[^>]*type="datetime-local"[^>]*>/g)??[];expect(fields).toHaveLength(3);const deadline=new Date(f.workflow.expiresAt),pad=(n:number)=>String(n).padStart(2,'0'),max=`${deadline.getFullYear()}-${pad(deadline.getMonth()+1)}-${pad(deadline.getDate())}T${pad(deadline.getHours())}:${pad(deadline.getMinutes())}:${pad(deadline.getSeconds())}`;for(const field of fields)expect(field).toContain(`max="${max}"`);expect(f.fetcher).not.toHaveBeenCalled();});
 it('an expired server workflow no longer offers an author form, while its schedule history remains visible',()=>{const f=setup(),html=f.render({workflowDetail:{...f.workflow,expiresAt:'2020-01-01T00:00:00.000Z'}});expect(html).not.toContain('datetime-local');expect(html).toContain('业务排程');expect(f.fetcher).not.toHaveBeenCalled();});
 it('read-only user has no author form or enabled command controls',()=>{const f=setup('read'),html=f.render();expect(html).not.toContain('datetime-local');expect(html).not.toContain('登记排程');expect(html).toContain('disabled');expect(f.fetcher).not.toHaveBeenCalled();});
 it('original unknown journal shows readonly verification and disables new commands across permission changes',()=>{const f=setup();storeBusinessAttempt({...identity,key:id(6),action:'author',workflowId:id(5),revision:2,planRevision:1,planHash:'a'.repeat(64),kind:'configuration_v2',spec:{notBefore:row.notBefore,windowStart:row.windowStart,windowEnd:row.windowEnd},state:'unknown'});const html=f.render();expect(html).toContain('原排程请求尚未核验');expect(html).toContain('核验原回执');expect(html).toContain(id(6));expect(html).toContain('disabled');expect(f.fetcher).not.toHaveBeenCalled();});
});
