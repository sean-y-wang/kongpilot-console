import {describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {OutboxRepositoryService,APPROVER_EVENT_TYPES} from '../../apps/console-api/src/modules/event-core/outbox-repository.service';
import {workflowNotificationText} from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {NotificationService} from '../../apps/console-api/src/modules/event-core/notification.service';
import {NotificationOperationsService,safeApprovalSetting} from '../../apps/console-api/src/modules/event-core/notification-operations.service';

const CID='11111111-1111-4111-8111-111111111111',WID='22222222-2222-4222-8222-222222222222',WF='33333333-3333-4333-8333-333333333333';
const users:Record<string,any>={a1:{id:'a1',username:'alice',super_admin:false},a2:{id:'a2',username:'bob',super_admin:false},a3:{id:'a3',username:'carol',super_admin:false}};
const event:any={id:'44444444-4444-4444-8444-444444444444',clusterId:CID,workspaceId:WID,eventType:'workflow.submitted',payloadSafe:{title:'待审批：网关实体变更 · 集群 prod · 发起人 dave',summary:'s'}};
function fakeTx(candidates:string[]){const inserts:any[][]=[];const sql:string[]=[];return {inserts,sql,tx:{
 one:vi.fn(async(q:string,p:any[])=>{if(q.includes('FROM event_records'))return {workflow_id:WF};if(q.includes('FROM users'))return users[p[0]]?{...users[p[0]]}:null;return null;}),
 query:vi.fn(async(q:string)=>{sql.push(q);return candidates.map(user_id=>({user_id}));}),
 exec:vi.fn(async(q:string,p:any[])=>{inserts.push(p);return 1;})} as any};}

describe('M11 default-on approver notifications',()=>{
 it('fan-out targets only submit/progress events',()=>{expect([...APPROVER_EVENT_TYPES].sort()).toEqual(['workflow.approval.progress','workflow.submitted']);});
 it('notifies active-stage candidates with a workflow link and the event title',async()=>{
  const access:any={canSourceRead:vi.fn(async()=>true),assertNotificationOwner:vi.fn(async()=>undefined)};
  const repo=new OutboxRepositoryService({} as any,{} as any,access);const f=fakeTx(['a1','a2']);
  expect(await (repo as any).approverNotifications(f.tx,event)).toBe(2);
  expect(f.inserts.map(p=>p[0])).toEqual(['a1','a2']);
  for(const p of f.inserts){expect(p.slice(1,7)).toEqual([CID,WID,event.id,event.payloadSafe.title,'s',WF]);}
  const q=f.sql[0];
  // requester, prior voters, opt-outs and non-active stages are excluded in SQL
  for(const frag of ["s.state='active'","w.state='pending'",'c.user_id IS DISTINCT FROM w.requester_user_id','FROM workflow_approvals','NOT o.approval_requests_enabled','x.candidate_version=w.candidate_version'])expect(q).toContain(frag);
  expect(access.assertNotificationOwner).toHaveBeenCalledWith(expect.objectContaining({id:'a1'}),'a1',CID,WID,'read');
 });
 it('skips candidates who lost source read or owner access, and inactive users; never widens authz',async()=>{
  const access:any={canSourceRead:vi.fn(async(a:any)=>a.id!=='a1'),assertNotificationOwner:vi.fn(async(a:any)=>{if(a.id==='a2')throw new ForbiddenException();})};
  const repo=new OutboxRepositoryService({} as any,{} as any,access);const f=fakeTx(['a1','a2','a3','gone']);
  expect(await (repo as any).approverNotifications(f.tx,event)).toBe(1);expect(f.inserts.map(p=>p[0])).toEqual(['a3']);
 });
 it('propagates non-authorization failures instead of silently dropping',async()=>{
  const access:any={canSourceRead:vi.fn(async()=>{throw new Error('db down');}),assertNotificationOwner:vi.fn()};
  const repo=new OutboxRepositoryService({} as any,{} as any,access);
  await expect((repo as any).approverNotifications(fakeTx(['a1']).tx,event)).rejects.toThrow('db down');
 });
 it('does nothing for events without a workflow or scope',async()=>{
  const access:any={canSourceRead:vi.fn(),assertNotificationOwner:vi.fn()};const repo=new OutboxRepositoryService({} as any,{} as any,access);
  const f=fakeTx(['a1']);f.tx.one=vi.fn(async()=>({workflow_id:null}));
  expect(await (repo as any).approverNotifications(f.tx,event)).toBe(0);
  expect(await (repo as any).approverNotifications(f.tx,{...event,workspaceId:null})).toBe(0);expect(access.canSourceRead).not.toHaveBeenCalled();
 });
 it('uses the workflow Approve-button directory when the workflow module is loaded',async()=>{
  const access:any={canSourceRead:vi.fn(async()=>true),assertNotificationOwner:vi.fn(async()=>undefined)};const directory={approvalRecipients:vi.fn(async()=>['a2'])};
  const repo=new OutboxRepositoryService({} as any,{} as any,access,{get:vi.fn(()=>directory)} as any);const f=fakeTx(['a2']);
  expect(await (repo as any).approverNotifications(f.tx,event)).toBe(1);expect(directory.approvalRecipients).toHaveBeenCalledWith(CID,WID,WF);
  expect((f.tx.query as any).mock.calls[0][1][3]).toEqual(['a2']);
  const none=new OutboxRepositoryService({} as any,{} as any,access,{get:vi.fn(()=>{throw new Error('missing');})} as any);const g=fakeTx([]);await (none as any).approverNotifications(g.tx,event);expect((g.tx.query as any).mock.calls[0][1][3]).toBeNull();
 });
 it('titles name the operation, cluster and requester',()=>{
  const t=workflowNotificationText('workflow.submitted','工单状态已更新',{id:WF,kind:'native-change',cluster:'prod-kong',workspace:'payments',requester:'dave'});
  expect(t.title).toBe('待审批：网关实体变更 · 集群 prod-kong · 发起人 dave');expect(t.summary).toContain('正在等待审批');expect(t.summary).toContain('工作区 payments');
  expect(workflowNotificationText('workflow.rejected','x',{id:WF,kind:'metrics-setup',cluster:'c',workspace:null,requester:null}).title).toBe('工单已驳回：监控通道配置 · 集群 c · 发起人 门户开发者');
  expect(workflowNotificationText('workflow.submitted','工单状态已更新',null)).toEqual({title:'工单状态已更新',summary:'工单状态已更新'});
  expect(workflowNotificationText('workflow.submitted','f',{id:WF,kind:'native-change',cluster:'x'.repeat(500),workspace:'w',requester:'y'.repeat(500)}).title.length).toBeLessThanOrEqual(256);
 });
 it('approval setting defaults on and validates opt-out input',async()=>{
  expect(safeApprovalSetting(null,CID,WID)).toMatchObject({approvalRequestsEnabled:true,explicit:false,revision:0});
  const svc=new NotificationOperationsService({} as any,{} as any,{} as any,{} as any);
  for(const b of [{},{clusterId:CID,workspaceId:WID,approvalRequestsEnabled:'no',revision:0},{clusterId:CID,workspaceId:WID,approvalRequestsEnabled:false,revision:-1},{clusterId:CID,workspaceId:WID,approvalRequestsEnabled:false,revision:0,extra:1}])
   await expect(svc.saveApprovalSetting({user:{id:'a1'} as any,idempotencyKey:'k-12345678'},b)).rejects.toThrow();
 });
 it('malformed notification ids are 404, never a database 500',async()=>{
  const db:any={one:vi.fn(async()=>{throw Object.assign(new Error('invalid input syntax for type uuid'),{code:'22P02'});})};
  const read=new NotificationService(db,{} as any,{permissionVersion:vi.fn()} as any);
  await expect(read.detail({id:'a1'} as any,'undefined')).rejects.toMatchObject({status:404});
  await expect(read.preference({id:'a1'} as any,'nope')).rejects.toMatchObject({status:404});
  const ops=new NotificationOperationsService(db,{} as any,{} as any,{} as any);const actor={user:{id:'a1'} as any,idempotencyKey:'k-12345678'};
  await expect(ops.mark(actor,'x',{revision:1},'read')).rejects.toMatchObject({status:404});
  await expect(ops.preferenceState(actor,'x',{},true)).rejects.toMatchObject({status:404});
  expect(db.one).not.toHaveBeenCalled();
 });
 it('format-1 directory: super admins and coarse cluster/workspace approve grants only, never the requester; format 2 defers to frozen candidates',async()=>{
  const g=(o:any)=>({user_id:'u',role_id:'r',role_code:'c',permission_id:'p',binding_id:'b',binding_source:'direct',module:'workflows',action:'approve',scope_values:[],...o});
  const grants:Record<string,any[]>={u1:[g({scope_type:'workspace',cluster_id:CID,workspace_id:WID,scope_values:[WID]})],u2:[g({scope_type:'workspace',cluster_id:CID,workspace_id:'99999999-9999-4999-8999-999999999999',scope_values:['99999999-9999-4999-8999-999999999999']})],u3:[g({scope_type:'entity',cluster_id:CID,workspace_id:WID,scope_values:[{entity_type:'services',entity_id:WF}]})],u4:[g({scope_type:'global',cluster_id:null,workspace_id:null})]};
  let row:any={id:WF,state:'pending',approval_required:true,approval_format:1,requester_user_id:'req'};
  const db={one:vi.fn(async()=>row),query:vi.fn(async(q:string,p:any[])=>q.includes('FROM users')?[{id:'sa',super_admin:true},{id:'u1'},{id:'u2'},{id:'u3'},{id:'u4'},{id:'u5'}]:(grants[p[0]]??[]))};
  const svc=Object.assign(Object.create(WorkflowService.prototype),{db});
  expect(await svc.approvalRecipients(CID,WID,WF)).toEqual(['sa','u1','u4']);
  expect(db.query.mock.calls[0][1]).toEqual(['req']);
  row={...row,approval_format:2};expect(await svc.approvalRecipients(CID,WID,WF)).toBeNull();
  row={...row,state:'approved'};expect(await svc.approvalRecipients(CID,WID,WF)).toEqual([]);
 });
});
