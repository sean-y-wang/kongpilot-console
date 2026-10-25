import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {ControlMetadataBusinessService} from '../../apps/console-api/src/modules/control-plane/control-metadata-business.service';
import {normalizeControlChangeRequest} from '../../apps/console-api/src/modules/control-plane/control-metadata-plan';
import {RecycleService} from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {defaultWorkspaceId as wid,workspaceFixture} from './workspace-test-fixture';

/** Actual original Recycle/Business ALS/Authorization/Snapshot validators;
 * SQL, outer transaction, immutable workflow authority and native transport
 * are controlled fixtures. No real HTTP, SQL040 migration or Kong is claimed. */
function fixture(){
 const cid=randomUUID(),id=randomUUID(),nativeId=randomUUID(),actorId=randomUUID(),actor:any={user:{id:actorId,username:'owner',superAdmin:false},workspaceId:wid,requestId:randomUUID(),ip:'192.0.2.81',idempotencyKey:'original-purge-key'};
 const secrets=new SecretService(),context=new KongExecutionContextService(),workflowId=randomUUID(),ws=workspaceFixture(cid),rootKey=`services:${nativeId}`;
 const graph={rootKey,complete:true,purpose:'recycle',capturedAt:new Date().toISOString(),nodes:[{key:rootKey,type:'services',id:nativeId,path:`/services/${nativeId}`,affected:true,
  dependencies:[],restorable:true,data:{id:nativeId,name:'Archived service',host:'echo.example',tags:['kos-ws-default']},restoreData:{id:nativeId,name:'Archived service',host:'echo.example',tags:['kos-ws-default']}}]};
 const state:any={mode:'approval',eligible:true,user:{id:actorId,username:'owner',super_admin:false,status:'active',deleted_at:null,force_password_change:false,permissions_epoch:7,credential_epoch:3},
  entry:{id,cluster_id:cid,workspace_id:wid,root_type:'services',original_id:nativeId,root_name:'Archived service',state:'deleted',parent_id:null,credential_kind:null,node_count:1,
   mutation_id:randomUUID(),revision:4,purged_at:null,expires_at:'2099-01-01T00:00:00Z',payload_secret:secrets.encrypt(graph,`recycle:${id}`)},
  grants:['recycle-bin','services'].flatMap(module=>['read','delete'].map(action=>({module,action,scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null})))};
 const writes:any[]=[],auditRows:any[]=[],calls:any[]=[],kong={request:vi.fn(async()=>{throw new Error('No native request allowed in this service-only metadata fixture');})};
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  calls.push({sql,p});if(sql.includes('m11_recycle_purge_available'))return{eligible:state.eligible};
  if(sql.includes('FROM recycle_entries'))return p[0]===cid&&p[1]===id?structuredClone(state.entry):null;
  if(sql.includes('FROM users'))return p[0]===actorId&&state.user.status==='active'&&!state.user.deleted_at?structuredClone(state.user):null;
  if(sql.includes('FROM iam_epoch'))return{version:10};
  if(sql.includes('FROM clusters'))return p[0]===cid?{id:cid,execution_mode:state.mode}:null;
  throw new Error('Unmodeled readonly SQL');}),query:vi.fn(async(sql:string)=>sql.includes('iam_effective_grants')?structuredClone(state.grants):[]),
  exec:vi.fn(async(sql:string,p:any[])=>{
   if(!sql.startsWith('UPDATE recycle_entries SET state=\'purged\''))throw new Error('Unexpected business write');
   const [cluster,target,workspace,revision,cipher,before]=p;
   if(cluster!==cid||target!==id||workspace!==wid||revision!==state.entry.revision||cipher!==state.entry.payload_secret||before!==state.entry.state)return 0;
   writes.push({sql,p});state.entry={...state.entry,state:'purged',payload_secret:null,purged_at:new Date().toISOString(),revision:state.entry.revision+1};return 1;
  }),transaction:vi.fn(async(fn:any)=>{const before=structuredClone(state),writeCount=writes.length,auditCount=auditRows.length;
   try{return await fn(db);}catch(error){Object.assign(state,before);writes.splice(writeCount);auditRows.splice(auditCount);throw error;}})};
 const authz=new AuthorizationService(db,ws.resolver,kong as any,context),audit={append:vi.fn(async(e:any,tx:any)=>{expect(tx).toBe(db);auditRows.push(e);return{id:randomUUID()};})},mutations={execute:vi.fn(async()=>{throw new Error('No direct Mutation escape');})};
 const recycle=new RecycleService(db,secrets,kong as any,mutations as any,{} as any,authz,audit as any,{} as any,{} as any,ws.resolver,context);
 // The business layer's private issued approval is genuine in this slice; the
 // enclosing workflow/SQL authority is a controlled fixture, never a live proof.
 vi.spyOn(context,'currentApprovedStep').mockReturnValue({kind:'metadata',stepId:randomUUID(),execution:{workflowId,clusterId:cid,actorId}} as any);
 const registration={installControlMetadataBridge:vi.fn()},business=new ControlMetadataBusinessService(db,secrets,registration as any,registration as any,registration as any,{} as any,recycle);business.onModuleInit();
 const issued=new WeakSet<object>(),policy={verifyCapture:vi.fn(async(h:object)=>{if(!issued.has(h))throw new ForbiddenException({code:'TEST_UNISSUED_APPROVAL'});}),
  verifyMutation:vi.fn(async(_h:any,_m:any,phase:string)=>{if(phase==='after'&&(state.entry.payload_secret!==null||state.entry.revision!==5))throw new Error('Unacknowledged original metadata');})};business.installApprovedPolicy(policy as any);
 const request:any={resource:'recycle-bin',operation:'purge',resourceId:id,input:{revision:4,workspaceId:wid,confirmed:true,confirm_name:'Archived service'}};
 const capture=()=>business.capture(request,cid,actor,db);
 const apply=async(prepared:any,h:object=Object.freeze({}))=>{issued.add(h);return db.transaction((tx:any)=>business.apply(h,prepared,actor,tx));};
 return{cid,id,nativeId,wid,workflowId,actor,secrets,context,state,graph,db,kong,mutations,audit,auditRows,writes,calls,recycle,business,request,capture,apply,policy};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M11 permanent recovery purge through original zero-native metadata domain',()=>{
 it('captures only non-secret versioned payload HMA without mutation or copying the encrypted recovery payload into the new intention',async()=>{
  const f=fixture(),prepared=await f.capture();expect(prepared).toMatchObject({request:f.request,mutation:{resource:'recycle-bin',operation:'purge',action:'delete',workspaceId:wid},before:{id:f.id,revision:4,payload_present:true,payload_hmac:f.secrets.fingerprint(f.state.entry.payload_secret)}});
  expect(JSON.stringify(prepared)).not.toContain(f.state.entry.payload_secret);expect(JSON.stringify(prepared)).not.toContain('echo.example');
  expect(f.writes).toHaveLength(0);expect(f.auditRows).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();
 });
 it('clears exactly the original payload with CAS and one revision advance while retaining the entry and all graph/node/receipt facts',async()=>{
  const f=fixture(),prepared=await f.capture();expect(await f.apply(prepared)).toEqual({id:f.id,purged:true});
  expect(f.state.entry).toMatchObject({id:f.id,revision:5,state:'purged',payload_secret:null});expect(f.writes).toHaveLength(1);
  expect(f.writes[0].sql).toContain('revision=$4 AND payload_secret=$5 AND state=$6');
  expect(f.calls.some(x=>x.sql.includes('FOR UPDATE'))).toBe(true);expect(f.calls.filter(x=>x.sql.includes('m11_recycle_purge_available')).length).toBeGreaterThanOrEqual(2);
  expect(f.auditRows[0]).toMatchObject({actorId:f.actor.user.id,entityId:f.id,action:'purge_recycle',workflowId:f.workflowId,before:{revision:4,payloadHmac:prepared.before.payload_hmac},after:{state:'purged',revision:5,payloadPresent:false}});
  expect(f.writes.some(x=>/DELETE|TRUNCATE|recycle_nodes|entity_change_/.test(x.sql))).toBe(false);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('refuses an absent original metadata execution frame before the payload write',async()=>{const f=fixture(),prepared=await f.capture();vi.mocked(f.context.currentApprovedStep).mockImplementation(()=>{throw new Error('No original step');});await expect(f.apply(prepared)).rejects.toThrow('No original step');expect(f.writes).toHaveLength(0);});
 it('preserves direct mode through the original Mutation and independently rechecks exact current payload/ref eligibility before CAS',async()=>{
  const f=fixture();f.state.mode='direct';f.mutations.execute.mockImplementation(async(_input:any,operation:any)=>operation({}));
  expect(await f.recycle.purge(f.cid,f.id,f.actor.user,{confirmed:true,confirm_name:'Archived service'},{workspaceId:wid})).toEqual({id:f.id,purged:true});
  expect(f.mutations.execute).toHaveBeenCalledOnce();expect(f.writes).toHaveLength(1);expect(f.state.entry.revision).toBe(5);
  expect(f.auditRows[0]).toMatchObject({before:{entryId:f.id,revision:4,payloadHmac:expect.any(String)},after:{state:'purged',revision:5,payloadPresent:false}});
 });
 it('keeps referenced payload intact in direct mode too',async()=>{const f=fixture();f.state.mode='direct';f.state.eligible=false;f.mutations.execute.mockImplementation(async(_input:any,operation:any)=>operation({}));await expect(f.recycle.purge(f.cid,f.id,f.actor.user,{confirmed:true,confirm_name:'Archived service'},{workspaceId:wid})).rejects.toMatchObject({response:{code:'RECYCLE_PURGE_REFERENCED'}});expect(f.writes).toHaveLength(0);});
 it('keeps direct approval-mode attempts outside the Mutation ledger and refuses a made-up execution handle',async()=>{
  const f=fixture();await expect(f.recycle.purge(f.cid,f.id,f.actor.user,{confirmed:true,confirm_name:'Archived service'},{workspaceId:wid})).rejects.toMatchObject({response:{code:'APPROVAL_REQUIRED'}});
  const prepared=await f.capture();await expect(f.business.apply({approved:true},prepared,f.actor,f.db)).rejects.toMatchObject({response:{code:'TEST_UNISSUED_APPROVAL'}});
  expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.writes).toHaveLength(0);
 });
 for(const change of ['revision','payload','state','workspace','permission','account','unknown-reference','confirmation'] as const)it(`refuses current ${change} change after original preparation without clearing any payload`,async()=>{
  const f=fixture();let prepared:any=await f.capture();
  if(change==='revision')f.state.entry.revision++;
  if(change==='payload')f.state.entry.payload_secret=f.secrets.encrypt(f.graph,`recycle:${f.id}`);
  if(change==='state'){f.state.entry.state='restoring';f.state.eligible=false;}
  if(change==='workspace')f.state.entry.workspace_id=randomUUID();
  if(change==='permission')f.state.grants=f.state.grants.filter((g:any)=>g.module!=='services'||g.action!=='delete');
  if(change==='account')f.state.user.status='disabled';
  if(change==='unknown-reference')f.state.eligible=false;
  if(change==='confirmation'){prepared=structuredClone(prepared);prepared.request.input.confirm_name='foreign';}
  const current=f.state.entry.payload_secret;await expect(f.apply(prepared)).rejects.toThrow();expect(f.state.entry.payload_secret).toBe(current);expect(f.writes).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('rechecks row and authorization inside the exact private operation callback and rolls back if final metadata verification fails',async()=>{
  const f=fixture(),prepared=await f.capture();f.policy.verifyMutation.mockImplementation(async(_h:any,_m:any,phase:string)=>{if(phase==='after')throw new Error('Final original receipt rejected');});
  await expect(f.apply(prepared)).rejects.toThrow('Final original receipt rejected');expect(f.state.entry.state).toBe('deleted');expect(f.state.entry.revision).toBe(4);expect(f.writes).toHaveLength(0);expect(f.auditRows).toHaveLength(0);
 });
});
describe('Purge intention strict selector independent of private authority',()=>{
 it('accepts only recycle-bin/purge with an exact UUID/version/confirmation scope',()=>{const f=fixture();expect(normalizeControlChangeRequest(f.request)).toEqual(f.request);});
 for(const field of ['approved','originalHandle','payload_secret','actorId','workflowId','transaction','executionMode'])it(`rejects caller-supplied ${field} material rather than ignoring it`,()=>{const f=fixture();expect(()=>normalizeControlChangeRequest({...f.request,input:{...f.request.input,[field]:'forged'}})).toThrow();});
 for(const input of [{revision:0},{revision:4.5},{workspaceId:randomUUID()+'/'},{workspaceId:null},{confirmed:false},{confirm_name:''}])it(`rejects malformed bounded scope ${JSON.stringify(input)}`,()=>{const f=fixture();expect(()=>normalizeControlChangeRequest({...f.request,input:{...f.request.input,...input}})).toThrow();});
});

/** Independent adversarial cases added by a reviewer, original owner suite retained. */
describe('Independent C04 final callback, complete graph and receipt boundaries',()=>{
 it('rechecks current child-object grants after taking the final original row lock',async()=>{
  const f=fixture(),prepared=await f.capture(),original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,p:any[])=>{const row=await original(sql,p);if(sql.includes('FROM recycle_entries')&&sql.includes('FOR UPDATE'))f.state.grants=f.state.grants.filter((g:any)=>g.module!=='services'||g.action!=='delete');return row;});
  await expect(f.apply(prepared)).rejects.toThrow();expect(f.state.entry.payload_secret).not.toBeNull();expect(f.writes).toHaveLength(0);expect(f.auditRows).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('refuses a reference that becomes live at the private mutation admission boundary',async()=>{
  const f=fixture(),prepared=await f.capture();f.policy.verifyMutation.mockImplementation(async(_h:any,_m:any,phase:string)=>{if(phase==='before')f.state.eligible=false;});
  await expect(f.apply(prepared)).rejects.toMatchObject({response:{code:'RECYCLE_PURGE_REFERENCED'}});expect(f.state.entry.payload_secret).not.toBeNull();expect(f.writes).toHaveLength(0);
 });
 it('refuses a zero-row exact CAS and retains the original payload and revision',async()=>{
  const f=fixture(),prepared=await f.capture(),cipher=f.state.entry.payload_secret;f.db.exec.mockResolvedValue(0);
  await expect(f.apply(prepared)).rejects.toMatchObject({response:{code:'RECYCLE_PURGE_CHANGED'}});expect(f.state.entry.payload_secret).toBe(cipher);expect(f.state.entry.revision).toBe(4);expect(f.auditRows).toHaveLength(0);
 });
 it('rolls back payload destruction if the original associated audit cannot be appended',async()=>{
  const f=fixture(),prepared=await f.capture(),cipher=f.state.entry.payload_secret;f.audit.append.mockRejectedValue(Error('AUDIT_TRANSACTION_REJECTED'));
  await expect(f.apply(prepared)).rejects.toThrow('AUDIT_TRANSACTION_REJECTED');expect(f.state.entry.payload_secret).toBe(cipher);expect(f.state.entry.state).toBe('deleted');expect(f.state.entry.revision).toBe(4);expect(f.writes).toHaveLength(0);
 });
 it('does not execute a second payload clear from the same successful captured request',async()=>{
  const f=fixture(),prepared=await f.capture();await f.apply(prepared);await expect(f.apply(prepared)).rejects.toThrow();expect(f.writes).toHaveLength(1);expect(f.state.entry.revision).toBe(5);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('requires grants for every affected graph child during capture instead of only the root grant',async()=>{
  const f=fixture(),child=randomUUID();f.graph.nodes.push({...f.graph.nodes[0],key:`routes:${child}`,type:'routes',id:child,path:`/routes/${child}`,dependencies:[f.graph.rootKey],data:{id:child,name:'Child route',host:'echo.example',tags:['kos-ws-default']},restoreData:{id:child,name:'Child route',host:'echo.example',tags:['kos-ws-default']}});
  f.state.entry.node_count=2;f.state.entry.payload_secret=f.secrets.encrypt(f.graph,`recycle:${f.id}`);
  await expect(f.capture()).rejects.toThrow();expect(f.writes).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('does not trust a caller-provided superAdmin flag over the current database principal',async()=>{
  const f=fixture();f.actor.user.superAdmin=true;f.state.grants=[];
  await expect(f.capture()).rejects.toThrow();expect(f.writes).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('does not accept changing the selected archive cycle while retaining its original material',async()=>{
  const f=fixture(),prepared=await f.capture(),forged=structuredClone(prepared);forged.request.resourceId=randomUUID();
  await expect(f.apply(forged)).rejects.toThrow();expect(f.writes).toHaveLength(0);expect(f.state.entry.payload_secret).not.toBeNull();
 });
 it('keeps actual successful public service result free of original cipher, graph and unrelated archive fields',async()=>{
  const f=fixture(),prepared=await f.capture(),cipher=f.state.entry.payload_secret,result=await f.apply(prepared);
  expect(Object.keys(result as object).sort()).toEqual(['id','purged']);expect(JSON.stringify(result)).not.toContain(cipher);expect(JSON.stringify(result)).not.toContain('echo.example');expect(JSON.stringify(f.auditRows)).not.toContain(cipher);
 });
});
