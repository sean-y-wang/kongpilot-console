import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {createControlWorkflowRoutingFixture} from '../fixtures/m11-control-workflow-routing.fixture';
/** Actual shared WorkflowService dispatcher/real Context ALS, Control Main,
 * business closures and private completion. SQL/Redis/approval issuer remain
 * controlled transport fixtures, not PostgreSQL040 or HTTP acceptance. */
function fixture(){const f=createControlWorkflowRoutingFixture(),id=randomUUID(),nativeId=randomUUID(),key=`services:${nativeId}`,graph={complete:true,rootKey:key,nodes:[{key,type:'services',id:nativeId,path:`/services/${nativeId}`,data:{id:nativeId,name:'Archived production service',host:'example.invalid',tags:[]},restoreData:{id:nativeId,host:'example.invalid'},affected:true,dependencies:[]}]};
 f.state().recycles.set(id,{id,cluster_id:f.cid,workspace_id:f.wid,revision:8,root_type:'services',original_id:nativeId,root_name:'Archived production service',parent_id:null,credential_kind:null,node_count:1,state:'deleted',payload_secret:f.secrets.encrypt(graph,`recycle:${id}`),mutation_id:randomUUID(),purged_at:null,expires_at:'2099-01-01T00:00:00.000Z'});
 const request={resource:'recycle-bin',operation:'purge',resourceId:id,input:{revision:8,workspaceId:f.wid,confirmed:true,confirm_name:'Archived production service'}};return{...f,id,request};}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6d'.repeat(32));vi.stubEnv('APP_SECRET','recycle-purge-routing-original-signing-key-more-than32');vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','192.0.2.11,192.0.2.12,192.0.2.13');});afterEach(()=>vi.unstubAllEnvs());
describe('Actual shared Root workflow dispatcher for permanent payload purge',()=>{
 it('approves separately, snapshots Native0 metadata, commits its exact original fact and reads the original completed key after the payload is gone',async()=>{
  const f=fixture(),prepared=await f.prepare(f.request);expect(f.state().recycles.get(f.id).payload_secret).not.toBeNull();await f.submit(prepared);f.approveFixture();
  const completion=vi.spyOn(f.workflow,'verifyMetadataCompletion'),receipt=await f.executeRoot();expect(receipt).toMatchObject({kind:'control-metadata',state:'succeeded',propagation:'acknowledged',steps:[{operationId:null,remoteStarted:false,remoteCompleted:true}]});
  expect(f.state().recycles.get(f.id)).toMatchObject({revision:9,state:'purged',payload_secret:null});expect(f.state().facts.size).toBe(1);expect(completion).toHaveBeenCalledOnce();
  const events=[...f.state().audit.values()];expect(events.filter((a:any)=>['purge_recycle','control.metadata'].includes(a.action)).every((a:any)=>a.workflowId===f.plan().workflowId)).toBe(true);
  const writes=f.writes.length;expect(await f.receiptRoot()).toMatchObject({state:'succeeded',kind:'control-metadata',action:'execute'});expect(f.writes).toHaveLength(writes);
  expect(f.approved.assertNative).not.toHaveBeenCalled();expect(f.approved.mutationBinding).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();
 });
 for(const change of ['revision','restore-state','current-grants','unresolved-reference'])it(`blocks ${change} after approval before payload clear`,async()=>{
  const f=fixture(),prepared=await f.prepare(f.request);await f.submit(prepared);f.approveFixture();
  if(change==='revision')f.state().recycles.get(f.id).revision++;if(change==='restore-state'){f.state().recycles.get(f.id).state='restoring';f.state().recycleEligible=false;}if(change==='current-grants')f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>g.module!=='services'||g.action!=='delete'));if(change==='unresolved-reference')f.state().recycleEligible=false;
  const cipher=f.state().recycles.get(f.id).payload_secret;await expect(f.executeRoot()).rejects.toThrow();expect(f.state().recycles.get(f.id).payload_secret).toBe(cipher);expect(f.state().facts.size).toBe(0);expect(f.writes.some(s=>s.startsWith("UPDATE recycle_entries SET state='purged'"))).toBe(false);
 });
});
