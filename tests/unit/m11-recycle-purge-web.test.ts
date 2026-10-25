import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {normalizeControlChange,controlDirectCommand,normalizeControlReceipt,controlPreparedAllowed,type ControlAttempt} from '../../apps/console-web/src/api/control-changes.model';
import {writeControlDirectOnce,readControlOriginal,controlDirectReceiptCompleted} from '../../apps/console-web/src/api/control-changes';
import {setApiActorId} from '../../apps/console-web/src/api/client';
const actor=randomUUID(),cid=randomUUID(),wid=randomUUID(),entryId=randomUUID(),nativeId=randomUUID(),key=randomUUID(),identity={actor,version:`${actor}:4:9`},csrf='source-only-csrf-token-0123456789';
const change:any={resource:'recycle-bin',operation:'purge',resourceId:entryId,input:{revision:4,workspaceId:wid,confirmed:true,confirm_name:'Archived service'}};
const attempt:any={...identity,key,phase:'direct',state:'unknown',createdAt:new Date().toISOString(),resource:'recycle-bin',operation:'purge',clusterId:cid,resourceId:entryId,targetWorkspaceId:wid};
function receipt(){return{intentId:randomUUID(),resource:'recycle-bin',operation:'purge',resourceId:entryId,materialHmac:'a'.repeat(64),state:'prepared',workflowId:null,revision:null,planHash:null,clusterId:cid,workspaceId:wid,expiresAt:new Date(Date.now()+600000).toISOString(),nativeRequestsSent:0,
 preview:{request:change,before:{id:entryId,revision:4,root_type:'services',original_id:nativeId,payload_present:true,payload_hmac:'b'.repeat(64)},after:{resource:'recycle-bin',operation:'purge',resourceId:entryId,input:change.input},affectedScopes:[{clusterId:cid,workspaceId:wid,clusterRevision:2,workspaceRevision:3}],confirmationName:'Archived service'}};}
beforeEach(()=>setApiActorId(actor));afterEach(()=>{setApiActorId(undefined);vi.unstubAllGlobals();});
describe('Purge web protocol and fixed original key semantics (controlled fetch, no browser/server claims)',()=>{
 it('uses the exact original entry version and workspace in a fixed BFF-only command',()=>{expect(normalizeControlChange(change)).toEqual(change);expect(controlDirectCommand(change,cid,wid)).toEqual({path:`/clusters/${cid}/recycle-bin/${entryId}/purge?workspaceId=${wid}`,method:'POST',body:change.input});});
 it.each(['create','update','archive','restore','deactivate'])('rejects recycle-bin/%s and purge under another resource',operation=>{expect(()=>normalizeControlChange({...change,operation})).toThrow();expect(()=>normalizeControlChange({...change,resource:'workspaces'})).toThrow();});
 it('requires both typed confirmation/version and a canonical real target workspace',()=>{for(const patch of [{revision:0},{revision:'4'},{workspaceId:null},{workspaceId:wid+'/'},{confirmed:false},{confirm_name:''},{approved:true},{payload_secret:'forged'}])expect(()=>normalizeControlChange({...change,input:{...change.input,...patch}})).toThrow();expect(()=>controlDirectCommand(change,cid,randomUUID())).toThrow();});
 it('validates purge preview, real affected scope and metadata-only action before enabling submit',()=>{
  const r=normalizeControlReceipt(receipt()),grant=(module:string,action:string)=>({module,action,scope_type:'workspace',scope_values:[wid],cluster_id:cid,workspace_id:wid}),cap:any={platformAdmin:false,grants:[grant('recycle-bin','delete'),grant('workflows','write')]};
  expect(controlPreparedAllowed(r,cap,false)).toBe(true);expect(controlPreparedAllowed(r,{...cap,grants:[grant('recycle-bin','read'),grant('workflows','write')]},false)).toBe(false);expect(controlPreparedAllowed(r,cap,true)).toBe(false);
  for(const patch of [{operation:'restore'},{resource:'workspaces'},{nativeRequestsSent:1}])expect(()=>normalizeControlReceipt({...receipt(),...patch})).toThrow();
  const foreign=receipt();foreign.preview.affectedScopes[0].workspaceId=randomUUID();expect(()=>normalizeControlReceipt(foreign)).toThrow();
 });
 it('accepts only a genuine direct purge ACK and never follows an unknown response with retry or session refresh',async()=>{
  const fetcher=vi.fn(async()=>new Response(JSON.stringify({data:{id:entryId,purged:true}}),{status:201}));vi.stubGlobal('fetch',fetcher);
  expect(await writeControlDirectOnce(identity,change,cid,wid,key,csrf)).toEqual({id:entryId,purged:true});expect(fetcher).toHaveBeenCalledOnce();
  fetcher.mockReset().mockRejectedValue(new Error('network-response-unknown'));await expect(writeControlDirectOnce(identity,change,cid,wid,key,csrf)).rejects.toMatchObject({code:'CONTROL_RESULT_UNKNOWN'});expect(fetcher).toHaveBeenCalledOnce();
 });
 it('reads the original purge key with GET in its original workspace and requires the exact actor/type/id/action receipt',async()=>{
  const fetcher=vi.fn(async()=>new Response(JSON.stringify({data:{state:'uncertain'}}),{status:200}));vi.stubGlobal('fetch',fetcher);await readControlOriginal(identity,attempt as ControlAttempt);
  expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/clusters/${cid}/mutations/by-key/${key}?workspaceId=${wid}`);expect((fetcher.mock.calls[0] as any)[1].method).toBe('GET');expect(fetcher).toHaveBeenCalledOnce();
  const proof={id:randomUUID(),actor_id:actor,cluster_id:cid,workspace_id:wid,entity_type:'recycle_entries',entity_id:entryId,action:'purge',state:'succeeded',remote_completed:true};expect(controlDirectReceiptCompleted(proof,attempt)).toBe(true);
  for(const patch of [{actor_id:randomUUID()},{entity_id:nativeId},{action:'delete'},{workspace_id:randomUUID()},{remote_completed:false},{state:'uncertain'}])expect(controlDirectReceiptCompleted({...proof,...patch},attempt)).toBe(false);
 });
});
