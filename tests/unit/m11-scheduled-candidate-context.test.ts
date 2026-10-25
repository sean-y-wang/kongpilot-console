import {describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

function fixture(maxCalls=8){
 const context=new KongExecutionContextService(),handle=Object.freeze({}),tokens=new WeakSet<object>();let live=true,current=true;
 const source:any={id:'source',admin_url:'http://source:8001',revision:1},target:any={id:'target',admin_url:'http://target:8001',revision:2};
 const proof:any=Object.freeze({version:1,origin:'workflow-schedule-candidate-read',sessionId:null,readOnly:true,actor:{id:'reviewer'},
  expiresAt:new Date(Date.now()+29000).toISOString(),scope:{limits:{maxCalls,maxPages:2,maxRecords:10,maxBytes:1048576},resources:[
   {clusterId:'source',workspaceId:'source-w',path:'/services',kind:'collection'},
   {clusterId:'target',workspaceId:'target-w',path:'/routes',kind:'collection'}]},registries:[
   {clusterId:'source',workspaceId:'source-w',transportScope:transportScopeFor(source.admin_url),clusterRevision:1},
   {clusterId:'target',workspaceId:'target-w',transportScope:transportScopeFor(target.admin_url),clusterRevision:2}]});
 const genericRequest=vi.fn(async()=>{throw Error('GENERIC_ACTOR_READ_FORBIDDEN');}),genericResponse=vi.fn(async()=>{throw Error('GENERIC_RESPONSE_FORBIDDEN');});
 context.installPolicy({authorizeRequest:genericRequest,authorizeResponse:genericResponse});
 const allocate=vi.fn(async(h:any,request:any)=>{if(h!==handle||!current)throw Error('CURRENT_GRANTS_DENIED');
  if(request.method!=='GET'||request.body!==undefined)throw Error('READ_ONLY');const token=Object.freeze({});tokens.add(token);return token;});
 const verify=vi.fn(async(h:any)=>{if(h!==handle||!current)throw Error('CURRENT_GRANTS_DENIED');return proof;});
 context.installWorkflowScheduleCandidateReadPolicy({verifyHandle:verify,async verifyRequest(token){if(!tokens.has(token)||!current)throw Error('CURRENT_GRANTS_DENIED');return proof;},assertLive(h){if(h!==handle||!live)throw Error('CANDIDATE_CLOSED');},authorizeRequest:allocate,
  async authorizeResponse(token,response){if(!tokens.has(token)||!current)throw Error('CURRENT_RESPONSE_DENIED');tokens.delete(token);return response;}});
 return{context,handle,proof,source,target,genericRequest,genericResponse,allocate,verify,revoke(){current=false;},close(){live=false;}};
}
describe('pre-claim candidate reads use original readonly authority',()=>{
 it('rejects copies and HTTP ancestry before any native request',async()=>{
  const f=fixture();await expect(f.context.runWorkflowScheduleCandidateRead({},async()=>{})).rejects.toThrow('CURRENT_GRANTS_DENIED');
  await f.context.runHttp({},async()=>{await expect(f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{})).rejects.toMatchObject({response:{code:'WORKFLOW_CANDIDATE_EXISTING_CONTEXT_FORBIDDEN'}});});
  expect(f.allocate).not.toHaveBeenCalled();
 });
 it('can read exact source and target registries without adopting an HTTP session',async()=>{
  const f=fixture();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   expect(f.context.current().sessionId).toBeUndefined();expect(f.context.current().clusterId).toBeUndefined();
   for(const [cluster,path]of [[f.source,'/services'],[f.target,'/routes']]as const){
    const ticket=await f.context.authorizeRequest(cluster,'GET',path,undefined,{size:20});
    await f.context.refreshAuthorization(ticket);await f.context.beforeNativeSend(ticket);
    await expect(f.context.authorizeResponse(ticket,{data:[],next:null})).resolves.toEqual({data:[],next:null});
   }
   expect(f.allocate).toHaveBeenCalledTimes(2);expect(f.genericRequest).not.toHaveBeenCalled();expect(f.genericResponse).not.toHaveBeenCalled();
  });
 });
 it.each(['POST','PATCH','DELETE'])('cannot turn the read principal into %s authority',async method=>{
  const f=fixture();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   await expect(f.context.authorizeRequest(f.source,method,'/services',undefined,{})).rejects.toMatchObject({response:{code:'WORKFLOW_CANDIDATE_READ_ONLY'}});
  });expect(f.allocate).not.toHaveBeenCalled();
 });
 it('rejects foreign registry, changed endpoint and undeclared paths',async()=>{
  const f=fixture();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   for(const cluster of [{...f.source,id:'foreign'},{...f.source,admin_url:'http://different:8001'}])
    await expect(f.context.authorizeRequest(cluster,'GET','/services',undefined,{})).rejects.toMatchObject({response:{code:'WORKFLOW_CANDIDATE_SCOPE_CHANGED'}});
   await expect(f.context.authorizeRequest(f.source,'GET','/consumers',undefined,{})).rejects.toMatchObject({response:{code:'WORKFLOW_CANDIDATE_PATH_FORBIDDEN'}});
  });expect(f.allocate).not.toHaveBeenCalled();
 });
 it('rechecks current permissions before the wire without reallocating the cursor token',async()=>{
  const f=fixture();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.source,'GET','/services',undefined,{});f.revoke();
   await expect(f.context.beforeNativeSend(ticket)).rejects.toThrow('CURRENT_GRANTS_DENIED');expect(f.allocate).toHaveBeenCalledTimes(1);
  });
 });
 it('charges source and target reads against one ancestor budget',async()=>{
  const f=fixture(1);await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.source,'GET','/services',undefined,{});await f.context.authorizeResponse(ticket,{data:[],next:null});
   await expect(f.context.authorizeRequest(f.target,'GET','/routes',undefined,{})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CALL_LIMIT'}});
  });expect(f.allocate).toHaveBeenCalledTimes(1);
 });
 it('cannot detach into the independent configuration-job namespace',async()=>{
  const f=fixture();f.context.installConfigurationJobPolicy({verifyHandle:vi.fn(async()=>{throw Error('BORROWED');})});
  await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   await expect(f.context.runConfigurationJob({},async()=>{})).rejects.toMatchObject({response:{code:'WORKFLOW_CANDIDATE_JOB_ADOPTION_FORBIDDEN'}});
  });
 });
});
