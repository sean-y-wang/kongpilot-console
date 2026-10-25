import {vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import * as outbound from '../../../apps/console-api/src/infrastructure/kong/outbound';
import {WorkflowScheduledAuthorityService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import {preNamespaceApprovalFixture} from './workflow-pre-namespace-approval-fixture';
/** Actual Authority/Runtime/Material/Validation/Context/Kong SDK. Original
 * Namespace issuance and SQL/lease/network are explicit Source adapters; no
 * business execution or Native write is claimed by this component fixture. */
export async function portalPartyObservationFixture(reviewers=3){
 const rounds:any[]=[],verifiers:any[]=[];const install=WorkflowScheduledAuthorityService.prototype.installPortalPartyObservationRoundRunner;
 vi.spyOn(WorkflowScheduledAuthorityService.prototype,'installPortalPartyObservationRoundRunner').mockImplementation(function(runner:any){
  const verifier=install.call(this,{run:async(original:any,fn:any)=>{rounds.push(original);return runner.run(original,fn);}});verifiers.push(verifier);return verifier;
 });
 const f=await preNamespaceApprovalFixture('portal-credential-issue',reviewers,'user',true),wire:any[]=[],nativeService=structuredClone(f.service),grantState:{expiresAt:string|null;source:'user'|'team'}={expiresAt:null,source:'user'},teamBinding={id:randomUUID(),roleId:randomUUID(),teamId:randomUUID()};
 const bindings=new Map<string,{id:string;roleId:string}>(),query=f.db.query.getMockImplementation()!;
 f.db.query.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.includes('FROM iam_effective_grants')&&sql.includes('binding_current'))return f.tables.iam_effective_grants.filter((g:any)=>g.user_id===args[0]).map((grant:any)=>{
   let binding=bindings.get(grant.user_id);if(!binding){binding={id:randomUUID(),roleId:randomUUID()};bindings.set(grant.user_id,binding);}
   if(grantState.source==='team')binding=teamBinding;
   Object.assign(grant,{binding_id:binding.id,role_id:binding.roleId,binding_source:grantState.source});
   return{grant,binding:{id:binding.id,role_id:binding.roleId,...(grantState.source==='team'?{team_id:teamBinding.teamId}:{user_id:grant.user_id}),status:'active',expires_at:grantState.expiresAt},binding_current:grantState.expiresAt===null||Date.parse(grantState.expiresAt)>Date.now(),binding_expires_at:grantState.expiresAt,observed_at:new Date().toISOString()};
  });return query(sql,args);
 });
 vi.spyOn(outbound,'outboundJson').mockImplementation(async(_url,path,method,_body,_query,_auth,_timeout,beforeSend,prepareSend)=>{
  if(method!=='GET')throw Error('SOURCE_NO_NATIVE_WRITE');await prepareSend?.();beforeSend?.();let body:any,status=200;
  if(path.startsWith('/schemas/'))body={fields:[]};
  else if(path===`/services/${f.service.id}`)body=nativeService;
  else if(path.startsWith('/plugins/')){const material=await f.compiler.portalMaterial(f.plan,f.db);body=path===`/plugins/${material.publicationProof.aclPluginId}`?material.publicationProof.aclPlugin:material.publicationProof.keyAuthPlugin;}
  else if(path===`/consumers/${f.plan.generated!.consumerId}`){status=404;body={message:'Not found'};}
  else throw Error('SOURCE_UNPLANNED_PATH:'+path);
  const read={path,actorId:f.context.current().actor?.id,body};await f.state.callback?.(read);wire.push({path,actorId:read.actorId,namespace:f.context.hasWorkflowScheduledNamespace()});
  return{status,body:read.body,bytes:Buffer.byteLength(JSON.stringify(read.body)),jsonParsed:true};
 });
 return{...f,grantState,nativeService,wire,rounds,verifiers,verifier:()=>verifiers[0]};
}
