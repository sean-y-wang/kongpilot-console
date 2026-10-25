import {expect,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {ConfigurationService,CONFIGURATION_SOURCE_SUBMISSION_DISPOSITION_QUERY} from '../../../apps/console-api/src/modules/configuration/configuration.service';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../../apps/console-api/src/infrastructure/secret.service';
import type {ConfigPlan,CaptureGraph,CaptureObject} from '../../../apps/console-api/src/modules/configuration/configuration.types';
const id=(n:number)=>`ab000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
/** Real plan() façade and real historical entity-grant evaluation. Storage
 * adapters are deliberately synthetic and reject every unexpected SQL;
 * these tests do not claim actual PostgreSQL transactions or HTTP acceptance. */
export function createSourceDispositionFixture(initial:unknown={rejected:false,registered:false}){
 const context=new KongExecutionContextService(),secrets=new SecretService(),trace:string[]=[],handle=Object.freeze({});
 const actor:any={user:{id:id(1),username:'current-reader',superAdmin:false},workspaceId:id(3),requestId:id(4)},sid=id(5);
 const scope:any={clusterId:id(2),workspaceId:id(3),transportScope:'a'.repeat(64),kind:'workspace',rootIds:[]};
 const state={disposition:initial as any,wholeWrite:true,read:true,current:true,missingPlan:false,manifestAvailable:true,sourceActor:id(1),provider:true,afterDisposition:undefined as undefined|(()=>void)};
 const before={id:id(10),name:'service',host:'upstream.example',path:'/before',tags:['kos-ws-default']},body={path:'/after'};
 const step:any={stepId:id(11),stepOrder:1,objectKey:`services:${id(10)}`,entityType:'services',objectWorkspaceId:scope.workspaceId,nativeId:id(10),allocatedNativeId:null,parentId:null,credentialKind:null,
  permissionAction:'write',mutationAction:'update',dependencies:[],body,before,clearMap:[],bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before),nativeRequests:[{method:'PATCH',canonicalPath:`/services/${id(10)}`,body,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before)}],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
 const plan:ConfigPlan={scope,mode:'merge',steps:[step],sourceManifestHmac:'b'.repeat(64),baselineManifestHmac:'c'.repeat(64),schemaHmac:'d'.repeat(64),permissionVersion:'current-PV',clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt:new Date(Date.now()+600000).toISOString()};
 const summary:any={id:id(6),jobId:id(7),revision:1,planRevision:1,planHash:secrets.fingerprint(plan),state:'ready',recoveryComplete:true,deleteCount:0};
 const row:any={...summary,source_job_id:id(7),scope_kind:'workspace',root_ids:[],authority_domain:null,durable_issue_id:null};
 const source:any={id:id(7),cluster_id:scope.clusterId,workspace_id:scope.workspaceId,actor_id:id(1),authority_domain:null,durable_issue_id:null,plan_id:summary.id,plan_revision:1,plan_hash:summary.planHash,safe_progress:{baselineSnapshotId:id(8),baselineVersion:1,counts:{update:1},sharedReferences:0}};
 const object:CaptureObject={objectKey:step.objectKey,entityType:'services',nativeId:id(10),objectWorkspaceId:scope.workspaceId,ownershipTags:before.tags,affected:true,referenceOnly:false,dependencies:[],payload:before,beforeHmac:step.beforeHmac,schemaHmac:plan.schemaHmac,observedAt:new Date().toISOString(),recovery:{state:'complete',blockerCodes:[]}};
 const baseline={scope,objects:[object]} as CaptureGraph;
 const db:any={one:vi.fn(async(sql:string,args:unknown[])=>{
  if(sql==='SELECT p.*,j.scope_kind,j.root_ids,j.authority_domain,j.durable_issue_id FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id WHERE p.id=$1 AND p.cluster_id=$2 AND p.workspace_id=$3'){
   trace.push('scoped-plan');if(state.missingPlan||args[0]!==summary.id||args[1]!==scope.clusterId||args[2]!==scope.workspaceId)return null;return row;
  }
  if(sql==='SELECT execution_mode FROM clusters WHERE id=$1'){expect(args).toEqual([scope.clusterId]);trace.push('cluster-mode');return{execution_mode:'approval'};}
  if(sql==='SELECT * FROM configuration_jobs WHERE id=$1'){expect(args).toEqual([source.id]);trace.push('source');return{...source,actor_id:state.sourceActor};}
  if(sql==='SELECT j.safe_progress FROM configuration_jobs j JOIN configuration_plans p ON p.source_job_id=j.id WHERE p.id=(SELECT id FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id IN(SELECT plan_id FROM configuration_plan_versions WHERE plan_hash=$3) LIMIT 1)'){
   expect(args).toEqual([scope.clusterId,scope.workspaceId,secrets.fingerprint(plan)]);trace.push('grants-baseline');return{safe_progress:source.safe_progress};
  }
  if(sql===CONFIGURATION_SOURCE_SUBMISSION_DISPOSITION_QUERY){
   expect(args).toEqual([summary.id,scope.clusterId,scope.workspaceId]);expect(trace).toContain('entity-grants');expect(trace).toContain('changes');trace.push('source-disposition');state.afterDisposition?.();return state.disposition;
  }
  throw Error(`UNEXPECTED_SQL:${sql}`);
 }),exec:vi.fn(async()=>{throw Error('NO_MUTATION_ALLOWED');}),query:vi.fn(async()=>{throw Error('UNEXPECTED_SQL_QUERY');})};
 const access:any={acquireJob:vi.fn(async(input:any)=>{trace.push('scope-admission');if(context.current().sessionId!==sid||!state.current)throw new ForbiddenException({code:'CURRENT_SESSION_INVALID'});expect(input.actor.id).toBe(actor.user.id);expect(input.clusterId).toBe(scope.clusterId);expect(input.workspaceId).toBe(scope.workspaceId);return handle;}),
  description:vi.fn(async(selected:any)=>{expect(selected).toBe(handle);return{actor:actor.user,scope,permissionVersion:'current-PV'};}),
  assertCurrent:vi.fn(async(selected:any,input:any)=>{trace.push('closing-current');expect(selected).toBe(handle);expect(input).toEqual({phase:'read'});if(!state.current||context.current().sessionId!==sid)throw new ForbiddenException({code:'CURRENT_SESSION_OR_PERMISSION_CHANGED'});return{scope,actorId:actor.user.id};})};
 const authz:any={snapshot:vi.fn(async()=>{trace.push('entity-grants');return{user:actor.user,grants:state.read?[{module:'services',action:'read',cluster_id:scope.clusterId,workspace_id:scope.workspaceId,scope_type:'workspace',scope_values:[scope.workspaceId]},...(state.wholeWrite?[{module:'services',action:'write',cluster_id:scope.clusterId,workspace_id:scope.workspaceId,scope_type:'workspace',scope_values:[scope.workspaceId]}]:[])]:[]};}),hasWholeWorkspace:vi.fn(async()=>state.wholeWrite),hasWholeCluster:vi.fn(async()=>false)};
 const repo:any={readPlanSummary:vi.fn(async(selected:any,input:any)=>{expect(selected).toBe(handle);expect(input).toEqual({scope,planId:summary.id});trace.push('summary');return summary;}),readPlan:vi.fn(async(selected:any,input:any)=>{expect(selected).toBe(handle);expect(input).toEqual({scope,planId:summary.id,planRevision:1,planHash:summary.planHash});trace.push('manifest');if(!state.manifestAvailable)throw new ForbiddenException({code:'MANIFEST_INVALID'});return plan;}),readSnapshot:vi.fn(async(selected:any,input:any)=>{expect(selected).toBe(handle);expect(input).toEqual({scope,snapshotId:id(8),version:1});trace.push('baseline');return baseline;}),listChanges:vi.fn(async()=>{trace.push('changes');return{items:[{stepId:step.stepId,mutationAction:'update',diff:[]}],nextCursor:null};}),createJob:vi.fn()};
 const workspaces:any={resolve:vi.fn(async()=>({id:scope.workspaceId}))},durable:any={unsupportedReason:vi.fn(()=>null),canSubmit:vi.fn(async(selected:any,s:any,p:any,a:any)=>{trace.push('durable-admission');expect(selected).toBe(handle);expect(s.id).toBe(source.id);expect(p).toBe(plan);expect(a).toBe(actor);return true;})},kong:any={request:vi.fn()},native:any={execute:vi.fn()};
 const service=new ConfigurationService(db,{}as any,secrets,context,{}as any,authz,workspaces,access,repo,{}as any,native,{}as any,{}as any,{}as any,kong,{}as any,{}as any,undefined,durable);
 const read=(cid=scope.clusterId,pid=summary.id,session=sid)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,session);return service.plan(cid,pid,{},actor);});
 return{service,db,access,authz,repo,durable,kong,native,read,state,trace,row,source,actor,scope,summary,plan,context,secrets,handle,sid};
}
