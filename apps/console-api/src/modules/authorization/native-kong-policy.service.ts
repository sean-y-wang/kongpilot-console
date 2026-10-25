import { ForbiddenException, HttpException, Inject, Injectable, Logger, Optional, ServiceUnavailableException } from '@nestjs/common';
import { writeFailureDiagnostic } from '../../infrastructure/kong/write-failure-diagnostics';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService, KongExecutionFrame, KongPolicyCluster, approvedNativePacketScope } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from './authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { ENTITIES, GLOBAL_CREDENTIAL_COLLECTIONS } from '../../infrastructure/kong/policy';
import { permissionAction, permissionModule } from '../../common/authorization.types';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { isIP } from 'node:net';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import type { MetricsWriteInput } from '../metrics/metrics.types';
import type { PortalAuthBoundaryPolicy, PortalBoundaryReadPermit } from '../workflows/approved-execution.types';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import type { EntityChangeRecycleNativePolicy, EntityChangeRecycleNativeOperation, EntityChangeRecycleNativeInput, EntityChangeRecycleArchiveInput } from './entity-change-recycle-native-policy.types';
import { TargetAppendNativePolicy, type TargetAppendAuthorization, type TargetAppendPermissionInput, type TargetAppendReadScope } from './target-append-native-policy';
import type { EntityScheduledTargetWeightPacketProof } from '../workflows/entity-scheduled-namespace.types';

export interface ScheduledTargetAppendBridge {
 verifyOriginalPacket(originalNamespaceHandle:object,originalPacketHandle:object,packetKey:string):Promise<Readonly<EntityScheduledTargetWeightPacketProof>>;
}

interface Decision {
 frame:KongExecutionFrame; clusterId:string; workspaceId?:string; method:string; path:string;
 kind:'private'|'schema'|'entity'|'list'|'health'|'info'|'write'|'governance'|'promotion-recovery'; type?:string; parentId?:string;
 platformAdmin:boolean; before?:any; version?:string; primaryCreate?:{id:string;actorId:string;entityType:string};
 targetAppend?:Readonly<TargetAppendAuthorization>; globalCredential?:boolean;
}
const writes=new Set(['POST','PUT','PATCH','DELETE']);
const credentials=new Set(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
const recycleUuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const entityRecycleColumns=['entity_change_source_id','entity_change_baseline_id','entity_change_attempt_id','entity_change_packet_key'] as const;
const denied=(code='KONG_PERMISSION_DENIED')=>new ForbiddenException({code,message:'当前网关操作未获得有效授权'});

/** Installed before bootstrap probes. Transport has no default allow path. */
@Injectable()
export class NativeKongPolicyService {
 private readonly decisions=new WeakSet<object>();
 private entityChangeRecyclePolicy?:Readonly<EntityChangeRecycleNativePolicy>;
 private readonly targetAppendPolicy:TargetAppendNativePolicy;
 private scheduledTargetBridge?:Readonly<ScheduledTargetAppendBridge>;
 private readonly scheduledTargetReferences=new WeakMap<object,{frame:KongExecutionFrame;namespaceHandle:object;packetHandle:object;packetKey:string;operationId:string;workflowId:string}>();
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly kong:KongService,
  private readonly execution:KongExecutionContextService,private readonly authz:AuthorizationService,
  private readonly workspaces:WorkspaceResolverService,
  @Optional() @Inject('METRICS_WRITE_FENCE') private readonly metricsFence?:{beforeNativeWrite(input:MetricsWriteInput):Promise<unknown>},
  @Optional() @Inject('PORTAL_AUTH_BOUNDARY') private readonly portalBoundary?:PortalAuthBoundaryPolicy){
  this.targetAppendPolicy=new TargetAppendNativePolicy({kong,secrets,
   runFreshRead:(scope,lookup)=>{
    this.targetAppendFrame(scope);
    // 'authorization' has a smaller fixed ceiling. Match the existing
    // parent-scoped effective-target preflight capability, without changing
    // Context's budgets or allowing any additional endpoint.
    return this.execution.runInternalRead(scope.clusterId,'entity-preflight',lookup,{workspaceId:scope.workspaceId,paths:[...scope.paths],
     maxCalls:scope.maxCalls,maxPages:scope.maxPages,maxRecords:scope.maxRecords,maxBytes:scope.maxBytes,timeoutMs:scope.timeoutMs});
   },
   assertOriginalScheduled:async(reference,input)=>{
    const frame=this.targetAppendFrame({...input,origin:'scheduled-entity',originalScheduledReference:reference});
    const original=this.scheduledTargetReferences.get(reference)!;
    if(!this.scheduledTargetBridge)throw denied('TARGET_APPEND_SCHEDULED_BRIDGE_REQUIRED');
    const proof=await this.scheduledTargetBridge.verifyOriginalPacket(original.namespaceHandle,original.packetHandle,original.packetKey);
    this.targetAppendFrame({...input,origin:'scheduled-entity',originalScheduledReference:reference});
    if(proof.namespace.origin!=='scheduled-entity'||proof.namespace.sessionId!==null||proof.namespace.actor.id!==frame.actor!.id
     ||proof.namespace.clusterId!==input.clusterId||proof.namespace.workspaceId!==input.workspaceId||proof.namespace.claim.workflowId!==original.workflowId
     ||proof.packet.key!==original.packetKey||proof.packet.nativeType!=='targets'||proof.packet.mutationAction!=='update'||proof.packet.parentId!==input.upstreamId
     ||proof.packet.originalNativeId!==input.originalNativeId||proof.packet.nativeId!==(input.body as any)?.id||proof.packet.canonicalPath!==input.canonicalPath
     ||proof.packet.beforeHmac!==this.secrets.fingerprint(input.approvedBefore)||proof.packet.bodyHmac!==this.secrets.fingerprint(input.approvedBody)
     ||proof.packet.bodyHmac!==this.secrets.fingerprint(input.body))throw denied('TARGET_APPEND_SCHEDULED_PACKET_CHANGED');
   },
   assertWorkspaceAndWrite:async input=>{
    const frame=this.targetAppendFrame(input);
    await this.member(input.clusterId,'targets',input.entity,input.workspaceId,input.upstreamId);
    await this.authz.assertEntity(frame.actor!,input.clusterId,'targets','write',input.entity,input.workspaceId);
    this.targetAppendFrame(input);
   }});
 }
 installScheduledTargetAppendBridge(delegate:ScheduledTargetAppendBridge):void{
  if(this.scheduledTargetBridge||!delegate||typeof delegate.verifyOriginalPacket!=='function')throw denied('TARGET_APPEND_SCHEDULED_BRIDGE_INVALID');
  this.scheduledTargetBridge=Object.freeze({verifyOriginalPacket:delegate.verifyOriginalPacket.bind(delegate)});
 }
 private targetAppendFrame(scope:Pick<TargetAppendReadScope|TargetAppendPermissionInput,'actorId'|'sessionId'|'clusterId'|'workspaceId'|'origin'|'originalScheduledReference'>):KongExecutionFrame{
  const frame=this.execution.current();
  if(scope.origin==='scheduled-entity'){
   const original=scope.originalScheduledReference&&this.scheduledTargetReferences.get(scope.originalScheduledReference);
   if(!original||!this.scheduledTargetBridge||frame!==original.frame||frame.kind!=='operation'||!frame.actor||frame.sessionId!=null||scope.sessionId!==null
    ||frame.actor.id!==scope.actorId||frame.clusterId!==scope.clusterId||frame.workspaceId!==scope.workspaceId||frame.operation?.operationId!==original.operationId
    ||this.execution.requireEntityScheduledNamespaceHandle()!==original.namespaceHandle||this.execution.requireEntityChangePacketFrame(frame)!==original.packetHandle)
    throw denied('TARGET_APPEND_SCHEDULED_SOURCE_REQUIRED');return frame;
  }
  if(frame.kind!=='operation'||!frame.actor||!frame.sessionId||frame.actor.id!==scope.actorId||frame.sessionId!==scope.sessionId
   ||frame.clusterId!==scope.clusterId||frame.workspaceId!==scope.workspaceId||this.execution.hasEntityScheduledNamespace())throw denied('TARGET_APPEND_HTTP_SOURCE_REQUIRED');
  this.execution.requireEntityChangePacketFrame(frame);return frame;
 }
 private async targetAppendWrite(frame:KongExecutionFrame,op:any,path:string,body:unknown,payload:any,parentId:string):Promise<Readonly<TargetAppendAuthorization>>{
  const packetHandle=this.execution.requireEntityChangePacketFrame(frame),scheduled=this.execution.hasEntityScheduledNamespace();
  if(!frame.actor||(scheduled?frame.sessionId!=null:!frame.sessionId)
   ||['id','cluster_id','workspace_id','actor_id','workflow_id','entity_id','entity_change_source_id','entity_change_baseline_id','entity_change_attempt_id'].some(field=>!recycleUuid.test(op[field]??''))
   ||op.remote_completed!==false||op.parent_id!==parentId||op.credential_kind!=null
   ||typeof op.entity_change_packet_key!=='string'||!/^[a-zA-Z\d_.:-]{1,128}$/.test(op.entity_change_packet_key)
   ||typeof op.idempotency_key!=='string'||!/^[a-zA-Z\d_.:-]{1,128}$/.test(op.idempotency_key)
   ||['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(field=>op[field]!=null))throw denied('TARGET_APPEND_HTTP_SOURCE_REQUIRED');
  let before:unknown;
  try{before=this.secrets.decrypt(op.before_secret,`mutation:${op.id}:before`);}catch{throw denied('TARGET_APPEND_MUTATION_SECRETS_INVALID');}
  // Ask the fixed Root policy for the original packet binding. SQL-shaped
  // columns, helper DTOs and a real frame alone cannot substitute a different
  // packet, baseline, new UUID, original key or authenticated before/body.
  const binding=await this.execution.approvedMutationBinding({clusterId:op.cluster_id,workspaceId:op.workspace_id,actor:frame.actor,
   entityType:'targets',entityId:op.entity_id,action:'update',before,payload,idempotencyKey:op.idempotency_key,parentId});
  if(!binding||!('version'in binding)||binding.version!==3||binding.workflowId!==op.workflow_id||binding.sourceId!==op.entity_change_source_id
   ||binding.baselineId!==op.entity_change_baseline_id||binding.attemptId!==op.entity_change_attempt_id||binding.packetKey!==op.entity_change_packet_key
   ||binding.nativeId!==payload?.id||binding.beforeHmac!==this.secrets.fingerprint(before))throw denied('TARGET_APPEND_PACKET_BINDING_INVALID');
  const common={actorId:frame.actor.id,clusterId:op.cluster_id,
   workspaceId:op.workspace_id,upstreamId:parentId,originalNativeId:op.entity_id,method:'POST',mutationAction:'update',canonicalPath:path,
   body,approvedBody:payload,approvedBefore:before} as const;
  if(!scheduled)return this.targetAppendPolicy.authorize({...common,origin:'http',sessionId:frame.sessionId!});
  if(!this.scheduledTargetBridge||frame!==this.execution.current()||frame.operation?.operationId!==op.id||op.state!=='running'||op.remote_started!==true)
   throw denied('TARGET_APPEND_SCHEDULED_SOURCE_REQUIRED');
  const namespaceHandle=this.execution.requireEntityScheduledNamespaceHandle(),reference=Object.freeze({});
  this.scheduledTargetReferences.set(reference,{frame,namespaceHandle,packetHandle,packetKey:op.entity_change_packet_key,operationId:op.id,workflowId:op.workflow_id});
  try{return await this.targetAppendPolicy.authorize({...common,origin:'scheduled-entity',sessionId:null,originalScheduledReference:reference});}
  finally{this.scheduledTargetReferences.delete(reference);}
 }
 install():void {this.execution.installPolicy({authorizeRequest:(...args)=>this.authorizeRequest(...args),authorizeResponse:(...args)=>this.authorizeResponse(...args),beforeNativeSend:(...args)=>this.beforeNativeSend(...args)});}
 installEntityChangeRecyclePolicy(delegate:EntityChangeRecycleNativePolicy):void{
  const methods=['assertDeleteArchive','resolveRestoreArchive','assertRestoreArchive','assertCurrentBeforeSend'] as const;
  if(this.entityChangeRecyclePolicy||!delegate||methods.some(method=>typeof delegate[method]!=='function'))throw denied('ENTITY_CHANGE_RECYCLE_POLICY_INVALID');
  this.entityChangeRecyclePolicy=Object.freeze(Object.fromEntries(methods.map(method=>[method,delegate[method].bind(delegate)]))) as unknown as Readonly<EntityChangeRecycleNativePolicy>;
 }
 private entityRecycleOperation(operation:any):boolean{return entityRecycleColumns.some(field=>operation[field]!=null);}
 /** Complete V3 SQL evidence is necessary, but only the context's genuine
  * opaque packet plus Root's fixed verifier can authorize its recycle graph. */
 private entityRecycleInput(frame:KongExecutionFrame,operation:any,path:string,body:unknown,parsed:ReturnType<NativeKongPolicyService['parse']>,action:'delete'|'restore'):Readonly<EntityChangeRecycleNativeInput>{
  if(!this.entityChangeRecyclePolicy)throw denied('ENTITY_CHANGE_RECYCLE_POLICY_UNAVAILABLE');
  this.execution.requireEntityChangePacketFrame(frame);
  if(!frame.actor||!frame.operation||frame.operation.operationId!==operation.id||frame.actor.id!==operation.actor_id
   ||frame.clusterId!==operation.cluster_id||frame.workspaceId!==operation.workspace_id||frame.operation.action!==action||operation.action!==action
   ||operation.state!=='running'||operation.remote_started!==true||operation.remote_completed!==false
   ||['id','cluster_id','workspace_id','actor_id','workflow_id','entity_id','entity_change_source_id','entity_change_baseline_id','entity_change_attempt_id'].some(field=>!recycleUuid.test(operation[field]??''))
   ||typeof operation.entity_change_packet_key!=='string'||!/^[a-zA-Z\d_.:-]{1,128}$/.test(operation.entity_change_packet_key)
   ||typeof operation.idempotency_key!=='string'||!/^[a-zA-Z\d_.:-]{1,128}$/.test(operation.idempotency_key)
   ||typeof operation.before_secret!=='string'||typeof operation.payload_secret!=='string'
   ||['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(field=>operation[field]!=null)
   ||(operation.entity_type==='credentials'?operation.credential_kind!==parsed.type:operation.entity_type!==parsed.type)
   ||(operation.parent_id??null)!==(parsed.parentType==='consumers'||parsed.parentType==='upstreams'?parsed.parentId??null:null)
   ||(operation.credential_kind??null)!==(credentials.has(parsed.type)?parsed.type:null))throw denied('ENTITY_CHANGE_RECYCLE_PACKET_INVALID');
  const fields=['id','cluster_id','workspace_id','actor_id','workflow_id','entity_type','entity_id','action','idempotency_key','state','remote_started','remote_completed',
   'entity_change_source_id','entity_change_baseline_id','entity_change_attempt_id','entity_change_packet_key','before_secret','payload_secret'];
  const tuple=Object.freeze({...Object.fromEntries(fields.map(field=>[field,operation[field]])),parent_id:operation.parent_id??null,credential_kind:operation.credential_kind??null}) as unknown as Readonly<EntityChangeRecycleNativeOperation>;
  return Object.freeze({frame,operation:tuple,canonicalPath:path,body,nativeType:parsed.type,...(parsed.parentType==='consumers'||parsed.parentType==='upstreams'?{parentId:parsed.parentId}:{}),
   ...(credentials.has(parsed.type)?{credentialKind:parsed.type}:{})});
 }
 private entityRecycleArchiveInput(input:Readonly<EntityChangeRecycleNativeInput>,entry:any,graph:any,node:any):Readonly<EntityChangeRecycleArchiveInput>{
  return Object.freeze({...input,entry:Object.freeze({...entry}),graph:immutableJson(graph),node:immutableJson(node)});
 }
 private decision(value:Decision):Decision{this.decisions.add(value);return Object.freeze(value);}
 private async fresh(cid:string,path:string):Promise<any>{
  return this.execution.runPortalNativeParentRead(cid,path,()=>this.kong.request(cid,'GET',path));
 }
 private async member(cid:string,type:string,entity:any,wid:string,parentId?:string):Promise<void>{
  let owner=entity;
  if(type==='targets'||credentials.has(type)){
   const field=type==='targets'?'upstream':'consumer',parentType=type==='targets'?'upstreams':'consumers';
   const actualId=entity?.[field]?.id??parentId;if(!actualId||parentId&&actualId!==parentId)throw denied('KONG_PARENT_MISMATCH');
   owner=await this.fresh(cid,`/${parentType}/${encodeURIComponent(actualId)}`);
  }
  this.workspaces.assertMembership(await this.workspaces.listScope(cid,wid),owner);
 }
 private async references(frame:KongExecutionFrame,cid:string,type:string,entity:any,wid:string,serviceObservation?:{readonly serviceHostUpstream?:unknown|null;readonly serviceReferences?:readonly Readonly<{entityType:'certificates'|'ca_certificates';entity:unknown}>[]}):Promise<void>{
  const refs:Record<string,string>=type==='routes'?{service:'services'}:type==='plugins'?{service:'services',route:'routes',consumer:'consumers'}:type==='snis'?{certificate:'certificates'}:type==='services'?{client_certificate:'certificates'}:{};
  const values:Array<[string,string]>=[];
  for(const [field,kind] of Object.entries(refs)){const value=entity?.[field],id=typeof value==='string'?value:value?.id;if(id)values.push([kind,id]);}
  if(type==='services'&&Array.isArray(entity?.ca_certificates))for(const value of entity.ca_certificates){const id=typeof value==='string'?value:value?.id;if(id)values.push(['ca_certificates',id]);}
  if(type==='services'&&typeof entity?.host==='string'&&!isIP(entity.host.replace(/^\[|\]$/g,''))){
   try{const upstream=serviceObservation&&Object.hasOwn(serviceObservation,'serviceHostUpstream')?serviceObservation.serviceHostUpstream:await this.fresh(cid,`/upstreams/${encodeURIComponent(entity.host)}`);
    if(upstream!==null){if(serviceObservation&&Object.hasOwn(serviceObservation,'serviceHostUpstream')&&(!upstream||typeof upstream!=='object'||(upstream as any).name!==entity.host))throw denied('CONFIGURATION_SERVICE_REFERENCE_CHANGED');await this.member(cid,'upstreams',upstream,wid);await this.authz.assertEntity(frame.actor!,cid,'upstreams','read',upstream,wid);}}
   catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
  }
  for(const [kind,id] of values){
   const actual=serviceObservation&&type==='services'?serviceObservation.serviceReferences?.find(ref=>ref.entityType===kind&&(ref.entity as any)?.id===id)?.entity:await this.fresh(cid,`/${kind}/${encodeURIComponent(id)}`);
   if(!actual)throw denied('CONFIGURATION_SERVICE_TLS_REFERENCE_REQUIRED');
   await this.workspaces.assertMembership(await this.workspaces.listScope(cid,wid),actual);
   try{await this.authz.assertEntity(frame.actor!,cid,kind,'read',actual,wid);}
   catch(error){
    // The child write has already proved every binding. A parent writer may
    // use that private identity without obtaining its public configuration.
    // Certificate references retain their separate read requirement.
    const inheritedParent=type==='routes'&&kind==='services'||type==='plugins'&&['services','routes','consumers'].includes(kind);
    if(!inheritedParent||!(error instanceof HttpException&&error.getStatus()===403))throw error;
    await this.authz.assertEntity(frame.actor!,cid,kind,'write',actual,wid);
   }
  }
 }
 private parse(path:string):{type:string;parentId?:string;parentType?:string;list:boolean;globalCredential?:boolean}{
  const parts=path.split('/').filter(Boolean).map(part=>decodeURIComponent(part));
  if(parts.length===1&&Object.hasOwn(GLOBAL_CREDENTIAL_COLLECTIONS,parts[0]))return {type:GLOBAL_CREDENTIAL_COLLECTIONS[parts[0]],list:true,globalCredential:true};
  if(parts[0]==='routes'&&parts.length===3&&parts[2]==='service')return {type:'services',parentId:parts[1],parentType:'routes',list:false};
  if(parts[0]==='plugins'&&parts.length===3&&['service','route','consumer'].includes(parts[2]))return {type:({service:'services',route:'routes',consumer:'consumers'} as Record<string,string>)[parts[2]],parentId:parts[1],parentType:'plugins',list:false};
  if(parts[0]==='consumers'&&credentials.has(parts[2]))return {type:parts[2],parentId:parts[1],parentType:'consumers',list:parts.length===3};
  if(parts[0]==='upstreams'&&parts[2]==='targets')return {type:'targets',parentId:parts[1],parentType:'upstreams',list:parts.length===3||parts[3]==='all'};
  if(parts[0]==='services'&&parts[2]==='routes')return {type:'routes',parentId:parts[1],parentType:'services',list:parts.length===3};
  if(parts[0]==='certificates'&&parts[2]==='snis')return {type:'snis',parentId:parts[1],parentType:'certificates',list:parts.length===3};
  if(parts[0]==='upstreams'&&parts[2]==='health')return {type:'targets',parentId:parts[1],parentType:'upstreams',list:true};
  return {type:parts[0],list:parts.length===1};
 }
 private child(entity:any,type:string,parentId?:string):any{
  if(!parentId)return entity;
  const field=type==='targets'?'upstream':credentials.has(type)?'consumer':type==='routes'?'service':type==='snis'?'certificate':null;
  if(!field)return entity;
  if(entity?.[field]?.id&&entity[field].id!==parentId)throw denied('KONG_PARENT_MISMATCH');
  return {...entity,[field]:{id:parentId}};
 }
 private childParent(parsed:ReturnType<NativeKongPolicyService['parse']>):string|undefined{
  return parsed.parentType==='consumers'&&credentials.has(parsed.type)||parsed.parentType==='upstreams'&&parsed.type==='targets'
   ||parsed.parentType==='services'&&parsed.type==='routes'||parsed.parentType==='certificates'&&parsed.type==='snis'?parsed.parentId:undefined;
 }
 private exactBody(actual:unknown,approved:unknown):void{
  if(this.secrets.fingerprint(actual??null)!==this.secrets.fingerprint(approved??null))throw denied('KONG_OPERATION_PAYLOAD_MISMATCH');
 }
 private async observeChildren(cid:string,type:string,items:any[]):Promise<void>{
  if(type!=='targets'&&!credentials.has(type))return;
  const parentType=type==='targets'?'upstreams':'consumers',field=type==='targets'?'upstream':'consumer',uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
  const rows=items.filter(item=>uuid.test(item?.id??'')&&uuid.test(item?.[field]?.id??'')).map(item=>({child_id:item.id,parent_id:item[field].id}));if(!rows.length)return;
  await this.db.exec(`INSERT INTO entity_parent_index(cluster_id,child_type,child_id,parent_type,parent_id)
   SELECT $1,$2,r.child_id,$3,r.parent_id FROM jsonb_to_recordset($4::jsonb) AS r(child_id uuid,parent_id uuid)
   ON CONFLICT(cluster_id,child_type,child_id) DO UPDATE SET parent_type=excluded.parent_type,parent_id=excluded.parent_id,observed_at=now()`,[cid,type,parentType,JSON.stringify(rows)]);
 }
 private async internal(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string):Promise<Decision>{
  if(method!=='GET')throw denied('KONG_READ_CAPABILITY_WRITE_FORBIDDEN');
  if(frame.kind==='system-read'){
   if(frame.actor||!['probe','indexer','metrics-scrape','metrics-catalog','event-observation'].includes(frame.purpose??''))throw denied();
   if(frame.purpose==='event-observation'){
    this.execution.assertEventObservationRead(frame);
    if(!/^1\.5\.\d+$/.test(cluster.version??'')||['disabled','incompatible'].includes(String(cluster.status)))throw denied('OBSERVATION_CLUSTER_UNAVAILABLE');
   }
   if(frame.purpose==='metrics-scrape'||frame.purpose==='metrics-catalog'){
    if(!/^1\.5\.\d+$/.test(cluster.version??'')||cluster.status==='disabled')throw denied('KONG_METRICS_CLUSTER_UNAVAILABLE');
    if(frame.purpose==='metrics-scrape'&&(!Array.isArray(cluster.enabled_plugins)||!cluster.enabled_plugins.includes('prometheus')))throw denied('KONG_METRICS_PLUGIN_UNAVAILABLE');
   }
   return this.decision({frame,clusterId:cluster.id,method,path,kind:'private',platformAdmin:false});
  }
  if(!frame.actor)throw denied();
  const snapshot=await this.authz.snapshot(frame.actor);
  if(frame.purpose==='portal-recovery-boundary'){
   await this.execution.assertPortalRecoveryBoundaryRead(frame);
   if(snapshot.user.forcePasswordChange)throw denied('PASSWORD_CHANGE_REQUIRED');
   return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'private',platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
  }
  if(frame.purpose==='portal-boundary'){
   this.execution.assertPortalBoundaryRead(frame);
   if(snapshot.user.forcePasswordChange)throw denied('PASSWORD_CHANGE_REQUIRED');
   await this.operation(frame,cluster);
   return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'private',platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
  }
  // Read capabilities keep raw data private to a bounded server operation.
  // Actual graph nodes and references are independently authorized before
  // preview, archival or native execution; filtered graphs are never "complete".
  if(frame.purpose==='probe')await this.authz.assertCluster(snapshot.user,cluster.id,'clusters','write',frame.workspaceId);
  else if(frame.purpose!=='authorization'){
   const module=frame.module??'entities',action=frame.action?permissionAction(frame.action):'read';
   await this.authz.assertCluster(snapshot.user,cluster.id,module,action,frame.workspaceId);
  }else if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>grant.cluster_id===null||grant.cluster_id===cluster.id))throw denied();
  return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'private',platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
 }
 private async operation(frame:KongExecutionFrame,cluster:KongPolicyCluster):Promise<any>{
  const scope=frame.operation;
  if(!scope||!frame.actor||scope.clusterId!==cluster.id||scope.actor.id!==frame.actor.id||scope.workspaceId!==frame.workspaceId)throw denied('KONG_NATIVE_OPERATION_REQUIRED');
  const op=await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1 AND cluster_id=$2',[scope.operationId,cluster.id]);
  if(!op||op.state!=='running'||op.actor_id!==frame.actor.id||op.workspace_id!==frame.workspaceId||op.entity_type!==scope.entityType||op.action!==scope.action||op.remote_started!==true)throw denied('KONG_NATIVE_OPERATION_INVALID');
  return op;
 }
 private async archive(frame:KongExecutionFrame,operation:any,path:string,body:unknown):Promise<any>{
  const cap=frame.archive;if(!cap||cap.operationId!==operation.id)throw denied('KONG_RECYCLE_CAPABILITY_REQUIRED');
  const entityInput=this.entityRecycleOperation(operation)?this.entityRecycleInput(frame,operation,path,body,this.parse(path),'delete'):null;
  const entry=await this.db.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[operation.cluster_id,cap.entryId]);
  if(!entry||entry.actor_id!==operation.actor_id||entry.workspace_id!==operation.workspace_id||(entityInput?entry.mutation_id!==null:entry.mutation_id!==operation.id)
   ||!entry.payload_secret||!['deleting','partially_deleted'].includes(entry.state))throw denied('KONG_RECYCLE_ARCHIVE_INVALID');
  const graph=this.secrets.decrypt<any>(entry.payload_secret,`recycle:${entry.id}`);
  if(graph.complete!==true||graph.purpose==='migration'||!Array.isArray(graph.nodes))throw denied('KONG_RECYCLE_ARCHIVE_INVALID');
  const node=graph.nodes.find((item:any)=>item.affected===true&&item.path===path);
  if(!node||!cap.nodes.some(item=>item.path===path&&item.type===node.type&&item.id===node.id))throw denied('KONG_RECYCLE_NODE_INVALID');
  if(entityInput){await this.entityChangeRecyclePolicy!.assertDeleteArchive(this.entityRecycleArchiveInput(entityInput,entry,graph,node));this.execution.requireEntityChangePacketFrame(frame);}
  return node;
 }
 private async allowedWrite(frame:KongExecutionFrame,op:any,method:string,path:string,body:any,parsed:ReturnType<NativeKongPolicyService['parse']>,cluster:KongPolicyCluster,query:Record<string,string|number>):Promise<{before?:any;workspaceId:string;targetAppend?:Readonly<TargetAppendAuthorization>}>{
  const payload=op.payload_secret?this.secrets.decrypt<any>(op.payload_secret,`mutation:${op.id}:payload`):null;
  const wid=op.workspace_id;
  if(op.entity_type==='workspace_migration'){
   if(method!=='PATCH'||!body||Object.keys(body).length!==1||!Array.isArray(body.tags))throw denied('KONG_MIGRATION_WRITE_INVALID');
   const plan=await this.db.one<any>('SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2',[op.cluster_id,op.entity_id]);
   if(!plan||plan.operation_id!==op.id||plan.actor_id!==op.actor_id||plan.state!=='running'||plan.plan_hash!==payload?.plan_hash)throw denied('KONG_MIGRATION_PLAN_INVALID');
   const approved=this.secrets.decrypt<any>(plan.payload_secret,`workspace-migration:${plan.id}`);
   const node=approved.nodes?.find((item:any)=>item.path===path&&item.type===parsed.type&&item.inheritedOnly!==true);
   if(!node||this.secrets.fingerprint([...body.tags].sort())!==this.secrets.fingerprint([...node.afterTags].sort()))throw denied('KONG_MIGRATION_NODE_INVALID');
   const before=await this.fresh(op.cluster_id,path);
   const stable={...before};delete stable.tags;delete stable.updated_at;
   if(before.id!==node.id||this.secrets.fingerprint(stable)!==node.configFingerprint)throw denied('KONG_MIGRATION_STATE_CHANGED');
   const actual=await this.workspaces.classify(op.cluster_id,before.tags);
   if(!actual.workspace||actual.workspace.id!==plan.source_workspace_id&&actual.workspace.id!==plan.target_workspace_id)throw denied();
   const sourceGraph=[...approved.nodes,...approved.referenceNodes],targetGraph=[...approved.nodes.map((item:any)=>({...item,data:item.inheritedOnly?item.data:{...item.data,tags:item.afterTags}})),...approved.referenceNodes];
   await this.authz.assertMigrationEntity(frame.actor!,op.cluster_id,parsed.type,'write',node.data,plan.source_workspace_id,sourceGraph);
   await this.authz.assertMigrationEntity(frame.actor!,op.cluster_id,parsed.type,'write',{...before,tags:body.tags},plan.target_workspace_id,targetGraph);
   return {before,workspaceId:plan.target_workspace_id};
  }
  if(method==='DELETE'){
   const node=await this.archive(frame,op,path,body);
   let before:any;
   if(parsed.type==='targets')before=await this.execution.runInternalRead(op.cluster_id,'recycle-check',async()=>{
    const current=(await currentEffectiveTarget(this.kong,op.cluster_id,parsed.parentId!,node.data.target)).target;
    if(current?.id!==node.id)throw denied('KONG_TARGET_NOT_EFFECTIVE');return current;
   },{paths:[`/upstreams/${encodeURIComponent(parsed.parentId!)}/targets`],maxCalls:100,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
   else before=await this.fresh(op.cluster_id,path);
   const comparable=(value:any)=>{const result={...value};if(parsed.type==='certificates')delete result.snis;return result;};
   if(this.secrets.fingerprint(comparable(before))!==this.secrets.fingerprint(comparable(node.data)))throw denied('KONG_RECYCLE_STATE_CHANGED');
   await this.member(op.cluster_id,parsed.type,before,wid,parsed.parentId);
   await this.authz.assertEntity(frame.actor!,op.cluster_id,parsed.type,'delete',this.child(before,parsed.type,parsed.parentId),wid);
   return {before,workspaceId:wid};
  }
  if(op.action==='restore'){
   const entityInput=this.entityRecycleOperation(op)?this.entityRecycleInput(frame,op,path,body,parsed,'restore'):null;
   let archiveId=payload?.entryId;
   if(entityInput){
    if(payload&&Object.hasOwn(payload,'entryId')||body&&Object.hasOwn(body,'entryId'))throw denied('ENTITY_CHANGE_RECYCLE_PAYLOAD_INVALID');
    const resolved=await this.entityChangeRecyclePolicy!.resolveRestoreArchive(entityInput);this.execution.requireEntityChangePacketFrame(frame);
    if(!resolved||Object.keys(resolved).length!==1||!recycleUuid.test(resolved.entryId??''))throw denied('ENTITY_CHANGE_RECYCLE_ARCHIVE_INVALID');
    archiveId=resolved.entryId;
   }
   const entry=archiveId?await this.db.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[op.cluster_id,archiveId]):null;
   if(!entry||entry.workspace_id!==wid||entry.state!=='restoring'||!entry.payload_secret)throw denied('KONG_RESTORE_ARCHIVE_INVALID');
   if(entityInput?entry.mutation_id!==null:entry.mutation_id==null)throw denied('KONG_RESTORE_ARCHIVE_INVALID');
   const graph=this.secrets.decrypt<any>(entry.payload_secret,`recycle:${entry.id}`);
   if(entityInput&&(graph.complete!==true||graph.purpose==='migration'||!Array.isArray(graph.nodes)))throw denied('KONG_RESTORE_ARCHIVE_INVALID');
   const candidates=graph.nodes?.filter((item:any)=>item.affected===true&&item.type===parsed.type&&item.path.replace(/\/[^/]+$/,'')===path
    &&(parsed.type==='targets'?item.data?.target===body?.target:item.id===body?.id));
   const node=candidates?.length===1?candidates[0]:null;
   if(method!=='POST'||!node)throw denied('KONG_RESTORE_NODE_INVALID');
   if(entityInput){await this.entityChangeRecyclePolicy!.assertRestoreArchive(this.entityRecycleArchiveInput(entityInput,entry,graph,node));this.execution.requireEntityChangePacketFrame(frame);}
   const restored=this.child(body,parsed.type,parsed.parentId);
   if(parsed.type!=='targets'&&restored.id!==node.id)throw denied('KONG_RESTORE_ID_INVALID');
   const expected={...(node.restoreData??node.data)};delete expected.created_at;delete expected.updated_at;delete expected.ttl;
   if(parsed.type==='targets'){
    delete expected.upstream;
    const parent=graph.nodes?.find((item:any)=>item.type==='upstreams'&&item.id===parsed.parentId&&item.affected===true
      &&item.data?.id===parsed.parentId&&item.path===`/upstreams/${encodeURIComponent(parsed.parentId!)}`&&node.dependencies?.includes(item.key));
    let originalAbsent=false;
    if(parent){
     const currentParent=await this.fresh(op.cluster_id,parent.path);
     const comparable=(value:any)=>Object.fromEntries(Object.entries(value).filter(([key])=>!['created_at','updated_at','ttl'].includes(key)));
     if(currentParent.id!==parent.id||this.secrets.fingerprint(comparable(currentParent))!==this.secrets.fingerprint(comparable(parent.data)))throw denied('KONG_RESTORE_PARENT_CHANGED');
     try{await this.fresh(op.cluster_id,node.path);}catch(error){
      if(!(error instanceof HttpException&&error.getStatus()===404))throw error;originalAbsent=true;
     }
    }
    // A fully removed Upstream has no Target history and permits exact ID
    // reconstruction. A single Target archive retains append-only history.
    // The genuine V3 verifier above has authenticated the original sealed
    // packet and allocated native ID. Retained Target history requires a new
    // immutable append ID; legacy restores keep their existing ID policy.
    if(entityInput)expected.id=op.entity_id;
    else if(!originalAbsent)delete expected.id;
   }
   // V3 prepares explicit SNI successor packets, so certificate creation must
   // not implicitly recreate names outside that sealed packet sequence.
   if(entityInput&&parsed.type==='certificates')delete expected.snis;
   this.exactBody(body,expected);
   await this.member(op.cluster_id,parsed.type,restored,wid,parsed.parentId);
   await this.authz.assertEntity(frame.actor!,op.cluster_id,parsed.type,'write',restored,wid);
   await this.references(frame,op.cluster_id,parsed.type,restored,wid);
   return {workspaceId:wid};
  }
  // A native service write may stamp only its explicitly associated SNIs.
  if(op.entity_type==='certificates'&&parsed.type==='snis'&&method==='PATCH'){
   const before=await this.fresh(op.cluster_id,path);
   const certificateId=op.entity_id??(await this.db.one<any>('SELECT entity_id FROM mutation_operations WHERE id=$1',[op.id]))?.entity_id;
   if(!certificateId||before.certificate?.id!==certificateId||!payload?.snis?.includes(before.name)||!body||Object.keys(body).some(key=>key!=='tags'))throw denied('KONG_SNI_STAMP_INVALID');
   const prepared=await this.workspaces.prepareCreate(op.cluster_id,'snis',{tags:before.tags},wid);this.exactBody(body,{tags:prepared.tags});
   await this.member(op.cluster_id,'snis',{...before,...body},wid);
   await this.authz.assertEntity(frame.actor!,op.cluster_id,'snis','write',{...before,...body},wid);return {before,workspaceId:wid};
  }
  const nativeType=op.entity_type==='credentials'?frame.operation?.credentialKind:op.entity_type;
  if(parsed.type!==nativeType)throw denied('KONG_OPERATION_ENTITY_MISMATCH');
  if((parsed.type==='targets'||credentials.has(parsed.type))&&parsed.parentId!==(op.parent_id??frame.operation?.parentId))throw denied('KONG_OPERATION_PARENT_MISMATCH');
  if(method==='POST'){
   if(!parsed.list&&!/\/targets\/[^/]+\/(healthy|unhealthy)$/.test(path))throw denied('KONG_OPERATION_PATH_MISMATCH');
   if(parsed.type==='targets'&&/\/(healthy|unhealthy)$/.test(path)){
    const desired=path.slice(path.lastIndexOf('/')+1);if(op.action!==`mark_${desired}`||payload?.state!==desired)throw denied('KONG_HEALTH_STATE_MISMATCH');this.exactBody(body,null);
    const before=await this.fresh(op.cluster_id,path.replace(/\/(healthy|unhealthy)$/,''));
    const collection=`/upstreams/${encodeURIComponent(parsed.parentId!)}/targets`;
    const effective=await this.execution.runInternalRead(op.cluster_id,'entity-preflight',()=>currentEffectiveTarget(this.kong,op.cluster_id,parsed.parentId!,before.target),{paths:[collection],maxCalls:100,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
    if(effective.target?.id!==before.id)throw denied('KONG_TARGET_NOT_EFFECTIVE');
    if(before.id!==op.entity_id)throw denied();await this.member(op.cluster_id,'targets',before,wid,parsed.parentId);await this.authz.assertEntity(frame.actor!,op.cluster_id,'targets','write',this.child(before,'targets',parsed.parentId),wid);return {before,workspaceId:wid};
   }
   if(parsed.type==='targets'&&op.action==='update'&&this.entityRecycleOperation(op)){
    const targetAppend=await this.targetAppendWrite(frame,op,path,body,payload,parsed.parentId!);
    return{before:targetAppend.before,workspaceId:wid,targetAppend};
   }
   // Durable configuration_v2 Target weight append: POST creates a new historical
   // row while the sealed before is the prior effective Target. Approved native
   // matching requires that before on the decision; omitting it fingerprints as
   // null and fails CONFIGURATION_APPROVED_NATIVE_MISMATCH. Entity-recycle V3
   // stays on the branch above (and rejects configuration_* mutation columns).
   if(parsed.type==='targets'&&op.action==='update'){
    if(!op.before_secret)throw denied('KONG_OPERATION_STATE_CHANGED');
    let before:any;
    try{before=this.secrets.decrypt(op.before_secret,`mutation:${op.id}:before`);}catch{throw denied('KONG_OPERATION_STATE_CHANGED');}
    if(!before||before.id!==op.entity_id)throw denied('KONG_OPERATION_ID_MISMATCH');
    this.exactBody(body,payload);
    await this.member(op.cluster_id,parsed.type,body,wid,parsed.parentId);
    await this.authz.assertEntity(frame.actor!,op.cluster_id,parsed.type,'write',this.child(body,parsed.type,parsed.parentId),wid);
    await this.references(frame,op.cluster_id,parsed.type,body,wid);
    return {before,workspaceId:wid};
   }
   if(op.action!=='create')throw denied('KONG_OPERATION_ACTION_MISMATCH');
   this.exactBody(body,payload);
   await this.member(op.cluster_id,parsed.type,body,wid,parsed.parentId);
   await this.authz.assertEntity(frame.actor!,op.cluster_id,parsed.type,'write',this.child(body,parsed.type,parsed.parentId),wid);
   await this.references(frame,op.cluster_id,parsed.type,body,wid);
   return {workspaceId:wid};
  }
  const observed=typeof this.execution.readScheduledConfigurationNativeBefore==='function'?await this.execution.readScheduledConfigurationNativeBefore(frame,cluster,method,path,body,query):null;
  const before=observed?observed.before:await this.fresh(op.cluster_id,path);
  if(op.action!=='update'||method!=='PATCH')throw denied('KONG_OPERATION_ACTION_MISMATCH');this.exactBody(body,payload);
  if(!before||before.id!==op.entity_id)throw denied('KONG_OPERATION_ID_MISMATCH');
  if(!op.before_secret||this.secrets.fingerprint(before)!==this.secrets.fingerprint(this.secrets.decrypt<any>(op.before_secret,`mutation:${op.id}:before`)))throw denied('KONG_OPERATION_STATE_CHANGED');
  await this.member(op.cluster_id,parsed.type,before,wid,parsed.parentId);await this.member(op.cluster_id,parsed.type,{...before,...body},wid,parsed.parentId);
  await this.authz.assertEntity(frame.actor!,op.cluster_id,parsed.type,'write',this.child(before,parsed.type,parsed.parentId),wid);
  await this.authz.assertEntity(frame.actor!,op.cluster_id,parsed.type,'write',this.child({...before,...body},parsed.type,parsed.parentId),wid);
  await this.references(frame,op.cluster_id,parsed.type,{...before,...body},wid,observed??undefined);
  return {before,workspaceId:wid};
 }
 async authorizeRequest(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string,body:unknown,_query:Record<string,string|number>):Promise<Decision>{
  if(await this.execution.assertPromotionRecoveryRequest(frame,cluster,method,path,body,_query))return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'promotion-recovery',platformAdmin:false});
  if(await this.execution.assertGovernanceRequest(frame,cluster,method,path,body,_query))return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'governance',platformAdmin:false});
  if(frame.kind==='system-read'||frame.kind==='internal-read')return this.internal(frame,cluster,method,path);
  if(!frame.actor||frame.clusterId!==cluster.id)throw denied();
  const snapshot=await this.authz.snapshot(frame.actor),parsed=this.parse(path);
  if(snapshot.user.forcePasswordChange)throw denied('PASSWORD_CHANGE_REQUIRED');
  if(/^\/cache\/[A-Za-z0-9_.:%-]+$/.test(path)){
   if(method==='DELETE'){
    if(!await this.execution.assertToolboxRequest(frame,cluster,method,path,body,_query))throw denied('CACHE_EXECUTION_HANDLE_REQUIRED');
    await this.authz.assertWholeCluster(snapshot.user,cluster.id,'toolbox','write');
   }else if(method==='GET')await this.authz.assertWholeCluster(snapshot.user,cluster.id,'toolbox','read');
   else throw denied('CACHE_OPERATION_FORBIDDEN');
   return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'info',platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
  }
  if(writes.has(method)){
   const op=await this.operation(frame,cluster);
   const grant=await this.allowedWrite(frame,op,method,path,body,parsed,cluster,_query);
   const approvedScope=approvedNativePacketScope(frame,method,path);
   await this.execution.assertApprovedOperation(frame,cluster,{clusterId:cluster.id,transportScope:transportScopeFor(cluster.admin_url,cluster.transport_scope),
    workspaceId:op.entity_type==='workspace_migration'?approvedScope.workspaceId!:grant.workspaceId,operationId:op.id,method,canonicalPath:path,body,before:grant.before,mutationAction:op.action,
    parentId:approvedScope.parentId,credentialKind:approvedScope.credentialKind,query:_query},'authorize');
   if(snapshot.version!==await this.authz.permissionVersion(snapshot.user))throw denied('PERMISSIONS_CHANGED');
   const primaryCreate=method==='POST'&&op.action==='create'&&parsed.list&&(parsed.type===op.entity_type||op.entity_type==='credentials'&&parsed.type===frame.operation?.credentialKind)?{id:op.id,actorId:op.actor_id,entityType:op.entity_type}:undefined;
   return this.decision({frame,clusterId:cluster.id,workspaceId:grant.workspaceId,method,path,kind:'write',type:parsed.type,parentId:this.childParent(parsed),before:grant.before,platformAdmin:snapshot.user.superAdmin,version:snapshot.version,primaryCreate,
    ...(grant.targetAppend?{targetAppend:grant.targetAppend}:{})});
  }
  if(/^\/(?:schemas\/|plugins\/schema\/)/.test(path)||path==='/plugins/enabled'){
   const entity=path.startsWith('/schemas/')?path.slice(9):'plugins';await this.authz.assertCluster(snapshot.user,cluster.id,entity,'read',frame.workspaceId);
   return this.decision({frame,clusterId:cluster.id,workspaceId:frame.workspaceId,method,path,kind:'schema',platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
  }
  if(path==='/status'){
   await this.authz.assertWholeCluster(snapshot.user,cluster.id,'toolbox','read');return this.decision({frame,clusterId:cluster.id,method,path,kind:'info',platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
  }
  if(!(ENTITIES as readonly string[]).includes(parsed.type)&&parsed.type!=='targets'&&!credentials.has(parsed.type))throw denied('KONG_INFO_PRIVATE');
  // A global credential collection spans every Consumer of the cluster. It is
  // read-only and only for actors whose grants already cover all Consumers and
  // all credentials of that kind cluster-wide; everyone else keeps using the
  // per-Consumer path with its parent membership checks.
  if(parsed.globalCredential){
   if(method!=='GET')throw denied('KONG_GLOBAL_CREDENTIAL_LIST_FORBIDDEN');
   if(!snapshot.user.superAdmin&&!(await this.authz.hasWholeCluster(snapshot.user,cluster.id,'consumers','read')&&await this.authz.hasWholeCluster(snapshot.user,cluster.id,parsed.type,'read')))throw denied('KONG_GLOBAL_CREDENTIAL_LIST_FORBIDDEN');
  }
  const wid=(await this.workspaces.resolve(cluster.id,frame.workspaceId)).id;
  await this.authz.assertCluster(snapshot.user,cluster.id,parsed.type,'read',wid);
  if(parsed.parentType&&parsed.parentId){
   const parent=await this.fresh(cluster.id,`/${parsed.parentType}/${encodeURIComponent(parsed.parentId)}`);
   await this.member(cluster.id,parsed.parentType,parent,wid);
   if(parsed.parentType==='consumers'||parsed.parentType==='upstreams'){
    const child=parsed.list?undefined:await this.fresh(cluster.id,path);
    await this.authz.assertNestedParentScope(snapshot.user,cluster.id,parsed.parentType,parent,parsed.type,'read',wid,child);
   }else await this.authz.assertEntity(snapshot.user,cluster.id,parsed.parentType,'read',parent,wid);
  }
  return this.decision({frame,clusterId:cluster.id,workspaceId:wid,method,path,kind:path.endsWith('/health')?'health':parsed.list?'list':'entity',type:parsed.type,parentId:this.childParent(parsed),...(parsed.globalCredential?{globalCredential:true}:{}),platformAdmin:snapshot.user.superAdmin,version:snapshot.version});
 }
 /** Close old attribution durably before a native packet. prepareWrite is
  * called both before DNS and after DNS, so the repository keys this by the
  * immutable operation/request fingerprint. A native response alone cannot
  * settle the parent operation or reopen any closed membership epoch. */
 async beforeNativeSend(frame:KongExecutionFrame,cluster:KongPolicyCluster,method:string,path:string,body:unknown,query:Record<string,string|number>,value:unknown,permit:PortalBoundaryReadPermit):Promise<void>{
  if(!value||typeof value!=='object'||!this.decisions.has(value))throw denied('KONG_POLICY_TICKET_INVALID');
  const decision=value as Decision;
  if(!writes.has(method))return;
  if(method==='DELETE'&&path.startsWith('/cache/')){
   if(decision.kind!=='info'||decision.frame!==frame||decision.clusterId!==cluster.id||decision.method!==method||decision.path!==path||!await this.execution.assertToolboxRequest(frame,cluster,method,path,body,query,true))throw denied('CACHE_EXECUTION_HANDLE_REQUIRED');
   await this.authz.assertWholeCluster(frame.actor!,cluster.id,'toolbox','write');return;
  }
  if(decision.kind!=='write'||decision.frame!==frame||decision.clusterId!==cluster.id||decision.method!==method||decision.path!==path||!frame.operation)throw denied('KONG_NATIVE_OPERATION_INVALID');
  if(!this.metricsFence){
   if(process.env.METRICS_BRIDGE_ENABLED==='true')throw new ServiceUnavailableException({code:'METRICS_FENCE_UNAVAILABLE',message:'指标归属写入栅栏未初始化，变更已停止'});
  }else await this.metricsFence.beforeNativeWrite({cid:cluster.id,transportScope:transportScopeFor(cluster.admin_url,cluster.transport_scope),operationId:frame.operation.operationId,
   requestFingerprint:this.secrets.fingerprint({method,path,body:body??null}),entityType:decision.type??frame.operation.entityType,
   entityId:decision.before?.id,method,path,before:decision.before,body});
  const nativeScope=approvedNativePacketScope(frame,method,path);
  if(this.portalBoundary)await this.portalBoundary.assertBeforeNativeSend({clusterId:cluster.id,transportScope:transportScopeFor(cluster.admin_url,cluster.transport_scope),
   workspaceId:decision.workspaceId!,operationId:frame.operation.operationId,method,canonicalPath:path,body,before:decision.before,
   mutationAction:frame.operation.action??'',parentId:nativeScope.parentId,credentialKind:nativeScope.credentialKind},permit);
  else if(process.env.PORTAL_ENABLED==='true')throw new ServiceUnavailableException({code:'PORTAL_BOUNDARY_UNAVAILABLE',message:'门户认证边界未初始化，变更已停止'});
  // Database persistence introduces a final await. Recheck both the durable
  // operation and current grants after it; revoked authority sends no packet.
  const refreshed=await this.authorizeRequest(frame,cluster,method,path,body,query);
  if(refreshed.kind!=='write'||refreshed.version!==decision.version)throw denied('PERMISSIONS_CHANGED');
  if(['delete','restore'].includes(frame.operation.action??'')){
   const op=await this.operation(frame,cluster);if(this.entityRecycleOperation(op)){
    const input=this.entityRecycleInput(frame,op,path,body,this.parse(path),op.action);
    await this.entityChangeRecyclePolicy!.assertCurrentBeforeSend(input);
    this.execution.requireEntityChangePacketFrame(frame);
   }
  }
 }
 async authorizeResponse(value:unknown,result:any):Promise<any>{
  if(!value||typeof value!=='object'||!this.decisions.has(value))throw denied('KONG_POLICY_TICKET_INVALID');
  const ticket=value as Decision;if(ticket.kind==='promotion-recovery')return this.execution.promotionRecoveryResponse(ticket.frame,ticket.path,result);if(ticket.kind==='governance')return this.execution.governanceResponse(ticket.frame,ticket.path,result);if(!ticket.frame.actor)return result;
  try{
   const snapshot=await this.authz.snapshot(ticket.frame.actor);
   if(ticket.kind==='private')return result;
   if(ticket.kind==='info'){
    if(snapshot.user.forcePasswordChange)throw denied('PASSWORD_CHANGE_REQUIRED');
    await this.authz.assertWholeCluster(snapshot.user,ticket.clusterId,'toolbox',ticket.method==='GET'?'read':'write');
   }
   if(ticket.kind==='list'||ticket.kind==='health'){
    if(!Array.isArray(result?.data))throw denied('KONG_LIST_RESPONSE_INVALID');
    if(ticket.parentId&&(ticket.type==='targets'||credentials.has(ticket.type!)))await this.member(ticket.clusterId,ticket.type!,{},ticket.workspaceId!,ticket.parentId);
    const scope=await this.workspaces.listScope(ticket.clusterId,ticket.workspaceId);
    if(ticket.globalCredential&&result.data.some((item:any)=>!/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(item?.consumer?.id??'')))throw denied('KONG_PARENT_MISMATCH');
    const items=result.data.map((item:any)=>this.child(item,ticket.type!,ticket.parentId)).filter((item:any)=>ticket.type==='targets'||credentials.has(ticket.type!)||this.workspaces.matches(scope,item));
    const visible=await this.authz.filterEntities(snapshot.user,ticket.clusterId,ticket.type!,items,ticket.workspaceId);
    if(await this.authz.permissionVersion(snapshot.user)!==snapshot.version)throw denied('PERMISSIONS_CHANGED');
    await this.observeChildren(ticket.clusterId,ticket.type!,visible);
    return {...result,data:visible,total:null,...(!snapshot.user.superAdmin?{console_permission_projection:true}:{})};
   }
   if(ticket.kind==='entity'){await this.member(ticket.clusterId,ticket.type!,result,ticket.workspaceId!,ticket.parentId);await this.authz.assertEntity(snapshot.user,ticket.clusterId,ticket.type!,'read',this.child(result,ticket.type!,ticket.parentId),ticket.workspaceId);}
   if(ticket.kind==='write'&&ticket.method!=='DELETE'){
    // Check the unmodified response only. Root's transport observer/status
    // verifier remains the authority for a real 201 and its exact HMAC.
    if(ticket.targetAppend)this.targetAppendPolicy.assertRawResponse(ticket.targetAppend,result);
    const entity=result?.entity??result;
    if(entity?.id)await this.member(ticket.clusterId,ticket.type!,entity,ticket.workspaceId!,ticket.parentId);
    if(entity?.id)await this.authz.assertEntity(snapshot.user,ticket.clusterId,ticket.type!,'write',this.child(entity,ticket.type!,ticket.parentId),ticket.workspaceId);
    if(ticket.primaryCreate){
     if(!/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(entity?.id??''))throw denied('KONG_CREATE_RESPONSE_INVALID');
     const recorded=await this.db.exec(`UPDATE mutation_operations SET entity_id=$5 WHERE id=$1 AND cluster_id=$2 AND actor_id=$3 AND entity_type=$4 AND action='create' AND state='running' AND remote_started=true AND (entity_id IS NULL OR entity_id=$5)`,[ticket.primaryCreate.id,ticket.clusterId,ticket.primaryCreate.actorId,ticket.primaryCreate.entityType,entity.id]);
     if(recorded!==1)throw denied('KONG_CREATE_RECEIPT_CHANGED');
    }
   }
   if(await this.authz.permissionVersion(snapshot.user)!==snapshot.version)throw denied('PERMISSIONS_CHANGED');
   if(ticket.kind==='entity'||ticket.kind==='write'&&ticket.method!=='DELETE')await this.observeChildren(ticket.clusterId,ticket.type!,[this.child(result?.entity??result,ticket.type!,ticket.parentId)]);
   return ticket.kind==='schema'?stripSensitiveSchemaDefaults(result,this.secrets):result;
  }catch(error){
   if(ticket.kind==='write'){
    try{Logger.warn(writeFailureDiagnostic('native-policy-response',ticket.clusterId,error,ticket.frame.operation?.operationId),NativeKongPolicyService.name);}
    catch{/* Preserve the original unknown-result contract if logging fails. */}
    throw new ServiceUnavailableException({code:'KONG_WRITE_RESULT_UNKNOWN',message:'写入后授权或响应核验发生变化，请核验原操作回执，勿重复提交'});
   }
   throw error;
  }
 }
}
