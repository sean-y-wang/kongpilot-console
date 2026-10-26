import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import {BadRequestException,ConflictException,ForbiddenException,Injectable,NotFoundException,OnModuleInit,ServiceUnavailableException} from '@nestjs/common';
import {createHash,randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {KongActorScope} from '../../infrastructure/kong/actor-scope';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {AuditService} from '../audit/audit.service';
import {AuthorizationService} from '../authorization/authorization.service';
import {validGrant,coarseGrantMatches} from '../authorization/grant-policy';
import {EntityService} from '../entities/entities.service';
import type {EntityActor} from '../entities/entities.types';
import {WorkspaceResolverService} from '../workspaces/workspace-resolver.service';
import {MetricsSettingsService} from '../metrics/metrics-settings.service';
import {MetricsCredentialsService} from '../metrics/metrics-credentials.service';
import {MetricsSourceService} from './providers/metrics-source.service';
import {WorkflowPlansService} from '../workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../workflows/workflow-registry.service';
import {normalizeWorkflowApprovalPolicy} from '../workflows/workflow-approval-policy';
import {workflowId,workflowKey} from '../workflows/workflow-validation';
import type {WorkflowPlanV1,WorkflowStep,WorkflowHandlerInput} from '../workflows/workflow.types';
import {exactKeys,metricsId} from './vitals-query';
import {assertMetricsSetupPlan,metricsSetupSteps,metricsSetupPublicProjection} from './vitals-setup-plan';
import {metricsSetupAad,type MetricsSetupIntent,type MetricsSetupControl,type MetricsSetupPlugin,type MetricsSetupApprovedDelegate,type MetricsSetupExecutionBridge,type MetricsSetupExecutionDelegate} from './vitals-setup.types';

const conflict=(code:string,message?:string)=>new ConflictException({code,...(message?{message}:{})}),deny=(code:string)=>new ForbiddenException({code});
/** Prepared intentions are immutable console facts, never transport permits.
 * The fixed Approved bridge is mandatory even for an apparently valid plan.
 * Kong has no transaction across its plugins and these SQL settings: original
 * partial/unknown native receipts are retained and are never automatically sent again. */
@Injectable()
export class VitalsSetupService implements OnModuleInit {
 private bridge?:Readonly<MetricsSetupExecutionBridge>;
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,private readonly audit:AuditService,
  private readonly authz:AuthorizationService,private readonly execution:KongExecutionContextService,private readonly kong:KongService,
  private readonly entities:EntityService,private readonly workspaces:WorkspaceResolverService,private readonly sources:MetricsSourceService,
  private readonly settings:MetricsSettingsService,private readonly credentials:MetricsCredentialsService,private readonly plans:WorkflowPlansService,
  private readonly registry:WorkflowRegistryService){}
 onModuleInit():void{this.registry.register('metrics.setup.settings',{authorize:(plan,actor,action)=>this.assertSubject(plan,actor.user.id,action),
  prepare:async input=>{await this.assertSubject(input.plan,input.actor.user.id,'write');},
  inspect:async(input,tx)=>{const intent=await this.bound(input.plan,tx),current=await this.control(intent.clusterId,tx);return{before:current,revision:current.revision};},
  apply:input=>this.apply(input)});}
 installExecutionBridge(bridge:MetricsSetupExecutionBridge):void{
  if(this.bridge||!bridge||typeof bridge.verify!=='function'||Object.keys(bridge).some(k=>k!=='verify'))throw conflict('METRICS_SETUP_BRIDGE_ALREADY_INSTALLED');
  this.bridge=Object.freeze({verify:bridge.verify.bind(bridge)});
 }
 private originalBridge():Readonly<MetricsSetupExecutionBridge>{if(!this.bridge)throw new ServiceUnavailableException({code:'METRICS_SETUP_EXECUTION_BRIDGE_REQUIRED'});return this.bridge;}
 approvedDelegate():Readonly<MetricsSetupApprovedDelegate>{return Object.freeze({verifyIntent:(p:WorkflowPlanV1,tx?:DbService)=>this.verifyIntent(p,tx),
  assertSubject:(p:WorkflowPlanV1,id:string,a:'read'|'write'|'approve',tx?:DbService)=>this.assertSubject(p,id,a,tx),
  verifyReviewer:(id:string,p:WorkflowPlanV1,tx?:DbService)=>this.verifyReviewer(id,p,tx),nativeWorkspace:(p:WorkflowPlanV1,s:WorkflowStep,tx?:DbService)=>this.nativeWorkspace(p,s,tx)});}
 executionDelegate():Readonly<MetricsSetupExecutionDelegate>{return Object.freeze({runManagedNative:<T>(p:WorkflowPlanV1,id:string,fn:()=>Promise<T>)=>this.runManagedNative(p,id,fn),
  nativeWorkspace:(p:WorkflowPlanV1,s:WorkflowStep,tx?:DbService)=>this.nativeWorkspace(p,s,tx),reviewPreview:(p:WorkflowPlanV1,a:EntityActor)=>this.reviewPreview(p,a)});}
 private actor(actor:EntityActor,cid:string,wid:string):string{const frame=this.execution.current();
  if(!frame.actor||frame.actor.id!==actor.user.id||frame.clusterId!==cid||frame.workspaceId!==wid||!frame.sessionId||frame.operation||frame.archive
   ||this.execution.hasWorkflowScheduledNamespace())throw deny('METRICS_SETUP_HTTP_ACTOR_REQUIRED');return frame.sessionId;}
 private async session(actor:EntityActor,cid:string,wid:string,tx=this.db):Promise<any>{const sid=this.actor(actor,cid,wid);
  const row=await tx.one<any>(`SELECT s.id,s.expires_at,u.credential_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2
   AND s.revoked_at IS NULL AND s.expires_at>now() AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[sid,actor.user.id]);
  if(!row)throw deny('METRICS_SETUP_SESSION_REVOKED');return row;}
 private async identity(id:string,tx=this.db){const user=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change",[workflowId(id)]),epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!user||!epoch)throw deny('METRICS_SETUP_PRINCIPAL_REVOKED');const grants=(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[id])).filter(validGrant);
  return{user,grants,version:`${user.id}:${user.permissions_epoch}:${epoch.version}`};}
 private whole(identity:Awaited<ReturnType<VitalsSetupService['identity']>>,cid:string,module:string,action:'read'|'write'|'approve'):boolean{
  return identity.user.super_admin===true||identity.grants.some(g=>coarseGrantMatches(g,module,action,{clusterId:cid})&&g.scope_type==='global'&&g.workspace_id===null);
 }
 private async scope(cid:string,wid:string,id:string,action:'read'|'write'|'approve',tx=this.db){const identity=await this.identity(id,tx);
  // Managed global plugins affect the entire cluster. A workspace/tag/entity
  // grant cannot substitute for platform administration and complete grants.
  if(identity.user.super_admin!==true||!this.whole(identity,cid,'monitoring',action)||!this.whole(identity,cid,'plugins',action==='approve'?'write':action)
   ||!this.whole(identity,cid,'workflows',action))throw deny('METRICS_SETUP_PLATFORM_PERMISSION_REQUIRED');
  const cluster=await tx.one<any>(`SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL${action==='read'?'':' FOR SHARE'}`,[cid]);
  const workspace=await tx.one<any>(`SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 AND deleted_at IS NULL${action==='read'?'':' FOR SHARE'}`,[cid,wid]);
  if(!cluster||cluster.status==='disabled'||!isSupportedKong(cluster.version??'')||!workspace||!workspace.is_default||workspace.status!=='active')
   throw conflict('METRICS_SETUP_DEFAULT_WORKSPACE_REQUIRED','请在默认工作区设置集群全局监控；已有其他工作区的全局插件须先使用工作区迁移入口移至默认工作区');
  if(action!=='read'&&(cluster.execution_mode!=='approval'||!cluster.enabled_plugins?.includes('prometheus')))throw conflict('METRICS_SETUP_APPROVAL_SCOPE_REQUIRED');
  return{identity,cluster,workspace};
 }
 private async control(cid:string,tx=this.db):Promise<Readonly<MetricsSetupControl>>{const row=await tx.one<any>('SELECT * FROM metrics_settings WHERE cluster_id=$1',[cid]);
  return immutableJson({revision:Number(row?.revision??0),activeSourceId:row?.active_source_id??null,enabled:row?.enabled??false,collectorEnabled:row?.collector_enabled??false,
   credentialGeneration:Number(row?.credential_generation??0),maxAgeMs:Number(row?.max_age_ms??15000),capabilities:row?.safe_capabilities??{}});
 }
 private async globals(cid:string,names:readonly string[],wid:string):Promise<Map<string,any>>{
  return this.execution.runInternalRead(cid,'entity-preflight',async()=>{const found=new Map<string,any>();let cursor:string|undefined;
   for(let page=0;page<10;page++){const result=await this.kong.list(cid,'/plugins',{size:100},cursor,`metrics-approval:${names.join(':')}`);
    for(const p of result.items)if(names.includes(p.name)&&!p.service?.id&&!p.route?.id&&!p.consumer?.id){if(found.has(p.name))throw conflict('METRICS_GLOBAL_PLUGIN_CONFLICT');found.set(p.name,p);}
    if(!result.nextCursor)return found;cursor=result.nextCursor;
   }throw conflict('METRICS_SETUP_SCAN_INCOMPLETE');
  },{paths:['/plugins'],workspaceId:wid,maxCalls:12,maxPages:10,maxRecords:1000,maxBytes:8*1024*1024,timeoutMs:15000});
 }
 private async schema(cid:string,name:string,wid:string):Promise<string>{return this.execution.runInternalRead(cid,'entity-preflight',async()=>this.secrets.fingerprint({entity:await this.kong.schema(cid,'plugins'),plugin:await this.kong.pluginSchema(cid,name)}),
  {paths:['/schemas/plugins',`/plugins/schema/${name}`],workspaceId:wid,maxCalls:2,maxBytes:2*1024*1024,timeoutMs:10000});}
 private async current(intent:Readonly<MetricsSetupIntent>,id:string,action:'read'|'write'|'approve',tx=this.db):Promise<void>{const now=await this.scope(intent.clusterId,intent.workspaceId,id,action,tx);
  if(action!=='read'){
   if(Date.parse(intent.expiresAt)<=Date.now()||now.cluster.revision!==intent.clusterRevision||now.workspace.revision!==intent.workspaceRevision
    ||transportScopeFor(now.cluster.admin_url,now.cluster.transport_scope)!==intent.transportScope)throw conflict('METRICS_SETUP_SCOPE_CHANGED');
   const author=await this.identity(intent.actorId,tx);if(author.version!==intent.permissionVersion||String(author.user.credential_epoch)!==intent.credentialEpoch||author.user.super_admin!==true)throw deny('METRICS_SETUP_AUTHOR_CHANGED');
   const session=await tx.one<any>('SELECT id FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() AND credential_epoch=$3',[intent.authoringSessionId,intent.actorId,intent.credentialEpoch]);
   if(!session)throw deny('METRICS_SETUP_AUTHOR_SESSION_REVOKED');
   await this.sources.assertCurrent(intent.clusterId,intent.source);
   if(this.secrets.fingerprint(await this.control(intent.clusterId,tx))!==this.secrets.fingerprint(intent.settings))throw conflict('METRICS_SETUP_SETTINGS_CHANGED');
   if(intent.mode==='collector'){const ingest=await this.credentials.getActiveIngestCredential(intent.clusterId);
    if(!intent.ingest||ingest.generation!==intent.ingest.generation||ingest.fingerprint!==intent.ingest.fingerprint||ingest.generation!==intent.settings.credentialGeneration)throw conflict('METRICS_SETUP_GENERATION_CHANGED');
    const endpoint=intent.plugins.find(p=>p.name==='http-log')?.payload.config as any,verified=await this.credentials.verifyManagedIngestUrl(intent.clusterId,endpoint?.http_endpoint??'');
    if(!verified.valid||verified.generation!==intent.ingest.generation||verified.fingerprint!==intent.ingest.fingerprint)throw conflict('METRICS_SETUP_MANAGED_ENDPOINT_CHANGED');
   }
  }
  if((await this.identity(id,tx)).version!==now.identity.version)throw deny('METRICS_SETUP_PERMISSIONS_CHANGED');
  if(action!=='read'&&Date.parse(intent.expiresAt)<=Date.now())throw conflict('METRICS_SETUP_INTENT_EXPIRED');
 }
 private async load(cid:string,wid:string,id:string,tx=this.db):Promise<Readonly<MetricsSetupIntent>>{const row=await tx.one<any>('SELECT * FROM metrics_setup_intents WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[workflowId(id),cid,wid]);
  if(!row)throw new NotFoundException({code:'METRICS_SETUP_INTENT_NOT_FOUND'});let value:MetricsSetupIntent;
  try{value=this.secrets.decrypt(row.material_secret,metricsSetupAad(row.id));}catch{throw conflict('METRICS_SETUP_INTENT_INVALID');}
  if(!value||value.version!==1||value.id!==row.id||value.clusterId!==cid||value.workspaceId!==wid||value.workflowId!==row.workflow_id||value.actorId!==row.actor_id
   ||value.authoringSessionId!==row.authoring_session_id||value.idempotencyKey!==row.idempotency_key||value.requestHmac!==row.request_hmac||value.permissionVersion!==row.permission_version
   ||value.credentialEpoch!==String(row.credential_epoch)||this.secrets.fingerprint(value)!==row.material_hmac||value.mode!==row.mode||value.source.id!==row.source_id
   ||new Date(row.issued_at).toISOString()!==value.issuedAt||new Date(row.expires_at).toISOString()!==value.expiresAt||Buffer.byteLength(JSON.stringify(value))>2*1024*1024
   ||value.source.revision!==row.source_revision||value.settings.revision!==row.settings_revision||value.settings.credentialGeneration!==row.credential_generation
   ||value.plugins.length!==(value.mode==='collector'?2:1)||value.plugins.some((p,i)=>p.name!==(i?'http-log':'prometheus')||p.workspaceId!==wid||p.workspaceRevision!==value.workspaceRevision))throw conflict('METRICS_SETUP_INTENT_INVALID');
  const manifest=await tx.query<any>('SELECT * FROM metrics_setup_plugin_material WHERE intent_id=$1 ORDER BY step_order',[value.id]);
  if(manifest.length!==value.plugins.length||manifest.some((m,index)=>{const p=value.plugins[index];return m.cluster_id!==cid||m.workspace_id!==wid||m.material_hmac!==row.material_hmac
   ||m.name!==p.name||m.step_order!==index+1||m.action!==p.action||m.native_id!==p.nativeId||m.before_hmac!==this.secrets.fingerprint(p.before)
   ||m.payload_hmac!==this.secrets.fingerprint(p.payload)||m.schema_hmac!==p.schemaHmac||m.path_hmac!==this.secrets.fingerprint(p.action==='create'?'/plugins':`/plugins/${p.nativeId}`);}))throw conflict('METRICS_SETUP_MATERIAL_MANIFEST_INVALID');
  return immutableJson(value);
 }
 private async bound(plan:WorkflowPlanV1,tx=this.db):Promise<Readonly<MetricsSetupIntent>>{const final=assertMetricsSetupPlan(plan),intent=await this.load(plan.clusterId,plan.workspaceId,plan.subject.id,tx);
  const request=await tx.one<any>('SELECT * FROM metrics_setup_requests WHERE id=$1 AND workflow_id=$2 AND cluster_id=$3 AND workspace_id=$4',[intent.id,plan.workflowId,plan.clusterId,plan.workspaceId]);
  let index=0;const expected=metricsSetupSteps(intent,v=>this.secrets.fingerprint(v),()=>plan.steps[index++].id);
  if(!request||intent.workflowId!==plan.workflowId||intent.actorId!==plan.requester.id||request.actor_id!==intent.actorId||request.material_hmac!==this.secrets.fingerprint(intent)
   ||request.request_hmac!==intent.requestHmac||request.idempotency_key!==intent.workflowKey||plan.expiresAt!==intent.expiresAt||plan.issuedAt!==intent.issuedAt
   ||this.secrets.fingerprint(plan.definition)!==this.secrets.fingerprint(intent.definition)||this.secrets.fingerprint(plan.steps)!==this.secrets.fingerprint(expected)
   ||this.secrets.fingerprint(plan.scope)!==this.secrets.fingerprint({transportScope:intent.transportScope,clusterRevision:intent.clusterRevision,workspaceRevision:intent.workspaceRevision})
   ||(final.metadata as any).materialHmac!==request.material_hmac)throw conflict('METRICS_SETUP_BINDING_INVALID');return intent;
 }
 async verifyIntent(plan:WorkflowPlanV1,tx=this.db):Promise<void>{await this.bound(plan,tx);}
 async assertSubject(plan:WorkflowPlanV1,id:string,action:'read'|'write'|'approve',tx=this.db):Promise<void>{const intent=await this.bound(plan,tx),frame=this.execution.current();
  if(frame.actor?.id!==id||frame.clusterId!==plan.clusterId||frame.workspaceId!==plan.workspaceId||!frame.sessionId||this.execution.hasWorkflowScheduledNamespace())throw deny('METRICS_SETUP_HTTP_ACTOR_REQUIRED');
  if(action==='write'&&(id!==intent.actorId||frame.sessionId!==intent.authoringSessionId))throw deny('METRICS_SETUP_AUTHOR_MISMATCH');await this.current(intent,id,action,tx);
 }
 async verifyReviewer(id:string,plan:WorkflowPlanV1,tx=this.db):Promise<void>{const intent=await this.bound(plan,tx);await this.current(intent,id,id===intent.actorId?'write':'approve',tx);}
 async nativeWorkspace(plan:WorkflowPlanV1,step:WorkflowStep,tx=this.db):Promise<string>{const intent=await this.bound(plan,tx),plugin=intent.plugins[step.order-1];
  if(step.kind!=='native'||!plugin||plan.steps[step.order-1]?.id!==step.id||plugin.nativeId!==step.entityId||plugin.workspaceId!==plan.workspaceId)throw deny('METRICS_SETUP_NATIVE_SCOPE_INVALID');return plugin.workspaceId;}
 async runManagedNative<T>(plan:WorkflowPlanV1,executionId:string,fn:()=>Promise<T>):Promise<T>{const bridge=this.originalBridge();await bridge.verify(plan,workflowId(executionId),'native');
  const intent=await this.bound(plan),actor=this.execution.current().actor;if(!actor)throw deny('METRICS_SETUP_HTTP_ACTOR_REQUIRED');
  await this.assertSubject(plan,actor.id,'write');for(const p of intent.plugins)if(await this.schema(plan.clusterId,p.name,plan.workspaceId)!==p.schemaHmac)throw conflict('METRICS_SETUP_SCHEMA_CHANGED');
  await this.redis.assertLeaseOwnership();await bridge.verify(plan,executionId,'native');
  const result=await this.execution.runManagedMetricsProvision(plan.clusterId,fn);
  await this.current(intent,actor.id,'write');await this.redis.assertLeaseOwnership();return result;
 }
 @KongActorScope({module:'monitoring',action:'write',queryArg:1})
 async prepare(cid:string,query:Record<string,unknown>,raw:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
  exactKeys(query,['workspaceId']);exactKeys(raw,['sourceId','mode','confirmed','confirm_name']);metricsId(cid);const wid=metricsId(query.workspaceId)!,key=workflowKey(actor.idempotencyKey);
  if(!['native_prometheus','collector'].includes(raw.mode as string))throw new BadRequestException({code:'INVALID_METRICS_SETUP'});const sourceId=metricsId(raw.sourceId)!;
  const requestHmac=this.secrets.fingerprint({clusterId:cid,workspaceId:wid,sourceId,mode:raw.mode,confirmed:raw.confirmed,confirm_name:raw.confirm_name});
  return this.redis.withLock(`metrics-setup-prepare:${actor.user.id}:${key}`,()=>this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');const session=await this.session(actor,cid,wid,tx),scope=await this.scope(cid,wid,actor.user.id,'write',tx);
   if(raw.confirmed!==true||raw.confirm_name!==scope.cluster.name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'请二次确认集群名称；全局监控影响全部工作区'});
   const existing=await tx.one<any>('SELECT * FROM metrics_setup_intents WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
   if(existing){if(existing.cluster_id!==cid||existing.workspace_id!==wid||existing.request_hmac!==requestHmac)throw conflict('IDEMPOTENCY_CONFLICT');return this.publicReceipt(await this.load(cid,wid,existing.id,tx),actor,tx);}
   const legacyKey=`metrics:${createHash('sha256').update(`${key}:parent`).digest('hex')}`;
   if(await tx.one('SELECT id FROM iam_operations WHERE actor_id=$1 AND cluster_id=$2 AND idempotency_key=$3',[actor.user.id,cid,legacyKey]))throw conflict('METRICS_SETUP_LEGACY_RECEIPT_REQUIRED','原设置键已有执行记录，请读取原回执，不会重新创建监控变更');
   const source=await this.sources.read(cid,sourceId);if(source.type!=='prometheus')throw new BadRequestException({code:'METRICS_SETUP_REQUIRES_PROMETHEUS'});
   const control=await this.control(cid,tx),collector=raw.mode==='collector';if(collector&&!scope.cluster.enabled_plugins?.includes('http-log'))throw conflict('KONG_METRICS_COLLECTOR_UNAVAILABLE');
   const ingest=collector?await this.credentials.getActiveIngestCredential(cid):null;
   if(ingest&&(ingest.generation!==control.credentialGeneration||ingest.generation<1))throw conflict('METRICS_SETUP_GENERATION_CHANGED');
   const names=collector?['prometheus','http-log']:['prometheus'],globals=await this.globals(cid,names,wid),plugins:MetricsSetupPlugin[]=[];
   for(const name of names){const before=globals.get(name)??null,membership=before?await this.workspaces.classify(cid,before.tags):null;
    if(before&&(membership?.state!=='resolved'||membership.workspace?.id!==wid))throw conflict('METRICS_SETUP_PLUGIN_WORKSPACE_REQUIRED','已有全局监控插件不属于默认工作区，请先通过工作区迁移入口迁移；设置不会自动改标签');
    const config=name==='prometheus'?{}:{http_endpoint:`http://kongos:${ingest!.token}@telemetry-collector:9093/ingest/${cid}`,method:'POST',retry_count:0,queue_size:1,flush_timeout:1};
    const body=before?{enabled:true,config}:{id:randomUUID(),name,enabled:true,config},prepared=await this.entities.prepareCore(cid,'plugins',before?'update':'create',before?.id,body,{...actor,workspaceId:wid});
    if(this.secrets.fingerprint(prepared.before)!==this.secrets.fingerprint(before)||prepared.references.length)throw conflict('METRICS_SETUP_PLUGIN_CHANGED');
    plugins.push({name:name as MetricsSetupPlugin['name'],workspaceId:wid,workspaceRevision:scope.workspace.revision,nativeId:prepared.payload.id??before.id,action:before?'update':'create',before:prepared.before,
     payload:prepared.payload,schemaHmac:await this.schema(cid,name,wid)});
   }
   const finalGlobals=await this.globals(cid,names,wid);for(const p of plugins)if(this.secrets.fingerprint(finalGlobals.get(p.name)??null)!==this.secrets.fingerprint(p.before))throw conflict('METRICS_SETUP_PLUGIN_CHANGED');
   await this.plans.definitions(cid,wid,actor.user.id,tx);const definition=await this.plans.definition(cid,wid,'metrics-setup' as any,tx),version=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[cid,wid,definition.id,definition.version]);
   if(version?.approval_format!==2||this.secrets.fingerprint(version.policy)!==definition.policyHash)throw conflict('METRICS_SETUP_V2_POLICY_REQUIRED');const policy=normalizeWorkflowApprovalPolicy(version.policy,'metrics-setup' as any);
   const now=Date.now(),id=randomUUID(),intent:Readonly<MetricsSetupIntent>=immutableJson({version:1,id,workflowId:randomUUID(),actorId:actor.user.id,authoringSessionId:session.id,credentialEpoch:String(session.credential_epoch),permissionVersion:scope.identity.version,
    idempotencyKey:key,workflowKey:`metrics-${id}`,requestHmac,clusterId:cid,workspaceId:wid,clusterName:scope.cluster.name,clusterRevision:scope.cluster.revision,workspaceRevision:scope.workspace.revision,
    transportScope:transportScopeFor(scope.cluster.admin_url,scope.cluster.transport_scope),definition,mode:raw.mode as MetricsSetupIntent['mode'],source,settings:control,ingest:ingest?{generation:ingest.generation,fingerprint:ingest.fingerprint}:null,plugins,
    issuedAt:new Date(now).toISOString(),expiresAt:new Date(Math.min(now+86400000,now+policy.intentTtlHours*3600000,new Date(session.expires_at).getTime())).toISOString()});
   await this.current(intent,actor.user.id,'write',tx);await tx.exec(`INSERT INTO metrics_setup_intents(id,cluster_id,workspace_id,actor_id,authoring_session_id,workflow_id,idempotency_key,request_hmac,
    material_hmac,material_secret,credential_epoch,permission_version,mode,source_id,source_revision,settings_revision,credential_generation,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
    [id,cid,wid,actor.user.id,session.id,intent.workflowId,key,requestHmac,this.secrets.fingerprint(intent),this.secrets.encrypt(intent,metricsSetupAad(id)),intent.credentialEpoch,intent.permissionVersion,intent.mode,sourceId,source.revision,control.revision,control.credentialGeneration,intent.issuedAt,intent.expiresAt]);
   for(const [order,p] of intent.plugins.entries())await tx.exec(`INSERT INTO metrics_setup_plugin_material(intent_id,cluster_id,workspace_id,name,step_order,action,native_id,material_hmac,before_hmac,payload_hmac,schema_hmac,path_hmac)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[id,cid,wid,p.name,order+1,p.action,p.nativeId,this.secrets.fingerprint(intent),this.secrets.fingerprint(p.before),this.secrets.fingerprint(p.payload),p.schemaHmac,this.secrets.fingerprint(p.action==='create'?'/plugins':`/plugins/${p.nativeId}`)]);
   await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,entityType:'metrics_setup_intents',entityId:id,action:'metrics.setup.prepare',requestId:actor.requestId,ip:actor.ip,result:'success',after:{mode:intent.mode,sourceId,materialHmac:this.secrets.fingerprint(intent),nativeRequestsSent:0}},tx);
   await this.redis.assertLeaseOwnership();return this.publicReceipt(intent,actor,tx);
  }));
 }
 @KongActorScope({module:'monitoring',action:'write',queryArg:2,actorArg:4})
 async submit(cid:string,id:string,query:Record<string,unknown>,raw:unknown,actor:EntityActor):Promise<Record<string,unknown>>{exactKeys(query,['workspaceId']);exactKeys(raw,['revision','materialHmac','confirmed','confirm_name']);
  const wid=metricsId(query.workspaceId)!,key=workflowKey(actor.idempotencyKey);return this.redis.withLock(`metrics-setup-submit:${id}`,()=>this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');const session=await this.session(actor,cid,wid,tx),intent=await this.load(cid,wid,id,tx);
   if(intent.actorId!==actor.user.id||intent.authoringSessionId!==session.id)throw deny('METRICS_SETUP_AUTHOR_MISMATCH');
   if(raw.revision!==1||raw.materialHmac!==this.secrets.fingerprint(intent)||raw.confirmed!==true||raw.confirm_name!==intent.clusterName)throw conflict('METRICS_SETUP_CONFIRMATION_CHANGED');
   const existing=await tx.one<any>('SELECT submit_key FROM metrics_setup_requests WHERE id=$1',[id]);
   if(existing){if(existing.submit_key!==key)throw conflict('METRICS_SETUP_ALREADY_SUBMITTED');return this.executionReceipt(intent,actor,tx);}
   await this.current(intent,actor.user.id,'write',tx);const globals=await this.globals(cid,intent.plugins.map(p=>p.name),wid);
   for(const p of intent.plugins)if(this.secrets.fingerprint(globals.get(p.name)??null)!==this.secrets.fingerprint(p.before)||await this.schema(cid,p.name,wid)!==p.schemaHmac)throw conflict('METRICS_SETUP_PLUGIN_CHANGED');
   const definition=await this.plans.definition(cid,wid,'metrics-setup' as any,tx);if(this.secrets.fingerprint(definition)!==this.secrets.fingerprint(intent.definition))throw conflict('METRICS_SETUP_POLICY_CHANGED');
   await tx.exec('INSERT INTO metrics_setup_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,submit_key,request_hmac,material_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
    [id,cid,wid,actor.user.id,intent.workflowId,intent.workflowKey,key,intent.requestHmac,this.secrets.fingerprint(intent)]);
   const plan:WorkflowPlanV1={version:1,kind:'metrics-setup' as any,clusterId:cid,workspaceId:wid,workflowId:intent.workflowId,planRevision:1,executionMode:'approval',approvalRequired:true,
    subject:{type:'metrics_setup_requests' as any,id},requester:{type:'console',id:actor.user.id},definition:intent.definition,issuedAt:intent.issuedAt,expiresAt:intent.expiresAt,
    scope:{transportScope:intent.transportScope,clusterRevision:intent.clusterRevision,workspaceRevision:intent.workspaceRevision},prerequisites:[],steps:metricsSetupSteps(intent,v=>this.secrets.fingerprint(v),randomUUID)};
   assertMetricsSetupPlan(plan);await this.plans.persist(plan,intent.workflowKey,{clusterId:cid,workspaceId:wid,sourceId:intent.source.id,mode:intent.mode,confirmed:true,confirm_name:intent.clusterName},tx,{requestId:actor.requestId,ip:actor.ip});
   await this.current(intent,actor.user.id,'write',tx);await this.redis.assertLeaseOwnership();return this.executionReceipt(intent,actor,tx);
  }));}
 private projectPlugin(configuration:unknown):unknown{return metricsSetupPublicProjection(configuration,this.secrets);}
 private preview(intent:Readonly<MetricsSetupIntent>):Record<string,unknown>{return{confirmationName:intent.clusterName,source:{id:intent.source.id,name:intent.source.name,type:'prometheus',revision:intent.source.revision},
  before:this.secrets.redact({plugins:intent.plugins.map(p=>({name:p.name,id:p.nativeId,action:p.action,configuration:this.projectPlugin(p.before)})),settings:intent.settings}),
  after:this.secrets.redact({plugins:intent.plugins.map(p=>({name:p.name,id:p.nativeId,action:p.action,configuration:this.projectPlugin(p.payload)})),settings:{...intent.settings,revision:intent.settings.revision===0?2:intent.settings.revision+1,activeSourceId:intent.source.id,enabled:true,collectorEnabled:intent.mode==='collector'||intent.settings.collectorEnabled}}),
  nativeRequestsPlanned:intent.plugins.length,scope:{workspaceId:intent.workspaceId,defaultWorkspaceOnly:true,affectsAllWorkspaces:true},credentialsExposed:false,
  notices:['全局监控影响集群全部工作区；本入口仅接受默认工作区的全局插件，其他归属须先迁移','native_prometheus 模式保留现有采集器设置；collector 引用已有采集凭证，不执行凭证登记或轮换','插件写入与控制台设置不具备跨系统事务；部分执行或未知结果只核验原回执，不自动重发']};}
 async reviewPreview(plan:WorkflowPlanV1,actor:EntityActor):Promise<Record<string,unknown>>{await this.assertSubject(plan,actor.user.id,'read');const intent=await this.bound(plan),preview=this.preview(intent);
  const diff=plan.steps.map(step=>({id:step.id,kind:step.kind,operation:step.mutationAction??step.handler,entityType:step.entityType,entityId:step.entityId,
   before:metricsSetupPublicProjection(step.before,this.secrets),after:metricsSetupPublicProjection(step.kind==='native'?step.mutationPayload:step.metadata,this.secrets)}));
  await this.assertSubject(plan,actor.user.id,'read');return{diff,preview,impact:{subject:plan.subject,nativeRequests:intent.plugins.length,affectsAllWorkspaces:true,defaultWorkspaceOnly:true,
   partialFailure:'原执行键只读取回执，不自动重放未知或部分完成的插件请求',rollback:'插件快照仍须当前授权下重新预览及审批；采集凭证不回滚或复用旧token'}};}
 private async executionReceipt(intent:Readonly<MetricsSetupIntent>,actor:EntityActor,tx=this.db):Promise<Record<string,unknown>>{await this.current(intent,actor.user.id,'read',tx);const identity=await this.identity(actor.user.id,tx);
  const request=await tx.one<any>('SELECT workflow_id FROM metrics_setup_requests WHERE id=$1',[intent.id]),workflow=request?await tx.one<any>('SELECT id,state,revision,plan_hash FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[request.workflow_id,intent.clusterId,intent.workspaceId]):null;
  if(request&&!workflow)throw conflict('METRICS_SETUP_WORKFLOW_RECEIPT_MISSING');const steps=workflow?await tx.query<any>(`SELECT s.id,s.step_key,s.state,s.operation_id,m.remote_started,m.remote_completed,s.error_code
    FROM workflow_steps s LEFT JOIN mutation_operations m ON m.id=s.operation_id WHERE s.workflow_id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3 AND s.plan_revision=1 ORDER BY s.step_order`,[workflow.id,intent.clusterId,intent.workspaceId]):[];
  await this.current(intent,actor.user.id,'read',tx);if((await this.identity(actor.user.id,tx)).version!==identity.version)throw deny('METRICS_SETUP_PERMISSIONS_CHANGED');
  await this.session(actor,intent.clusterId,intent.workspaceId,tx);
  return{intentId:intent.id,clusterId:intent.clusterId,workspaceId:intent.workspaceId,materialHmac:this.secrets.fingerprint(intent),workflowId:workflow?.id??null,state:workflow?.state==='pending'?'submitted':workflow?.state??'prepared',
   revision:workflow?.revision??1,planHash:workflow?.plan_hash??null,steps:steps.map(s=>({id:s.id,name:s.step_key,state:s.state,operationId:s.operation_id??null,remoteStarted:s.remote_started??false,remoteCompleted:s.remote_completed??false,errorCode:s.error_code??null}))};
 }
 private async publicReceipt(intent:Readonly<MetricsSetupIntent>,actor:EntityActor,tx=this.db):Promise<Record<string,unknown>>{if(actor.user.id!==intent.actorId||actor.workspaceId!==intent.workspaceId)throw deny('METRICS_SETUP_INTENT_OWNER_REQUIRED');
  const receipt=await this.executionReceipt(intent,actor,tx);return{...receipt,sourceId:intent.source.id,mode:intent.mode,revision:1,expiresAt:intent.expiresAt,
   preview:['succeeded','partial','failed','uncertain'].includes(String(receipt.state))?null:this.preview(intent)};
 }
 @KongActorScope({module:'monitoring',queryArg:2,actorArg:3})
 async get(cid:string,id:string,query:Record<string,unknown>,actor:EntityActor):Promise<Record<string,unknown>>{exactKeys(query,['workspaceId']);const wid=metricsId(query.workspaceId)!;await this.session(actor,cid,wid);return this.publicReceipt(await this.load(cid,wid,id),actor);}
 @KongActorScope({module:'monitoring',queryArg:2,actorArg:3})
 async byKey(cid:string,key:string,query:Record<string,unknown>,actor:EntityActor):Promise<Record<string,unknown>>{exactKeys(query,['workspaceId']);const wid=metricsId(query.workspaceId)!;workflowKey(key);await this.session(actor,cid,wid);await this.scope(cid,wid,actor.user.id,'read');
  const row=await this.db.one<any>('SELECT id FROM metrics_setup_intents WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND idempotency_key=$4',[actor.user.id,cid,wid,key]);
  return row?this.publicReceipt(await this.load(cid,wid,row.id),actor):{state:'not_prepared',intentId:null};}
 @KongActorScope({module:'monitoring',queryArg:2,actorArg:3})
 async receipt(cid:string,id:string,query:Record<string,unknown>,actor:EntityActor):Promise<Record<string,unknown>>{exactKeys(query,['workspaceId']);const wid=metricsId(query.workspaceId)!;await this.session(actor,cid,wid);const intent=await this.load(cid,wid,id);
  if(actor.user.id!==intent.actorId)throw deny('METRICS_SETUP_INTENT_OWNER_REQUIRED');return this.executionReceipt(intent,actor);}
 private async apply(input:WorkflowHandlerInput):Promise<Record<string,unknown>>{const {plan,actor,executionId,transaction:tx}=input,bridge=this.originalBridge();await bridge.verify(plan,executionId,'metadata',tx);
  const intent=await this.bound(plan,tx),final=assertMetricsSetupPlan(plan);if(input.step.id!==final.id)throw deny('METRICS_SETUP_METADATA_STEP_INVALID');
  await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
  const authorSession=await tx.one<any>('SELECT id FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() AND credential_epoch=$3 FOR SHARE',[intent.authoringSessionId,actor.user.id,intent.credentialEpoch]);
  if(!authorSession)throw deny('METRICS_SETUP_AUTHOR_SESSION_REVOKED');
  await tx.one('SELECT cluster_id FROM metrics_settings WHERE cluster_id=$1 FOR UPDATE',[plan.clusterId]);
  const lockedSource=await tx.one<any>('SELECT id,revision FROM data_sources WHERE cluster_id=$1 AND id=$2 AND enabled=true AND deleted_at IS NULL FOR SHARE',[plan.clusterId,intent.source.id]);
  if(!lockedSource||lockedSource.revision!==intent.source.revision)throw conflict('METRICS_SETUP_SOURCE_CHANGED');
  await this.assertSubject(plan,actor.user.id,'write',tx);await this.execution.assertApprovedMetadataStep({handler:'metrics.setup.settings',actor:actor.user,clusterId:plan.clusterId,workspaceId:plan.workspaceId,
   entityType:'metrics_setup_requests',entityId:intent.id,before:intent.settings,revision:intent.settings.revision,payload:final.metadata},tx);
  const running=await tx.one<any>(`SELECT e.id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id JOIN workflow_steps s ON s.workflow_id=w.id
   WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND e.execution_actor_id=$5 AND e.state='executing' AND w.state='executing'
    AND e.plan_hash=$6 AND w.plan_hash=e.plan_hash AND e.plan_revision=1 AND w.plan_revision=1 AND e.approval_format=2 AND e.approval_set_id=w.approval_set_id AND e.approval_set_hmac=w.approval_set_hmac
    AND s.id=$7 AND s.kind='metadata' AND s.handler='metrics.setup.settings' AND s.state='running' AND s.plan_hash=e.plan_hash AND s.plan_revision=1`,[executionId,plan.workflowId,plan.clusterId,plan.workspaceId,actor.user.id,this.secrets.fingerprint(plan),final.id]);
  if(!running)throw deny('METRICS_SETUP_APPROVED_EXECUTION_REQUIRED');const ids:string[]=[];
  for(const step of plan.steps.slice(0,-1)){
   const row=await tx.one<any>(`SELECT m.*,s.state AS step_state,s.after_fingerprint,s.receipt_secret AS step_receipt_secret FROM workflow_steps s JOIN mutation_operations m ON m.id=s.operation_id
     WHERE s.id=$1 AND s.workflow_id=$2 AND s.plan_revision=1 AND s.plan_hash=$3`,[step.id,plan.workflowId,this.secrets.fingerprint(plan)]);
   if(!row||row.step_state!=='succeeded'||row.state!=='succeeded'||row.remote_started!==true||row.remote_completed!==true||row.actor_id!==actor.user.id||row.cluster_id!==plan.clusterId
    ||row.workspace_id!==plan.workspaceId||row.workflow_id!==plan.workflowId||row.workflow_execution_id!==executionId||row.workflow_step_id!==step.id||row.workflow_plan_revision!==1
    ||row.workflow_plan_hash!==this.secrets.fingerprint(plan)||row.entity_type!=='plugins'||row.entity_id!==step.entityId||row.action!==step.mutationAction||row.idempotency_key!==step.mutationIdempotencyKey
    ||!row.before_secret||!row.payload_secret||!row.result_secret||!row.step_receipt_secret||this.secrets.fingerprint(this.secrets.decrypt(row.before_secret,`mutation:${row.id}:before`))!==step.beforeFingerprint
    ||this.secrets.fingerprint(this.secrets.decrypt(row.payload_secret,`mutation:${row.id}:payload`))!==step.mutationPayloadHmac)throw conflict('METRICS_SETUP_NATIVE_RECEIPT_INCOMPLETE');
   const result=this.secrets.decrypt<any>(row.result_secret,`mutation:${row.id}:result`),path=`/plugins/${step.entityId}`,plugin=intent.plugins[step.order-1],receipt=this.secrets.decrypt<any>(row.step_receipt_secret,`workflow:${executionId}:${step.id}:receipt`)?.receipt;
   if(!receipt||receipt.operationId!==row.id||receipt.state!=='succeeded'||receipt.remoteStarted!==true||receipt.remoteCompleted!==true||receipt.entityId!==step.entityId
    ||row.after_fingerprint!==this.secrets.fingerprint(result))throw conflict('METRICS_SETUP_NATIVE_RECEIPT_INVALID');
   if(result?.id!==step.entityId||result.name!==plugin.name||result.enabled!==true||['service','route','consumer'].some(k=>result[k]?.id)
    ||Object.keys((plugin.payload.config as any)??{}).some(k=>this.secrets.fingerprint(result.config?.[k])!==this.secrets.fingerprint((plugin.payload.config as any)[k])))throw conflict('METRICS_SETUP_NATIVE_RESULT_INVALID');
   const observed=await this.execution.runInternalRead(plan.clusterId,'operation-check',()=>this.kong.request(plan.clusterId,'GET',path),{paths:[path],workspaceId:plan.workspaceId,maxCalls:1,maxRecords:1,timeoutMs:5000});
   if(this.secrets.fingerprint(observed)!==this.secrets.fingerprint(result))throw conflict('METRICS_SETUP_NATIVE_RESULT_DRIFTED');ids.push(row.id);
  }
  await this.current(intent,actor.user.id,'write',tx);await this.redis.assertLeaseOwnership();await bridge.verify(plan,executionId,'metadata',tx);
  const permission=await this.authz.permissionVersion(actor.user,tx),configured=await this.settings.configure(plan.clusterId,{revision:intent.settings.revision,activeSourceId:intent.source.id,enabled:true,
   collectorEnabled:intent.mode==='collector'||intent.settings.collectorEnabled},{actorId:actor.user.id,requestId:actor.requestId,ip:actor.ip},tx);
  const after=await this.control(plan.clusterId,tx),expected={...intent.settings,revision:intent.settings.revision===0?2:intent.settings.revision+1,activeSourceId:intent.source.id,enabled:true,collectorEnabled:intent.mode==='collector'||intent.settings.collectorEnabled};
  if(this.secrets.fingerprint(after)!==this.secrets.fingerprint(expected)||configured.revision!==after.revision)throw conflict('METRICS_SETUP_SETTINGS_RESULT_INVALID');
  const result=immutableJson({intentId:intent.id,mode:intent.mode,sourceId:intent.source.id,pluginId:intent.plugins[0].nativeId,...(intent.plugins[1]?{collectorPluginId:intent.plugins[1].nativeId}:{}),
   settingsRevision:after.revision,propagation:{state:'pending',message:'全局插件配置生效中；等待数据库传播、抓取和 epoch 基线样本建立'}});
  await tx.exec(`INSERT INTO metrics_setup_completion_facts(intent_id,cluster_id,workspace_id,workflow_id,execution_id,step_id,actor_id,session_id,plan_hash,material_hmac,
   native_operation_ids,before_settings_revision,after_settings_revision,credential_generation,result_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::uuid[],$12,$13,$14,$15)`,
   [intent.id,plan.clusterId,plan.workspaceId,plan.workflowId,executionId,final.id,actor.user.id,intent.authoringSessionId,this.secrets.fingerprint(plan),this.secrets.fingerprint(intent),ids,intent.settings.revision,after.revision,after.credentialGeneration,this.secrets.fingerprint(result)]);
  await this.sources.assertCurrent(plan.clusterId,intent.source);const scope=await this.scope(plan.clusterId,plan.workspaceId,actor.user.id,'write',tx);
  if(scope.cluster.revision!==intent.clusterRevision||scope.workspace.revision!==intent.workspaceRevision||transportScopeFor(scope.cluster.admin_url,scope.cluster.transport_scope)!==intent.transportScope)throw conflict('METRICS_SETUP_SCOPE_CHANGED');
  if(await this.authz.permissionVersion(actor.user,tx)!==permission)throw deny('METRICS_SETUP_PERMISSIONS_CHANGED');
  if(Date.parse(intent.expiresAt)<=Date.now())throw conflict('METRICS_SETUP_INTENT_EXPIRED');
  await this.redis.assertLeaseOwnership();return result;
 }
}
