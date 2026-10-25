import {BadRequestException,ConflictException,ForbiddenException,Injectable,NotFoundException,HttpException} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {encodeTag} from '../../infrastructure/kong/tags';
import {AuthorizationService} from '../authorization/authorization.service';
import {WorkspaceResolverService} from '../workspaces/workspace-resolver.service';
import {ConfigurationService} from '../configuration/configuration.service';
import {parseDeckDocument} from '../config-transfer';
import {validateBatchSelection} from '../toolbox/batch-plan';
import {AuditService} from '../audit/audit.service';
import {metadataAuditScope} from '../event-producers/native-audit-scope';
import type {EntityActor} from '../entities/entities.types';
import {GovernanceAuthorityService} from './governance-authority.service';
import {GovernanceInventoryService} from './governance-inventory.service';
import type {GovernanceInventory,GovernanceInventoryObject,GovernanceReadHandle,GovernanceScheduleLocator} from './governance-inventory.types';
import {GovernanceRepositoryService} from './governance-repository.service';
import {GovernanceMetadataService} from './governance-metadata.service';
import {governanceId,governanceKey,governanceObject,governancePage,governanceConfirm,inspectionInput,comparisonInput,promotionInput,governanceFailureCode} from './governance-input';
import {BUILTIN_LINT_RULES,GOVERNANCE_ENGINE_VERSION,inspectGovernanceInventory} from './inspection-engine';
import {lintContextFromInventory,type GovernanceLintRule,type LintFinding,GovernanceLintError} from './lint-types';
import {compileGovernanceFix} from './governance-fix-compiler';
import {compareLogicalEnvironments} from './drift-engine';
import type {GovernanceReceipt,GovernanceMetadataResource} from './governance-storage.types';
import {assertGovernanceOriginalDomain,governanceOriginalLock} from './governance-original-key';

const fail=(code:string)=>new ConflictException({code,message:'治理材料、权限或配置已变化，请核验原回执'});
const fixCatalog=[
 {code:'owner_tag_add',fields:[{name:'ownerTag',type:'string',required:true}]},
 {code:'route_https_only',fields:[{name:'protocols',type:'array',enum:['https','grpcs','tls'],required:true}]},
 {code:'service_timeouts_set',fields:['connectTimeout','writeTimeout','readTimeout'].map(name=>({name,type:'integer',min:1,required:true}))},
 {code:'entity_rename',fields:[{name:'name',type:'string',required:true}]},
 {code:'reference_replace_or_clear',fields:[{name:'operation',type:'enum',enum:['replace','clear'],required:true},{name:'replacementId',type:'uuid'},{name:'replacementIds',type:'array'}]},
 {code:'unused_certificate_archive',fields:[]},
 {code:'baseline_plugin_configure',fields:[{name:'pluginName',type:'string',required:true},{name:'config',type:'record',required:true},{name:'ownerTag',type:'string'}]},
 {code:'annotation_description_set',fields:[{name:'description',type:'string',required:true}]},
];
/** Reads compile immutable diagnostics. Configuration changes only reach the existing M8/metadata writers. */
@Injectable()
export class GovernanceService {
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,private readonly context:KongExecutionContextService,
  private readonly authz:AuthorizationService,private readonly workspaces:WorkspaceResolverService,private readonly authority:GovernanceAuthorityService,
  private readonly inventory:GovernanceInventoryService,private readonly repo:GovernanceRepositoryService,private readonly metadata:GovernanceMetadataService,
  private readonly configuration:ConfigurationService,private readonly audit:AuditService,private readonly kong?:KongService){}
 private async scope(cid:string,actor:EntityActor,module='governance',action='read'){
  cid=governanceId(cid);const ws=await this.workspaces.resolve(cid,actor.workspaceId);await this.authz.assertCluster(actor.user,cid,module,action,ws.id);
  return{cid,wid:ws.id,actor:{...actor,workspaceId:ws.id},version:await this.authz.permissionVersion(actor.user)};
 }
 private async discoveryScope(cid:string,actor:EntityActor){cid=governanceId(cid);const ws=await this.workspaces.resolve(cid,actor.workspaceId);let allowed=false;
  for(const module of ['governance','lint','drift','promote'])try{await this.authz.assertCluster(actor.user,cid,module,'read',ws.id);allowed=true;break;}catch(error){if(!(error instanceof ForbiddenException))throw error;}
  if(!allowed)throw new ForbiddenException({code:'GOVERNANCE_MODULE_READ_REQUIRED'});return{cid,wid:ws.id,actor:{...actor,workspaceId:ws.id},version:await this.authz.permissionVersion(actor.user)};
 }
 private async fence(actor:EntityActor,version:string):Promise<void>{if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'GOVERNANCE_PERMISSIONS_CHANGED'});}
 private async auditRun(tx:DbService,row:any,actor:EntityActor,action:string,after:unknown,result='success'):Promise<void>{await this.audit.append({actorId:actor.user.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,entityType:'governance_runs',entityId:row.id,requestId:actor.requestId,ip:actor.ip,action,after,result,scopeHints:metadataAuditScope(row.kind==='comparison'?'drift':'governance','governance_runs',row.id,row.workspace_id)},tx);}
 private physical(o:GovernanceInventoryObject):Record<string,unknown>{return{...o.payload,id:o.nativeId,tags:Array.isArray(o.payload.tags)?o.payload.tags.map(tag=>encodeTag(String(tag))):[]};}
 private async assertInventoryRead(inv:GovernanceInventory,actor:EntityActor,module:string):Promise<void>{
  const frame=this.context.peek?.();
  if(frame?.clusterId&&frame.clusterId!==inv.scope.clusterId){
   if(!['governance','drift','promote'].includes(module))throw new ForbiddenException({code:'GOVERNANCE_HISTORY_MODULE_INVALID'});
   // The peer is a registered, persisted comparison scope, and this handle
   // revalidates the real HTTP identity/SID/grants. Do not broaden the generic
   // internal-read CID guard or manufacture an actor frame for a peer.
   const handle=await this.authority.acquireActor(inv.scope.clusterId,{scope:inv.scope.kind,workspaceId:inv.scope.workspaceId,serviceIds:inv.scope.rootIds,module:module as 'governance'|'drift'|'promote'},{...actor,workspaceId:inv.scope.workspaceId});
   return this.authority.runRead(handle,()=>this.assertInventoryReadLocal(inv,{...actor,workspaceId:inv.scope.workspaceId},module));
  }
  return this.assertInventoryReadLocal(inv,actor,module);
 }
 private async assertInventoryReadLocal(inv:GovernanceInventory,actor:EntityActor,module:string):Promise<void>{
  if(inv.scope.kind==='cluster')await this.authz.assertWholeCluster(actor.user,inv.scope.clusterId,module,'read');else await this.authz.assertCluster(actor.user,inv.scope.clusterId,module,'read',inv.scope.workspaceId);
  const parentReceipts=new Map<string,'exists'|'missing'>(),parentDeadline=Date.now()+10000;let parentReads=0;
  for(const o of inv.objects){if(!o.objectWorkspaceId){if(!await this.authz.hasWholeCluster(actor.user,inv.scope.clusterId,module,'read')||!await this.authz.hasWholeCluster(actor.user,inv.scope.clusterId,o.entityType==='targets'?'upstreams':o.entityType,'read'))throw new ForbiddenException({code:'GOVERNANCE_HISTORY_SCOPE_DENIED'});continue;}
   if(o.entityType==='targets'){
    const parent=inv.objects.find(p=>p.entityType==='upstreams'&&p.nativeId===o.parentId);if(!parent||parent.objectWorkspaceId!==o.objectWorkspaceId||(o.payload.upstream as any)?.id!==parent.nativeId)throw fail('GOVERNANCE_HISTORY_TARGET_PARENT_CHANGED');
    await this.authz.assertScopedResource(actor.user,inv.scope.clusterId,module,'read','upstreams',this.physical(parent),parent.objectWorkspaceId);
    await this.authz.assertEntity(actor.user,inv.scope.clusterId,'targets','read',this.physical(o),parent.objectWorkspaceId);continue;
   }
   await this.authz.assertScopedResource(actor.user,inv.scope.clusterId,module,'read',o.entityType,this.physical(o),o.objectWorkspaceId);
   let native=this.physical(o);
   if(o.entityType==='plugins'&&(await this.authz.hasWholeWorkspace(actor.user,inv.scope.clusterId,o.objectWorkspaceId,'plugins','read'))&&(inv.scope.kind==='cluster'?await this.authz.hasWholeCluster(actor.user,inv.scope.clusterId,module,'read'):await this.authz.hasWholeWorkspace(actor.user,inv.scope.clusterId,o.objectWorkspaceId,module,'read'))){
    // History of a real orphan must remain readable, but only confirmed
    // missing parents are removed from the permission candidate. Existing
    // foreign bindings remain and use the ordinary inherited-policy denial.
    native={...native};for(const [field,parentType]of [['service','services'],['route','routes'],['consumer','consumers']]){const id=(native[field] as any)?.id;if(!id)continue;if(typeof id!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id)){delete native[field];continue;}if(!this.kong)throw fail('GOVERNANCE_HISTORY_PARENT_VERIFIER_UNAVAILABLE');const path=`/${parentType}/${id}`;
     if(!parentReceipts.has(path)){if(++parentReads>100||Date.now()>=parentDeadline)throw fail('GOVERNANCE_HISTORY_VERIFICATION_BUDGET');
      try{await this.context.runInternalRead(inv.scope.clusterId,'authorization',()=>this.kong!.request(inv.scope.clusterId,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:Math.min(5000,parentDeadline-Date.now())});parentReceipts.set(path,'exists');}catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;parentReceipts.set(path,'missing');}}
     if(parentReceipts.get(path)==='missing')delete native[field];}
   }
   await this.authz.assertEntity(actor.user,inv.scope.clusterId,o.entityType,'read',native,o.objectWorkspaceId);
  }
 }
 private async effectiveRules(cid:string,wid:string,codes?:string[]):Promise<{rules:GovernanceLintRule[];hash:string}>{
  const stored=await this.repo.ruleContents(cid,wid),all=new Map(BUILTIN_LINT_RULES.map(r=>[r.code,r]));for(const row of stored)all.set(row.code,{code:row.code,given:row.content.given,then:row.content.then,severity:row.content.severity,description:row.content.description,enabled:row.enabled&&row.content.enabled!==false});
  if(codes?.some(code=>!all.has(code)))throw new BadRequestException({code:'UNKNOWN_GOVERNANCE_RULE'});const rules=[...all.values()].filter(rule=>!codes||codes.includes(rule.code));if(rules.length>200)throw fail('GOVERNANCE_RULE_LIMIT');return{rules,hash:this.secrets.fingerprint(rules)};
 }
 private async analyze(inv:GovernanceInventory,rules:GovernanceLintRule[]){return inspectGovernanceInventory(lintContextFromInventory(inv),{builtinRules:[],rules,securityBaselinePlugins:inv.scope.kind==='cluster'?['rate-limiting']:[]});}
 private async completeComparisonPluginSchemas(sourceHandle:GovernanceReadHandle,source:GovernanceInventory,targetHandle:GovernanceReadHandle,target:GovernanceInventory):Promise<void>{
  // Schema requirements come from the actual authorized configured objects,
  // not the enabled-plugin catalog. Each gateway supplies its own schema;
  // a source-only plugin must never borrow the source schema for its target.
  const required=[...new Set([...source.objects,...target.objects].filter(object=>object.entityType==='plugins').map(object=>object.payload.name as string))].sort();
  for(const [handle,inventory]of [[sourceHandle,source],[targetHandle,target]] as const){
   const missing=required.filter(name=>!Object.hasOwn(inventory.pluginSchemas,name));
   if(missing.length)await this.inventory.enrichPluginSchemas(handle,inventory,missing);
  }
 }
 async capabilities(cid:string,actor:EntityActor):Promise<any>{const s=await this.discoveryScope(cid,actor),c=await this.db.one<any>('SELECT execution_mode,version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]),can=(module:string,action='read')=>this.authz.hasWholeWorkspace(actor.user,cid,s.wid,module,action);
  const [ruleRead,ruleWrite,ruleDelete,scheduleRead,scheduleWrite,scheduleDelete,driftRead,promotePlan]=await Promise.all([can('lint'),can('lint','write'),can('lint','delete'),can('governance'),can('governance','write'),can('governance','delete'),can('drift'),can('promote','write')]);await this.fence(actor,s.version);
  const adapterAvailable=/^1\.5\.\d+$/.test(c?.version??'');return{clusterId:cid,workspaceId:s.wid,executionMode:c.execution_mode,inspection:adapterAvailable,ruleRead,ruleWrite,ruleDelete,scheduleRead,scheduleWrite,scheduleDelete,driftRead,driftCompare:adapterAvailable&&driftRead,promotePlan:adapterAvailable&&promotePlan,adapterAvailable};
 }
 async catalog(cid:string,actor:EntityActor):Promise<any>{const s=await this.discoveryScope(cid,actor);await this.fence(actor,s.version);return{engineVersion:GOVERNANCE_ENGINE_VERSION,builtinRules:BUILTIN_LINT_RULES,predicates:['required','exists','type','enum','equals','includes','min','max','length','tags_contains','https_only','reference_exists','matches'],fixActions:fixCatalog,globalBaselinePolicy:{scope:'cluster',plugins:['rate-limiting'],automaticFix:false},limits:{nativePages:100,nativeRecords:10000,nativeBytes:33554432,nativeCalls:500,nativeDeadlineMs:120000,ruleLimit:200}};}
 private receiptOfRun(row:any,entity?:Record<string,unknown>):GovernanceReceipt{return{id:row.id,actorId:row.actor_id,clusterId:row.cluster_id,workspaceId:row.workspace_id,idempotencyKey:row.idempotency_key,domain:'governance',kind:row.kind,state:row.state,registrationCompleted:true,submissionCompleted:false,executionCompleted:['succeeded','incomplete','failed'].includes(row.state),nativeExecutionRequested:false,...(entity?{entity}:{})};}
 private reportSummary(row:any):Record<string,any>{return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,kind:'inspection',state:row.run_state??'succeeded',quality:row.quality,projection:row.projection,objectCount:row.object_count,findingCount:row.finding_count,counts:row.counts,observedFrom:new Date(row.observed_from).toISOString(),observedUntil:new Date(row.observed_until).toISOString(),createdAt:new Date(row.created_at).toISOString(),capabilities:{read:true,fix:false}};}
 private async priorRun(row:any,actor:EntityActor):Promise<GovernanceReceipt>{
  if(row.kind==='inspection'){const ref=await this.repo.reportForRun(row.id);if(!ref)return this.receiptOfRun(row);const report=await this.repo.report(ref.id,row.cluster_id,row.workspace_id),inv=this.repo.inventory(report);await this.assertInventoryRead(inv,actor,'governance');return this.receiptOfRun(row,this.reportSummary(report));}
  const ref=await this.db.one<any>('SELECT id FROM governance_comparisons WHERE run_id=$1',[row.id]);if(!ref)return this.receiptOfRun(row);const cmp=await this.checkedComparison(row.cluster_id,ref.id,actor);return this.receiptOfRun(row,this.comparisonSummary(cmp.row,cmp.source,cmp.target));
 }
 private mapFindings(inv:GovernanceInventory,findings:readonly LintFinding[]):any[]{return findings.map(f=>{const object=inv.objects.find(o=>o.entityType===f.entityType&&o.nativeId===f.nativeId);return{id:randomUUID(),ruleCode:f.ruleCode,severity:f.severity,entityType:f.entityType??'cluster',nativeId:f.nativeId,parentId:object?.parentId,objectWorkspaceId:object?.objectWorkspaceId,fieldPath:f.field??'',reasonCode:f.reasonCodes[0]??f.code,description:f.description,safeEvidence:{status:f.status,code:f.code,relatedObjects:f.relatedObjects??[]},fixActions:f.status==='confirmed'?f.fixCodes:[]};});}
 async inspect(cid:string,body:unknown,actor:EntityActor):Promise<GovernanceReceipt>{const input=inspectionInput(body),s=await this.scope(cid,actor),key=governanceKey(actor.idempotencyKey);
  return this.redis.withLock(governanceOriginalLock(actor.user.id,key),async()=>{
   await assertGovernanceOriginalDomain(this.db,actor.user.id,key,'analysis');
   const registration=await this.db.transaction(async tx=>{const r=await this.repo.beginRun({clusterId:cid,workspaceId:s.wid,actorId:actor.user.id,sessionId:this.context.current().sessionId,origin:'http',key,kind:'inspection',request:input},tx);if(!r.existing)await this.auditRun(tx,r.row,s.actor,'governance.inspection.requested',{scope:input.scope,rootCount:input.serviceIds.length},'pending');return r;});
   if(registration.existing)return this.priorRun(registration.row,s.actor);
   try{const captured=await this.inventory.captureActor(cid,{...input,workspaceId:s.wid},s.actor),rules=await this.effectiveRules(cid,s.wid,input.ruleCodes),result=await this.analyze(captured.inventory,rules.rules),reportId=randomUUID(),findings=this.mapFindings(captured.inventory,result.findings);
    await this.authority.assertCurrent(captured.handle);await this.fence(actor,s.version);
    await this.db.transaction(async tx=>{await this.repo.saveReport({id:reportId,run:registration.row,inventory:captured.inventory,result,rulesHmac:rules.hash,engineVersion:GOVERNANCE_ENGINE_VERSION,findings},tx);await this.repo.finishRun(registration.row.id,captured.inventory.completeness==='complete'&&result.complete?'succeeded':'incomplete',undefined,tx);await this.auditRun(tx,registration.row,s.actor,'governance.inspection.complete',{reportId,findingCount:findings.length,quality:captured.inventory.completeness});});
    return this.priorRun(await this.repo.run(registration.row.id,cid,s.wid),s.actor);
   }catch(error){await this.recordFailure(registration.row,s.actor,error);throw error;}
  });
 }
 private async recordFailure(row:any,actor:EntityActor,error:unknown):Promise<void>{
  // A failed COMMIT may already have sealed a report. Never relabel its terminal fact or repeat analysis.
  const actual=await this.repo.run(row.id,row.cluster_id,row.workspace_id).catch(()=>null);if(!actual||actual.state!=='running')return;
  const code=governanceFailureCode(error),known=error instanceof HttpException&&!/UNKNOWN|UNCERTAIN/.test(code),state=known?'failed':'uncertain';
  await this.db.transaction(async tx=>{await this.repo.finishRun(row.id,state,error,tx);await this.auditRun(tx,row,actor,'governance.analysis.failed',{errorCode:code},state);});
 }
 async reports(cid:string,query:Record<string,any>,actor:EntityActor):Promise<any>{const s=await this.scope(cid,actor),binding=this.secrets.fingerprint({kind:'reports',actor:actor.user.id,version:s.version,cid,wid:s.wid,...query,cursor:undefined}),page=await this.repo.directory('governance_reports',cid,s.wid,query,binding),items=[];
  for(const r of page.items){try{await this.assertInventoryRead(this.repo.inventory(r),s.actor,'governance');items.push(this.reportSummary(r));}catch(error){if(!(error instanceof ForbiddenException))throw error;}}await this.fence(actor,s.version);return{...page,items};
 }
 async report(cid:string,id:string,actor:EntityActor):Promise<any>{const s=await this.scope(cid,actor),r=await this.repo.report(id,cid,s.wid),inv=this.repo.inventory(r);await this.assertInventoryRead(inv,s.actor,'governance');const fix=await this.authz.hasWholeWorkspace(actor.user,cid,s.wid,'governance','write')&&(await this.authz.hasWholeWorkspace(actor.user,cid,s.wid,'snapshots','write')||await this.authz.hasWholeWorkspace(actor.user,cid,s.wid,'annotations','write')),entity=this.reportSummary(r);entity.capabilities.fix=fix;await this.fence(actor,s.version);return{entity,coverage:r.coverage,ruleResults:r.rule_results,reasonCodes:r.reason_codes,capabilities:{read:true,fix}};}
 async findings(cid:string,id:string,query:Record<string,any>,actor:EntityActor):Promise<any>{const s=await this.scope(cid,actor);await this.report(cid,id,s.actor);const binding=this.secrets.fingerprint({kind:'findings',actor:actor.user.id,version:s.version,cid,wid:s.wid,id,...query,cursor:undefined}),page=await this.repo.findings(id,cid,s.wid,query,binding);await this.fence(actor,s.version);return{...page,items:page.items.map((f:any)=>({id:f.id,ruleCode:f.rule_code,severity:f.severity,entityType:f.entity_type,nativeId:f.native_id,parentId:f.parent_id,objectWorkspaceId:f.object_workspace_id,fieldPath:f.field_path,reasonCode:f.reason_code,description:f.description,safeEvidence:f.safe_evidence,fixActions:f.fix_actions}))};}
 async resources(cid:string,type:GovernanceMetadataResource,query:Record<string,any>,actor:EntityActor):Promise<any>{if(type==='entity_annotations')throw fail('GOVERNANCE_RESOURCE_DIRECTORY_INVALID');const module=type==='governance_rules'?'lint':'governance',s=await this.scope(cid,actor,module);await this.authz.assertWholeWorkspace(actor.user,cid,s.wid,module,'read');const binding=this.secrets.fingerprint({type,actor:actor.user.id,version:s.version,cid,wid:s.wid,...query,cursor:undefined}),page=await this.repo.directory(type,cid,s.wid,query,binding),items=[];
  for(const row of page.items){const actual=await this.repo.resource(type,row.id,cid,s.wid);if(actual)items.push(await this.resourceView(type,actual,s.actor));}await this.fence(actor,s.version);return{...page,items};
 }
 private async resourceView(type:GovernanceMetadataResource,row:any,actor:EntityActor):Promise<any>{const module=type==='governance_rules'?'lint':'governance',write=await this.authz.hasWholeWorkspace(actor.user,row.cluster_id,row.workspace_id,module,'write'),del=await this.authz.hasWholeWorkspace(actor.user,row.cluster_id,row.workspace_id,module,'delete');return{...this.metadata.resourceView(row),...(type==='governance_schedules'?{ownerUserId:row.owner_user_id,nextRunAt:row.next_run_at?new Date(row.next_run_at).toISOString():null,...await this.repo.scheduleExecutionStatus(row.id,row.current_version)}:{}),capabilities:{read:true,write:write&&row.state!=='deleted',delete:del&&row.state!=='deleted',restore:write&&row.state==='deleted',clone:write}};}
 async resource(cid:string,type:GovernanceMetadataResource,id:string,actor:EntityActor):Promise<any>{const module=type==='governance_rules'?'lint':'governance',s=await this.scope(cid,actor,module);await this.authz.assertWholeWorkspace(actor.user,cid,s.wid,module,'read');const row=await this.repo.resource(type,id,cid,s.wid);if(!row)throw new NotFoundException({code:'GOVERNANCE_RESOURCE_NOT_FOUND'});await this.fence(actor,s.version);return{entity:await this.resourceView(type,row,s.actor)};}
 async cloneRule(cid:string,id:string,body:unknown,actor:EntityActor):Promise<GovernanceReceipt>{const v=governanceObject(body,['code','name']),current=await this.resource(cid,'governance_rules',id,actor),e=current.entity;return this.metadata.mutate(cid,'governance_rules',undefined,'create',{code:v.code,name:v.name,description:e.description,severity:e.severity,given:e.given,then:e.then,enabled:e.enabled},actor);}
 private comparisonSummary(row:any,source:GovernanceInventory,target:GovernanceInventory):Record<string,any>{const c=row.counts;return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,source:{clusterId:source.scope.clusterId,workspaceId:source.scope.workspaceId,scope:source.scope.kind,serviceIds:source.scope.rootIds},target:{clusterId:target.scope.clusterId,workspaceId:target.scope.workspaceId,scope:target.scope.kind,serviceIds:target.scope.rootIds},state:row.run_state??'succeeded',quality:row.quality,counts:{added:c.sourceOnly,removed:c.targetOnly,modified:c.changed,unchanged:c.unchanged},threshold:row.threshold,thresholdExceeded:row.threshold_exceeded,createdAt:new Date(row.created_at).toISOString(),capabilities:{read:true,promotePlan:false},confirmationName:`PROMOTE ${row.id}`};}
 private async checkedComparison(cid:string,id:string,actor:EntityActor):Promise<{row:any;source:GovernanceInventory;target:GovernanceInventory}>{const s=await this.scope(cid,actor,'drift'),row=await this.repo.comparison(id,cid,s.wid);await this.authz.assertCluster(actor.user,row.target_cluster_id,'drift','read',row.target_workspace_id);const {source,target}=this.repo.comparisonInventories(row);await this.assertInventoryRead(source,s.actor,'drift');await this.assertInventoryRead(target,{...s.actor,workspaceId:target.scope.workspaceId},'drift');await this.fence(actor,s.version);return{row,source,target};}
 async compare(cid:string,body:unknown,actor:EntityActor):Promise<GovernanceReceipt>{const input=comparisonInput(body),s=await this.scope(cid,actor,'drift'),key=governanceKey(actor.idempotencyKey);await this.authz.assertCluster(actor.user,input.target.clusterId,'drift','read',input.target.workspaceId);
  return this.redis.withLock(governanceOriginalLock(actor.user.id,key),async()=>{await assertGovernanceOriginalDomain(this.db,actor.user.id,key,'analysis');const reg=await this.db.transaction(async tx=>{const r=await this.repo.beginRun({clusterId:cid,workspaceId:s.wid,actorId:actor.user.id,sessionId:this.context.current().sessionId,origin:'http',key,kind:'comparison',request:input},tx);if(!r.existing)await this.auditRun(tx,r.row,s.actor,'governance.comparison.requested',{kind:'readonly_dual_environment'},'pending');return r;});if(reg.existing)return this.priorRun(reg.row,s.actor);
   try{const source=await this.inventory.captureActor(cid,{scope:input.scope,serviceIds:input.serviceIds,workspaceId:s.wid,module:'drift'},s.actor),target=await this.inventory.captureActor(input.target.clusterId,{scope:input.target.scope,serviceIds:input.target.serviceIds,workspaceId:input.target.workspaceId,module:'drift'},{...s.actor,workspaceId:input.target.workspaceId});
    if(source.inventory.scope.transportScope===target.inventory.scope.transportScope)throw new BadRequestException({code:'GOVERNANCE_DISTINCT_ENVIRONMENTS_REQUIRED'});
    await this.completeComparisonPluginSchemas(source.handle,source.inventory,target.handle,target.inventory);
    const policy={includeEnvironmentFields:input.includeEnvironmentFields},result=compareLogicalEnvironments(source.inventory,target.inventory,{sourcePolicy:policy,targetPolicy:policy,threshold:{maxChangedObjects:input.threshold},fingerprint:v=>this.secrets.fingerprint(v)}),id=randomUUID();
    const sourceNativeFingerprints=await this.inventory.privateFingerprints(source.handle,source.inventory),targetNativeFingerprints=await this.inventory.privateFingerprints(target.handle,target.inventory);
    await this.authority.assertCurrent(source.handle);await this.authority.assertCurrent(target.handle);await this.fence(actor,s.version);
    await this.db.transaction(async tx=>{await this.repo.saveComparison({id,run:reg.row,source:source.inventory,target:target.inventory,sourceNativeFingerprints,targetNativeFingerprints,policy,result,threshold:input.threshold},tx);await this.repo.finishRun(reg.row.id,result.completeness==='complete'?'succeeded':'incomplete',undefined,tx);await this.auditRun(tx,reg.row,s.actor,'governance.comparison.complete',{comparisonId:id,quality:result.completeness});if(result.threshold.notify)await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:s.wid,entityType:'governance_comparisons',entityId:id,requestId:actor.requestId,ip:actor.ip,action:'governance.drift.threshold_crossed',after:{comparisonId:id},scopeHints:metadataAuditScope('drift','governance_comparisons',id,s.wid)},tx);});
    return this.priorRun(await this.repo.run(reg.row.id,cid,s.wid),s.actor);
   }catch(error){await this.recordFailure(reg.row,s.actor,error);throw error;}
  });
 }
 async comparisons(cid:string,query:Record<string,any>,actor:EntityActor):Promise<any>{const s=await this.scope(cid,actor,'drift'),binding=this.secrets.fingerprint({kind:'comparisons',actor:actor.user.id,version:s.version,cid,wid:s.wid,...query,cursor:undefined}),page=await this.repo.directory('governance_comparisons',cid,s.wid,query,binding),items=[];for(const row of page.items){try{const c=await this.checkedComparison(cid,row.id,s.actor);items.push(this.comparisonSummary(c.row,c.source,c.target));}catch(error){if(!(error instanceof ForbiddenException))throw error;}}await this.fence(actor,s.version);return{...page,items};}
 async comparison(cid:string,id:string,query:Record<string,any>,actor:EntityActor):Promise<any>{const c=await this.checkedComparison(cid,id,actor),p=governancePage(query),binding=this.secrets.fingerprint({id,actor:actor.user.id,version:await this.authz.permissionVersion(actor.user),size:p.size}),cursor=new (await import('../portal/portal-input')).PortalCursor(),position=cursor.decode(p.cursor,binding),start=position?.index??0;if(!Number.isSafeInteger(start)||start<0)throw new BadRequestException({code:'INVALID_CURSOR'});
  const all=c.row.safe_changes as any[],items=all.slice(start,start+p.size).map(change=>{const object=c.source.objects.find(o=>o.entityType===change.entityType&&o.nativeId===change.sourceNativeId);return{...change,sourceObjectKey:object?(object.entityType==='targets'?`targets:${object.parentId}:${object.nativeId}`:`${object.entityType}:${object.nativeId}`):null};}),summary=this.comparisonSummary(c.row,c.source,c.target);summary.capabilities.promotePlan=await this.canPromote(c,actor);return{entity:summary,items,size:p.size,total:null,nextCursor:start+p.size<all.length?cursor.encode(binding,{index:start+p.size}):null};
 }
 private objectKey(object:GovernanceInventoryObject):string{return object.entityType==='targets'?`targets:${object.parentId}:${object.nativeId}`:`${object.entityType}:${object.nativeId}`;}
 private async canPromote(c:{row:any;source:GovernanceInventory;target:GovernanceInventory},actor:EntityActor):Promise<boolean>{const material=this.repo.comparisonMaterials(c.row);return c.row.quality==='complete'&&material.source.nativeFingerprints!==null&&material.target.nativeFingerprints!==null&&await this.authz.hasWholeWorkspace(actor.user,c.source.scope.clusterId,c.source.scope.workspaceId,'promote','write')&&await this.authz.hasWholeWorkspace(actor.user,c.target.scope.clusterId,c.target.scope.workspaceId,'promote','write');}
 async sourceObjects(cid:string,id:string,query:Record<string,any>,actor:EntityActor):Promise<any>{
  const c=await this.checkedComparison(cid,id,actor),p=governancePage(query),filter=query.entityType;
  if(filter!==undefined&&!['services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis'].includes(filter))throw new BadRequestException({code:'GOVERNANCE_SOURCE_OBJECT_FILTER_INVALID'});
  const version=await this.authz.permissionVersion(actor.user),binding=this.secrets.fingerprint({kind:'source-objects',cid,wid:c.source.scope.workspaceId,id,actor:actor.user.id,version,filter:filter??null,size:p.size}),cursor=new(await import('../portal/portal-input')).PortalCursor(),decoded=cursor.decode(p.cursor,binding),start=decoded?.index??0;
  if(!Number.isSafeInteger(start)||start<0)throw new BadRequestException({code:'INVALID_CURSOR'});
  const all=c.source.objects.filter(o=>filter===undefined||o.entityType===filter).slice().sort((a,b)=>this.objectKey(a).localeCompare(this.objectKey(b))),items=all.slice(start,start+p.size).map(o=>{const label=o.payload.name??(o.entityType==='consumers'?o.payload.username:undefined),name=typeof label==='string'&&label.length<=256&&!label.startsWith('[REDACTED')?label:undefined;return{objectKey:this.objectKey(o),entityType:o.entityType,nativeId:o.nativeId,...(o.parentId?{parentId:o.parentId}:{}),...(name?{name}:{}),referenceOnly:o.referenceOnly===true,objectWorkspaceId:o.objectWorkspaceId,eligible:o.referenceOnly!==true&&o.managedBoundary!=='portal'&&o.managedBoundary!=='metrics'};});
  const capabilities={read:true,promotePlan:await this.canPromote(c,actor)};await this.fence(actor,version);return{comparisonId:id,quality:c.row.quality,capabilities,items,size:p.size,total:null,nextCursor:start+p.size<all.length?cursor.encode(binding,{index:start+p.size}):null};
 }
 async fixPlan(cid:string,reportId:string,findingId:string,body:unknown,actor:EntityActor):Promise<any>{
  const value=governanceObject(body,['action','values']),s=await this.scope(cid,actor,'governance','write'),key=governanceKey(actor.idempotencyKey),h=this.secrets.fingerprint({reportId,findingId,input:value});
  return this.redis.withLock(governanceOriginalLock(actor.user.id,key),async()=>{
   await assertGovernanceOriginalDomain(this.db,actor.user.id,key,'fix');
   const prior=await this.repo.fixByKey(actor.user.id,key);if(prior){if(prior.cluster_id!==cid||prior.workspace_id!==s.wid||prior.report_id!==reportId||prior.finding_id!==findingId||prior.request_hmac!==h)throw fail('IDEMPOTENCY_CONFLICT');return this.fixReceipt(prior,s.actor,true);}
   await this.report(cid,reportId,s.actor);const finding=await this.repo.finding(findingId,reportId,cid,s.wid),historical=this.repo.inventory(await this.repo.report(reportId,cid,s.wid));
   if(finding.safe_evidence.status!=='confirmed'||!finding.fix_actions.includes(value.action))throw new BadRequestException({code:'GOVERNANCE_FINDING_NOT_FIXABLE'});
   const targetWid=finding.object_workspace_id??s.wid;
   const annotation=value.action==='annotation_description_set',nativeAction=value.action==='unused_certificate_archive'?'delete':'write';
   if(annotation)await this.authz.assertWholeWorkspace(actor.user,cid,targetWid,'annotations','write');
   else if(historical.scope.kind==='cluster')await this.authz.assertWholeCluster(actor.user,cid,'snapshots','write');
   else await this.authz.assertWholeWorkspace(actor.user,cid,targetWid,'snapshots','write');
   const selected=historical.objects.find((o:GovernanceInventoryObject)=>o.entityType===finding.entity_type&&o.nativeId===finding.native_id);
   if(selected)await this.authz.assertEntity(actor.user,cid,selected.entityType,nativeAction,this.physical(selected),targetWid);
   else if(finding.entity_type==='cluster')await this.authz.assertWholeCluster(actor.user,cid,'plugins','write');
   else throw fail('GOVERNANCE_FIX_OBJECT_MISSING');
   await this.fence(actor,s.version);
   const row=await this.db.transaction(async tx=>{const registered=await this.repo.beginFix({id:randomUUID(),clusterId:cid,workspaceId:s.wid,targetWorkspaceId:targetWid,reportId,findingId,actorId:actor.user.id,key,request:value},tx);await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:s.wid,entityType:'governance_fix_requests',entityId:registered.id,requestId:actor.requestId,ip:actor.ip,action:'governance.fix.plan.requested',after:{reportId,findingId,action:value.action},result:'pending',scopeHints:metadataAuditScope('governance','governance_fix_requests',registered.id,s.wid)},tx);return registered;});
   const child={...s.actor,workspaceId:targetWid,idempotencyKey:`governance-fix-${row.id}`};let childStarted=false;
   try{const current=await this.inventory.captureActor(cid,{scope:historical.scope.kind,serviceIds:historical.scope.rootIds,workspaceId:s.wid},s.actor),rules=await this.effectiveRules(cid,s.wid),fresh=await this.analyze(current.inventory,rules.rules),issue=fresh.findings.find((f:LintFinding)=>f.nativeId===finding.native_id&&(f.entityType??'cluster')===finding.entity_type&&(f.field??'')===finding.field_path&&f.code===finding.safe_evidence.code&&f.ruleCode===finding.rule_code&&f.status==='confirmed');if(!issue)throw fail('GOVERNANCE_FIX_ISSUE_CHANGED');
    const actualObject=current.inventory.objects.find(o=>o.entityType===issue.entityType&&o.nativeId===issue.nativeId);if(actualObject&&(actualObject.objectWorkspaceId??s.wid)!==targetWid)throw fail('GOVERNANCE_FIX_OBJECT_SCOPE_CHANGED');
    const compiled=compileGovernanceFix(lintContextFromInventory(current.inventory),issue,value as any);if(compiled.blockerCodes.length)throw fail(compiled.blockerCodes[0]);await this.authority.assertCurrent(current.handle);await this.fence(actor,s.version);
    if(compiled.kind==='annotation'){const a=compiled.annotation!,before=await this.repo.resource('entity_annotations',a.nativeId,cid,targetWid,this.db,false,a.entityType),operation=before?'update':'create',input={entityType:a.entityType,nativeId:a.nativeId,description:a.description,...(before?{revision:before.revision}:{})},descriptor={version:1,domain:'metadata',resourceType:'entity_annotations',resourceId:a.nativeId,operation,requestHmac:this.secrets.fingerprint({type:'entity_annotations',target:a.nativeId,operation,input})};await this.bindFixChild(row,descriptor,s.actor);childStarted=true;await this.metadata.mutate(cid,'entity_annotations',a.nativeId,operation,input,child);}
    else{const scope={clusterId:cid,workspaceId:targetWid,transportScope:current.inventory.scope.transportScope,kind:compiled.kind==='archive'?'workspace':historical.scope.kind,rootIds:compiled.kind==='archive'?[]:historical.scope.rootIds},input=compiled.kind==='archive'?{toolboxBatch:validateBatchSelection({action:'delete',roots:[{type:compiled.archive!.entityType,id:compiled.archive!.nativeId}]})}:{mode:'merge',documentHmac:this.secrets.fingerprint(parseDeckDocument(compiled.yaml!).document),basicPasswordIntents:{}};
     await this.bindFixChild(row,{version:1,domain:'configuration',kind:'import',scope,requestHmac:this.secrets.fingerprint({scope,kind:'import',input})},s.actor);childStarted=true;
     if(compiled.kind==='archive')await this.configuration.createToolboxBatchPlan(cid,{action:'delete',roots:[{type:compiled.archive!.entityType,id:compiled.archive!.nativeId}]},child);else await this.configuration.importDocument(cid,{scope:historical.scope.kind,serviceIds:historical.scope.rootIds,yaml:compiled.yaml,mode:'merge'},child);
    }
    return this.fixReceipt(await this.repo.fixByKey(actor.user.id,key),s.actor,true);
   }catch(error){const sqlKnown=await this.db.one<any>('SELECT id FROM configuration_jobs WHERE actor_id=$1 AND idempotency_key=$2 UNION ALL SELECT id FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2 UNION ALL SELECT id FROM governance_metadata_requests WHERE actor_id=$1 AND idempotency_key=$2 LIMIT 1',[actor.user.id,child.idempotencyKey]);
    const ambiguous=!!sqlKnown||childStarted;
    await this.db.transaction(async tx=>{const current=await tx.one<any>('SELECT state FROM governance_fix_requests WHERE id=$1 FOR UPDATE',[row.id]);if(current?.state==='planning'){await tx.exec("UPDATE governance_fix_requests SET state=$2,error_code=$3,updated_at=now() WHERE id=$1 AND state='planning'",[row.id,ambiguous?'uncertain':'blocked',governanceFailureCode(error)]);await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:s.wid,entityType:'governance_fix_requests',entityId:row.id,requestId:actor.requestId,ip:actor.ip,action:'governance.fix.plan.failed',after:{errorCode:governanceFailureCode(error),childRegistrationObserved:!!sqlKnown},result:ambiguous?'uncertain':'failed',scopeHints:metadataAuditScope('governance','governance_fix_requests',row.id,s.wid)},tx);}});if(error instanceof GovernanceLintError)throw new BadRequestException({code:error.code,message:'修复输入不符合当前对象、字段或规则约束'});throw error;
   }
  });
 }
 private async bindFixChild(row:any,descriptor:Record<string,any>,actor:EntityActor):Promise<void>{await this.db.transaction(async tx=>{await this.repo.bindFixChild(row.id,descriptor.domain,descriptor,tx);await this.audit.append({actorId:actor.user.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,entityType:'governance_fix_requests',entityId:row.id,requestId:actor.requestId,ip:actor.ip,action:'governance.fix.child.sealed',after:{kind:descriptor.domain},scopeHints:metadataAuditScope('governance','governance_fix_requests',row.id,row.workspace_id)},tx);});}
 private async fixReceipt(row:any,actor:EntityActor,reconcile:boolean):Promise<any>{
  await this.report(row.cluster_id,row.report_id,{...actor,workspaceId:row.workspace_id});const childKey=`governance-fix-${row.id}`;
  const descriptor=this.repo.fixChild(row),job=await this.db.one<any>('SELECT id,kind,request_hmac,plan_id,plan_revision,plan_hash,state FROM configuration_jobs WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND idempotency_key=$4',[actor.user.id,row.cluster_id,row.target_workspace_id,childKey]);
  if(job&&(!descriptor||descriptor.domain!=='configuration'||job.kind!==descriptor.kind||job.request_hmac!==descriptor.requestHmac))throw fail('GOVERNANCE_FIX_CHILD_SOURCE_MISMATCH');
  let metadata:GovernanceReceipt|null=null;if(!job){const actualIntent=await this.db.one<any>('SELECT id,resource_type,resource_id,operation,request_hmac FROM governance_metadata_requests WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND idempotency_key=$4',[actor.user.id,row.cluster_id,row.target_workspace_id,childKey]),actualIam=await this.db.one<any>('SELECT id,module,target_id,payload_secret FROM iam_operations WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND idempotency_key=$4',[actor.user.id,row.cluster_id,row.target_workspace_id,childKey]);
   if(actualIntent){if(!descriptor||descriptor.domain!=='metadata'||actualIntent.resource_type!==descriptor.resourceType||actualIntent.resource_id!==descriptor.resourceId||actualIntent.operation!==descriptor.operation||actualIntent.request_hmac!==descriptor.requestHmac)throw fail('GOVERNANCE_FIX_CHILD_SOURCE_MISMATCH');}
   if(actualIam){const payload=this.secrets.decrypt<any>(actualIam.payload_secret,`iam:${actualIam.id}:payload`);if(!descriptor||descriptor.domain!=='metadata'||actualIam.module!=='annotations'||actualIam.target_id!==descriptor.resourceId||payload.governanceResource!==descriptor.resourceType||payload.resourceId!==descriptor.resourceId||payload.operation!==descriptor.operation||payload.originalRequestHmac!==descriptor.requestHmac)throw fail('GOVERNANCE_FIX_CHILD_SOURCE_MISMATCH');}
   if(actualIntent||actualIam)metadata=await this.metadata.receipt(row.cluster_id,childKey,{...actor,workspaceId:row.target_workspace_id});
  }
  if(reconcile&&['planning','uncertain'].includes(row.state)&&(job?.state==='succeeded'||metadata?.domain==='iam'&&metadata.configurationCommitted||metadata?.domain==='workflow'&&metadata.submissionCompleted)){
   await this.db.transaction(async tx=>{const current=await tx.one<any>('SELECT * FROM governance_fix_requests WHERE id=$1 FOR UPDATE',[row.id]);if(current.state==='ready')return;
    await this.repo.completeFix(current,job?{jobId:job.id,planId:job.plan_id??undefined,planRevision:job.plan_revision??undefined,planHash:job.plan_hash??undefined}:{metadataOperationId:metadata!.id,metadataDomain:metadata!.domain as 'iam'|'workflow',workflowId:metadata!.workflowId},tx);
    await this.audit.append({actorId:actor.user.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,entityType:'governance_fix_requests',entityId:row.id,requestId:actor.requestId,ip:actor.ip,action:'governance.fix.plan',after:{jobId:job?.id??null,planId:job?.plan_id??null,metadataOperationId:metadata?.id??null,metadataOnlyReconciliation:true},scopeHints:metadataAuditScope('governance','governance_fix_requests',row.id,row.workspace_id)},tx);
   });row=await this.repo.fixByKey(actor.user.id,row.idempotency_key);
  }
  return{id:row.id,actorId:row.actor_id,clusterId:row.cluster_id,workspaceId:row.workspace_id,idempotencyKey:row.idempotency_key,domain:metadata?.domain??'governance',kind:'fix-plan',state:metadata?.state??row.state,governanceRequestId:row.id,governanceState:row.state,registrationCompleted:true,submissionCompleted:metadata?.submissionCompleted??false,executionCompleted:metadata?metadata.executionCompleted:row.state==='ready'||row.state==='blocked',configurationCommitted:metadata?.configurationCommitted??false,nativeExecutionRequested:false,metadataOnlyResult:!!metadata,metadataOperationId:metadata?.id,metadataChildKey:metadata?childKey:undefined,metadataReconciliationPending:row.state!=='ready'&&!!(job||metadata),targetClusterId:row.cluster_id,targetWorkspaceId:row.target_workspace_id,...(row.configuration_job_id||job?.id?{jobId:row.configuration_job_id??job.id}:{}),...(row.plan_id||job?.plan_id?{planId:row.plan_id??job.plan_id}:{}),...(row.workflow_id||metadata?.workflowId?{workflowId:row.workflow_id??metadata!.workflowId}:{}),...(metadata?.entity?{entity:metadata.entity}:{} )};
 }
 async reconcileReceipt(cid:string,key:string,body:unknown,actor:EntityActor):Promise<any>{key=governanceKey(key);const value=governanceObject(body,['confirmed','confirm_name']),s=await this.scope(cid,actor,'governance','write');governanceConfirm(value,`reconcile:${key}`);const row=await this.repo.fixByKey(actor.user.id,key);if(!row||row.cluster_id!==cid||row.workspace_id!==s.wid)throw new NotFoundException({code:'GOVERNANCE_FIX_REQUEST_NOT_FOUND'});return this.redis.withLock(governanceOriginalLock(actor.user.id,key),()=>this.fixReceipt(row,s.actor,true));}
 async promotePlan(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{const value=promotionInput(body),c=await this.checkedComparison(cid,id,actor),key=governanceKey(actor.idempotencyKey);governanceConfirm(value,`PROMOTE ${id}`);if(c.row.quality!=='complete')throw fail('GOVERNANCE_PROMOTION_COMPLETE_REQUIRED');const privateMaterial=this.repo.comparisonMaterials(c.row);if(!privateMaterial.source.nativeFingerprints||!privateMaterial.target.nativeFingerprints)throw fail('GOVERNANCE_PROMOTION_NEW_COMPARISON_REQUIRED');
  await this.authz.assertWholeWorkspace(actor.user,cid,c.source.scope.workspaceId,'promote','write');await this.authz.assertWholeWorkspace(actor.user,c.target.scope.clusterId,c.target.scope.workspaceId,'promote','write');
  return this.redis.withLock(governanceOriginalLock(actor.user.id,key),async()=>{
   await assertGovernanceOriginalDomain(this.db,actor.user.id,key,'promotion');
   const h=this.secrets.fingerprint({comparisonId:id,input:value}),old=await this.db.one<any>('SELECT * FROM governance_promotions WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
   if(old){if(old.cluster_id!==cid||old.workspace_id!==c.source.scope.workspaceId||old.request_hmac!==h)throw fail('IDEMPOTENCY_CONFLICT');return this.promotionReceipt(old);}
   const promotionId=randomUUID(),targetWs=await this.workspaces.get(c.target.scope.clusterId,c.target.scope.workspaceId),selection={...value,targetWorkspaceCode:targetWs.code};
   await this.db.transaction(async tx=>{await tx.exec(`INSERT INTO governance_promotions(id,cluster_id,workspace_id,comparison_id,target_cluster_id,target_workspace_id,actor_id,idempotency_key,request_hmac,selection_secret,selection_hmac,source_inventory_hmac,target_inventory_hmac,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'planning')`,[promotionId,cid,c.source.scope.workspaceId,id,c.target.scope.clusterId,c.target.scope.workspaceId,actor.user.id,key,h,this.secrets.encrypt(selection,this.repo.aad('promotion-selection',promotionId)),this.secrets.fingerprint(selection),c.row.source_inventory_hmac,c.row.target_inventory_hmac]);await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:c.source.scope.workspaceId,entityType:'governance_promotions',entityId:promotionId,requestId:actor.requestId,ip:actor.ip,action:'governance.promote.plan.requested',after:{comparisonId:id,includeEnvironmentFields:value.includeEnvironmentFields,includeSecrets:value.includeSecrets,includeCredentials:value.includeCredentials},result:'pending',scopeHints:metadataAuditScope('promote','governance_promotions',promotionId,c.source.scope.workspaceId)},tx);});
   // This fixed server bridge is Root-owned and enforces persistent origin on every generic M8 execution path.
   await this.configuration.createGovernancePromotionPlan({promotionId,sourceClusterId:cid,sourceWorkspaceId:c.source.scope.workspaceId,targetClusterId:c.target.scope.clusterId,targetWorkspaceId:c.target.scope.workspaceId},actor);
   const row=await this.db.one<any>('SELECT * FROM governance_promotions WHERE id=$1',[promotionId]);return this.promotionReceipt(row);
  });
 }
 private promotionReceipt(row:any):GovernanceReceipt{return{id:row.id,actorId:row.actor_id,clusterId:row.cluster_id,workspaceId:row.workspace_id,idempotencyKey:row.idempotency_key,domain:'governance',kind:'promotion-plan',state:row.state,registrationCompleted:true,submissionCompleted:false,executionCompleted:row.state==='ready'||row.state==='blocked',nativeExecutionRequested:false,targetClusterId:row.target_cluster_id,targetWorkspaceId:row.target_workspace_id,...(row.error_code?{errorCode:row.error_code}:{}),...(row.configuration_job_id?{jobId:row.configuration_job_id}:{}),...(row.plan_id?{planId:row.plan_id}:{} )};}
 async receipt(cid:string,key:string,actor:EntityActor):Promise<GovernanceReceipt>{
  cid=governanceId(cid);key=governanceKey(key);const ws=await this.workspaces.resolve(cid,actor.workspaceId),scoped={...actor,workspaceId:ws.id},run=await this.repo.runByKey(actor.user.id,key);
  if(run){const s=await this.scope(cid,scoped,run.kind==='comparison'?'drift':'governance');if(run.cluster_id!==cid||run.workspace_id!==s.wid)throw fail('IDEMPOTENCY_CONFLICT');return this.priorRun(run,s.actor);}
  const fix=await this.repo.fixByKey(actor.user.id,key);if(fix){const s=await this.scope(cid,scoped);if(fix.cluster_id!==cid||fix.workspace_id!==s.wid)throw fail('IDEMPOTENCY_CONFLICT');return this.fixReceipt(fix,s.actor,false);}
  const p=await this.db.one<any>('SELECT * FROM governance_promotions WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);if(p){if(p.cluster_id!==cid||p.workspace_id!==ws.id)throw fail('IDEMPOTENCY_CONFLICT');
   // An original owner may discover the already registered target fact even
   // after losing source grants. This receipt contains no source material,
   // comparison details, names or fresh-read assertion; generic M8 execution
   // still independently enforces the persisted source origin.
   await this.authz.assertWholeWorkspace(actor.user,p.target_cluster_id,p.target_workspace_id,'promote','read');
   const target=await this.db.one<any>("SELECT c.id FROM clusters c JOIN workspaces w ON w.cluster_id=c.id WHERE c.id=$1 AND w.id=$2 AND c.deleted_at IS NULL AND c.status<>'disabled' AND w.status='active'",[p.target_cluster_id,p.target_workspace_id]);if(!target)throw fail('GOVERNANCE_PROMOTION_TARGET_UNAVAILABLE');
   return this.promotionReceipt(p);
  }
  const metadata=await this.metadata.receipt(cid,key,scoped);if(metadata)return metadata;throw new NotFoundException({code:'GOVERNANCE_OPERATION_NOT_FOUND'});
 }
 async runScheduled(locator:GovernanceScheduleLocator,payload:any):Promise<{runId:string;state:'succeeded'|'incomplete'}>{
  const sourceHandle=await this.authority.acquireDueSchedule(locator),description=await this.authority.description(sourceHandle),actor=description.actor,key=`governance-schedule-${locator.runId}`;
  const reg=await this.db.transaction(async tx=>{const r=await this.repo.beginRun({clusterId:locator.clusterId,workspaceId:locator.workspaceId,actorId:locator.ownerUserId,origin:'schedule',scheduleRunId:locator.runId,key,kind:payload.kind==='drift'?'comparison':'inspection',request:{scheduleId:locator.scheduleId,version:locator.version,scheduledAt:locator.scheduledAt}},tx);if(!r.existing)await this.auditRun(tx,r.row,actor,'governance.schedule.run.requested',{scheduleId:locator.scheduleId},'pending');return r;});
  if(reg.existing)throw fail('GOVERNANCE_SCHEDULE_ORIGINAL_RUN_EXISTS');
  try{const source=await this.inventory.capture(sourceHandle),id=randomUUID();
   if(payload.kind==='drift'){const targetHandle=await this.authority.acquireDueSchedule({...locator,side:'target'}),target=await this.inventory.capture(targetHandle);await this.completeComparisonPluginSchemas(sourceHandle,source,targetHandle,target);
    const previous=await this.db.one<any>('SELECT last_diff_hmac FROM governance_drift_states WHERE schedule_id=$1',[locator.scheduleId]),policy={includeEnvironmentFields:payload.includeEnvironmentFields===true},result=compareLogicalEnvironments(source,target,{sourcePolicy:policy,targetPolicy:policy,threshold:{maxChangedObjects:payload.threshold??0},previousFingerprint:previous?.last_diff_hmac,fingerprint:v=>this.secrets.fingerprint(v)});
    const sourceNativeFingerprints=await this.inventory.privateFingerprints(sourceHandle,source),targetNativeFingerprints=await this.inventory.privateFingerprints(targetHandle,target);
    await this.authority.assertCurrent(sourceHandle);await this.authority.assertCurrent(targetHandle);
    await this.db.transaction(async tx=>{await this.repo.saveComparison({id,run:reg.row,source,target,sourceNativeFingerprints,targetNativeFingerprints,policy,result,threshold:payload.threshold??0},tx);await this.repo.finishRun(reg.row.id,result.completeness==='complete'?'succeeded':'incomplete',undefined,tx);
     if(result.completeness==='complete'){await tx.exec(`INSERT INTO governance_drift_states(cluster_id,workspace_id,schedule_id,policy_hmac,last_comparison_id,last_diff_hmac,threshold_exceeded,revision) VALUES($1,$2,$3,$4,$5,$6,$7,1) ON CONFLICT(schedule_id) DO UPDATE SET policy_hmac=EXCLUDED.policy_hmac,last_comparison_id=EXCLUDED.last_comparison_id,last_diff_hmac=EXCLUDED.last_diff_hmac,threshold_exceeded=EXCLUDED.threshold_exceeded,revision=governance_drift_states.revision+1,updated_at=now()`,[locator.clusterId,locator.workspaceId,locator.scheduleId,this.secrets.fingerprint(policy),id,result.fingerprint,result.threshold.exceeded]);if(result.threshold.notify)await this.audit.append({actorId:actor.user.id,clusterId:locator.clusterId,workspaceId:locator.workspaceId,entityType:'governance_comparisons',entityId:id,requestId:actor.requestId,action:'governance.drift.threshold_crossed',after:{comparisonId:id},scopeHints:metadataAuditScope('drift','governance_comparisons',id,locator.workspaceId)},tx);}await this.auditRun(tx,reg.row,actor,'governance.schedule.run.complete',{comparisonId:id});});
   }else{const rules=await this.effectiveRules(locator.clusterId,locator.workspaceId,payload.ruleCodes),result=await this.analyze(source,rules.rules);await this.authority.assertCurrent(sourceHandle);await this.db.transaction(async tx=>{await this.repo.saveReport({id,run:reg.row,inventory:source,result,rulesHmac:rules.hash,engineVersion:GOVERNANCE_ENGINE_VERSION,findings:this.mapFindings(source,result.findings)},tx);await this.repo.finishRun(reg.row.id,source.completeness==='complete'&&result.complete?'succeeded':'incomplete',undefined,tx);await this.auditRun(tx,reg.row,actor,'governance.schedule.run.complete',{reportId:id});});}
   const terminal=await this.repo.run(reg.row.id,locator.clusterId,locator.workspaceId);return{runId:reg.row.id,state:terminal.state==='succeeded'?'succeeded':'incomplete'};
  }catch(error){await this.recordFailure(reg.row,actor,error);throw error;}
 }
}
