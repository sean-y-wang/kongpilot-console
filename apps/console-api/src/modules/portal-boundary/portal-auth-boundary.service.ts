import { ConflictException, ForbiddenException, HttpException, Inject, Injectable, Optional } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService, type ScheduledPortalPreparationPhase } from '../../infrastructure/kong/execution-context.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { normalizeEntityAuthorizationView } from '../entities/entity-reference';
import { decodePublicationProof } from '../portal/portal-proof';
import { APPROVED_PORTAL_STEP_POLICY, ApprovedPortalStepPolicy, PortalAuthBoundaryPolicy, PortalBoundaryReadPermit, PortalNativePacket, PortalPreparedPacket } from '../workflows/approved-execution.types';
import { assertPortalAuthenticationBoundary, assertPortalCaptureStable, PortalConsumerBoundary, PortalGraph, PortalPublicationBoundary } from './auth-graph';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const blocked=(code:string)=>new ForbiddenException({code,message:'此操作影响门户受管对象或认证边界，请使用当前有效的门户工作流'});
const changed=()=>new ConflictException({code:'PORTAL_AUTH_GRAPH_CHANGED',message:'门户认证元数据在核验期间变化，请核验原回执后重新检查'});
const infrastructureMessages=Object.freeze({
 KONG_EXECUTION_CALL_LIMIT:'执行调用量超过上限，流程已停止，请核验原执行回执',
 KONG_EXECUTION_RESPONSE_LIMIT:'执行响应数据超过上限，流程已停止，请核验原执行回执',
 KONG_EXECUTION_CONTEXT_EXPIRED:'执行上下文已过期，流程已停止，请核验原执行回执',
});
/** Only these already public infrastructure codes survive an Approved denial.
 * Never forward arbitrary response fields, messages, causes or stacks. */
function infrastructureFailure(error:unknown):HttpException|null{
 try{
  if(!(error instanceof HttpException))return null;
  const status=error.getStatus(),response=error.getResponse();
  if(!Number.isInteger(status)||status<400||status>599||!response||typeof response!=='object'||Array.isArray(response))return null;
  const descriptor=Object.getOwnPropertyDescriptor(response,'code'),code=descriptor&&'value'in descriptor?descriptor.value:undefined;
  if(typeof code!=='string'||!Object.hasOwn(infrastructureMessages,code))return null;
  return new HttpException({code,message:infrastructureMessages[code as keyof typeof infrastructureMessages]},status);
 }catch{return null;}
}
interface Ownership {publications:any[];grants:any[];credentials:any[];}
function object(value:unknown):Record<string,any>{
 if(!value||typeof value!=='object'||Array.isArray(value))throw blocked('PORTAL_AUTH_GRAPH_INVALID');
 return value as Record<string,any>;
}
/** Apply only defaults observed in this target's actual schema. This private
 * prospective model never rewrites the sealed native request. */
function defaults(value:any,schema:any):any{
 const result=structuredClone(value);
 for(const field of schema?.fields??[]){
  const [name,definition]=Object.entries(field)[0]??[];if(!name||!definition||typeof definition!=='object')continue;
  const d=definition as any;
  if(result[name]===undefined&&Object.hasOwn(d,'default'))result[name]=structuredClone(d.default);
  if(d.type==='record'&&result[name]!==null){
   if(result[name]===undefined)result[name]={};
   if(result[name]&&typeof result[name]==='object'&&!Array.isArray(result[name]))result[name]=defaults(result[name],d);
  }
 }return result;
}

/** Independent final-send policy. No Engine, business controller or developer
 * identity can mint its private capture capability. Physical ownership uses
 * the immutable captured endpoint, including revoked and remapped history. */
@Injectable()
export class PortalAuthBoundaryService implements PortalAuthBoundaryPolicy {
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly kong:KongService,
  private readonly execution:KongExecutionContextService,private readonly workspaces:WorkspaceResolverService,
  @Optional() @Inject(APPROVED_PORTAL_STEP_POLICY) private readonly approved?:ApprovedPortalStepPolicy){
   if(typeof execution.installPortalPreparationSupportPolicy==='function')execution.installPortalPreparationSupportPolicy({assertPaths:(original,paths)=>this.assertPreparationSupportPaths(original,paths)});
  }
 private async assertPreparationSupportPaths(original:Readonly<ScheduledPortalPreparationPhase>,paths:readonly string[]):Promise<void>{
  this.execution.assertScheduledPortalPreparationPhase(original);
  if(original.purpose!=='before-send'||original.namespace.kind!=='portal-credential-issue'||original.namespaceHandle!==this.execution.requireWorkflowScheduledNamespaceHandle()
    ||original.method!=='POST'||!/^\/consumers(?:\/[a-f\d-]{36}\/(?:acls|key-auth))?$/i.test(original.path))throw blocked('PORTAL_PREPARATION_SUPPORT_PACKET_INVALID');
  const history=await this.ownership(original.transportScope);this.execution.assertScheduledPortalPreparationPhase(original);
  const expected=['/services','/routes','/plugins',...[...new Set<string>(history.grants.filter(row=>this.authenticationRisk(row)).map(row=>row.consumer_id))].flatMap(id=>[`/consumers/${id}`,`/consumers/${id}/acls`])];
  if(paths.length!==expected.length||paths.some((path,index)=>path!==expected[index]))throw blocked('PORTAL_PREPARATION_SUPPORT_PATHS_CHANGED');
 }

 private async ownership(scope:string):Promise<Ownership>{
  const publications=await this.db.query<any>(`SELECT p.*, proof.publication_id,proof.publication_revision,
   proof.publication_proof_secret,proof.publication_proof_hmac,proof.workflow_id AS proof_workflow_id,
   proof.workflow_execution_id,proof.workflow_plan_revision,proof.workflow_plan_hash,
   e.state AS proof_execution_state,w.state AS proof_workflow_state,w.kind AS proof_workflow_kind
   FROM portal_publications p LEFT JOIN portal_publication_proofs proof ON proof.cluster_id=p.cluster_id
   AND proof.workspace_id=p.workspace_id AND proof.publication_id=p.id AND proof.publication_revision=p.published_revision
   LEFT JOIN workflow_executions e ON e.cluster_id=proof.cluster_id AND e.workspace_id=proof.workspace_id AND e.id=proof.workflow_execution_id
   LEFT JOIN workflows w ON w.cluster_id=proof.cluster_id AND w.workspace_id=proof.workspace_id AND w.id=proof.workflow_id
   WHERE p.transport_scope=$1 AND (p.published_revision IS NOT NULL OR p.state='pending') ORDER BY p.id LIMIT 10001`,[scope]);
  const grants=await this.db.query<any>('SELECT * FROM portal_application_grants WHERE transport_scope=$1 ORDER BY id LIMIT 10001',[scope]);
  const credentials=await this.db.query<any>(`SELECT c.* FROM portal_credentials c JOIN portal_application_grants g
   ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.grant_id
   WHERE g.transport_scope=$1 ORDER BY c.id LIMIT 10001`,[scope]);
  if(publications.length+grants.length+credentials.length>10000)throw blocked('PORTAL_AUTH_GRAPH_BUDGET');
  return {publications,grants,credentials};
 }
 private managed(input:PortalNativePacket | PortalPreparedPacket,history:Ownership):boolean{
  const parts=input.canonicalPath.split('/').filter(Boolean).map(part=>decodeURIComponent(part).toLowerCase());
  const consumer=parts[0]==='consumers'?parts[1]:undefined;
  const consumerIds=new Set(history.grants.map(row=>row.consumer_id));
  if(consumer&&consumerIds.has(consumer))return true;
  const body=input.body as any,before=input.before as any;
  // Reserved membership is an authorization fact. Adding it to an unrelated
  // Consumer would bypass the developer request and credential approval flow.
  // Removing an externally introduced rogue membership remains possible via
  // the ordinary audited recycle path; it grants no Portal access.
  if(parts[0]==='consumers'&&parts[2]==='acls'&&input.method!=='DELETE'){
   const group=Object.hasOwn(body??{},'group')?body.group:before?.group;
   if(typeof group==='string'&&/^kos-portal-api-[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(group))return true;
  }
  // A deleted native UUID can be recreated under a different Consumer. Its
  // immutable historical identity must remain protected as well as its parent.
  if(parts[0]==='consumers'&&['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(parts[2])){
   const credentialIds=new Set([...history.credentials.map(row=>row.kong_id),...history.grants.map(row=>row.acl_id)]);
   if([parts[3],body?.id,before?.id].some(value=>typeof value==='string'&&credentialIds.has(value.toLowerCase())))return true;
  }
  // Parent identity can come from an archive/operation rather than the URL.
  return [input.parentId,before?.consumer?.id,body?.consumer?.id].some(value=>typeof value==='string'&&consumerIds.has(value.toLowerCase()))
   ||parts[0]==='consumers'&&[body?.id,before?.id].some(value=>typeof value==='string'&&consumerIds.has(value.toLowerCase()));
 }
 private publications(history:Ownership):PortalPublicationBoundary[]{
  return history.publications.map(row=>{
   if(row.published_revision!==null){
    if(row.proof_execution_state!=='succeeded'||row.proof_workflow_state!=='succeeded'||row.proof_workflow_kind!=='portal-publication')throw blocked('PORTAL_PUBLICATION_PROOF_INVALID');
    let proof;try{proof=decodePublicationProof({...row,workflow_id:row.proof_workflow_id},this.secrets);}catch{throw blocked('PORTAL_PUBLICATION_PROOF_INVALID');}
    if(proof.serviceId!==row.service_id||proof.aclGroup!==row.acl_group||proof.aclPluginId!==row.acl_plugin_id||proof.keyAuthPluginId!==row.key_auth_plugin_id
     ||proof.service?.id!==row.service_id||proof.aclPlugin?.id!==proof.aclPluginId||proof.keyAuthPlugin?.id!==proof.keyAuthPluginId)throw blocked('PORTAL_PUBLICATION_PROOF_INVALID');
   }
   return {id:row.id,serviceId:row.service_id,aclGroup:row.acl_group,keyAuthPluginId:row.key_auth_plugin_id,aclPluginId:row.acl_plugin_id,established:row.published_revision!==null};
  });
 }
 /** SQL deferred constraints prove a released reservation had no execution or
  * issued native identity. Its historical ownership remains in managed(). */
 private authenticationRisk(grant:any):boolean {
  return grant.state!=='revoked'&&grant.reservation_released_at==null;
 }
 private async capture(input:PortalNativePacket,permit:PortalBoundaryReadPermit,history:Ownership):Promise<{graph:PortalGraph;risks:PortalConsumerBoundary[]}>{
  return this.captureGraph(input.clusterId,history,(paths,fn,limits)=>this.execution.runPortalBoundaryRead(permit,paths,fn,limits),input);
 }
 private async captureGraph(clusterId:string,history:Ownership,
  runRead:<T>(paths:readonly string[],fn:()=>Promise<T>,limits:{maxCalls:number;maxPages:number;maxRecords:number;maxBytes:number;timeoutMs:number})=>Promise<T>,
  nativeChange?:Readonly<PortalNativePacket | PortalPreparedPacket>):Promise<{graph:PortalGraph;risks:PortalConsumerBoundary[]}>{
  // Revoked rows retain ownership forever. Only a terminal revoke may remove
  // authentication risk; SQL constraints couple that state to exact receipts.
  const liveGrants=history.grants.filter(row=>this.authenticationRisk(row));
  const consumerIds=[...new Set<string>(liveGrants.map(row=>row.consumer_id))];
  const paths=['/services','/routes','/plugins',...consumerIds.flatMap(id=>[`/consumers/${id}`,`/consumers/${id}/acls`])];
  if(paths.length>128)throw blocked('PORTAL_AUTH_GRAPH_BUDGET');
  return runRead(paths,async()=>{
   let pages=0,records=0,bytes=0;
   const list=async(path:string):Promise<any[]>=>{
    const result:any[]=[],seen=new Set<string>();let cursor:string|undefined;
    do{
     if(++pages>100)throw blocked('PORTAL_AUTH_GRAPH_BUDGET');
     const page=await this.kong.list(clusterId,path,{size:100},cursor);
     if(!Array.isArray(page.items))throw blocked('PORTAL_AUTH_GRAPH_INCOMPLETE');
     records+=page.items.length;bytes+=Buffer.byteLength(JSON.stringify(page.items));
     if(records>10000||bytes>32*1024*1024)throw blocked('PORTAL_AUTH_GRAPH_BUDGET');
     result.push(...page.items);
     if(page.nextCursor){if(seen.has(page.nextCursor))throw blocked('PORTAL_AUTH_GRAPH_INCOMPLETE');seen.add(page.nextCursor);}
     cursor=page.nextCursor??undefined;
    }while(cursor);return result;
   };
   const graph:PortalGraph={services:await list('/services'),routes:await list('/routes'),plugins:await list('/plugins')};
   const risks:PortalConsumerBoundary[]=[];
   for(const consumerId of consumerIds){
    const grants=liveGrants.filter(row=>row.consumer_id===consumerId);
    let consumer:any;
    try{consumer=await this.kong.request(clusterId,'GET',`/consumers/${consumerId}`);}catch(error:any){
     if(error?.getStatus?.()!==404)throw error;
     if(grants.some(row=>['active','rotating','revoking'].includes(row.state)))throw blocked('PORTAL_MANAGED_CONSUMER_MISSING');
    }
    if(consumer&&consumer.id!==consumerId)throw blocked('PORTAL_AUTH_GRAPH_INVALID');
    const rows=consumer?await list(`/consumers/${consumerId}/acls`):[];
    const groups=rows.map(row=>{if(!uuid.test(row.id??'')||typeof row.group!=='string'||!row.group||row.consumer?.id!==consumerId)throw blocked('PORTAL_AUTH_GRAPH_INVALID');return row.group;});
    const parts=nativeChange?.canonicalPath.split('/').filter(Boolean)??[];
    if(nativeChange&&parts[0]==='consumers'&&parts[1]?.toLowerCase()===consumerId&&parts[2]==='acls'){
     const target=parts[3]?.toLowerCase(),before=nativeChange.before as any,body=nativeChange.body as any;
     const prospective=rows.filter(row=>row.id!==target&&row.id!==before?.id);
     if(nativeChange.method!=='DELETE')prospective.push({...before,...body,id:body?.id??before?.id??('operationId' in nativeChange?nativeChange.operationId:nativeChange.nativeId),consumer:{id:consumerId}});
     groups.splice(0,groups.length,...prospective.map(row=>row.group));
    }
    for(const grant of grants)risks.push({consumerId,publicationId:grant.publication_id,groups:[...new Set([...groups,grant.acl_group])]});
   }
   return {graph,risks};
  },{maxCalls:250,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
 }
 /** A current private metadata recovery ancestor permits only a bounded actual
  * graph observation. There is no prospective packet or native exception. */
 async assertCurrentIssueRecoveryBoundary():Promise<void>{
  const proof=await this.execution.currentIssueActivationRecovery();
  const history=await this.ownership(proof.transportScope),stamp=this.secrets.fingerprint(history);
  if(!history.grants.some(row=>row.workflow_id===proof.workflowId&&row.cluster_id===proof.clusterId&&row.workspace_id===proof.workspaceId))throw blocked('PORTAL_RECOVERY_SUBJECT_MISMATCH');
  const publications=this.publications(history);
  const capture=await this.captureGraph(proof.clusterId,history,(paths,fn,limits)=>this.execution.runPortalRecoveryBoundaryRead(paths,fn,limits));
  assertPortalAuthenticationBoundary(capture.graph,publications,capture.risks);
  if(this.secrets.fingerprint(await this.ownership(proof.transportScope))!==stamp)throw changed();
  await this.execution.currentIssueActivationRecovery();
 }
 private async prospective(input:PortalNativePacket | PortalPreparedPacket,graph:PortalGraph,history:Ownership):Promise<void>{
  const match=/^\/(services|routes|plugins)(?:\/([^/]+))?$/.exec(input.canonicalPath);if(!match)return;
  const type=match[1] as keyof PortalGraph,id=match[2]?.toLowerCase(),rows=graph[type],current=id?rows.find(row=>row.id===id):undefined;
  if(input.method==='PATCH'||input.method==='DELETE')assertPortalCaptureStable(input.before,current,value=>this.secrets.fingerprint(value));
  if(input.method==='DELETE'){graph[type]=rows.filter(row=>row.id!==id);return;}
  let next=normalizeEntityAuthorizationView(type,{...current,...object(input.body)});
  if(input.method==='POST'||input.method==='PUT'){
   const paths=[`/schemas/${type}`,...(type==='plugins'?[`/plugins/schema/${encodeURIComponent(next.name)}`]:[])];
   const schemas=await this.execution.runInternalRead(input.clusterId,'entity-preflight',async()=>({entity:await this.kong.schema(input.clusterId,type),
    config:type==='plugins'?await this.kong.pluginSchema(input.clusterId,next.name):null}),{paths,maxCalls:4});
   next=defaults(next,schemas.entity);
   // Kong 1.5's old plugin-schema endpoint returns config fields directly.
   if(type==='plugins')next.config=defaults(object(next.config??{}),schemas.config);
   next.id=next.id??id??('operationId' in input?input.operationId:input.nativeId);
   if(rows.some(row=>row.id===next.id))throw blocked('PORTAL_AUTH_GRAPH_CHANGED');
  }
  next=normalizeEntityAuthorizationView(type,next);
  for(const pub of history.publications){
   const serviceAffected=type==='services'&&next.id===pub.service_id;
   const routeAffected=type==='routes'&&(current?.service?.id===pub.service_id||next.service?.id===pub.service_id);
   const pluginAffected=type==='plugins'&&[pub.acl_plugin_id,pub.key_auth_plugin_id].includes(next.id);
   if(routeAffected&&current?.service?.id&&current.service.id!==next.service?.id)throw blocked('PORTAL_PUBLISHED_BINDING_IMMUTABLE');
   if(serviceAffected||routeAffected||pluginAffected){
    const scope=await this.workspaces.listScope(pub.cluster_id,pub.workspace_id);
    if(!this.workspaces.matches(scope,next))throw blocked('PORTAL_PUBLISHED_WORKSPACE_IMMUTABLE');
   }
  }
  graph[type]=id?rows.map(row=>row.id===id?next:row):[...rows,next];
 }
 /** An ordinary credential create/restore cannot change Services, Routes,
  * Plugins or a managed Consumer's ACLs. Prove that exact disjoint footprint
  * on every invocation; do not cache a graph, permission, owner or allowance.
  * Final Native pre-send still performs its original full graph observation. */
 private async ordinaryCredentialDisjoint(input:Readonly<PortalPreparedPacket>,history:Ownership,stamp:string):Promise<boolean>{
  const frame=this.execution.current();
  if(!frame.actor||!frame.sessionId||!['actor','operation'].includes(frame.kind)
    ||this.execution.hasEntityScheduledNamespace()||this.execution.hasWorkflowScheduledNamespace()
    ||input.method!=='POST'||!['create','restore'].includes(input.mutationAction)||input.before!==null)return false;
  const match=/^\/consumers\/([a-f\d-]{36})\/(key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)$/.exec(input.canonicalPath);
  if(!match||!uuid.test(match[1])||input.parentId!==match[1]||input.credentialKind!==match[2])return false;
  const body=object(input.body),parentId=match[1],kind=match[2],packetStamp=this.secrets.fingerprint(input);
  const live=()=>{if(this.execution.current()!==frame||this.secrets.fingerprint(input)!==packetStamp)throw changed();};
  if(body.id!==input.nativeId||!uuid.test(input.nativeId))return false;
  // Published ownership keeps its original authenticated receipt checks,
  // even when this packet has no graph effect on the publication.
  this.publications(history);
  if(body.consumer!==undefined&&(!body.consumer||typeof body.consumer!=='object'||Array.isArray(body.consumer)||body.consumer.id!==parentId))return false;
  // Current and proposed reserved memberships remain on the complete old
  // boundary path. Names alone never prove that a Consumer is unmanaged.
  if(kind==='acls'&&(typeof body.group!=='string'||!body.group||/^kos-portal-api-/i.test(body.group)
    ||history.publications.some(row=>row.acl_group===body.group)||history.grants.some(row=>row.acl_group===body.group)))return false;
  const path=`/consumers/${parentId}`;let consumer:any;
  try{consumer=await this.execution.runInternalRead(input.clusterId,'entity-preflight',()=>this.kong.request(input.clusterId,'GET',path),
    {paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000,workspaceId:input.workspaceId});}
  catch(error){live();if(error instanceof HttpException&&error.getStatus()===404)return false;throw error;}
  live();if(consumer?.id!==parentId||typeof consumer.username!=='string'||!consumer.username
    ||/^kos-portal-/i.test(consumer.username)||history.grants.some(row=>row.id===consumer.custom_id))return false;
  const scope=await this.workspaces.listScope(input.clusterId,input.workspaceId);
  live();if(!this.workspaces.matches(scope,consumer))return false;
  const current=await this.ownership(input.transportScope);
  live();if(this.secrets.fingerprint(current)!==stamp||this.managed(input,current))throw changed();
  return true;
 }
 /** A new, absent, unpublished Service has no reachable Route surface yet.
  * This reduces compiler preflight only; the final-send full graph remains
  * mandatory and observes any new native references or ownership changes. */
 private async ordinaryAbsentServiceCreate(input:Readonly<PortalPreparedPacket>,history:Ownership,stamp:string):Promise<boolean>{
  const frame=this.execution.current(),body=input.body as any;
  if(!frame.actor||!frame.sessionId||!['actor','operation'].includes(frame.kind)
   ||this.execution.hasEntityScheduledNamespace()||this.execution.hasWorkflowScheduledNamespace()
   ||input.method!=='POST'||input.mutationAction!=='create'||input.canonicalPath!=='/services'
   ||input.before!==null||input.parentId!==undefined||input.credentialKind!==undefined
   ||!body||typeof body!=='object'||Array.isArray(body)||body.id!==input.nativeId||!uuid.test(input.nativeId))return false;
  this.publications(history);
  if(history.publications.some(row=>row.service_id===input.nativeId))return false;
  const packetStamp=this.secrets.fingerprint(input),live=()=>{
   if(this.execution.current()!==frame||this.secrets.fingerprint(input)!==packetStamp)throw changed();
  };
  const path=`/services/${input.nativeId}`;let absent=false;
  try{await this.execution.runInternalRead(input.clusterId,'entity-preflight',()=>this.kong.request(input.clusterId,'GET',path),
   {paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000,workspaceId:input.workspaceId});}
  catch(error){live();if(error instanceof HttpException&&error.getStatus()===404)absent=true;else throw error;}
  live();if(!absent)return false;
  const current=await this.ownership(input.transportScope);
  live();if(this.secrets.fingerprint(current)!==stamp)throw changed();
  return true;
 }
 /** Fixed compiler preflight. These reads cannot grant the managed-object
  * exception or create a mutation/metrics fence; before-send stays separate. */
 async assertPreparedChange(input:Readonly<PortalPreparedPacket>):Promise<void>{
  const frame=this.execution.current();
  const scheduled=!frame.sessionId?await this.execution.verifyEntityScheduledNamespace('packet'):null;
  if(!frame.actor||(!frame.sessionId&&!scheduled)||frame.clusterId!==input.clusterId||frame.workspaceId!==input.workspaceId
   ||scheduled&&(scheduled.version!==1||scheduled.origin!=='scheduled-entity'||scheduled.sessionId!==null||frame.sessionId!=null
    ||this.execution.current()!==frame||scheduled.actor.id!==frame.actor.id||scheduled.claim.ownerId!==frame.actor.id
    ||scheduled.clusterId!==input.clusterId||scheduled.workspaceId!==input.workspaceId
    ||scheduled.claim.clusterId!==input.clusterId||scheduled.claim.workspaceId!==input.workspaceId
    ||scheduled.claim.ownerCredentialEpoch!==scheduled.credentialEpoch||scheduled.transportScope!==input.transportScope)
   ||!uuid.test(input.nativeId)||!['POST','PATCH','DELETE'].includes(input.method))throw blocked('PORTAL_PREPARATION_CONTEXT_REQUIRED');
  try{
  if(!/^\/(?:services|routes|plugins|consumers)(?:\/|$)/.test(input.canonicalPath))return;
  const identity='[a-f\\d]{8}-[a-f\\d]{4}-[1-8][a-f\\d]{3}-[89ab][a-f\\d]{3}-[a-f\\d]{12}';
  const normalized=new RegExp(`^/(?:services|routes|plugins)(?:/${identity})?$|^/consumers(?:/${identity}(?:/(?:key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)(?:/${identity})?)?)?$`,'i');
  if(!normalized.test(input.canonicalPath))throw blocked('PORTAL_AUTH_NATIVE_PATH_UNSUPPORTED');
  const history=await this.ownership(input.transportScope),stamp=this.secrets.fingerprint(history);
  if(this.managed(input,history))throw blocked('PORTAL_MANAGED_OBJECT');
  if(!history.publications.length&&!history.grants.some(row=>this.authenticationRisk(row)))return;
  if(await this.ordinaryCredentialDisjoint(input,history,stamp))return;
  if(await this.ordinaryAbsentServiceCreate(input,history,stamp))return;
  const capture=await this.captureGraph(input.clusterId,history,(paths,fn,limits)=>
   this.execution.runInternalRead(input.clusterId,'entity-preflight',fn,{...limits,paths:[...paths],workspaceId:input.workspaceId}),input);
  await this.prospective(input,capture.graph,history);
  assertPortalAuthenticationBoundary(capture.graph,this.publications(history),capture.risks);
  if(this.secrets.fingerprint(await this.ownership(input.transportScope))!==stamp)throw changed();
  }finally{
   // This read-only preflight cannot adopt a no-SID actor. Keep the exact
   // original namespace/current frame live across every graph/read await,
   // including the no-publication early return; native permits stay separate.
   if(scheduled&&(await this.execution.verifyEntityScheduledNamespace('packet')!==scheduled||this.execution.current()!==frame))
    throw blocked('PORTAL_PREPARATION_CONTEXT_REQUIRED');
  }
 }
 async assertBeforeNativeSend(input:Readonly<PortalNativePacket>,permit:PortalBoundaryReadPermit):Promise<void>{
  // Certificate/target/cache packets cannot change authentication or ownership.
  if(!/^\/(?:services|routes|plugins|consumers)(?:\/|$)/.test(input.canonicalPath))return;
  const identity='[a-f\\d]{8}-[a-f\\d]{4}-[1-8][a-f\\d]{3}-[89ab][a-f\\d]{3}-[a-f\\d]{12}';
  const normalized=new RegExp(`^/(?:services|routes|plugins)(?:/${identity})?$|^/consumers(?:/${identity}(?:/(?:key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)(?:/${identity})?)?)?$`,'i');
  if(!normalized.test(input.canonicalPath))throw blocked('PORTAL_AUTH_NATIVE_PATH_UNSUPPORTED');
  const history=await this.ownership(input.transportScope),stamp=this.secrets.fingerprint(history);
  if(this.managed(input,history)){
   if(!this.approved)throw blocked('PORTAL_MANAGED_OBJECT');
   try{await this.approved.assertNativeWrite(input);}catch(error){throw infrastructureFailure(error)??blocked('PORTAL_MANAGED_OBJECT');}
  }
  if(!history.publications.length&&!history.grants.some(row=>this.authenticationRisk(row)))return;
  const publications=this.publications(history),capture=await this.capture(input,permit,history);
  await this.prospective(input,capture.graph,history);
  assertPortalAuthenticationBoundary(capture.graph,publications,capture.risks);
  if(this.secrets.fingerprint(await this.ownership(input.transportScope))!==stamp)throw changed();
 }
}
