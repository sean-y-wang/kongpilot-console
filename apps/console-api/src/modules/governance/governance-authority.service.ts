import { ConflictException, ForbiddenException, HttpException, Injectable, OnModuleInit } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongExecutionContextService, KongExecutionFrame, GovernanceReadProof } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { KongService } from '../../infrastructure/kong/kong.service';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import type { EntityActor } from '../entities/entities.types';
import { GOVERNANCE_ENTITY_TYPES, GovernanceAuthorityDescription, GovernanceCaptureInput, GovernanceEntityType, GovernanceReadHandle, GovernanceScheduleLocator, GovernanceScope } from './governance-inventory.types';

const UUID=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const LIMITS={calls:500,pages:100,records:10000,bytes:33554432};
const denied=(code='GOVERNANCE_AUTHORITY_REQUIRED')=>new ForbiddenException({code,message:'治理只读授权已失效或不符合所选范围'});
const changed=(code='GOVERNANCE_SCOPE_CHANGED')=>new ConflictException({code,message:'治理采集期间范围或授权发生变化，请重新发起巡检'});
interface State {
  actor:EntityActor; sessionId?:string; originFrame?:KongExecutionFrame; scope:GovernanceScope;
  module:'governance'|'drift'|'promote'; credentialEpoch:number; permissionVersion:string; expiresAt:number;
  clusterRevision:number; workspaceRevision:number; endpointHmac:string; writeEpoch:string;
  version:string;
  projection:boolean; permittedTypes:GovernanceEntityType[]; busy:boolean; usage:typeof LIMITS;
  schedule?:GovernanceScheduleLocator&{policyHmac:string;side:'source'|'target'};
  schedulePeer?:{scope:GovernanceScope;clusterRevision:number;workspaceRevision:number;endpointHmac:string;writeEpoch:string};
  inventoryCapture?:object;
}

/** A fixed GET origin, independent of recoverable M8 material and native write authority. */
@Injectable()
export class GovernanceAuthorityService implements OnModuleInit {
  private readonly handles=new WeakMap<object,State>();
  private readonly nativeCaptures=new WeakMap<object,{handle:GovernanceReadHandle;fingerprints:Map<string,string>}>();
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly execution:KongExecutionContextService,
    private readonly authz:AuthorizationService,private readonly workspaces:WorkspaceResolverService,private readonly kong:KongService){}
  onModuleInit():void{this.execution.installGovernanceReadPolicy({verifyHandle:handle=>this.verifyHandle(handle),startRead:handle=>this.startRead(handle),endRead:(handle,usage)=>this.endRead(handle,usage),filterResponse:(handle,path,result)=>this.filterResponse(handle,path,result)});}
  private state(handle:unknown):State{const state=handle&&typeof handle==='object'?this.handles.get(handle):undefined;if(!state)throw denied();return state;}
  private id(value:string):string{if(!UUID.test(value??''))throw denied('GOVERNANCE_SCOPE_INVALID');return value;}
  private async identity(id:string,sessionId?:string){
    const row=await this.db.one<any>("SELECT id,username,super_admin,credential_epoch,force_password_change FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL",[this.id(id)]);
    const epoch=Number(row?.credential_epoch);if(!row||row.force_password_change||!Number.isSafeInteger(epoch)||epoch<1)throw denied('GOVERNANCE_OWNER_INACTIVE');
    let expiresAt=Date.now()+120000;
    if(sessionId){const session=await this.db.one<any>('SELECT expires_at,credential_epoch FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()',[this.id(sessionId),id]);
      if(!session||Number(session.credential_epoch)!==epoch)throw denied('GOVERNANCE_SESSION_EXPIRED');expiresAt=Math.min(expiresAt,new Date(session.expires_at).getTime());}
    return {actor:{id:row.id,username:row.username,superAdmin:row.super_admin===true},epoch,expiresAt};
  }
  private async registry(cid:string,wid:string){
    const cluster=await this.db.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL',[this.id(cid)]);
    const workspace=await this.workspaces.resolve(cid,this.id(wid));
    if(!cluster||!/^1\.5\.\d+$/.test(cluster.version??'')||['disabled','incompatible'].includes(cluster.status)||workspace.status!=='active')throw denied('GOVERNANCE_SCOPE_UNAVAILABLE');
    const transportScope=transportScopeFor(cluster.admin_url,cluster.transport_scope);
    return {cluster,workspace,transportScope,endpointHmac:this.secrets.fingerprint({url:cluster.admin_url,scope:transportScope,version:cluster.version,secret:cluster.connection_secret??null,enabled:cluster.enabled_plugins??[]})};
  }
  private async writeEpoch(scope:GovernanceScope){
    const row=await this.db.one<any>(`SELECT count(*)::text AS count,max(f.created_at)::text AS latest_time,
      (SELECT id::text FROM metrics_write_fences WHERE transport_scope=$1 ORDER BY created_at DESC,id DESC LIMIT 1) AS latest_id
      FROM metrics_write_fences f WHERE f.transport_scope=$1`,[scope.transportScope]);
    const active=await this.db.one<any>(`SELECT count(*)::text AS count FROM mutation_operations WHERE
      (transport_scope=$1 OR(transport_scope IS NULL AND cluster_id=$2)) AND state IN('pending','running','uncertain')`,[scope.transportScope,scope.clusterId]);
    if(Number(active?.count??0)>0)throw changed('GOVERNANCE_NATIVE_CHANGE_IN_PROGRESS');
    return this.secrets.fingerprint(row??null);
  }
  private async grants(actor:EntityActor,scope:GovernanceScope,module:State['module']){
    const wid=scope.kind==='cluster'?undefined:scope.workspaceId;
    await this.authz.assertCluster(actor.user,scope.clusterId,module,'read',wid);
    const whole=(type:string)=>scope.kind==='cluster'?this.authz.hasWholeCluster(actor.user,scope.clusterId,type,'read'):this.authz.hasWholeWorkspace(actor.user,scope.clusterId,scope.workspaceId,type,'read');
    let complete=await whole(module);const permittedTypes:GovernanceEntityType[]=[];
    for(const type of GOVERNANCE_ENTITY_TYPES){
      try{await this.authz.assertCluster(actor.user,scope.clusterId,type,'read',wid);permittedTypes.push(type);if(!await whole(type))complete=false;}
      catch(error){if(!(error instanceof HttpException&&error.getStatus()===403))throw error;complete=false;}
    }
    if(!permittedTypes.length)throw denied('GOVERNANCE_NATIVE_READ_REQUIRED');
    if(scope.kind==='cluster'&&!complete)throw denied('GOVERNANCE_CLUSTER_WHOLE_SCOPE_REQUIRED');
    return {projection:!complete,permittedTypes};
  }
  async acquireActor(cid:string,input:GovernanceCaptureInput,actor:EntityActor):Promise<GovernanceReadHandle>{
    const frame=this.execution.current();if(!frame.actor||!frame.sessionId||frame.actor.id!==actor.user?.id||!['http','actor'].includes(frame.kind)||frame.operation||frame.archive)throw denied('GOVERNANCE_HTTP_ORIGIN_REQUIRED');
    this.execution.assertGovernanceOrigin(frame,frame.actor.id,frame.sessionId);
    return this.acquire(cid,input,actor,frame.sessionId,frame);
  }
  private async acquire(cid:string,input:GovernanceCaptureInput,actor:EntityActor,sid?:string,originFrame?:KongExecutionFrame,schedule?:State['schedule']):Promise<GovernanceReadHandle>{
    if(!input||!['cluster','workspace','services'].includes(input.scope)||input.module!==undefined&&!['governance','drift','promote'].includes(input.module))throw denied('GOVERNANCE_SCOPE_INVALID');
    const roots=[...(input.serviceIds??[])].map(id=>this.id(id));if(roots.length>100||new Set(roots).size!==roots.length||(input.scope==='services')!==(roots.length>0))throw denied('GOVERNANCE_SCOPE_INVALID');
    const identity=await this.identity(actor.user.id,sid),workspace=await this.workspaces.resolve(this.id(cid),input.workspaceId??actor.workspaceId),registry=await this.registry(cid,workspace.id);
    const liveActor={...actor,user:identity.actor,workspaceId:workspace.id};
    const scope:GovernanceScope={clusterId:cid,workspaceId:workspace.id,kind:input.scope,rootIds:roots,transportScope:registry.transportScope};
    const snapshot=await this.authz.snapshot(identity.actor),module=input.module??'governance',grants=await this.grants(liveActor,scope,module);
    const state:State={actor:liveActor,sessionId:sid,originFrame,scope,module,credentialEpoch:identity.epoch,permissionVersion:snapshot.version,expiresAt:identity.expiresAt,
      clusterRevision:registry.cluster.revision,workspaceRevision:registry.workspace.revision,endpointHmac:registry.endpointHmac,writeEpoch:await this.writeEpoch(scope),version:registry.cluster.version,...grants,
      busy:false,usage:{calls:0,pages:0,records:0,bytes:0},schedule};
    const handle=Object.freeze({}) as GovernanceReadHandle;this.handles.set(handle,state);await this.assertCurrent(handle);return handle;
  }
  private async scheduleRow(locator:GovernanceScheduleLocator){
    for(const id of [locator.scheduleId,locator.clusterId,locator.workspaceId,locator.ownerUserId,locator.runId])this.id(id);
    const row=await this.db.one<any>(`SELECT s.*,v.payload,v.policy_hmac,r.id AS schedule_run_id,r.schedule_version,r.scheduled_at,r.creator_id,
      r.lease_generation,r.lease_until,r.state AS run_state FROM governance_schedules s JOIN governance_schedule_versions v
      ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=s.current_version
      JOIN governance_schedule_runs r ON r.cluster_id=s.cluster_id AND r.workspace_id=s.workspace_id AND r.schedule_id=s.id AND r.id=$4
      WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3 AND s.state='active'`,[locator.scheduleId,locator.clusterId,locator.workspaceId,locator.runId]);
    if(!row||row.owner_user_id!==locator.ownerUserId||row.creator_id!==locator.ownerUserId||row.current_version!==locator.version||row.schedule_version!==locator.version||row.revision!==locator.revision
      ||row.run_state!=='running'||row.lease_generation!==locator.leaseGeneration||new Date(row.lease_until).getTime()<=Date.now()||new Date(row.scheduled_at).toISOString()!==locator.scheduledAt
      ||this.secrets.fingerprint(row.payload)!==row.policy_hmac)throw changed('GOVERNANCE_SCHEDULE_AUTHORITY_CHANGED');
    return row;
  }
  async acquireDueSchedule(locator:GovernanceScheduleLocator&{side?:'source'|'target'}):Promise<GovernanceReadHandle>{
    if(this.execution.peek())throw denied('GOVERNANCE_TIMER_ORIGIN_REQUIRED');
    const row=await this.scheduleRow(locator),payload=row.payload,side=locator.side??'source';
    if(side==='target'&&(payload.kind!=='drift'||!payload.target))throw denied('GOVERNANCE_SCHEDULE_TARGET_INVALID');
    const target=side==='target'?payload.target:{clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:payload.scope,serviceIds:payload.serviceIds};
    const identity=await this.identity(row.owner_user_id);
    const sourceRegistry=await this.registry(row.cluster_id,row.workspace_id);if(row.transport_scope!==sourceRegistry.transportScope)throw changed('GOVERNANCE_SCHEDULE_TRANSPORT_CHANGED');
    const handle=await this.acquire(target.clusterId,{scope:target.scope??'workspace',workspaceId:target.workspaceId,serviceIds:target.serviceIds,module:payload.kind==='drift'?'drift':'governance'},
      {user:identity.actor,workspaceId:target.workspaceId,requestId:`governance-schedule-${locator.runId}`},undefined,undefined,{...locator,policyHmac:row.policy_hmac,side});
    if(payload.kind==='drift'){
      const peer=side==='source'?payload.target:{clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:payload.scope,serviceIds:payload.serviceIds},registry=await this.registry(peer.clusterId,peer.workspaceId);
      const peerScope:GovernanceScope={clusterId:peer.clusterId,workspaceId:peer.workspaceId,kind:peer.scope??'workspace',rootIds:peer.serviceIds??[],transportScope:registry.transportScope};
      if(peerScope.transportScope===this.state(handle).scope.transportScope)throw denied('GOVERNANCE_DRIFT_DISTINCT_TRANSPORT_REQUIRED');
      await this.grants({user:identity.actor,workspaceId:peer.workspaceId},peerScope,'drift');
      this.state(handle).schedulePeer={scope:peerScope,clusterRevision:registry.cluster.revision,workspaceRevision:registry.workspace.revision,endpointHmac:registry.endpointHmac,writeEpoch:await this.writeEpoch(peerScope)};
    }
    await this.assertCurrent(handle);return handle;
  }
  async assertCurrent(handle:GovernanceReadHandle):Promise<void>{
    const state=this.state(handle);if(Date.now()>=state.expiresAt)throw denied('GOVERNANCE_AUTHORITY_EXPIRED');
    if(state.originFrame&&state.sessionId)this.execution.assertGovernanceOrigin(state.originFrame,state.actor.user.id,state.sessionId);
    const identity=await this.identity(state.actor.user.id,state.sessionId);if(identity.epoch!==state.credentialEpoch)throw changed('GOVERNANCE_CREDENTIALS_CHANGED');
    if(await this.authz.permissionVersion(identity.actor)!==state.permissionVersion)throw changed('GOVERNANCE_PERMISSIONS_CHANGED');
    const registry=await this.registry(state.scope.clusterId,state.scope.workspaceId);
    if(registry.cluster.revision!==state.clusterRevision||registry.workspace.revision!==state.workspaceRevision||registry.transportScope!==state.scope.transportScope||registry.endpointHmac!==state.endpointHmac)throw changed();
    if(await this.writeEpoch(state.scope)!==state.writeEpoch)throw changed('GOVERNANCE_CONFIGURATION_CHANGED');
    if(state.schedule){const row=await this.scheduleRow(state.schedule);if(row.policy_hmac!==state.schedule.policyHmac)throw changed('GOVERNANCE_SCHEDULE_AUTHORITY_CHANGED');
      const target=state.schedule.side==='target'?row.payload.target:{clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:row.payload.scope??'workspace',serviceIds:row.payload.serviceIds??[]};
      if(target.clusterId!==state.scope.clusterId||target.workspaceId!==state.scope.workspaceId||(target.scope??'workspace')!==state.scope.kind||this.secrets.fingerprint(target.serviceIds??[])!==this.secrets.fingerprint(state.scope.rootIds))throw changed('GOVERNANCE_SCHEDULE_AUTHORITY_CHANGED');
      const sourceRegistry=await this.registry(row.cluster_id,row.workspace_id);if(row.transport_scope!==sourceRegistry.transportScope)throw changed('GOVERNANCE_SCHEDULE_TRANSPORT_CHANGED');
      if(state.schedulePeer){const peer=state.schedulePeer,current=await this.registry(peer.scope.clusterId,peer.scope.workspaceId);
        if(current.cluster.revision!==peer.clusterRevision||current.workspace.revision!==peer.workspaceRevision||current.transportScope!==peer.scope.transportScope||current.endpointHmac!==peer.endpointHmac||await this.writeEpoch(peer.scope)!==peer.writeEpoch)throw changed('GOVERNANCE_SCHEDULE_PEER_CHANGED');}
    }
    if(await this.authz.permissionVersion(identity.actor)!==state.permissionVersion)throw changed('GOVERNANCE_PERMISSIONS_CHANGED');
  }
  async description(handle:GovernanceReadHandle):Promise<GovernanceAuthorityDescription>{await this.assertCurrent(handle);const state=this.state(handle);return structuredClone({actor:state.actor,scope:state.scope,projection:state.projection,permittedTypes:state.permittedTypes,permissionVersion:state.permissionVersion,expiresAt:state.expiresAt,version:state.version});}
  async verifyHandle(handle:object):Promise<GovernanceReadProof>{await this.assertCurrent(handle as GovernanceReadHandle);const state=this.state(handle);return {actor:state.actor.user,sessionId:state.sessionId,clusterId:state.scope.clusterId,workspaceId:state.scope.workspaceId,transportScope:state.scope.transportScope,module:state.module,permissionVersion:state.permissionVersion,credentialEpoch:state.credentialEpoch,expiresAt:state.expiresAt,origin:state.schedule?'timer':'http',projection:state.projection,kind:state.scope.kind,rootIds:[...state.scope.rootIds]};}
  private async startRead(handle:object){const state=this.state(handle);if(state.busy)throw denied('GOVERNANCE_READ_ALREADY_RUNNING');state.busy=true;
    try{const proof=await this.verifyHandle(handle);
    const remaining={maxCalls:LIMITS.calls-state.usage.calls,maxPages:LIMITS.pages-state.usage.pages,maxRecords:LIMITS.records-state.usage.records,maxBytes:LIMITS.bytes-state.usage.bytes,timeoutMs:Math.floor(state.expiresAt-Date.now())};
    if(Object.values(remaining).some(value=>value<1))throw denied('GOVERNANCE_BUDGET_EXHAUSTED');return {proof,limits:remaining};}catch(error){state.busy=false;throw error;}}
  private endRead(handle:object,usage:typeof LIMITS){const state=this.state(handle);for(const key of Object.keys(LIMITS) as Array<keyof typeof LIMITS>)state.usage[key]+=usage[key];state.busy=false;}
  async runRead<T>(handle:GovernanceReadHandle,fn:()=>Promise<T>):Promise<T>{return this.execution.runGovernanceRead(handle,fn);}
  usage(handle:GovernanceReadHandle):Readonly<typeof LIMITS>{return Object.freeze({...this.state(handle).usage});}
  /** Private server evidence only. Its token cannot authorize native reads or
   * reveal secrets; fingerprints are recorded exclusively after the actual
   * native response passes the current entity and module read policy. */
  async beginInventoryFingerprints(handle:GovernanceReadHandle):Promise<object>{
    await this.assertCurrent(handle);const state=this.state(handle);
    if(state.busy||state.inventoryCapture)throw denied('GOVERNANCE_INVENTORY_CAPTURE_ALREADY_RUNNING');
    const token=Object.freeze({});state.inventoryCapture=token;this.nativeCaptures.set(token,{handle,fingerprints:new Map()});return token;
  }
  async sealInventoryFingerprints(handle:GovernanceReadHandle,token:object):Promise<Readonly<Record<string,string>>>{
    await this.assertCurrent(handle);const state=this.state(handle),capture=this.nativeCaptures.get(token);
    if(state.busy||state.inventoryCapture!==token||capture?.handle!==handle)throw denied('GOVERNANCE_INVENTORY_CAPTURE_REQUIRED');
    const result=Object.freeze(Object.fromEntries([...capture.fingerprints.entries()].sort(([a],[b])=>a.localeCompare(b))));
    this.discardInventoryFingerprints(handle,token);return result;
  }
  discardInventoryFingerprints(handle:GovernanceReadHandle,token:object):void{
    const state=this.state(handle);if(state.inventoryCapture!==token||this.nativeCaptures.get(token)?.handle!==handle)return;
    delete state.inventoryCapture;this.nativeCaptures.delete(token);
  }
  private recordInventoryFingerprint(handle:GovernanceReadHandle,type:string,entity:any):void{
    const token=this.state(handle).inventoryCapture,capture=token?this.nativeCaptures.get(token):undefined;if(!capture)return;
    const queue:Array<{value:unknown;depth:number}>=[{value:entity,depth:0}];let nodes=0;
    while(queue.length){const item=queue.pop()!;if(++nodes>10000||item.depth>32)throw changed('GOVERNANCE_PAYLOAD_BUDGET');
      if(item.value&&typeof item.value==='object')for(const [key,value] of Object.entries(item.value)){if(['__proto__','prototype','constructor'].includes(key))throw changed('GOVERNANCE_PAYLOAD_KEY');queue.push({value,depth:item.depth+1});}}
    const key=`${type}:${entity.id}`,fingerprint=this.secrets.fingerprint(entity),previous=capture.fingerprints.get(key);
    if(previous&&previous!==fingerprint)throw changed('GOVERNANCE_CONFIGURATION_CHANGED');
    capture.fingerprints.set(key,fingerprint);
  }
  async managedBoundary(handle:GovernanceReadHandle,input:{entityType:string;nativeId:string;parentId?:string;payload:Record<string,unknown>}):Promise<'none'|'portal'|'metrics'>{
    await this.assertCurrent(handle);const physical=this.state(handle).scope.transportScope;
    if(await this.db.one(`SELECT id FROM portal_application_grants WHERE transport_scope=$1 AND(consumer_id=$2::uuid OR acl_id=$2::uuid OR consumer_id=$3::uuid)
      UNION ALL SELECT c.id FROM portal_credentials c JOIN portal_application_grants g ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.grant_id
      WHERE g.transport_scope=$1 AND(c.kong_id=$2::uuid OR c.consumer_id=$3::uuid)
      UNION ALL SELECT id FROM portal_publications WHERE transport_scope=$1 AND(service_id=$2::uuid OR acl_plugin_id=$2::uuid OR key_auth_plugin_id=$2::uuid) LIMIT 1`,[physical,input.nativeId,input.parentId??null]))return 'portal';
    if(input.entityType==='plugins'){
      const p=input.payload;if(p.name==='prometheus'&&!p.service&&!p.route&&!p.consumer)return 'metrics';
      if(await this.db.one("SELECT id FROM mutation_operations WHERE transport_scope=$1 AND entity_type='plugins' AND entity_id=$2 AND idempotency_key LIKE 'metrics:%' AND state='succeeded' LIMIT 1",[physical,input.nativeId]))return 'metrics';
      const endpoint=(p.config as any)?.http_endpoint;if(p.name==='http-log'&&typeof endpoint==='string')try{if(['telemetry-collector','metrics-collector'].includes(new URL(endpoint).hostname))return 'metrics';}catch{/* not evidence of a managed endpoint */}
    }return 'none';
  }
  private async visible(state:State,type:GovernanceEntityType|'targets',entity:any,parent?:any):Promise<boolean>{
    if(!entity||!UUID.test(entity.id??''))throw denied('GOVERNANCE_ENTITY_ID_INVALID');
    if(!state.projection){
      if(state.scope.kind==='cluster')return true;
      // Whole native grants authorize the subject itself, including a broken
      // FK that inspection must report. Do not traverse its FK as if this
      // were a recoverable M8 capture. Child scope comes from a fresh parent.
      if(!this.workspaces.matches(await this.workspaces.listScope(state.scope.clusterId,state.scope.workspaceId),type==='targets'?parent:entity))return false;
      if(type==='plugins'){
        const candidate={...entity};
        // A confirmed missing binding does not make the owned Plugin
        // unreadable for inspection. Existing bindings still use the real
        // inherited permission policy, including cross-workspace denial.
        for(const [field,parentType] of [['service','services'],['route','routes'],['consumer','consumers']]){
          const id=entity[field]?.id;if(!id)continue;if(!UUID.test(id)){delete candidate[field];continue;}
          try{await this.execution.runInternalRead(state.scope.clusterId,'authorization',()=>this.kong.request(state.scope.clusterId,'GET',`/${parentType}/${id}`),{paths:[`/${parentType}/${id}`],maxCalls:1});}
          catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;delete candidate[field];}
        }
        try{await this.authz.assertEntity(state.actor.user,state.scope.clusterId,'plugins','read',candidate,state.scope.workspaceId);}
        catch(error){if(error instanceof HttpException&&error.getStatus()===403)return false;throw error;}
      }
      return true;
    }
    const wid=state.scope.workspaceId;
    try{await this.authz.assertEntity(state.actor.user,state.scope.clusterId,type,'read',entity,wid);
      if(type!=='targets')await this.authz.assertScopedResource(state.actor.user,state.scope.clusterId,state.module,'read',type,entity,wid);
      else{const parent=await this.execution.runInternalRead(state.scope.clusterId,'authorization',()=>this.kong.request(state.scope.clusterId,'GET',`/upstreams/${entity.upstream?.id}`),{paths:[`/upstreams/${entity.upstream?.id}`],maxCalls:1});
        await this.authz.assertScopedResource(state.actor.user,state.scope.clusterId,state.module,'read','upstreams',parent,wid);}
      return true;}catch(error){if(error instanceof HttpException&&error.getStatus()===403)return false;throw error;}
  }
  private async filterResponse(handle:object,path:string,result:any):Promise<any>{
    await this.assertCurrent(handle as GovernanceReadHandle);const state=this.state(handle);
    if(path==='/')return{version:result?.version,endpoints:Array.isArray(result?.endpoints)?result.endpoints.filter((value:unknown)=>typeof value==='string'&&value.length<=256):[]};
    if(path==='/plugins/enabled')return{enabled_plugins:result?.enabled_plugins};
    if(path.startsWith('/schemas/')||path.startsWith('/plugins/schema/')){
      const queue:Array<{value:unknown;depth:number}>=[{value:result,depth:0}];let nodes=0;
      while(queue.length){const item=queue.pop()!;if(++nodes>10000||item.depth>32)throw changed('GOVERNANCE_SCHEMA_BUDGET');
        if(item.value&&typeof item.value==='object')for(const [key,value] of Object.entries(item.value)){if(['__proto__','prototype','constructor'].includes(key))throw changed('GOVERNANCE_SCHEMA_INVALID');queue.push({value,depth:item.depth+1});}}
      return stripSensitiveSchemaDefaults(result,this.secrets);
    }
    const parts=path.split('/').filter(Boolean),target=parts[0]==='upstreams'&&parts[2]==='targets',type=(target?'targets':parts[0]) as GovernanceEntityType|'targets';
    if(!state.permittedTypes.includes(target?'upstreams':type as GovernanceEntityType))throw denied('GOVERNANCE_NATIVE_READ_REQUIRED');
    const nested=parts[0]==='services'&&parts[2]==='routes',actualType=nested?'routes':type;
    const parent=target?await this.execution.runInternalRead(state.scope.clusterId,'authorization',()=>this.kong.request(state.scope.clusterId,'GET',`/upstreams/${parts[1]}`),{paths:[`/upstreams/${parts[1]}`],maxCalls:1}):undefined;
    const child=(value:any)=>target?{...value,upstream:{id:parts[1]}}:value;
    if(Array.isArray(result?.data)){
      let projected=state.projection;const workspaceScope=await this.workspaces.listScope(state.scope.clusterId,state.scope.workspaceId);
      const data=[];for(const original of result.data){if(target&&original.upstream?.id&&original.upstream.id!==parts[1])throw denied('GOVERNANCE_PARENT_MISMATCH');const entity=child(original);if(await this.visible(state,actualType,entity,parent)){data.push(entity);this.recordInventoryFingerprint(handle as GovernanceReadHandle,actualType,entity);}
        else if(state.scope.kind==='cluster'||this.workspaces.matches(workspaceScope,target?parent:entity))projected=true;}
      await this.assertCurrent(handle as GovernanceReadHandle);return {...result,data,total:null,...(projected?{console_permission_projection:true}:{})};
    }
    if(!await this.visible(state,actualType,child(result),parent))throw denied('GOVERNANCE_ENTITY_ACCESS_DENIED');
    this.recordInventoryFingerprint(handle as GovernanceReadHandle,actualType,child(result));
    await this.assertCurrent(handle as GovernanceReadHandle);return child(result);
  }
}
