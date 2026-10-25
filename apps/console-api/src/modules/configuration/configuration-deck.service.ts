import {ConflictException,ForbiddenException,Injectable,NotFoundException,OnModuleInit} from '@nestjs/common';
import {DbService} from '../../infrastructure/db.service';
import {SecretService,canonicalJson} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import type {AuthUser} from '../../common/auth';
import {AuditService} from '../audit/audit.service';
import {metadataAuditScope} from '../event-producers/native-audit-scope';
import {ConfigurationRepositoryService} from '../config-storage/configuration-repository.service';
import type {DeckConfigurationAccess,DeckSessionIssue,DeckSessionLocator,DeckAuthority,DeckIssueAuthority,DeckReadRequest,DeckPage,DeckPacket} from '../deck-adapter/deck.types';
import {ConfigurationAccessService} from './configuration-access.service';
import {ConfigurationService} from './configuration.service';
import type {ConfigurationAccessHandle,CaptureGraph,CaptureObject} from './configuration.types';
import {PortalCursor} from '../portal/portal-input';
import {configurationId} from './configuration-input';

const denied=()=>new ForbiddenException({code:'CONFIGURATION_DECK_AUTHORITY_DENIED'});
type Actor={user:AuthUser;sessionId:string;clusterId:string;workspaceId?:string;requestId:string};
/** Dedicated protocol authority. Read data comes from a complete encrypted
 * graph and is checked against current native and secret grants per response. */
@Injectable()
export class ConfigurationDeckService implements DeckConfigurationAccess,OnModuleInit{
  private readonly authorities=new WeakSet<object>();
  private readonly cursors=new PortalCursor();
  constructor(private readonly db:DbService,private readonly execution:KongExecutionContextService,private readonly access:ConfigurationAccessService,
    private readonly repo:ConfigurationRepositoryService,private readonly configuration:ConfigurationService,private readonly secrets:SecretService,private readonly audit:AuditService){}
  onModuleInit():void{this.repo.installDeckEvidenceWriter({sessionChanged:async(tx,e)=>{
    const f=this.execution.current(),s=e.after.scope;
    await this.audit.append({actorId:e.after.actorId,clusterId:s.clusterId,workspaceId:s.workspaceId,entityType:'configuration_deck_sessions',entityId:e.after.id,
      action:`configuration.deck.${e.action}`,before:e.before,after:e.after,requestId:f.requestId,ip:f.ip,scopeHints:metadataAuditScope('gitops','configuration_deck_sessions',e.after.id,s.workspaceId)},tx);
  }});}
  private genuine<T extends DeckAuthority|DeckIssueAuthority>(authority:T):T{this.authorities.add(authority);return Object.freeze(authority);}
  private async check(authority:DeckAuthority|DeckIssueAuthority):Promise<ConfigurationAccessHandle>{
    if(!this.authorities.has(authority)||!authority.handle)throw denied();const handle=authority.handle as ConfigurationAccessHandle,state=await this.access.description(handle);
    const locator='locator'in authority?authority.locator:null,cid=locator?.clusterId??(authority as DeckIssueAuthority).clusterId;
    if(state.actor.id!==authority.user.id||state.sessionId!==authority.sessionId||state.scope.clusterId!==cid||locator&&(state.scope.workspaceId!==locator.workspaceId||state.scope.transportScope!==locator.transportScope
      ||state.jobId!==locator.jobId||state.credentialEpoch!==locator.credentialEpoch||state.permissionVersion!==locator.permissionVersion||Date.parse(locator.expiresAt)<=Date.now()))throw denied();
    if(locator){const row=await this.db.one<any>("SELECT * FROM configuration_deck_sessions WHERE id=$1 AND state='active' AND expires_at>now()",[locator.id]);
      if(!row||row.cluster_id!==locator.clusterId||row.workspace_id!==locator.workspaceId||row.transport_scope!==locator.transportScope||row.actor_id!==locator.actorId||row.session_id!==locator.sessionId
        ||row.job_id!==locator.jobId||row.purpose!==locator.purpose||row.permission_version!==locator.permissionVersion||row.credential_epoch!==locator.credentialEpoch||new Date(row.expires_at).toISOString()!==locator.expiresAt
        ||(row.plan_id??undefined)!==locator.planId||(row.plan_revision??undefined)!==locator.planRevision||(row.plan_hash??undefined)!==locator.planHash)throw denied();}
    return handle;
  }
  private async graph(handle:ConfigurationAccessHandle):Promise<CaptureGraph>{
    const state=await this.access.description(handle),row=await this.db.one<any>('SELECT safe_progress FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND actor_id=$4',[state.jobId,state.scope.clusterId,state.scope.workspaceId,state.actor.id]);
    const id=row?.safe_progress.snapshotId??row?.safe_progress.baselineSnapshotId;
    if(typeof id!=='string')throw new ConflictException({code:'CONFIGURATION_DECK_CAPTURE_REQUIRED'});
    let graph=await this.repo.readSnapshot(handle,{scope:state.scope,snapshotId:id,version:row.safe_progress.baselineVersion});
    if(['apply','rollback'].includes(state.purpose))graph=await this.configuration.deckGraphObjects(state.jobId!,graph);
    await this.access.assertHistoricalGraph(handle,graph,true);
    if(!['apply','rollback'].includes(state.purpose)&&graph.objects.some(o=>o.credentialKind==='basic-auth'&&(o.recovery.state!=='complete'||!o.recovery.restorePayload)))throw new ConflictException({code:'CONFIGURATION_DECK_BASIC_PASSWORD_UNAVAILABLE'});
    return graph;
  }
  async authorizeDeckSessionIssue(input:DeckSessionIssue,actor:Actor):Promise<DeckIssueAuthority>{
    const frame=this.execution.current();if(frame.actor?.id!==actor.user.id||frame.sessionId!==actor.sessionId)throw denied();
    const handle=input.purpose==='write'?await this.configuration.deckExecutionHandle(input,actor):await this.access.acquireReadJob(input.jobId),state=await this.access.description(handle);
    if(state.scope.clusterId!==actor.clusterId||actor.workspaceId&&state.scope.workspaceId!==actor.workspaceId)throw denied();
    await this.graph(handle);
    return this.genuine({handle,user:state.actor,sessionId:state.sessionId!,clusterId:state.scope.clusterId,workspaceId:state.scope.workspaceId,jobId:input.jobId,purpose:input.purpose,credentialEpoch:state.credentialEpoch,expiresAt:new Date(state.expiresAt).toISOString()});
  }
  async acquireDeckSession(locator:DeckSessionLocator):Promise<DeckAuthority>{
    // This runs before the guard binds the outer HTTP actor. An isolated
    // verification frame uses the actual DB user and original active SID.
    const user=await this.db.one<any>("SELECT id,username,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false",[configurationId(locator.actorId)]);
    if(!user)throw denied();const actor:AuthUser={id:user.id,username:user.username,superAdmin:user.super_admin===true};
    const handle=await this.execution.runHttp({requestId:this.execution.peek()?.requestId},async()=>{
      this.execution.bindHttpActor(actor,locator.sessionId);
      return this.execution.runActor({actor,clusterId:locator.clusterId,workspaceId:locator.workspaceId,module:'snapshots',action:'read'},()=>locator.purpose==='write'?
        this.configuration.deckExecutionHandle({jobId:locator.jobId,purpose:'write',planId:locator.planId,planRevision:locator.planRevision,planHash:locator.planHash},{user:actor,sessionId:locator.sessionId,clusterId:locator.clusterId,workspaceId:locator.workspaceId,requestId:this.execution.current().requestId??''}):this.access.acquireReadJob(locator.jobId));
    });
    const authority=this.genuine({handle,user:actor,sessionId:locator.sessionId,locator:Object.freeze({...locator})});await this.check(authority);return authority;
  }
  async assertDeckCurrent(authority:DeckAuthority|DeckIssueAuthority,_phase:'request'|'response'):Promise<void>{await this.check(authority);}
  async readDeckRoot(authority:DeckAuthority):Promise<{version:string}>{const handle=await this.check(authority),graph=await this.graph(handle);await this.repo.chargeDeckSessionBudget(handle,authority.locator.id,{pages:0,records:1,bytes:64,calls:0});return{version:graph.kongVersion};}
  private collection(graph:CaptureGraph,input:{type:string;parentId?:string}):CaptureObject[]{
    return graph.objects.filter(o=>o.entityType===input.type||o.entityType==='credentials'&&o.credentialKind===input.type).filter(o=>!input.parentId||o.parentId===input.parentId);
  }
  private shape(o:CaptureObject):Record<string,unknown>{return structuredClone(o.credentialKind==='basic-auth'?o.recovery.restorePayload??o.payload:o.payload);}
  async readDeckCollection(authority:DeckAuthority,input:DeckReadRequest):Promise<DeckPage>{
    const handle=await this.check(authority),graph=await this.graph(handle),binding=this.secrets.fingerprint({session:authority.locator.id,job:authority.locator.jobId,type:input.type,parent:input.parentId??null,tags:input.tags??null,version:graph.versionId,
      objects:graph.objects.map(o=>({key:o.objectKey,id:o.nativeId,before:o.beforeHmac,payload:this.secrets.fingerprint(o.payload)})),permissions:authority.locator.permissionVersion});
    const after=this.cursors.decode(input.cursor,binding)?.offset??0;if(!Number.isSafeInteger(after)||after<0||input.size!==100)throw denied();
    let objects=this.collection(graph,input);if(input.tags){if(input.tags.includes('/'))throw denied();const tags=input.tags.split(',');objects=objects.filter(o=>tags.every(tag=>Array.isArray(o.payload.tags)&&o.payload.tags.includes(tag)));}
    if(after>objects.length)throw denied();const items:Record<string,unknown>[]=[],selected=objects.slice(after,after+100);let calls=0;
    for(const o of selected){if(authority.locator.purpose==='write'){const actual=await this.configuration.readLiveDeckObject(authority,o);items.push(actual.entity);calls+=actual.calls;}else items.push(this.shape(o));}
    await this.repo.chargeDeckSessionBudget(handle,authority.locator.id,{pages:1,records:items.length,bytes:Buffer.byteLength(canonicalJson(items)),calls});await this.check(authority);
    return{items,nextCursor:after+100<objects.length?this.cursors.encode(binding,{offset:after+100}):null};
  }
  async readDeckEntity(authority:DeckAuthority,input:{type:string;id:string;parentId?:string}):Promise<Record<string,unknown>>{
    const handle=await this.check(authority),graph=await this.graph(handle),o=this.collection(graph,input).find(o=>o.nativeId===input.id);if(!o)throw new NotFoundException({code:'CONFIGURATION_DECK_ENTITY_NOT_FOUND'});
    const live=authority.locator.purpose==='write'?await this.configuration.readLiveDeckObject(authority,o):null,entity=live?.entity??this.shape(o);
    await this.repo.chargeDeckSessionBudget(handle,authority.locator.id,{pages:0,records:1,bytes:Buffer.byteLength(canonicalJson(entity)),calls:live?.calls??0});await this.check(authority);return entity;
  }
  async executeDeckPacket(authority:DeckAuthority,input:DeckPacket):Promise<{status:200|201|204;entity?:Record<string,unknown>}>{
    await this.check(authority);if(authority.locator.purpose!=='write')throw denied();return this.configuration.executeDeckPacket(authority,input);
  }
  async authorizeDeckSessionRevoke(actor:Actor,id:string):Promise<DeckAuthority>{
    const row=await this.db.one<any>('SELECT * FROM configuration_deck_sessions WHERE id=$1 AND cluster_id=$2 AND actor_id=$3 AND session_id=$4',[configurationId(id),actor.clusterId,actor.user.id,actor.sessionId]);if(!row)throw denied();
    const locator:DeckSessionLocator={id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,transportScope:row.transport_scope,actorId:row.actor_id,sessionId:row.session_id,jobId:row.job_id,purpose:row.purpose,credentialEpoch:row.credential_epoch,permissionVersion:row.permission_version,revision:row.revision,expiresAt:new Date(row.expires_at).toISOString(),planId:row.plan_id??undefined,planRevision:row.plan_revision??undefined,planHash:row.plan_hash??undefined};
    if(actor.workspaceId&&actor.workspaceId!==row.workspace_id)throw denied();return this.acquireDeckSession(locator);
  }
}
