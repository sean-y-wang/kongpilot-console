import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { AuditService } from '../audit/audit.service';
import type { EntityActor } from '../entities/entities.types';
import { PortalCursor, portalConfirm, portalRevision, requirePortalCas } from '../portal/portal-input';
import { workflowKey } from '../workflows/workflow-validation';
import { assertPublicDraft, boundedName, TOOLBOX_ENTITIES, toolboxId, toolboxObject } from './toolbox-input';

const aad=(cid:string,wid:string,id:string,version:number)=>`draft:${cid}:${wid}:${id}:${version}`;
@Injectable()
export class DraftsService {
  private readonly cursors=new PortalCursor();
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly redis:RedisService,
    private readonly kong:KongService,private readonly context:KongExecutionContextService,private readonly authz:AuthorizationService,
    private readonly workspaces:WorkspaceResolverService,private readonly audit:AuditService){}
  private run<T>(cid:string,actor:EntityActor,action:string,fn:()=>Promise<T>):Promise<T>{
    return this.context.runActor({actor:actor.user,clusterId:toolboxId(cid),workspaceId:actor.workspaceId,module:'drafts',action},fn);
  }
  private async scope(cid:string,actor:EntityActor,action:string){const ws=await this.workspaces.resolve(cid,actor.workspaceId);await this.authz.assertCluster(actor.user,cid,'drafts',action,ws.id);return ws;}
  private async root(cid:string,wid:string,id:string,actor:EntityActor,db=this.db){
    const row=await db.one<any>('SELECT * FROM configuration_drafts WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND owner_user_id=$4',[cid,wid,toolboxId(id),actor.user.id]);
    if(!row)throw new NotFoundException({code:'DRAFT_NOT_FOUND'});return row;
  }
  private summary(row:any){return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,name:row.name,entityType:row.entity_type,nativeId:row.native_id,revision:row.revision,version:row.current_version,state:row.state,createdAt:row.created_at,updatedAt:row.updated_at};}
  private async nativeAccess(cid:string,wid:string,type:string,nativeId:string|null,payload:Record<string,any>|undefined,actor:EntityActor,write:boolean){
    if(!(TOOLBOX_ENTITIES as readonly string[]).includes(type))throw new BadRequestException({code:'INVALID_DRAFT_ENTITY'});
    await this.authz.assertCluster(actor.user,cid,type,write?'write':'read',wid);
    if(nativeId){
      const before=await this.context.runActor({actor:actor.user,clusterId:cid,workspaceId:wid,module:type,action:'read'},()=>this.kong.request(cid,'GET',`/${type}/${toolboxId(nativeId)}`));
      if(write){await this.authz.assertEntity(actor.user,cid,type,'write',before,wid);if(payload){
        const prepared=await this.workspaces.prepareCreate(cid,type,payload,wid);
        await this.authz.assertEntity(actor.user,cid,type,'write',{...before,...prepared},wid);
      }}
    }else if(payload){const prepared=await this.workspaces.prepareCreate(cid,type,payload,wid);await this.authz.assertEntity(actor.user,cid,type,write?'write':'read',prepared,wid);}
    else await this.authz.assertWholeWorkspace(actor.user,cid,wid,type,'read');
  }
  private async payload(row:any,db=this.db){
    const v=await db.one<any>('SELECT * FROM configuration_draft_versions WHERE cluster_id=$1 AND workspace_id=$2 AND draft_id=$3 AND version=$4',[row.cluster_id,row.workspace_id,row.id,row.current_version]);
    if(!v||v.created_by!==row.owner_user_id)throw new ConflictException({code:'DRAFT_VERSION_INVALID'});
    const payload=this.secrets.decrypt<Record<string,unknown>>(v.payload_secret,aad(row.cluster_id,row.workspace_id,row.id,v.version));assertPublicDraft(payload);
    if(this.secrets.fingerprint(payload)!==v.payload_hmac)throw new ConflictException({code:'DRAFT_VERSION_INVALID'});return payload;
  }
  async list(cid:string,query:Record<string,any>,actor:EntityActor){return this.run(cid,actor,'read',async()=>{
    const ws=await this.scope(cid,actor,'read'),size=Number(query.size??20);if(!Number.isInteger(size)||size<1||size>100||query.state!==undefined&&!['active','deleted'].includes(query.state))throw new BadRequestException({code:'INVALID_DRAFT_PAGE'});
    const version=await this.authz.permissionVersion(actor.user),binding=this.secrets.fingerprint({cid,wid:ws.id,owner:actor.user.id,version,size,state:query.state??'active'}),after=this.cursors.decode(query.cursor,binding);
    if(after&&(!Number.isFinite(Date.parse(after.createdAt))||typeof after.id!=='string'))throw new BadRequestException({code:'INVALID_CURSOR'});
    const rows=await this.db.query<any>(`SELECT * FROM configuration_drafts WHERE cluster_id=$1 AND workspace_id=$2 AND owner_user_id=$3 AND state=$4
      AND($5::timestamptz IS NULL OR(created_at,id)<($5::timestamptz,$6::uuid)) ORDER BY created_at DESC,id DESC LIMIT $7`,[cid,ws.id,actor.user.id,query.state??'active',after?.createdAt??null,after?.id??null,size+1]);
    const items=[];for(const row of rows.slice(0,size)){try{await this.nativeAccess(cid,ws.id,row.entity_type,row.native_id,row.native_id?undefined:await this.payload(row),actor,false);items.push(this.summary(row));}catch(error){if(!(error instanceof ForbiddenException||error instanceof NotFoundException))throw error;}}
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    const last=rows[Math.min(size,rows.length)-1];return{items,size,total:null,nextCursor:rows.length>size?this.cursors.encode(binding,{createdAt:new Date(last.created_at).toISOString(),id:last.id}):null};
  });}
  async get(cid:string,id:string,actor:EntityActor){return this.run(cid,actor,'read',async()=>{
    const ws=await this.scope(cid,actor,'read'),epoch=await this.authz.permissionVersion(actor.user),row=await this.root(cid,ws.id,id,actor),payload=await this.payload(row);
    await this.nativeAccess(cid,ws.id,row.entity_type,row.native_id,payload,actor,false);
    if(await this.authz.permissionVersion(actor.user)!==epoch)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    return{entity:this.summary(row),payload};
  });}
  async byKey(cid:string,key:string,actor:EntityActor){return this.run(cid,actor,'read',async()=>{
    const ws=await this.scope(cid,actor,'read'),epoch=await this.authz.permissionVersion(actor.user),row=await this.db.one<any>('SELECT id,actor_id,idempotency_key,cluster_id,workspace_id FROM toolbox_metadata_operations WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4 AND action LIKE \'draft.%\'',[cid,ws.id,actor.user.id,workflowKey(key)]);
    if(!row)throw new NotFoundException({code:'DRAFT_OPERATION_NOT_FOUND'});
    if(await this.authz.permissionVersion(actor.user)!==epoch)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    return{id:row.id,actorId:row.actor_id,idempotencyKey:row.idempotency_key,clusterId:row.cluster_id,workspaceId:row.workspace_id,kind:'draft-metadata',state:'succeeded',metadataCommitted:true,remoteStarted:false,remoteCompleted:false};
  });}
  async save(cid:string,id:string|undefined,body:unknown,actor:EntityActor){
    const value=toolboxObject(body,id?['revision','name','payload']:['name','entityType','nativeId','payload']);
    if(!id&&!(TOOLBOX_ENTITIES as readonly unknown[]).includes(value.entityType))throw new BadRequestException({code:'INVALID_DRAFT_ENTITY'});
    assertPublicDraft(value.payload);boundedName(value.name);if(id)portalRevision(value.revision);if(value.nativeId!==undefined)toolboxId(value.nativeId);
    return this.mutate(cid,id,id?'draft.update':'draft.create',value,actor);
  }
  async archive(cid:string,id:string,body:unknown,actor:EntityActor,restore=false){const value=toolboxObject(body,['revision','confirmed','confirm_name']);portalRevision(value.revision);return this.mutate(cid,id,restore?'draft.restore':'draft.archive',value,actor);}
  private async mutate(cid:string,id:string|undefined,action:string,value:Record<string,any>,actor:EntityActor){return this.run(cid,actor,action==='draft.archive'?'delete':'write',async()=>{
    const permission=action==='draft.archive'?'delete':'write',ws=await this.scope(cid,actor,permission),key=workflowKey(actor.idempotencyKey),requestHmac=this.secrets.fingerprint({cid,wid:ws.id,actor:actor.user.id,id:id??null,action,value});
    return this.redis.withLock(`toolbox-metadata:${actor.user.id}:${key}`,()=>this.db.transaction(async tx=>{
      const previous=await tx.one<any>('SELECT * FROM toolbox_metadata_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
      if(previous){if(previous.request_hmac!==requestHmac||previous.cluster_id!==cid||previous.workspace_id!==ws.id)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return this.secrets.decrypt(previous.result_secret,`toolbox-metadata:${previous.id}`);}
      const epoch=await this.authz.permissionVersion(actor.user,tx);await this.scope(cid,actor,permission);
      const before=id?await this.root(cid,ws.id,id,actor,tx):null,nativeId=before?.native_id??value.nativeId??null,type=before?.entity_type??value.entityType;
      if(before){if(before.revision!==value.revision)throw new ConflictException({code:'DRAFT_CHANGED'});if(action==='draft.restore'?before.state!=='deleted':before.state!=='active')throw new ConflictException({code:'DRAFT_STATE_CHANGED'});}
      if(['draft.archive','draft.restore'].includes(action))portalConfirm(value,before.name);
      if(action!=='draft.archive')await this.nativeAccess(cid,ws.id,type,nativeId,value.payload??(before?await this.payload(before,tx):undefined),actor,true);
      const draftId=id??randomUUID(),operationId=randomUUID(),version=before?before.current_version+(action==='draft.update'?1:0):1;
      if(!before)await tx.exec('INSERT INTO configuration_drafts(id,cluster_id,workspace_id,owner_user_id,name,entity_type,native_id,current_version) VALUES($1,$2,$3,$4,$5,$6,$7,1)',[draftId,cid,ws.id,actor.user.id,boundedName(value.name),type,nativeId]);
      else requirePortalCas(await tx.exec(`UPDATE configuration_drafts SET name=$5,current_version=$6,revision=revision+1,state=$7,deleted_at=$8,updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND owner_user_id=$4 AND revision=$9`,[id,cid,ws.id,actor.user.id,action==='draft.update'?boundedName(value.name):before.name,version,action==='draft.archive'?'deleted':'active',action==='draft.archive'?new Date():null,value.revision]));
      if(['draft.create','draft.update'].includes(action))await tx.exec('INSERT INTO configuration_draft_versions(cluster_id,workspace_id,draft_id,version,payload_secret,payload_hmac,operation_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[cid,ws.id,draftId,version,this.secrets.encrypt(value.payload,aad(cid,ws.id,draftId,version)),this.secrets.fingerprint(value.payload),operationId,actor.user.id]);
      const after=await this.root(cid,ws.id,draftId,actor,tx),result={entity:this.summary(after),operationId};
      await tx.exec('INSERT INTO toolbox_metadata_operations(id,cluster_id,workspace_id,actor_id,idempotency_key,request_hmac,action,subject_id,result_secret) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[operationId,cid,ws.id,actor.user.id,key,requestHmac,action,draftId,this.secrets.encrypt(result,`toolbox-metadata:${operationId}`)]);
      await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'configuration_drafts',entityId:draftId,action,requestId:actor.requestId,ip:actor.ip,before:before?this.summary(before):null,after:this.summary(after),result:'success',scopeHints:{quality:'verified',module:'drafts',subject:{type:'configuration_drafts',id:draftId},beforeExists:!!before,afterExists:true,beforeWorkspaceId:ws.id,afterWorkspaceId:ws.id,beforeTags:[],afterTags:[]}},tx);
      await this.redis.assertLeaseOwnership();if(await this.authz.permissionVersion(actor.user,tx)!==epoch)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});return result;
    }));
  });}
}
