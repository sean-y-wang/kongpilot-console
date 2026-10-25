import { BadRequestException, BadGatewayException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { workspaceTag } from '../../infrastructure/kong/tags';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuditService } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { EntityActor, objectBody, pageSize } from '../entities/entities.types';
import { MutationService } from '../mutations/mutation.service';
import { WorkspaceResolverService, WorkspaceRow } from './workspace-resolver.service';
import type { ControlBusinessBridge, ControlBusinessMutation } from '../control-plane/control-metadata.types';
import type { MutationContext } from '../mutations/mutation.service';

export interface WorkspaceListOptions {size?:number|string;cursor?:string;search?:string;status?:'active'|'disabled'|'deleted'}
export interface CreateWorkspaceInput {code:string;name:string;owner_user_id?:string|null;description?:string}
export interface UpdateWorkspaceInput {revision:number;name?:string;owner_user_id?:string|null;description?:string;status?:'active'|'disabled'}
export interface ConfirmWorkspaceInput {revision:number;confirmed:true;confirm_name:string}
const nativeKinds=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'];
const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const revisionConflict=()=>new ConflictException({code:'WORKSPACE_REVISION_CONFLICT',message:'工作区已变化，请刷新后重新提交'});

@Injectable()
export class WorkspaceService {
  private controlBridge?:Readonly<ControlBusinessBridge>;
  constructor(private readonly storageDb:DbService,private readonly resolver:WorkspaceResolverService,
    private readonly authz:AuthorizationService,private readonly mutations:MutationService,
    private readonly audit:AuditService,private readonly kong:KongService,private readonly execution:KongExecutionContextService){}
  private get db():DbService{return this.controlBridge?.currentTransaction()??this.storageDb;}
  installControlMetadataBridge(bridge:ControlBusinessBridge):void{
    const methods=['currentTransaction','allocateId','execute','completed']as const;
    if(this.controlBridge||!bridge||methods.some(name=>typeof bridge[name]!=='function'))throw new Error('Control metadata requires one fixed business bridge');
    this.controlBridge=Object.freeze({currentTransaction:bridge.currentTransaction.bind(bridge),allocateId:bridge.allocateId.bind(bridge),execute:bridge.execute.bind(bridge),completed:bridge.completed.bind(bridge)});
  }
  private newId():string{return this.controlBridge?.allocateId()??randomUUID();}
  private controlMutation<T>(mutation:ControlBusinessMutation,context:MutationContext,fn:(tx:DbService)=>Promise<T>):Promise<T>{
    const direct=()=>this.mutations.execute(context,()=>this.storageDb.transaction(fn));
    return this.controlBridge?this.controlBridge.execute(mutation,fn,direct):direct();
  }
  private async management(cid:string):Promise<WorkspaceRow>{
    const tx=this.controlBridge?.currentTransaction();if(!tx)return this.resolver.ensureDefault(cid);
    const row=await tx.one<WorkspaceRow>("SELECT * FROM workspaces WHERE cluster_id=$1 AND code='default' AND is_default=true",[cid]);
    if(!row)throw new ConflictException({code:'CONTROL_DEFAULT_WORKSPACE_REQUIRED',message:'请先初始化真实默认工作区再准备变更'});
    return row;
  }

  private signingKey():string{
    const value=process.env.APP_SECRET;if(!value||value.length<32)throw new Error('APP_SECRET must contain at least 32 characters');return value;
  }
  private sign(value:any):string{
    const encoded=Buffer.from(JSON.stringify({...value,expires:Date.now()+900000})).toString('base64url');
    return `${encoded}.${createHmac('sha256',this.signingKey()).update(encoded).digest('base64url')}`;
  }
  private cursor(value:string,binding:string):{id:string;createdAt:string;isDefault:boolean}{
    try{
      if(value.length>4096)throw new Error();const [encoded,signature,extra]=value.split('.');if(!encoded||!signature||extra)throw new Error();
      const expected=createHmac('sha256',this.signingKey()).update(encoded).digest(),actual=Buffer.from(signature,'base64url');
      if(actual.length!==expected.length||!timingSafeEqual(actual,expected))throw new Error();
      const result=JSON.parse(Buffer.from(encoded,'base64url').toString());
      if(result.binding!==binding||result.expires<Date.now()||!uuid.test(result.id)||typeof result.isDefault!=='boolean'||typeof result.createdAt!=='string'||!Number.isFinite(Date.parse(result.createdAt)))throw new Error();
      return result;
    }catch{throw new BadRequestException({code:'INVALID_CURSOR',message:'工作区分页游标无效、已过期或查询范围已改变'});}
  }
  private validate(input:unknown,allowed:string[]):Record<string,any>{
    const value=objectBody(input);if(Object.keys(value).some(key=>!allowed.includes(key)))throw new BadRequestException({code:'INVALID_WORKSPACE_FIELD',message:'工作区配置包含不支持的字段'});
    if(Object.hasOwn(value,'name')&&(typeof value.name!=='string'||!value.name.trim()||value.name.length>128))throw new BadRequestException({code:'INVALID_WORKSPACE_NAME',message:'工作区名称须为 1–128 个字符'});
    if(Object.hasOwn(value,'description')&&(typeof value.description!=='string'||value.description.length>8192))throw new BadRequestException({code:'INVALID_WORKSPACE_DESCRIPTION',message:'工作区描述最多 8192 个字符'});
    if(Object.hasOwn(value,'owner_user_id')&&value.owner_user_id!==null&&(typeof value.owner_user_id!=='string'||!uuid.test(value.owner_user_id)))throw new BadRequestException({code:'INVALID_WORKSPACE_OWNER',message:'负责人 ID 无效'});
    return value;
  }
  private revision(input:any):void{
    if(!Number.isInteger(input.revision)||input.revision<1||input.revision>=2147483647)throw new BadRequestException({code:'INVALID_WORKSPACE_REVISION',message:'请提供有效的工作区版本号'});
  }
  private confirm(input:any,row:WorkspaceRow):void{
    this.revision(input);if(input.confirmed!==true||input.confirm_name!==row.name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:`请二次确认并输入 ${row.name}`});
  }
  private async owner(tx:DbService,id?:string|null):Promise<void>{
    if(id&&!await tx.one("SELECT id FROM users WHERE id=$1 AND status='active' FOR SHARE",[id]))throw new BadRequestException({code:'WORKSPACE_OWNER_UNAVAILABLE',message:'负责人不存在或已禁用'});
  }
  private async metadataAudit(tx:DbService,actor:EntityActor,cid:string,row:WorkspaceRow,action:string,before:any):Promise<void>{
    await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:row.id,entityType:'workspaces',entityId:row.id,
      action:`workspace.metadata.${action}`,before,after:row,requestId:actor.requestId,ip:actor.ip},tx);
  }
  private context(cid:string,workspaceId:string,actor:EntityActor,action:string,before?:WorkspaceRow,payload?:any){
    return {clusterId:cid,workspaceId,actor:actor.user,entityType:'workspaces',entityId:before?.id,action,before,payload,
      requestId:actor.requestId,ip:actor.ip,idempotencyKey:actor.idempotencyKey};
  }
  private async authorized(cid:string,id:string,actor:EntityActor,action:string,includeDeleted=false):Promise<WorkspaceRow>{
    await this.authz.assertCluster(actor.user,cid,'workspaces',action,id);
    const row=await this.resolver.get(cid,id,includeDeleted,this.controlBridge?.currentTransaction());await this.authz.assertEntity(actor.user,cid,'workspaces',action,row,row.id);return row;
  }

  @KongActorScope({module:'workspaces',action:'read'})
  async list(cid:string,options:WorkspaceListOptions,actor:EntityActor):Promise<{items:WorkspaceRow[];nextCursor:string|null;size:number;total:null}>{
    if(Object.keys(options).some(key=>!['size','cursor','search','status'].includes(key)))throw new BadRequestException({code:'INVALID_WORKSPACE_QUERY',message:'工作区列表包含无效参数'});
    if(options.search!==undefined&&(typeof options.search!=='string'||options.search.length>128)||options.cursor!==undefined&&typeof options.cursor!=='string'
      ||options.status!==undefined&&!['active','disabled','deleted'].includes(options.status))throw new BadRequestException({code:'INVALID_WORKSPACE_QUERY',message:'工作区查询无效'});
    await this.authz.assertCluster(actor.user,cid,'workspaces','read');await this.resolver.ensureDefault(cid);
    const size=pageSize(options.size),search=options.search??'',status=options.status??null;
    const binding=createHash('sha256').update(JSON.stringify({cid,actor:actor.user.id,permissions:await this.authz.permissionVersion(actor.user),size,search,status})).digest('hex');
    const prior=options.cursor?this.cursor(options.cursor,binding):null,params:any[]=[cid,search,status];
    const where=["cluster_id=$1","($2='' OR position(lower($2) in lower(name))>0 OR position(lower($2) in lower(code))>0)","CASE WHEN $3::text IS NULL THEN status<>'deleted' ELSE status=$3 END"];
    if(prior){params.push(prior.isDefault,prior.createdAt,prior.id);where.push('(is_default,created_at,id)<($4::boolean,$5::timestamptz,$6::uuid)');}
    params.push(size+1);
    const rows=await this.db.query<WorkspaceRow>(`SELECT * FROM workspaces WHERE ${where.join(' AND ')} ORDER BY is_default DESC,created_at DESC,id DESC LIMIT $${params.length}`,params);
    const items=await this.authz.filterEntities(actor.user,cid,'workspaces',rows.slice(0,size));
    const last=rows[Math.min(size,rows.length)-1];
    return {items,nextCursor:rows.length>size&&last?this.sign({binding,id:last.id,createdAt:new Date(last.created_at).toISOString(),isDefault:last.is_default}):null,size,total:null};
  }
  @KongActorScope({module:'workspaces',action:'read',workspaceArg:1})
  get(cid:string,id:string,actor:EntityActor):Promise<WorkspaceRow>{return this.authorized(cid,id,actor,'read',true);}

  @KongActorScope({module:'workspaces',action:'write'})
  async create(cid:string,input:CreateWorkspaceInput,actor:EntityActor):Promise<WorkspaceRow>{
    const value=this.validate(input,['code','name','owner_user_id','description']);
    if(typeof value.code!=='string'||value.code==='default')throw new BadRequestException({code:'INVALID_WORKSPACE_CODE',message:'default 是系统保留工作区编码'});
    workspaceTag(value.code);if(!value.name)throw new BadRequestException({code:'INVALID_WORKSPACE_NAME',message:'请填写工作区名称'});
    await this.authz.assertCluster(actor.user,cid,'workspaces','write');const management=await this.management(cid),id=this.newId();
    return this.controlMutation({resource:'workspaces',operation:'create',clusterId:cid,resourceId:id,module:'workspaces',action:'write',workspaceId:management.id,actor,payload:value},this.context(cid,management.id,actor,'create',undefined,value),async tx=>{
      await this.owner(tx,value.owner_user_id);
      const row=await tx.one<WorkspaceRow>(`INSERT INTO workspaces(cluster_id,code,name,owner_user_id,description,id)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(cluster_id,code) DO NOTHING RETURNING *`,[cid,value.code,value.name.trim(),value.owner_user_id??null,value.description??'',id]);
      if(!row)throw new ConflictException({code:'WORKSPACE_CODE_RESERVED',message:'工作区编码已使用，软删除后仍不可复用'});
      await this.metadataAudit(tx,actor,cid,row,'created',null);return row;
    });
  }
  @KongActorScope({module:'workspaces',action:'write',workspaceArg:1})
  async update(cid:string,id:string,input:UpdateWorkspaceInput,actor:EntityActor):Promise<WorkspaceRow>{
    const value=this.validate(input,['revision','name','owner_user_id','description','status']);this.revision(value);
    if(Object.hasOwn(value,'status')&&!['active','disabled'].includes(value.status))throw new BadRequestException({code:'INVALID_WORKSPACE_STATUS',message:'工作区状态仅支持 active 或 disabled'});
    const before=await this.authorized(cid,id,actor,'write');
    if(before.is_default&&value.status==='disabled')throw new ConflictException({code:'DEFAULT_WORKSPACE_PROTECTED',message:'默认工作区不可停用'});
    return this.controlMutation({resource:'workspaces',operation:'update',clusterId:cid,resourceId:id,module:'workspaces',action:'write',workspaceId:id,actor,payload:value},this.context(cid,id,actor,'update',before,value),async tx=>{
      const current=await tx.one<WorkspaceRow>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,id]);
      if(!current||current.status==='deleted')throw new NotFoundException({code:'WORKSPACE_NOT_FOUND',message:'工作区不存在'});
      if(current.revision!==value.revision)throw revisionConflict();await this.owner(tx,value.owner_user_id);
      const row=await tx.one<WorkspaceRow>(`UPDATE workspaces SET name=$3,owner_user_id=$4,description=$5,status=$6,revision=revision+1,updated_at=now()
        WHERE cluster_id=$1 AND id=$2 AND revision=$7 AND status<>'deleted' RETURNING *`,[cid,id,value.name?.trim()??current.name,
        Object.hasOwn(value,'owner_user_id')?value.owner_user_id:current.owner_user_id,value.description??current.description,value.status??current.status,value.revision]);
      if(!row)throw revisionConflict();await this.metadataAudit(tx,actor,cid,row,'updated',current);return row;
    });
  }
  private retentionDays():number{
    const value=Number(process.env.RECYCLE_RETENTION_DAYS??30);if(!Number.isInteger(value)||value<1||value>3650)throw new BadRequestException({code:'INVALID_RECYCLE_RETENTION',message:'回收保留期须为 1–3650 天'});return value;
  }
  private async requireEmpty(cid:string,row:WorkspaceRow):Promise<void>{
    // A caller-visible page may hide unauthorized tag-group/entity objects.
    // Empty proof must inspect private raw pages across every native collection.
    await this.execution.runInternalRead(cid,'workspace-empty',async()=>{for(const type of nativeKinds){
      const page=await this.kong.list(cid,`/${type}`,{size:1,tags:workspaceTag(row.code)},undefined,`workspace-empty:${row.id}:${row.revision}`);
      if(!Array.isArray(page?.items)||page.items.length>1)throw new BadGatewayException({code:'WORKSPACE_EMPTY_UNVERIFIABLE',message:'无法核验工作区是否为空，尚未删除'});
      if(page.items.length||page.nextCursor)throw new ConflictException({code:'WORKSPACE_NOT_EMPTY',message:'工作区仍有实体或无效工作区标记；请先迁移或回收其实体'});
    }},{paths:nativeKinds.map(type=>`/${type}`),workspaceId:row.id,maxCalls:8,maxPages:8,maxRecords:8,maxBytes:8*1024*1024,timeoutMs:10000});
  }
  @KongActorScope({module:'workspaces',action:'delete',workspaceArg:1})
  async remove(cid:string,id:string,input:ConfirmWorkspaceInput,actor:EntityActor):Promise<{workspace:WorkspaceRow;state:'deleted'}>{
    const value=this.validate(input,['revision','confirmed','confirm_name']),before=await this.authorized(cid,id,actor,'delete');this.confirm(value,before);
    if(before.is_default)throw new ConflictException({code:'DEFAULT_WORKSPACE_PROTECTED',message:'默认工作区不可删除'});
    const days=this.retentionDays();
    return this.controlMutation({resource:'workspaces',operation:'archive',clusterId:cid,resourceId:id,module:'workspaces',action:'delete',workspaceId:id,actor,payload:value},this.context(cid,id,actor,'delete',before,value),async tx=>{
      await this.requireEmpty(cid,before);
      const current=await tx.one<WorkspaceRow>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,id]);
      if(!current||current.status==='deleted')throw new NotFoundException({code:'WORKSPACE_NOT_FOUND',message:'工作区不存在'});
      if(current.revision!==value.revision)throw revisionConflict();this.confirm(value,current);
      const after=await tx.one<WorkspaceRow>(`UPDATE workspaces SET status='deleted',deleted_at=now(),retention_until=now()+($4::int*interval '1 day'),
        revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND id=$2 AND revision=$3 AND is_default=false AND status<>'deleted' RETURNING *`,[cid,id,value.revision,days]);
      if(!after)throw revisionConflict();await this.metadataAudit(tx,actor,cid,after,'deleted',current);
      return {workspace:after,state:'deleted' as const};
    });
  }
  @KongActorScope({module:'workspaces',action:'write',workspaceArg:1})
  async restore(cid:string,id:string,input:ConfirmWorkspaceInput,actor:EntityActor):Promise<WorkspaceRow>{
    const value=this.validate(input,['revision','confirmed','confirm_name']),before=await this.authorized(cid,id,actor,'write',true);this.confirm(value,before);
    if(before.status!=='deleted')throw new ConflictException({code:'WORKSPACE_NOT_DELETED',message:'工作区未处于可恢复状态'});
    return this.controlMutation({resource:'workspaces',operation:'restore',clusterId:cid,resourceId:id,module:'workspaces',action:'write',workspaceId:id,actor,payload:value},this.context(cid,id,actor,'restore',before,value),async tx=>{
      const current=await tx.one<WorkspaceRow>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[cid,id]);
      if(!current||current.revision!==value.revision||current.status!=='deleted')throw revisionConflict();this.confirm(value,current);
      const row=await tx.one<WorkspaceRow>(`UPDATE workspaces SET status='active',deleted_at=NULL,retention_until=NULL,revision=revision+1,updated_at=now()
        WHERE cluster_id=$1 AND id=$2 AND revision=$3 AND status='deleted' RETURNING *`,[cid,id,value.revision]);
      if(!row)throw revisionConflict();await this.metadataAudit(tx,actor,cid,row,'restored',current);return row;
    });
  }
}
