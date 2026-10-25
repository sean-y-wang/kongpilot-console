import { BadRequestException, Body, Controller, Get, HttpException, Param, Post, Query, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from './authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { CREDENTIAL_KINDS, EntityActor, entityType, identifier, objectBody } from '../entities/entities.types';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';

@ApiTags('权限投影')
@Controller('clusters/:clusterId/authorization')
export class AuthorizationController {
 constructor(private readonly authz:AuthorizationService,private readonly kong:KongService,
  private readonly context:KongExecutionContextService,private readonly workspaces:WorkspaceResolverService,
  private readonly db:DbService,private readonly secrets:SecretService){}
 @Get('children')
 async children(@Param('clusterId') cid:string,@Query() query:any,@Req() actor:EntityActor){
  if(Object.keys(query).some(key=>!['workspaceId','type','size','cursor'].includes(key)))throw new BadRequestException({code:'INVALID_CHILD_QUERY',message:'子实体查询参数无效'});
  const size=query.size===undefined?20:Number(query.size),type=query.type;
  if(!Number.isInteger(size)||size<1||size>50||type!==undefined&&type!=='targets'&&!(CREDENTIAL_KINDS as readonly string[]).includes(type))throw new BadRequestException({code:'INVALID_CHILD_QUERY',message:'子实体类型或分页大小无效'});
  await this.authz.assertCluster(actor.user,cid,'entities','read',query.workspaceId);
  const workspace=await this.workspaces.resolve(cid,query.workspaceId),snapshot=await this.authz.snapshot(actor.user),permissionsVersion=snapshot.version;
  const binding=this.secrets.fingerprint({actor:actor.user.id,cid,wid:workspace.id,type:type??null,size,permissionsVersion,revision:workspace.revision});
  let previous:any=null;
  if(query.cursor){try{if(typeof query.cursor!=='string'||query.cursor.length>4096)throw new Error();previous=this.secrets.decrypt<any>(query.cursor,'child-navigation-cursor');if(previous.binding!==binding||previous.expires<Date.now()||typeof previous.type!=='string'||typeof previous.id!=='string')throw new Error();}catch{throw new BadRequestException({code:'CURSOR_EXPIRED',message:'子实体游标已失效，请刷新列表'});}}
  // Discovery reveals no registry names or parent configuration. Every result
  // still requires current actual-child authorization and a fresh nested read.
  const allowedTypes:string[]=[];
  for(const candidate of type?[type]:['targets',...CREDENTIAL_KINDS]){try{await this.authz.assertCluster(actor.user,cid,candidate,'read',workspace.id);allowedTypes.push(candidate);}catch(error){if(!(error instanceof HttpException&&error.getStatus()===403))throw error;}}
  if(!allowedTypes.length)throw new HttpException({code:'PERMISSION_DENIED',message:'当前账号无子实体读取权限'},403);
  const limit=Math.min(250,size*5+1),rows=await this.db.query<any>(`SELECT child_type,child_id::text,parent_type,parent_id::text FROM entity_parent_index
   WHERE cluster_id=$1 AND child_type=ANY($2::text[]) AND ($3::text IS NULL OR (child_type,child_id)>($3,$4::uuid)) ORDER BY child_type,child_id LIMIT $5`,[cid,allowedTypes,previous?.type??null,previous?.id??null,limit]);
  const items:any[]=[];let last:any=null,consumed=0;
  for(const row of rows){if(items.length>=size)break;last=row;consumed++;
   const path=`/${row.parent_type}/${identifier(row.parent_id)}/${row.child_type}/${identifier(row.child_id)}`;
   try{
    let entity=await this.context.runInternalRead(cid,'authorization',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000});
    if(entity?.id!==row.child_id||(row.child_type==='targets'?entity.upstream?.id:entity.consumer?.id)!==row.parent_id)continue;
    if(row.child_type==='targets'){
     const collection=`/upstreams/${identifier(row.parent_id)}/targets`,current=await this.context.runInternalRead(cid,'entity-preflight',()=>currentEffectiveTarget(this.kong,cid,row.parent_id,entity.target),{paths:[collection],maxCalls:100,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
     if(current.target?.id!==entity.id)continue;entity=current.target;
    }
    await this.authz.assertEntity(actor.user,cid,row.child_type,'read',entity,workspace.id);
    const flags=await this.authz.entityCapabilities(actor.user,cid,row.child_type,entity,workspace.id);
    items.push({type:row.child_type,id:entity.id,parent_id:row.parent_id,entity:this.secrets.redact(entity),...flags});
   }catch(error){if(!(error instanceof HttpException&&[403,404].includes(error.getStatus())))throw error;}
  }
  if(permissionsVersion!==await this.authz.permissionVersion(actor.user))throw new HttpException({code:'PERMISSIONS_CHANGED',message:'权限已变化，请刷新子实体列表'},403);
  const hasMore=consumed<rows.length||rows.length===limit,nextCursor=last&&hasMore?this.secrets.encrypt({binding,type:last.child_type,id:last.child_id,expires:Date.now()+900000},'child-navigation-cursor'):null;
  return {items,nextCursor,size,total:null,workspace_id:workspace.id,permissionsVersion,discovery:'observed-parent-index'};
 }
 @Post('entity-capabilities')
 async entityCapabilities(@Param('clusterId') cid:string,@Query('workspaceId') wid:string,@Body() body:unknown,@Req() actor:EntityActor){
  const input=objectBody(body);
  if(Object.keys(input).some(key=>key!=='entities')||!Array.isArray(input.entities)||input.entities.length>50)throw new BadRequestException({code:'INVALID_CAPABILITY_QUERY',message:'权限核验最多包含 50 个对象'});
  await this.authz.assertCluster(actor.user,cid,'entities','read',wid);
  const permissionsVersion=await this.authz.permissionVersion(actor.user),workspace=await this.workspaces.resolve(cid,wid),items:any[]=[];
  for(const value of input.entities){
   if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!['type','id','parent_id'].includes(key))||typeof value.type!=='string'||typeof value.id!=='string')throw new BadRequestException({code:'INVALID_CAPABILITY_QUERY',message:'对象标识无效'});
   let path:string;
   if(value.type==='targets'||(CREDENTIAL_KINDS as readonly string[]).includes(value.type)){
    if(typeof value.parent_id!=='string')throw new BadRequestException({code:'PARENT_ID_REQUIRED',message:'子对象权限核验必须指定所属父对象'});
    path=value.type==='targets'?`/upstreams/${identifier(value.parent_id)}/targets/${identifier(value.id)}`:`/consumers/${identifier(value.parent_id)}/${value.type}/${identifier(value.id)}`;
   }else{entityType(value.type);path=`/${value.type}/${identifier(value.id)}`;}
   try{
    let entity=await this.context.runInternalRead(cid,'authorization',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000});
    if(value.parent_id&&(value.type==='targets'?entity.upstream?.id:entity.consumer?.id)!==value.parent_id||entity?.id!==value.id)throw new HttpException({code:'ENTITY_IDENTITY_MISMATCH',message:'对象归属已变化，请刷新列表'},404);
    if(value.type==='targets'){
     const collection=`/upstreams/${identifier(value.parent_id)}/targets`;
     const current=await this.context.runInternalRead(cid,'entity-preflight',()=>currentEffectiveTarget(this.kong,cid,value.parent_id,entity.target),{paths:[collection],maxCalls:100,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
     if(current.target?.id!==entity.id)throw new HttpException({code:'TARGET_NOT_EFFECTIVE',message:'Target 已有新的有效记录，请刷新列表'},404);
     entity=current.target;
    }
    const flags=await this.authz.entityCapabilities(actor.user,cid,value.type,entity,workspace.id);
    items.push({type:value.type,id:value.id,...flags});
   }catch(error){if(!(error instanceof HttpException&&[403,404].includes(error.getStatus())))throw error;items.push({type:value.type,id:value.id,read:false,write:false,delete:false,approve:false,reveal:false});}
  }
  if(permissionsVersion!==await this.authz.permissionVersion(actor.user))throw new HttpException({code:'PERMISSIONS_CHANGED',message:'权限已变化，请刷新对象权限'},403);
  return {items,permissionsVersion};
 }
}
