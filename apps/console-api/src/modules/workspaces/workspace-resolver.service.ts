import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { workspaceTag } from '../../infrastructure/kong/tags';

export interface WorkspaceRow {
  id:string; cluster_id:string; code:string; name:string; owner_user_id:string|null; description:string;
  status:'active'|'disabled'|'deleted'; is_default:boolean; revision:number; deleted_at:string|null;
  retention_until:string|null; created_at:string; updated_at:string;
}
export interface WorkspaceFilter {
  workspaceId:string; workspaceRevision:number; mode:'default'|'tag'; workspaceTag:string;
  requestedTags:string[]; tagOperator:'and'|'or'; nativeTags?:string; requiresPostFilter:boolean; binding:string;
}
export interface WorkspaceResolution {state:'resolved'|'invalid';workspace:WorkspaceRow|null;reason?:string}
const reservedPrefix='kos-ws-';
const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
function validUuid(value:string):void {if(typeof value!=='string'||!uuid.test(value))throw new BadRequestException({code:'INVALID_WORKSPACE_ID',message:'集群或工作区 ID 无效'});}
function tags(value:unknown):string[]{
  if(value===undefined||value===null)return [];
  if(!Array.isArray(value)||value.length>1000||value.some(tag=>typeof tag!=='string'||!tag.length||tag.length>128))throw new BadRequestException({code:'INVALID_TAGS',message:'实体 tags 必须是有效的字符串数组'});
  return [...value];
}
function reserved(value:string[]):string[]{return value.filter(tag=>tag.startsWith(reservedPrefix));}
function expression(value?:string):{tags:string[];operator:'and'|'or'}{
  if(value===undefined||value==='')return {tags:[],operator:'and'};
  if(typeof value!=='string'||value.length>2048||value.includes(',')&&value.includes('/'))throw new BadRequestException({code:'INVALID_TAG_EXPRESSION',message:'标签过滤不能混合 AND 与 OR'});
  const operator=value.includes('/')?'or':'and',entries=value.split(operator==='or'?'/':',');
  if(entries.some(tag=>!tag.length||tag.length>128||!/^[a-zA-Z\d._~-]+$/.test(tag)))throw new BadRequestException({code:'INVALID_TAG_EXPRESSION',message:'标签过滤必须是已编码的有效物理标签'});
  return {tags:[...new Set(entries)].sort(),operator};
}

/** Database-only membership policy; AuthorizationService may depend on this provider without a cycle. */
@Injectable()
export class WorkspaceResolverService {
  constructor(private readonly db:DbService){}

  async ensureDefault(clusterId:string,transaction?:DbService):Promise<WorkspaceRow>{
    validUuid(clusterId);const db=transaction??this.db;
    await db.exec(`INSERT INTO workspaces(cluster_id,code,name,is_default) SELECT id,'default','默认工作区',true
      FROM clusters WHERE id=$1 AND deleted_at IS NULL ON CONFLICT(cluster_id,code) DO NOTHING`,[clusterId]);
    const row=await db.one<WorkspaceRow>("SELECT * FROM workspaces WHERE cluster_id=$1 AND code='default' AND is_default=true",[clusterId]);
    if(!row)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
    return row;
  }
  async get(clusterId:string,id:string,includeDeleted=false,transaction?:DbService):Promise<WorkspaceRow>{
    validUuid(clusterId);validUuid(id);
    const row=await (transaction??this.db).one<WorkspaceRow>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',[clusterId,id]);
    if(!row||!includeDeleted&&row.status==='deleted')throw new NotFoundException({code:'WORKSPACE_NOT_FOUND',message:'此集群中不存在该工作区'});
    return row;
  }
  async resolve(clusterId:string,workspaceId?:string):Promise<WorkspaceRow>{
    if(workspaceId===undefined)return this.ensureDefault(clusterId);
    try{return await this.get(clusterId,workspaceId);}catch(error){
      if(error instanceof NotFoundException)throw new ForbiddenException({code:'WORKSPACE_ACCESS_DENIED',message:'无法访问所选工作区'});
      throw error;
    }
  }
  async classify(clusterId:string,physicalTags:unknown):Promise<WorkspaceResolution>{
    validUuid(clusterId);let actual:string[];
    try{actual=tags(physicalTags);}catch{return {state:'invalid',workspace:null,reason:'INVALID_TAGS'};}
    const selected=reserved(actual);
    if(selected.length>1)return {state:'invalid',workspace:null,reason:'AMBIGUOUS_WORKSPACE_TAGS'};
    if(!selected.length||selected[0]===workspaceTag('default'))return {state:'resolved',workspace:await this.ensureDefault(clusterId)};
    const code=selected[0].slice(reservedPrefix.length);
    if(!/^[a-z][a-z0-9_-]{0,47}$/.test(code))return {state:'invalid',workspace:null,reason:'UNKNOWN_WORKSPACE_TAG'};
    const row=await this.db.one<WorkspaceRow>('SELECT * FROM workspaces WHERE cluster_id=$1 AND code=$2',[clusterId,code]);
    if(!row||row.status==='deleted')return {state:'invalid',workspace:null,reason:row?'DELETED_WORKSPACE':'UNKNOWN_WORKSPACE_TAG'};
    return {state:'resolved',workspace:row};
  }
  async listScope(clusterId:string,workspaceId?:string,requestedPhysicalTags?:string):Promise<WorkspaceFilter>{
    const workspace=await this.resolve(clusterId,workspaceId),requested=expression(requestedPhysicalTags),physical=workspaceTag(workspace.code);
    const mode=workspace.is_default?'default':'tag';
    const nativeTags=mode==='default'?(requested.tags.length?requested.tags.join(requested.operator==='or'?'/':','):undefined)
      :requested.operator==='or'?physical:[...new Set([physical,...requested.tags])].sort().join(',');
    const binding=createHash('sha256').update(JSON.stringify({clusterId,workspaceId:workspace.id,revision:workspace.revision,mode,
      workspaceTag:physical,requestedTags:requested.tags,tagOperator:requested.operator})).digest('hex');
    return {workspaceId:workspace.id,workspaceRevision:workspace.revision,mode,workspaceTag:physical,requestedTags:requested.tags,
      tagOperator:requested.operator,nativeTags,requiresPostFilter:mode==='default'||requested.operator==='or',binding};
  }
  matches(scope:WorkspaceFilter,entity:any):boolean{
    let actual:string[];try{actual=tags(entity?.tags);}catch{return false;}
    const selected=reserved(actual);
    if(selected.length>1)return false;
    if(scope.mode==='default'?(selected.length===1&&selected[0]!==scope.workspaceTag):(selected.length!==1||selected[0]!==scope.workspaceTag))return false;
    return scope.tagOperator==='or'?scope.requestedTags.length===0||scope.requestedTags.some(tag=>actual.includes(tag))
      :scope.requestedTags.every(tag=>actual.includes(tag));
  }
  assertMembership(scope:WorkspaceFilter,entity:any):void{
    if(!this.matches(scope,entity))throw new ForbiddenException({code:'WORKSPACE_ENTITY_MISMATCH',message:'对象不属于所选工作区，或其工作区标记无效'});
  }
  private writable(row:WorkspaceRow):void{
    if(row.status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED',message:'工作区已停用，不能修改配置'});
  }
  private copy(value:any):any{
    if(!value||typeof value!=='object'||Array.isArray(value))throw new BadRequestException({code:'INVALID_BODY',message:'配置必须是 JSON 对象'});
    return structuredClone(value);
  }
  private checkRequestedTags(actual:string[],allowed:string[],historical:string[]=[]):void{
    if(reserved(actual).some(tag=>!allowed.includes(tag)&&!historical.includes(tag)))throw new BadRequestException({code:'WORKSPACE_TAG_IMMUTABLE',message:'工作区保留标签不能通过普通实体表单修改，请使用工作区迁移'});
  }
  async prepareCreate(clusterId:string,_type:string,payload:any,workspaceId?:string):Promise<any>{
    const row=await this.resolve(clusterId,workspaceId);this.writable(row);
    const input=this.copy(payload),physical=workspaceTag(row.code),actual=tags(input.tags);
    this.checkRequestedTags(actual,[physical]);input.tags=[...new Set([...actual.filter(tag=>!tag.startsWith(reservedPrefix)),physical])];return input;
  }
  async prepareUpdate(clusterId:string,_type:string,before:any,patch:any,workspaceId?:string):Promise<any>{
    const row=await this.resolve(clusterId,workspaceId);this.writable(row);
    const scope=await this.listScope(clusterId,row.id);this.assertMembership(scope,before);
    const input=this.copy(patch);
    if(Object.hasOwn(input,'tags')){
      const original=reserved(tags(before?.tags)),actual=tags(input.tags);
      this.checkRequestedTags(actual,[scope.workspaceTag]);
      // Legacy untagged default objects stay untagged; existing reserved membership never disappears.
      input.tags=[...new Set([...actual.filter(tag=>!tag.startsWith(reservedPrefix)),...original])];
    }
    return input;
  }
  async prepareInheritedCreate(clusterId:string,type:string,parent:any,payload:any,workspaceId?:string):Promise<any>{
    const scope=await this.listScope(clusterId,workspaceId);this.assertMembership(scope,parent);
    return this.prepareCreate(clusterId,type,payload,scope.workspaceId);
  }
  async prepareInheritedUpdate(clusterId:string,_type:string,parent:any,before:any,patch:any,workspaceId?:string):Promise<any>{
    const row=await this.resolve(clusterId,workspaceId);this.writable(row);
    const scope=await this.listScope(clusterId,row.id);this.assertMembership(scope,parent);
    const input=this.copy(patch),actual=Object.hasOwn(input,'tags')?tags(input.tags):tags(before?.tags);
    this.checkRequestedTags(actual,[scope.workspaceTag],reserved(tags(before?.tags)));
    input.tags=[...new Set([...actual.filter(tag=>!tag.startsWith(reservedPrefix)),scope.workspaceTag])];return input;
  }
}
