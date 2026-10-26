import { kongCapabilities } from '../../infrastructure/kong/kong-capabilities';
import { ConflictException, HttpException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import type { EntityActor } from '../entities/entities.types';
import type { WorkflowStep, WorkflowPlanV1 } from '../workflows/workflow.types';
import { validateKnownFields } from '../../infrastructure/kong/schema';

@Injectable()
export class PortalNativeService {
  constructor(private readonly db:DbService,readonly secrets:SecretService,readonly kong:KongService,readonly context:KongExecutionContextService,readonly authz:AuthorizationService,readonly workspaces:WorkspaceResolverService){}
  actor<T>(cid:string,actor:EntityActor,module:string,action:string,fn:()=>Promise<T>):Promise<T>{return this.context.runActor({actor:actor.user,clusterId:cid,workspaceId:actor.workspaceId,module,action,requestId:actor.requestId},fn);}
  async read(cid:string,path:string,actor:EntityActor,action='write',module='portal'):Promise<any>{return this.actor(cid,actor,module,action,()=>this.context.runPortalMetadataRead(cid,path,()=>this.context.runInternalRead(cid,'inventory',()=>this.kong.request(cid,'GET',path),{paths:[path],maxCalls:1,maxBytes:2*1024*1024,workspaceId:actor.workspaceId})));}
  async collection(cid:string,path:string,actor:EntityActor,action='write'):Promise<any[]>{return this.actor(cid,actor,'portal',action,()=>this.context.runInternalRead(cid,'inventory',async()=>{
    const rows:any[]=[];let offset:string|undefined;for(let page=0;page<10;page++){
      const result:any=await this.kong.request(cid,'GET',path,undefined,{size:100,...(offset?{offset}:{})});if(!Array.isArray(result.data))throw new ConflictException({code:'PORTAL_NATIVE_RESPONSE_INVALID'});rows.push(...result.data);
      if(!result.next)return rows;try{offset=new URL(result.next,'http://kong').searchParams.get('offset')??undefined;}catch{throw new ConflictException({code:'PORTAL_NATIVE_RESPONSE_INVALID'});}if(!offset)throw new ConflictException({code:'PORTAL_NATIVE_RESPONSE_INVALID'});
    }throw new ConflictException({code:'PORTAL_PREFLIGHT_BUDGET'});
  },{paths:[path],maxCalls:10,maxPages:10,maxRecords:1000,maxBytes:2*1024*1024,workspaceId:actor.workspaceId}));}
  async service(cid:string,id:string,actor:EntityActor,action='write',module='portal'):Promise<any>{const service=await this.read(cid,`/services/${id}`,actor,action,module);await this.authz.assertScopedResource(actor.user,cid,module,action,'services',service,actor.workspaceId);return service;}
  async scope(cid:string,wid:string):Promise<WorkflowPlanV1['scope']&{executionMode:'direct'|'approval'}>{const row=await this.db.one<any>('SELECT revision,execution_mode,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]),ws=await this.workspaces.resolve(cid,wid);if(!row||row.status==='disabled'||!kongCapabilities(row.version??'').portalCredentials||ws.status!=='active')throw new ConflictException({code:'PORTAL_CLUSTER_UNAVAILABLE'});return{transportScope:await this.kong.transportScope(cid),clusterRevision:row.revision,workspaceRevision:ws.revision,executionMode:row.execution_mode};}
  nativeStep(order:number,type:string,action:'create'|'update'|'delete',payload:any,before:any,options:{id?:string;parentId?:string;credentialKind?:string;dependencies?:string[];workflowId:string}):WorkflowStep{
    const id=randomUUID(),nativeId=action==='create'?payload.id:options.id!,nativeType=options.credentialKind??type;
    const collection=type==='credentials'?`/consumers/${options.parentId}/${options.credentialKind}`:`/${type}`,path=action==='create'?collection:`${collection}/${nativeId}`,body=action==='delete'?undefined:payload;
    return{id,key:`${type}.${action}.${order}`,order,kind:'native',entityType:type,entityId:action==='create'?undefined:nativeId,parentId:options.parentId,credentialKind:options.credentialKind,permissionAction:action==='delete'?'delete':'write',dependencies:options.dependencies??[],mutationAction:action,mutationPayload:payload,mutationPayloadHmac:this.secrets.fingerprint(payload),mutationIdempotencyKey:`portal-${this.secrets.fingerprint({workflowId:options.workflowId,step:id}).slice(0,48)}`,before:before??null,beforeFingerprint:this.secrets.fingerprint(before??null),nativeRequests:[{method:action==='create'?'POST':action==='update'?'PATCH':'DELETE',canonicalPath:path,nativeType,nativeId,parentId:options.parentId,credentialKind:options.credentialKind,body,bodyHmac:this.secrets.fingerprint(body??null),beforeHmac:action==='create'?undefined:this.secrets.fingerprint(before)}]};
  }
  metadataStep(order:number,handler:string,type:string,id:string,before:any,metadata:any,dependencies:string[]):WorkflowStep{return{id:randomUUID(),key:handler,order,kind:'metadata',handler,entityType:type,entityId:id,permissionAction:'write',dependencies,nativeRequests:[],metadata,before,metadataBeforeHmac:this.secrets.fingerprint(before),metadataRevision:before?.revision??0,metadataPayloadHmac:this.secrets.fingerprint(metadata)};}
  async schema(cid:string,name:string,actor:EntityActor):Promise<any>{return this.read(cid,`/schemas/${name}`,actor);}
  check(payload:any,schema:any):void{validateKnownFields(payload,schema);}
  async absent(cid:string,path:string,actor:EntityActor):Promise<void>{try{await this.read(cid,path,actor);throw new ConflictException({code:'PORTAL_NATIVE_ID_EXISTS'});}catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}}
}
