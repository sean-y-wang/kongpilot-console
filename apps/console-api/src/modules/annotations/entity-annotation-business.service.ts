import {ConflictException,ForbiddenException,Injectable,OnModuleInit} from '@nestjs/common';
import {AsyncLocalStorage} from 'node:async_hooks';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {AuditService,type AuditEvent,type AuditOutboxReceipt} from '../audit/audit.service';
import type {EntityActor,EntityType} from '../entities/entities.types';
import {EntityAnnotationsService,type EntityAnnotationRow} from '../workspaces/entity-annotations.service';
import {WorkspaceResolverService} from '../workspaces/workspace-resolver.service';
import {iamId} from '../iam/iam.types';
import {normalizeAnnotationChangeRequest} from './entity-annotation-workflow-plan';
import type {AnnotationApprovedMutationPolicy,AnnotationBusinessMutation,AnnotationCapturedChange,AnnotationChangeRequest,AnnotationNativeNode,AnnotationNativeProof,AnnotationOriginalSource} from './entity-annotation-workflow.types';
const deny=()=>new ForbiddenException({code:'ANNOTATION_ORIGINAL_BUSINESS_REQUIRED'}),changed=()=>new ConflictException({code:'ANNOTATION_CURRENT_MATERIAL_CHANGED'});
interface Frame {active:boolean;mode:'capture'|'approved';tx:DbService;actorId:string;clusterId:string;workspaceId:string;request:Readonly<AnnotationChangeRequest>;
 executed:boolean;handle?:object;expected?:Readonly<AnnotationCapturedChange>;captured?:Readonly<AnnotationCapturedChange>;workflowId?:string;audit?:Readonly<AuditOutboxReceipt>;}
@Injectable()
export class EntityAnnotationBusinessService implements OnModuleInit {
 private readonly frames=new AsyncLocalStorage<Frame>();private source?:Readonly<AnnotationOriginalSource>;private policy?:Readonly<AnnotationApprovedMutationPolicy>;
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly annotations:EntityAnnotationsService,
  private readonly kong:KongService,private readonly resolver:WorkspaceResolverService,private readonly context:KongExecutionContextService,private readonly audit:AuditService){}
 onModuleInit():void{this.source=this.annotations.installAnnotationBusinessBridge({currentTransaction:()=>this.frame()?.tx,
  execute:(m,inspect,apply,direct)=>this.execute(m,inspect,apply,direct),appendAudit:(e,tx)=>this.appendAudit(e,tx)});}
 installApprovedPolicy(policy:AnnotationApprovedMutationPolicy):void{
  if(this.policy||!policy||typeof policy.verifyCapture!=='function'||typeof policy.verifyMutation!=='function'||Object.keys(policy).some(k=>!['verifyCapture','verifyMutation'].includes(k)))throw new Error('One complete fixed annotation policy is required');
  this.policy=Object.freeze({verifyCapture:policy.verifyCapture.bind(policy),verifyMutation:policy.verifyMutation.bind(policy)});
 }
 private frame():Frame|undefined{const f=this.frames.getStore();if(f&&!f.active)throw deny();return f;}
 private original():Readonly<AnnotationOriginalSource>{if(!this.source)throw deny();return this.source;}
 readAnnotation(capture:Readonly<AnnotationCapturedChange>,tx=this.db):Promise<EntityAnnotationRow|null>{const m=capture.mutation;return this.original().readAnnotation(m.clusterId,m.entityType,m.entityId,tx);}
 private invoke(r:Readonly<AnnotationChangeRequest>,cid:string,actor:EntityActor,wid:string):Promise<unknown>{
  return r.operation==='set'?this.annotations.set(cid,r.entityType,r.entityId,r.input as any,actor,wid):r.operation==='remove'
   ?this.annotations.remove(cid,r.entityType,r.entityId,r.input as any,actor,wid):this.annotations.restore(cid,r.entityType,r.entityId,r.input as any,actor,wid);
 }
 async capture(raw:unknown,cid:string,actor:EntityActor,wid:string,tx:DbService):Promise<Readonly<AnnotationCapturedChange>>{
  if(this.frame())throw deny();const request=normalizeAnnotationChangeRequest(raw),frame:Frame={active:true,mode:'capture',tx,actorId:actor.user.id,clusterId:cid,workspaceId:wid,request,executed:false};
  try{await this.frames.run(frame,()=>this.invoke(request,cid,actor,wid));if(!frame.executed||!frame.captured)throw deny();return frame.captured;}finally{frame.active=false;}
 }
 async apply(handle:object,capture:Readonly<AnnotationCapturedChange>,actor:EntityActor,tx:DbService):Promise<unknown>{
  if(!this.policy||this.frame())throw deny();const fixed=immutableJson(capture),binding=await this.policy.verifyCapture(handle,fixed,actor,tx);
  const frame:Frame={active:true,mode:'approved',tx,actorId:actor.user.id,clusterId:fixed.mutation.clusterId,workspaceId:fixed.mutation.workspaceId,request:fixed.request,expected:fixed,handle,executed:false,workflowId:iamId(binding.workflowId)};
  try{const result=await this.frames.run(frame,()=>this.invoke(frame.request,frame.clusterId,actor,frame.workspaceId));if(!frame.executed||!frame.audit)throw deny();return result;}finally{frame.active=false;}
 }
 async observe(capture:Readonly<AnnotationCapturedChange>,actor:EntityActor,action:'read'|'write'|'delete',tx=this.db):Promise<Readonly<AnnotationNativeProof>>{
  const m=capture.mutation;return this.readProof(m.clusterId,m.workspaceId,m.entityType,m.entityId,actor,action,tx);
 }
 private async readProof(cid:string,wid:string,type:EntityType,id:string,actor:EntityActor,action:'read'|'write'|'delete',_tx:DbService):Promise<Readonly<AnnotationNativeProof>>{
  const current=await this.original().observe(cid,type,id,actor,action,wid),root:AnnotationNativeNode={entityType:type,entity:current.entity,workspaceId:current.workspaceId},parents:AnnotationNativeNode[]=[],serviceRoutes:AnnotationNativeNode[]=[],seen=new Set([`${type}:${id}`]);
  const classify=async(t:EntityType,e:any):Promise<AnnotationNativeNode>=>{
   iamId(e?.id);const scope=await this.resolver.classify(cid,e.tags);if(scope.state!=='resolved'||!scope.workspace||scope.workspace.status==='deleted')throw changed();
   return {entityType:t,entity:e,workspaceId:scope.workspace.id};
  };
  const add=async(t:EntityType,pid:unknown):Promise<void>=>{if(!pid)return;const target=iamId(pid),key=`${t}:${target}`;if(seen.has(key))return;if(seen.size>=16)throw deny();seen.add(key);
   const path=`/${t}/${target}`,entity:any=await this.context.runInternalRead(cid,'authorization',()=>this.kong.request(cid,'GET',path),{paths:[path],workspaceId:wid,maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000});
   if(entity?.id!==target)throw changed();const node=await classify(t,entity);parents.push(node);if(t==='routes')await add('services',entity.service?.id);
  };
  await this.context.runActor({actor:actor.user,clusterId:cid,workspaceId:wid,module:'annotations',action,requestId:actor.requestId},async()=>{
   if(type==='routes')await add('services',(current.entity.service as any)?.id);
   if(type==='plugins')for(const [field,parent]of [['service','services'],['route','routes'],['consumer','consumers']]as const)await add(parent,(current.entity[field] as any)?.id);
   if(type==='services'){
    const path=`/services/${id}/routes`;await this.context.runInternalRead(cid,'authorization',async()=>{
     let offset:string|undefined;const offsets=new Set<string>(),ids=new Set<string>();
     for(let page=0;page<8;page++){
      const result:any=await this.kong.request(cid,'GET',path,undefined,{size:100,...(offset?{offset}:{})});if(!Array.isArray(result?.data)||result.data.length>100)throw changed();
      for(const entity of result.data){if(entity?.service?.id!==id||ids.has(entity?.id))throw changed();ids.add(iamId(entity.id));serviceRoutes.push(await classify('routes',entity));}
      if(result.next==null)return;if(typeof result.next!=='string')throw changed();const next=new URL(result.next,'http://kong.local');
      if(next.pathname!==path||!next.searchParams.has('offset')||[...next.searchParams.keys()].some(k=>!['offset','size'].includes(k)))throw changed();
      offset=next.searchParams.get('offset')!;if(!offset||offset.length>8192||offsets.has(offset))throw changed();offsets.add(offset);
     }throw new ForbiddenException({code:'ANNOTATION_RELATIONSHIP_BUDGET_EXHAUSTED'});
    },{paths:[path],workspaceId:wid,maxCalls:8,maxPages:8,maxRecords:800,maxBytes:4*1024*1024,timeoutMs:10000});
   }
  });
  return immutableJson({root,parents,serviceRoutes,routesComplete:true});
 }
 private async execute<T>(m:AnnotationBusinessMutation,inspect:(tx:DbService)=>Promise<EntityAnnotationRow|null>,apply:(tx:DbService,before:EntityAnnotationRow|null)=>Promise<T>,direct:()=>Promise<T>):Promise<T>{
  const f=this.frame();if(!f)return direct();if(f.executed||m.actor.user.id!==f.actorId||m.clusterId!==f.clusterId||m.workspaceId!==f.workspaceId||m.entityType!==f.request.entityType||m.entityId!==f.request.entityId||m.operation!==f.request.operation)throw deny();
  f.executed=true;const before=await inspect(f.tx),{actor,...pure}=m,actual=immutableJson(pure),proof=await this.readProof(m.clusterId,m.workspaceId,m.entityType,m.entityId,actor,m.action,f.tx);
  if(this.frame()!==f||this.secrets.fingerprint(proof.root.entity)!==this.secrets.fingerprint(m.entity))throw changed();
  if(f.mode==='capture'){f.captured=immutableJson({request:f.request,mutation:actual,before,nativeProof:proof});return undefined as T;}
  if(!f.handle||!f.expected||!this.policy||this.secrets.fingerprint(actual)!==this.secrets.fingerprint(f.expected.mutation)||this.secrets.fingerprint(before)!==this.secrets.fingerprint(f.expected.before)||this.secrets.fingerprint(proof)!==this.secrets.fingerprint(f.expected.nativeProof))throw changed();
  await this.policy.verifyMutation(f.handle,m,'before',f.tx);if(this.frame()!==f)throw deny();const result=await apply(f.tx,before),after=await this.original().readAnnotation(m.clusterId,m.entityType,m.entityId,f.tx);
  if(this.frame()!==f||!f.audit)throw deny();await this.policy.verifyMutation(f.handle,m,'after',f.tx,result,after,f.audit);if(this.frame()!==f)throw deny();return result;
 }
 private async appendAudit(event:AuditEvent,tx:DbService):Promise<AuditOutboxReceipt>{
  const f=this.frame();if(!f)return this.audit.append(event,tx);if(f.mode!=='approved'||!f.executed||f.tx!==tx||!f.workflowId||f.audit||event.actorId!==f.actorId||event.clusterId!==f.clusterId||event.workspaceId!==f.workspaceId||event.entityType!==f.request.entityType||event.entityId!==f.request.entityId||event.workflowId!=null)throw deny();
  const receipt=await this.audit.append({...event,workflowId:f.workflowId},tx);if(this.frame()!==f||!receipt?.id)throw deny();f.audit=Object.freeze({...receipt});return receipt;
 }
}
