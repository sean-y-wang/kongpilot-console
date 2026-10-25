import {ConflictException,ForbiddenException,Injectable,OnModuleInit,Optional} from '@nestjs/common';
import {AsyncLocalStorage} from 'node:async_hooks';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {ClustersService} from '../clusters/clusters.service';
import {DataSourcesService} from '../data-sources/data-sources.service';
import {WorkspaceService} from '../workspaces/workspace.service';
import {RecycleService} from '../recycle-bin/recycle.service';
import {IamMutationsService} from '../iam/iam-mutations.service';
import type {EntityActor} from '../entities/entities.types';
import {normalizeControlChangeRequest} from './control-metadata-plan';
import type {ControlApprovedMutationPolicy,ControlBusinessBridge,ControlBusinessMutation,ControlCapturedChange,ControlChangeRequest} from './control-metadata.types';

const deny=()=>new ForbiddenException({code:'CONTROL_ORIGINAL_BUSINESS_EXECUTION_REQUIRED'});
interface BusinessFrame {active:boolean;mode:'capture'|'approved';tx:DbService;actorId:string;clusterId:string;request:Readonly<ControlChangeRequest>;
 handle?:object;expected?:Readonly<ControlCapturedChange>;captured?:Readonly<ControlCapturedChange>;ids:string[];idIndex:number;executed:boolean;}
/** Re-enters the original validators and SQL closures. The explicit private
 * frame is scoped to one captured operation and never changes Direct policy. */
@Injectable()
export class ControlMetadataBusinessService implements OnModuleInit {
 private readonly frames=new AsyncLocalStorage<BusinessFrame>();
 private policy?:Readonly<ControlApprovedMutationPolicy>;
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly clusters:ClustersService,
  private readonly sources:DataSourcesService,private readonly workspaces:WorkspaceService,private readonly operations:IamMutationsService,@Optional() private readonly recycle?:RecycleService){}
 onModuleInit():void {
  const bridge:ControlBusinessBridge={currentTransaction:()=>this.frame()?.tx,allocateId:()=>this.allocateId(),completed:context=>this.frame()?Promise.resolve(null):this.operations.completed(context),
   execute:(mutation,fn,direct)=>this.execute(mutation,fn,direct)};
  this.clusters.installControlMetadataBridge(bridge);this.sources.installControlMetadataBridge(bridge);this.workspaces.installControlMetadataBridge(bridge);this.recycle?.installControlMetadataBridge(bridge);
 }
 installApprovedPolicy(policy:ControlApprovedMutationPolicy):void {
  if(this.policy||!policy||typeof policy.verifyCapture!=='function'||typeof policy.verifyMutation!=='function')throw new Error('One fixed control metadata policy is required');
  this.policy=Object.freeze({verifyCapture:policy.verifyCapture.bind(policy),verifyMutation:policy.verifyMutation.bind(policy)});
 }
 private frame():BusinessFrame|undefined {const frame=this.frames.getStore();if(frame&&!frame.active)throw deny();return frame;}
 private allocateId():string {const frame=this.frame();if(!frame)return randomUUID();
  if(frame.executed||frame.idIndex>=1)throw deny();
  const id=frame.mode==='capture'?randomUUID():frame.expected?.allocatedIds[frame.idIndex];if(!id)throw deny();
  frame.ids.push(id);frame.idIndex++;return id;
 }
 /** Probe projections and timestamps are deliberately excluded. Configuration
 * secrets remain encrypted inside the immutable prepared material. */
 async readConfig(request:Readonly<ControlChangeRequest>,clusterId:string,resourceId:string,tx:DbService=this.db):Promise<Readonly<Record<string,unknown>>|null>{
  if(request.resource==='recycle-bin'){if(!this.recycle)throw deny();return this.recycle.readControlPurgeConfig(clusterId,resourceId,tx);}
  let row:any;
  if(request.resource==='clusters')row=await tx.one('SELECT id,name,environment,admin_url,proxy_origin,transport_scope,labels,execution_mode,connection_secret,revision,deleted_at FROM clusters WHERE id=$1 FOR SHARE',[resourceId]);
  else if(request.resource==='data-sources')row=await tx.one('SELECT id,cluster_id,name,type,base_url,auth_secret,enabled,revision,deleted_at FROM data_sources WHERE cluster_id=$1 AND id=$2 FOR SHARE',[clusterId,resourceId]);
  else row=await tx.one('SELECT id,cluster_id,code,name,owner_user_id,description,is_default,status,revision,deleted_at,retention_until FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR SHARE',[clusterId,resourceId]);
  return row?immutableJson(row):null;
 }
 async assertPurgeSubject(capture:Readonly<ControlCapturedChange>,actor:EntityActor,action:string,tx:DbService):Promise<void>{
  if(capture.request.resource!=='recycle-bin'||!this.recycle)throw deny();
  await this.recycle.assertControlPurgeSubject(capture.mutation.clusterId,capture.mutation.resourceId,actor.user,action,capture.mutation.workspaceId!,tx);
 }
 private invoke(request:Readonly<ControlChangeRequest>,clusterId:string,actor:EntityActor):Promise<unknown>{
  const body=immutableJson(request.input),id=request.resourceId!;
  if(request.resource==='clusters')return request.operation==='update'?this.clusters.update(id,body,actor):this.clusters.deactivate(id,body,actor);
  if(request.resource==='data-sources')return request.operation==='create'?this.sources.create(clusterId,body,actor)
   :request.operation==='update'?this.sources.update(clusterId,id,body,actor):this.sources.deactivate(clusterId,id,body,actor);
  if(request.resource==='recycle-bin'){if(!this.recycle)throw deny();return this.recycle.purge(clusterId,id,actor.user,body as any,{requestId:actor.requestId,ip:actor.ip,idempotencyKey:actor.idempotencyKey,workspaceId:String(body.workspaceId),revision:Number(body.revision)});}
  return request.operation==='create'?this.workspaces.create(clusterId,body as any,actor):request.operation==='update'?this.workspaces.update(clusterId,id,body as any,actor)
   :request.operation==='archive'?this.workspaces.remove(clusterId,id,body as any,actor):this.workspaces.restore(clusterId,id,body as any,actor);
 }
 async capture(raw:unknown,clusterId:string,actor:EntityActor,tx:DbService):Promise<Readonly<ControlCapturedChange>>{
  const request=normalizeControlChangeRequest(raw);if(request.resource==='clusters'&&request.resourceId!==clusterId||this.frame())throw deny();
  const frame:BusinessFrame={active:true,mode:'capture',tx,actorId:actor.user.id,clusterId,request,ids:[],idIndex:0,executed:false};
  try {await this.frames.run(frame,()=>this.invoke(request,clusterId,actor));if(!frame.executed||!frame.captured)throw deny();return frame.captured;}
  finally {frame.active=false;}
 }
 async apply(originalHandle:object,capture:Readonly<ControlCapturedChange>,actor:EntityActor,tx:DbService):Promise<unknown>{
  if(!this.policy||this.frame())throw deny();const fixed=immutableJson(capture);
  await this.policy.verifyCapture(originalHandle,fixed,actor,tx);
  const frame:BusinessFrame={active:true,mode:'approved',tx,actorId:actor.user.id,clusterId:fixed.mutation.clusterId,request:fixed.request,handle:originalHandle,
   expected:fixed,ids:[],idIndex:0,executed:false};
  try {const result=await this.frames.run(frame,()=>this.invoke(frame.request,frame.clusterId,actor));
   if(!frame.executed||this.secrets.fingerprint(frame.ids)!==this.secrets.fingerprint(fixed.allocatedIds))throw deny();return result;}
  finally {frame.active=false;}
 }
 private async execute<T>(mutation:ControlBusinessMutation,fn:(tx:DbService)=>Promise<T>,direct:()=>Promise<T>):Promise<T>{
  const frame=this.frame();if(!frame)return direct();
  if(frame.executed||mutation.actor.user.id!==frame.actorId||mutation.clusterId!==frame.clusterId||mutation.resource!==frame.request.resource||mutation.operation!==frame.request.operation
   ||frame.request.resourceId&&mutation.resourceId!==frame.request.resourceId)throw deny();
  // Reserve synchronously before the first asynchronous read. Two callbacks
  // in the same ALS frame must never both pass the one-operation gate.
  frame.executed=true;
  const {actor,...pure}=mutation,actual=immutableJson(pure),before=await this.readConfig(frame.request,frame.clusterId,mutation.resourceId,frame.tx);
  if(this.frame()!==frame)throw deny();
  if(frame.request.operation==='create'?before!==null:before===null)throw new ConflictException({code:'CONTROL_METADATA_CHANGED'});
  if(frame.mode==='capture') {
   frame.captured=immutableJson({request:frame.request,mutation:actual,before,allocatedIds:frame.ids});return undefined as T;
  }
  if(!frame.expected||!frame.handle||!this.policy||this.secrets.fingerprint(actual)!==this.secrets.fingerprint(frame.expected.mutation)
   ||this.secrets.fingerprint(before)!==this.secrets.fingerprint(frame.expected.before))throw new ConflictException({code:'CONTROL_METADATA_CHANGED'});
  await this.policy.verifyMutation(frame.handle,mutation,'before',frame.tx);
  if(this.frame()!==frame)throw deny();
  const result=await fn(frame.tx),after=await this.readConfig(frame.request,frame.clusterId,mutation.resourceId,frame.tx);
  if(this.frame()!==frame)throw deny();
  await this.policy.verifyMutation(frame.handle,mutation,'after',frame.tx,result,after);
  if(this.frame()!==frame)throw deny();return result;
 }
}
