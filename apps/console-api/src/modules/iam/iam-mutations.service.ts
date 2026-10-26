import { BadRequestException,ConflictException,ForbiddenException,HttpException,Injectable,NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService, type AuditEvent } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { type IamActor,type IamScope,iamId } from './iam.types';
import type {IamApprovedMutationPolicy} from './iam-workflow.types';

export interface IamMutation extends IamScope {module:string;action:string;targetId?:string;payload:unknown;actor:IamActor}
/** Only a server callback can supply the actual SQL subject/readback. Scope and
 * actor remain bound to the operation; this context never enters its result. */
export interface IamBusinessAuditContext {
  entityType:string; entityId?:string|null; before:unknown; after:unknown;
  scopeHints?:AuditEvent['scopeHints'];
}
export type IamBusinessAuditSetter = (context:IamBusinessAuditContext)=>void;

/** Console metadata has its own durable ledger; no invented Kong cluster or remote call. */
@Injectable()
export class IamMutationsService {
  private approvedPolicy?:Readonly<IamApprovedMutationPolicy>;
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly audit:AuditService,private readonly authz:AuthorizationService){}
  installApprovedMetadataPolicy(policy:IamApprovedMutationPolicy):void{
    if(this.approvedPolicy||!policy||typeof policy.verify!=='function'||Object.keys(policy).some(k=>k!=='verify'))throw new Error('IAM approved metadata requires one fixed original-handle verifier');
    this.approvedPolicy=Object.freeze({verify:policy.verify.bind(policy)});
  }
  /** Explicit zero-native approval path. The ordinary direct-mode check is
   * untouched. A live original private handle and exact execution/step/intent
   * plus full current subject rules are required before any IAM SQL write. */
  async executeApprovedFixed<T>(context:IamMutation,originalHandle:object,tx:DbService,fn:(tx:DbService)=>Promise<T>):Promise<T>{
    if(!this.approvedPolicy||!tx||typeof tx.one!=='function'||typeof tx.exec!=='function'||typeof fn!=='function')throw new ForbiddenException({code:'IAM_APPROVED_METADATA_UNAVAILABLE'});
    await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR UPDATE NOWAIT');await this.redis.assertLeaseOwnership();
    const binding=await this.approvedPolicy.verify(originalHandle,context,'before',tx);
    if(binding.actorId!==context.actor.user.id)throw new ForbiddenException({code:'IAM_APPROVED_METADATA_BINDING_INVALID'});
    const key=`iam-approved-${binding.executionId}`,hash=this.secrets.fingerprint({actor:context.actor.user.id,module:context.module,action:context.action,target:context.targetId??null,
      clusterId:context.cluster_id,workspaceId:context.workspace_id,payload:context.payload});
    if(await tx.one('SELECT id FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[context.actor.user.id,key]))throw new ConflictException({code:'IAM_APPROVED_METADATA_ALREADY_EXECUTED'});
    const id=randomUUID();await tx.exec(`INSERT INTO iam_operations(id,actor_id,idempotency_key,request_hash,module,action,target_id,cluster_id,workspace_id,payload_secret)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[id,context.actor.user.id,key,hash,context.module,context.action,context.targetId??null,context.cluster_id,context.workspace_id,
        this.secrets.encrypt(context.payload,`iam:${id}:payload`)]);
    await this.audit.append({...this.event(context),...this.workflowAuditScope(context,binding),workflowId:binding.workflowId,action:`iam.${context.action}.requested`,after:context.payload,result:'pending'},tx);
    const result=await fn(tx);await this.redis.assertLeaseOwnership();
    const after=await this.approvedPolicy.verify(originalHandle,context,'after',tx,result);
    if(after.intentId!==binding.intentId||after.workflowId!==binding.workflowId||after.executionId!==binding.executionId||after.stepId!==binding.stepId
      ||after.planHash!==binding.planHash||after.planRevision!==binding.planRevision||after.actorId!==binding.actorId||after.sessionId!==binding.sessionId)throw new ForbiddenException({code:'IAM_APPROVED_METADATA_BINDING_INVALID'});
    if(after.clusterId!==binding.clusterId||after.workspaceId!==binding.workspaceId)throw new ForbiddenException({code:'IAM_APPROVED_METADATA_BINDING_INVALID'});
    const epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if(await tx.exec("UPDATE iam_operations SET state='succeeded',remote_completed=true,result_secret=$2,safe_result=$3::jsonb,updated_at=now() WHERE id=$1 AND state='running'",
      [id,this.secrets.encrypt(result,`iam:${id}:result`),JSON.stringify(this.secrets.redact(result))])!==1)throw new ConflictException({code:'IAM_APPROVED_METADATA_LEDGER_CHANGED'});
    await tx.exec(`INSERT INTO iam_workflow_mutation_facts(operation_id,intent_id,workflow_id,execution_id,step_id,cluster_id,workspace_id,actor_id,session_id,
      plan_revision,plan_hash,before_permission_version,after_permission_version,before_iam_epoch,after_iam_epoch,result_hmac,workflow_cluster_id,workflow_workspace_id,execution_origin,schedule_claim_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,[id,binding.intentId,binding.workflowId,binding.executionId,binding.stepId,context.cluster_id,context.workspace_id,
        binding.actorId,binding.sessionId,binding.planRevision,binding.planHash,binding.permissionVersion,after.permissionVersion,binding.iamEpoch,String(epoch?.version),this.secrets.fingerprint(result),binding.clusterId,binding.workspaceId,binding.scheduledClaimId?'scheduled':'session',binding.scheduledClaimId]);
    await this.audit.append({...this.event(context),...this.workflowAuditScope(context,binding),workflowId:binding.workflowId,action:`iam.${context.action}.approved`,after:result,result:'success'},tx);
    await this.redis.assertLeaseOwnership();return result;
  }
  private async authorize(context:IamMutation):Promise<void>{
    if(context.cluster_id)await this.authz.assertCluster(context.actor.user,context.cluster_id,context.module,context.action,context.workspace_id??undefined);
    else await this.authz.assertConsole(context.actor.user,context.module,context.action,context.targetId);
  }
  /** Global IAM targets have no cluster/workspace, but a workflow-linked audit
   * row must carry the workflow's own scope (audit_events_portal_workflow_scope). */
  private workflowAuditScope(context:IamMutation,binding:{clusterId:string;workspaceId:string}){
    return context.cluster_id&&context.workspace_id?{}:{clusterId:binding.clusterId,workspaceId:binding.workspaceId};}
  private event(context:IamMutation){return {actorId:context.actor.user.id,clusterId:context.cluster_id,workspaceId:context.workspace_id,
    entityType:context.module,entityId:context.targetId,requestId:context.actor.requestId,ip:context.actor.ip};}
  private async assertDirectScope(context:IamMutation,tx=this.db,lock=false):Promise<void>{
    if(!context.cluster_id)return;
    const cluster=await tx.one<{execution_mode:string;status:string}>('SELECT execution_mode,status FROM clusters WHERE id=$1 AND deleted_at IS NULL'+(lock?' FOR SHARE':''),[context.cluster_id]);
    if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
    if(cluster.execution_mode!=='direct')throw new ConflictException({code:'APPROVAL_REQUIRED',message:'此集群的身份配置变更须审批，禁止直接执行'});
    if(cluster.status==='disabled')throw new ConflictException({code:'CLUSTER_DISABLED',message:'集群已停用，不能修改配置'});
  }
  async completed<T>(context:IamMutation):Promise<{result:T}|null>{
    await this.authorize(context);const key=context.actor.idempotencyKey;if(!key)return null;
    if(!/^[A-Za-z\d_.:-]{1,128}$/.test(key))throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY',message:'幂等键格式无效'});
    const old=await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[context.actor.user.id,key]);if(!old)return null;
    const hash=this.secrets.fingerprint({actor:context.actor.user.id,module:context.module,action:context.action,target:context.targetId??null,clusterId:context.cluster_id,workspaceId:context.workspace_id,payload:context.payload});
    if(old.request_hash!==hash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键已用于不同身份变更'});
    return old.state==='succeeded'&&old.remote_completed===true&&old.result_secret?{result:this.secrets.decrypt<T>(old.result_secret,`iam:${old.id}:result`)}:null;
  }
  async execute<T>(context:IamMutation,fn:(tx:DbService,operationId:string,setBusinessAudit:IamBusinessAuditSetter)=>Promise<T>):Promise<T>{
    await this.authorize(context);
    const key=context.actor.idempotencyKey??randomUUID();if(!/^[A-Za-z\d_.:-]{1,128}$/.test(key))throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY',message:'幂等键格式无效'});
    const hash=this.secrets.fingerprint({actor:context.actor.user.id,module:context.module,action:context.action,target:context.targetId??null,
      clusterId:context.cluster_id,workspaceId:context.workspace_id,payload:context.payload});
    return this.redis.withLock(`iam-operation:${context.actor.user.id}:${key}`,async()=>{
      await this.authorize(context);
      const old=await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[context.actor.user.id,key]);
      if(old){if(old.request_hash!==hash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键已用于不同身份变更'});
        if(old.state==='succeeded'&&old.remote_completed===true&&old.result_secret)return this.secrets.decrypt<T>(old.result_secret,`iam:${old.id}:result`);
        throw new ConflictException({code:'IAM_RESULT_UNCERTAIN',message:'此身份变更已经尝试执行，请先核验原回执',operationId:old.id,state:old.state});}
      await this.assertDirectScope(context);
      const id=randomUUID();
      await this.db.transaction(async tx=>{
        await tx.exec(`INSERT INTO iam_operations(id,actor_id,idempotency_key,request_hash,module,action,target_id,cluster_id,workspace_id,payload_secret)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[id,context.actor.user.id,key,hash,context.module,context.action,context.targetId??null,
          context.cluster_id,context.workspace_id,this.secrets.encrypt(context.payload,`iam:${id}:payload`)]);
        await this.audit.append({...this.event(context),action:`iam.${context.action}.requested`,after:context.payload,result:'pending'},tx);
      });
      try{return await this.db.transaction(async tx=>{
        // Avoid exhausting the pool with writers waiting while the lock owner
        // performs fresh authorization queries on another pooled connection.
        await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR UPDATE NOWAIT');
        await this.assertDirectScope(context,tx,true);
        await this.authorize(context);await this.redis.assertLeaseOwnership();
        let businessAudit:IamBusinessAuditContext|undefined,auditSetterActive=true;
        const setBusinessAudit:IamBusinessAuditSetter=value=>{
          if(!auditSetterActive||businessAudit||!value||typeof value!=='object'||Array.isArray(value)
            ||Object.keys(value).some(name=>!['entityType','entityId','before','after','scopeHints'].includes(name))
            ||typeof value.entityType!=='string'||!/^[A-Za-z\d_.-]{1,128}$/.test(value.entityType)
            ||value.entityId!=null&&(typeof value.entityId!=='string'||!/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value.entityId))
            ||!Object.hasOwn(value,'before')||!Object.hasOwn(value,'after'))throw new BadRequestException({code:'INVALID_IAM_BUSINESS_AUDIT'});
          businessAudit=structuredClone(value);
        };
        let result:T;
        try{result=await fn(tx,id,setBusinessAudit);}finally{auditSetterActive=false;}
        await this.redis.assertLeaseOwnership();
        await this.authorize(context);
        await this.assertDirectScope(context,tx,true);
        await tx.exec("UPDATE iam_operations SET state='succeeded',remote_completed=true,result_secret=$2,safe_result=$3::jsonb,updated_at=now() WHERE id=$1",
          [id,this.secrets.encrypt(result,`iam:${id}:result`),JSON.stringify(this.secrets.redact(result))]);
        await this.audit.append({...this.event(context),entityType:businessAudit?.entityType??context.module,
          entityId:businessAudit?.entityId??context.targetId,action:`iam.${context.action}`,
          before:businessAudit?.before??null,after:businessAudit?businessAudit.after:result,
          ...(businessAudit?.scopeHints?{scopeHints:businessAudit.scopeHints}:{}),result:'success'},tx);
        await this.redis.assertLeaseOwnership();
        return result;
      });}catch(error:any){
        // COMMIT may have succeeded even if its acknowledgement was lost. A
        // durable exact original terminal ledger is the only replay proof;
        // never invoke the callback again or label that committed fact failed.
        const committed=await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[context.actor.user.id,key]).catch(()=>null);
        if(committed?.id===id&&committed.request_hash===hash&&committed.state==='succeeded'&&committed.remote_completed===true&&committed.result_secret){
          await this.authorize(context);return this.secrets.decrypt<T>(committed.result_secret,`iam:${id}:result`);
        }
        if(error?.code==='55P03')error=new ConflictException({code:'IAM_WRITE_BUSY',message:'另一个授权变更正在提交，请核验回执后重试'});
        if(error?.code==='23505')error=new ConflictException({code:'IAM_DUPLICATE_RESOURCE',message:'资源或授权已存在，请刷新后重试'});
        if(['23503','23514','22P02'].includes(error?.code))error=new BadRequestException({code:'INVALID_IAM_SCOPE',message:'身份配置违反资源范围约束'});
        const response=error instanceof HttpException?error.getResponse():null;
        const code=(response&&typeof response==='object'&&'code'in response?String(response.code):'IAM_OPERATION_FAILED');
        const uncertain=!(error instanceof HttpException)||error.getStatus()>=500;
        await this.db.transaction(async tx=>{
          await tx.exec("UPDATE iam_operations SET state=$2,remote_completed=$3,error_code=$4,safe_result=$5::jsonb,updated_at=now() WHERE id=$1 AND state='running'",
            [id,uncertain?'uncertain':'failed',!uncertain,code,JSON.stringify({code})]);
          await this.audit.append({...this.event(context),action:`iam.${context.action}`,result:uncertain?'uncertain':'failed'},tx);
        }).catch(()=>undefined);
        if(uncertain)throw new HttpException({code:'IAM_RESULT_UNCERTAIN',message:'身份变更结果需要核验，请勿使用新幂等键重试',operationId:id,state:'uncertain'},503);
        throw error;
      }
    });
  }
  async receipt(actor:IamActor,keyOrId:string,byKey=false):Promise<any>{
    if(byKey&&!/^[A-Za-z\d_.:-]{1,128}$/.test(keyOrId))throw new BadRequestException('幂等键无效');
    if(!byKey)iamId(keyOrId);
    const row=await this.db.one<any>(`SELECT * FROM iam_operations WHERE actor_id=$1 AND ${byKey?'idempotency_key':'id'}=$2`,[actor.user.id,keyOrId]);
    if(!row)throw new NotFoundException({code:'IAM_OPERATION_NOT_FOUND',message:'身份变更回执不存在'});
    if(row.actor_id!==actor.user.id)throw new ForbiddenException();
    try {
      if(row.cluster_id)await this.authz.assertCluster(actor.user,row.cluster_id,row.module,'read',row.workspace_id??undefined);
      else await this.authz.assertConsole(actor.user,row.module,'read',row.target_id??undefined);
    }catch(error){
      if(!(error instanceof ForbiddenException))throw error;
      // A write-only principal can still verify its own original operation.
      await this.authorize({...row,actor,targetId:row.target_id,payload:null});
    }
    const {id,state,remote_completed,error_code,module,action,target_id,cluster_id,workspace_id,created_at,updated_at}=row;
    return {id,state,remote_completed,error_code,module,action,target_id,cluster_id,workspace_id,created_at,updated_at,safe_result:this.secrets.redact(row.safe_result??null)};
  }
}
