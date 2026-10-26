import { withoutUnsupportedTags } from '../workspaces/workspace-resolver.service';
import { CREDENTIAL_SCHEMAS, type CredentialKind } from '../entities/entities.types';
import { ConflictException, Injectable } from '@nestjs/common';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { MutationService, type MutationContext } from '../mutations/mutation.service';
import { RecycleService } from '../recycle-bin/recycle.service';
import { CredentialStoreService } from '../credentials/credential-store.service';
import { EntityIndexService } from '../entities/entity-index.service';
import { ConfigurationAccessService } from './configuration-access.service';
import type { ConfigurationAccessHandle, ConfigurationPlanStep } from './configuration.types';

const changed=()=>new ConflictException({code:'CONFIGURATION_NATIVE_PLAN_CHANGED',message:'配置与已确认计划不一致，已停止执行'});
/** The full immutable wire body is sent once. In particular plugin maps are
 * replaced exactly; EntityService's interactive secret-preserving merge is
 * deliberately not a configuration-plan compiler. All transport policy,
 * locks, archive checks, audit and uncertainty handling remain mandatory. */
@Injectable()
export class ConfigurationNativeService {
  constructor(private readonly access:ConfigurationAccessService,private readonly kong:KongService,
    private readonly execution:KongExecutionContextService,private readonly secrets:SecretService,
    private readonly authz:AuthorizationService,private readonly workspaces:WorkspaceResolverService,
    private readonly mutations:MutationService,private readonly recycle:RecycleService,
    private readonly credentials:CredentialStoreService,private readonly index:EntityIndexService){}
  receipt(context:MutationContext):Promise<any>{return this.mutations.inspectStepReceipt(context);}

  async context(handle:ConfigurationAccessHandle,step:ConfigurationPlanStep,jobStepId:string):Promise<MutationContext>{
    const a=await this.access.description(handle),packet=step.nativeRequests[0];
    if(step.referenceOnly||step.blockerCodes.length||step.nativeRequests.length!==1||!packet
      ||this.secrets.fingerprint(step.body)!==step.bodyHmac||this.secrets.fingerprint(step.before)!==step.beforeHmac
      ||this.secrets.fingerprint(packet.body)!==packet.bodyHmac||packet.beforeHmac!==step.beforeHmac)throw changed();
    return{actor:a.actor,clusterId:a.scope.clusterId,workspaceId:step.objectWorkspaceId,entityType:step.entityType,
      entityId:(step.mutationAction==='create'?step.allocatedNativeId:step.nativeId)??undefined,action:step.mutationAction,
      parentId:step.parentId??undefined,credentialKind:step.credentialKind??undefined,payload:structuredClone(step.body),
      // A sealed CREATE has no old resource to authorize. Keep its null HMAC
      // above; MutationService encrypts the absent before as canonical null.
      // Update/delete and unexpected non-null CREATE inputs retain preflight.
      before:step.mutationAction==='create'&&step.before===null?undefined:structuredClone(step.before),
      idempotencyKey:`configuration-${a.jobId}-${jobStepId}`,requestId:a.requestId,ip:a.ip,
      ...(step.mutationAction==='delete'?{confirmName:String(step.body?.confirm_name)}:{})};
  }
  async execute(handle:ConfigurationAccessHandle,step:ConfigurationPlanStep,jobStepId:string):Promise<{receipt:any;after:unknown;result:any;effectiveNativeId:string|null}>{
    const context=await this.context(handle,step,jobStepId),packet=step.nativeRequests[0],type=step.credentialKind??step.entityType;
    await this.access.assertCurrent(handle,{phase:'step',jobId:context.idempotencyKey?this.access.currentJob().jobId:undefined});
    if(step.before!==null)await this.authz.assertEntity(context.actor,context.clusterId,type,step.permissionAction,step.before,context.workspaceId);
    if(step.mutationAction!=='delete'){
      let prepared:any;
      if(step.entityType==='credentials'||step.entityType==='targets'){
        const parentType=step.entityType==='targets'?'upstreams':'consumers',parentPath=`/${parentType}/${step.parentId}`;
        const parent=await this.execution.runInternalRead(context.clusterId,'entity-preflight',()=>this.kong.request<any>(context.clusterId,'GET',parentPath),{paths:[parentPath],maxCalls:1});
        await this.authz.assertEntity(context.actor,context.clusterId,parentType,'read',parent,context.workspaceId);
        prepared=step.mutationAction==='create'?await this.workspaces.prepareInheritedCreate(context.clusterId,step.entityType,parent,step.body,context.workspaceId):
          await this.workspaces.prepareInheritedUpdate(context.clusterId,step.entityType,parent,step.before,step.body,context.workspaceId);
      }else prepared=step.mutationAction==='create'?await this.workspaces.prepareCreate(context.clusterId,step.entityType,step.body,context.workspaceId):
        await this.workspaces.prepareUpdate(context.clusterId,step.entityType,step.before,step.body,context.workspaceId);
      // Mirror the planner: a Kong <1.4 credential schema has no tags, and the sealed body omits them.
      if(step.entityType==='credentials'&&step.body&&!Object.hasOwn(step.body,'tags')&&isCredentialKind(step.credentialKind)){
        const schema=await Promise.resolve().then(()=>this.kong.schema(context.clusterId,CREDENTIAL_SCHEMAS[step.credentialKind as CredentialKind])).catch(()=>null);
        prepared=withoutUnsupportedTags(prepared,schema);
      }
      if(canonicalJson(prepared)!==canonicalJson(step.body)||canonicalJson(packet.body)!==canonicalJson(step.body))throw changed();
      const entity={...(step.before as any??{}),...prepared,id:step.allocatedNativeId??step.nativeId};
      if(step.parentId)entity[step.entityType==='targets'?'upstream':'consumer']={id:step.parentId};
      await this.authz.assertEntity(context.actor,context.clusterId,type,'write',entity,context.workspaceId);
    }
    const result=step.mutationAction==='delete'?await this.recycle.archiveAndDelete(context,true):
      await this.mutations.execute(context,async()=>{
        const entity=await this.kong.request<any>(context.clusterId,packet.method,packet.canonicalPath,packet.body);
        const expected=step.allocatedNativeId??step.nativeId;if(entity?.id!==expected)throw changed();
        if(step.entityType==='credentials')await this.credentials.save(context.clusterId,step.parentId!,step.credentialKind!,entity,step.body??{});
        else if(step.entityType!=='targets')await this.index.upsert(context.clusterId,step.entityType,entity);
        return{entity,propagation:'pending'};
      });
    const receipt=await this.mutations.inspectStepReceipt(context);
    if(!receipt||receipt.state!=='succeeded'||!receipt.remoteCompleted)throw new ConflictException({code:'CONFIGURATION_NATIVE_RECEIPT_MISSING',state:'uncertain'});
    let after:unknown=null;
    if(step.mutationAction!=='delete'){
      const id=receipt.entityId,path=step.entityType==='credentials'?`/consumers/${step.parentId}/${step.credentialKind}/${id}`:
        step.entityType==='targets'?`/upstreams/${step.parentId}/targets/${id}`:`/${step.entityType}/${id}`;
      after=await this.execution.runInternalRead(context.clusterId,'operation-check',()=>this.kong.request(context.clusterId,'GET',path),{paths:[path],maxCalls:1});
    }
    return{receipt,after,result:this.secrets.redact(result),effectiveNativeId:receipt.entityId};
  }
}

function isCredentialKind(value:unknown):value is CredentialKind{return typeof value==='string'&&Object.hasOwn(CREDENTIAL_SCHEMAS,value);}
