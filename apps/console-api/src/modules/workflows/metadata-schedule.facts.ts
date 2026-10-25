import {isMetadataScheduledKind,MetadataScheduleRejected,type MetadataExecutionRecheck,type MetadataScheduledKind} from './metadata-schedule.guard';
import {metadataSubjectSealSource} from './metadata-schedule.registry';
import type {WorkflowScheduleStored} from './workflow-schedule.contract';

/** SQL041 generic production `load` port for metadata scheduled executors.
 * Same lock order as annotation: iam_epoch FOR SHARE → users FOR SHARE → subject. */
export interface MetadataScheduleFactsSql{one<T>(sql:string,params:readonly unknown[]):Promise<T|null>}
export interface MetadataScheduleFactsInput{
  readonly stored:Readonly<WorkflowScheduleStored>;
  readonly sealedPermissionVersion:string;
  readonly hasDomainWrite:()=>Promise<boolean>;
  readonly seal:(material:Readonly<{kind:MetadataScheduledKind;subjectId:string;materialHmac:string;workflowId:string}>)=>string;
  /** For entity-style subjects: derive material hmac from the row. */
  readonly entityMaterialHmac?:(row:Readonly<Record<string,unknown>>)=>string;
}
const reject=(code:string):never=>{throw new MetadataScheduleRejected(code);};

export async function loadMetadataScheduleFacts(sql:MetadataScheduleFactsSql,input:MetadataScheduleFactsInput):Promise<Readonly<Omit<MetadataExecutionRecheck,'claim'>>>{
  const {draft,plan}=input.stored,b=draft.binding,d=draft.delegation;
  if(!isMetadataScheduledKind(b.kind)||b.kind!==d.kind||b.kind!==plan.kind||b.subjectType!==d.subjectType||b.subjectId!==d.subjectId)
    reject('METADATA_SCHEDULE_KIND');
  const kind=b.kind as MetadataScheduledKind;
  const src=metadataSubjectSealSource(b.subjectType);
  await sql.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE',[]);
  const iam=await sql.one<{version:string|number}>('SELECT version FROM iam_epoch WHERE singleton=true',[]);
  const user=await sql.one<{status:string;deleted_at:unknown;force_password_change:boolean;credential_epoch:string|number;permissions_epoch:string|number}>(
    'SELECT status,deleted_at,force_password_change,credential_epoch,permissions_epoch FROM users WHERE id=$1 FOR SHARE',[d.ownerId]);
  if(!iam||!user)reject('METADATA_SCHEDULE_REQUESTER_INACTIVE');
  let materialHmac:string;let workflowId=b.workflowId;
  if(src.style==='request'){
    const request=await sql.one<Record<string,unknown>>(
      `SELECT ${src.materialColumn} AS material_hmac,workflow_id,cluster_id,workspace_id FROM ${src.table} WHERE id=$1`,[b.subjectId]);
    if(!request||request.cluster_id!==b.clusterId||request.workspace_id!==b.workspaceId||request.workflow_id!==b.workflowId)
      reject('METADATA_SCHEDULE_SUBJECT_CHANGED');
    materialHmac=String(request!.material_hmac);workflowId=String(request!.workflow_id);
  }else{
    const row=await sql.one<Record<string,unknown>>(
      `SELECT id,revision,cluster_id,workspace_id FROM ${src.table} WHERE id=$1`,[b.subjectId]);
    if(!row||row.cluster_id!==b.clusterId||row.workspace_id!==b.workspaceId)reject('METADATA_SCHEDULE_SUBJECT_CHANGED');
    if(!input.entityMaterialHmac)reject('METADATA_SCHEDULE_SUBJECT_CHANGED');
    materialHmac=input.entityMaterialHmac!(row!);
  }
  const active=user!.status==='active'&&user!.deleted_at==null&&user!.force_password_change!==true;
  return Object.freeze({
    admission:Object.freeze({kind,executionMode:plan.executionMode,approvalRequired:plan.approvalRequired,subjectType:b.subjectType,subjectId:b.subjectId,
      requester:Object.freeze({...b.requester}),ownerId:d.ownerId,ownerCredentialEpoch:d.ownerCredentialEpoch,subjectSealHmac:d.subjectSealHmac,
      windowStart:draft.spec.windowStart,notBefore:draft.spec.notBefore,windowEnd:draft.spec.windowEnd,expiresAt:d.expiresAt}),
    sealedPermissionVersion:input.sealedPermissionVersion,
    currentSubjectSealHmac:input.seal({kind,subjectId:b.subjectId,materialHmac,workflowId}),
    current:Object.freeze({userActive:active,credentialEpoch:String(user!.credential_epoch),permissionsEpoch:String(user!.permissions_epoch),
      iamEpoch:String(iam!.version),hasDomainWrite:active&&await input.hasDomainWrite()}),
  });
}
