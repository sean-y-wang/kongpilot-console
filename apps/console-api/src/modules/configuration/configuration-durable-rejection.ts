import {ForbiddenException} from '@nestjs/common';
import {timingSafeEqual} from 'node:crypto';
import {SecretService} from '../../infrastructure/secret.service';
import type {DbService} from '../../infrastructure/db.service';
export const DURABLE_REJECTION_KIND='durable-submission-rejected-v1' as const;
export const DURABLE_REJECTION_CODE='CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED' as const;
export interface DurableConfigurationRejectionFact {
 readonly domain:typeof DURABLE_REJECTION_KIND;readonly effectScope:'durable-registration';readonly code:typeof DURABLE_REJECTION_CODE;
 readonly id:string;readonly clusterId:string;readonly workspaceId:string;readonly ownerId:string;readonly authoringSessionId:string;
 readonly credentialEpoch:number;readonly permissionVersion:string;readonly sourceJobId:string;readonly sourcePlanId:string;readonly sourcePlanRevision:number;readonly sourcePlanHash:string;
 readonly sourceKind:'import'|'rollback';readonly idempotencyKey:string;readonly requestHmac:string;readonly admissionIssuedAt:string;readonly admissionExpiresAt:string;
 readonly rejectedAt:string;readonly freshPlanHmac:string;readonly baselineSnapshotId:string;readonly baselineVersion:number;readonly baselineManifestHmac:string;
}
export const DURABLE_REJECTION_QUERY=`SELECT r.*,j.scope_kind,j.root_ids,j.transport_scope,j.actor_id AS source_owner_id,
 EXISTS(SELECT 1 FROM configuration_durable_issues i WHERE i.source_plan_id=r.source_plan_id OR(i.owner_id=r.owner_id AND i.prepare_key=r.prepare_key)) AS has_registration,
 EXISTS(SELECT 1 FROM configuration_jobs existing WHERE existing.actor_id=r.owner_id AND existing.idempotency_key=r.prepare_key) AS has_job
 FROM configuration_durable_rejections r JOIN configuration_jobs j ON j.id=r.source_job_id AND j.cluster_id=r.cluster_id AND j.workspace_id=r.workspace_id
 WHERE r.cluster_id=$1 AND r.workspace_id=$2 AND r.owner_id=$3 AND r.prepare_key=$4`;
export const DURABLE_REJECTION_CONFLICT_QUERY=`SELECT id FROM configuration_durable_rejections WHERE(source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3) OR(owner_id=$4 AND prepare_key=$5)`;
export const DURABLE_REJECTION_INSERT=`INSERT INTO configuration_durable_rejections(id,cluster_id,workspace_id,owner_id,authoring_session_id,credential_epoch,permission_version,
 source_job_id,source_plan_id,source_plan_revision,source_plan_hash,source_kind,prepare_key,request_hmac,admission_issued_at,admission_expires_at,rejected_at,
 fresh_plan_hmac,baseline_snapshot_id,baseline_version,baseline_manifest_hmac,rejection_hmac)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`;
const keys=['domain','effectScope','code','id','clusterId','workspaceId','ownerId','authoringSessionId','credentialEpoch','permissionVersion','sourceJobId','sourcePlanId','sourcePlanRevision','sourcePlanHash','sourceKind','idempotencyKey','requestHmac','admissionIssuedAt','admissionExpiresAt','rejectedAt','freshPlanHmac','baselineSnapshotId','baselineVersion','baselineManifestHmac']as const;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,hex=/^[0-9a-f]{64}$/;
const fail=()=>new ForbiddenException({code:'CONFIGURATION_DURABLE_REJECTION_INVALID'});
function decode(value:unknown):DurableConfigurationRejectionFact{
 if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw fail();
 const r=value as any,own=Reflect.ownKeys(r);if(own.length!==keys.length||own.some(k=>typeof k!=='string'||!keys.includes(k as any)))throw fail();
 for(const k of keys){const d=Object.getOwnPropertyDescriptor(r,k);if(!d||!d.enumerable||!Object.hasOwn(d,'value'))throw fail();}
 if(r.domain!==DURABLE_REJECTION_KIND||r.effectScope!=='durable-registration'||r.code!==DURABLE_REJECTION_CODE||!['import','rollback'].includes(r.sourceKind))throw fail();
 for(const k of ['id','clusterId','workspaceId','ownerId','authoringSessionId','sourceJobId','sourcePlanId','baselineSnapshotId'])if(typeof r[k]!=='string'||!uuid.test(r[k]))throw fail();
 for(const k of ['sourcePlanHash','requestHmac','freshPlanHmac','baselineManifestHmac'])if(typeof r[k]!=='string'||!hex.test(r[k]))throw fail();
 for(const k of ['credentialEpoch','sourcePlanRevision','baselineVersion'])if(!Number.isSafeInteger(r[k])||r[k]<1)throw fail();
 if(typeof r.idempotencyKey!=='string'||!/^[A-Za-z\d._:-]{8,128}$/.test(r.idempotencyKey))throw fail();
 if(typeof r.permissionVersion!=='string'||!new RegExp('^'+r.ownerId+':[1-9]\\d*:[1-9]\\d*$').test(r.permissionVersion))throw fail();
 for(const k of ['admissionIssuedAt','admissionExpiresAt','rejectedAt'])if(typeof r[k]!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(r[k])||new Date(r[k]).toISOString()!==r[k])throw fail();
 const issued=Date.parse(r.admissionIssuedAt),expires=Date.parse(r.admissionExpiresAt),rejected=Date.parse(r.rejectedAt);
 if(issued>=expires||expires>issued+300000||rejected<issued||rejected>=expires)throw fail();
 return Object.freeze(Object.fromEntries(keys.map(k=>[k,r[k]])))as unknown as DurableConfigurationRejectionFact;
}
const iso=(v:any)=>new Date(v).toISOString();
export function durableRejectionProjection(fact:DurableConfigurationRejectionFact):Readonly<Record<string,unknown>>{
 const r=decode(fact);return Object.freeze({domain:'configuration',authorityDomain:'durable-configuration-v1',receiptKind:DURABLE_REJECTION_KIND,
 result:'rejected',commandCompleted:true,registrationCompleted:false,registrationRejected:true,submissionCompleted:false,knownNoEffect:true,
 effectScope:'durable-registration',nativeWrites:'none',idempotencyKey:r.idempotencyKey,actorId:r.ownerId,clusterId:r.clusterId,workspaceId:r.workspaceId,
 sourceJobId:r.sourceJobId,sourcePlanId:r.sourcePlanId,sourcePlanRevision:r.sourcePlanRevision,sourcePlanHash:r.sourcePlanHash,
 rejectionId:r.id,rejectedAt:r.rejectedAt,code:r.code,newPreviewRequired:true});
}
/** A metadata-only append-only refusal proof. It grants no execution authority,
 * carries no raw configuration/secrets, and never treats generic HTTP errors as a receipt. */
export class ConfigurationDurableRejectionRepository {
 constructor(private readonly secrets:SecretService){}
 seal(value:unknown):Readonly<{fact:DurableConfigurationRejectionFact;hmac:string}>{const fact=decode(value);return Object.freeze({fact,hmac:this.secrets.fingerprint(fact)});}
 async insert(tx:DbService,value:DurableConfigurationRejectionFact):Promise<void>{
  const {fact:r,hmac}=this.seal(value);await tx.exec(DURABLE_REJECTION_INSERT,[r.id,r.clusterId,r.workspaceId,r.ownerId,r.authoringSessionId,r.credentialEpoch,r.permissionVersion,
   r.sourceJobId,r.sourcePlanId,r.sourcePlanRevision,r.sourcePlanHash,r.sourceKind,r.idempotencyKey,r.requestHmac,r.admissionIssuedAt,r.admissionExpiresAt,r.rejectedAt,
   r.freshPlanHmac,r.baselineSnapshotId,r.baselineVersion,r.baselineManifestHmac,hmac]);
 }
 async read(tx:DbService,cid:string,wid:string,ownerId:string,key:string):Promise<Readonly<{fact:DurableConfigurationRejectionFact;scopeKind:string;rootIds:string[];transportScope:string}>|null>{
  const r=await tx.one<any>(DURABLE_REJECTION_QUERY,[cid,wid,ownerId,key]);if(!r)return null;
  const fact=decode({domain:DURABLE_REJECTION_KIND,effectScope:r.effect_scope,code:r.code,id:r.id,clusterId:r.cluster_id,workspaceId:r.workspace_id,ownerId:r.owner_id,
   authoringSessionId:r.authoring_session_id,credentialEpoch:Number(r.credential_epoch),permissionVersion:r.permission_version,sourceJobId:r.source_job_id,sourcePlanId:r.source_plan_id,
   sourcePlanRevision:r.source_plan_revision,sourcePlanHash:r.source_plan_hash,sourceKind:r.source_kind,idempotencyKey:r.prepare_key,requestHmac:r.request_hmac,
   admissionIssuedAt:iso(r.admission_issued_at),admissionExpiresAt:iso(r.admission_expires_at),rejectedAt:iso(r.rejected_at),freshPlanHmac:r.fresh_plan_hmac,
   baselineSnapshotId:r.baseline_snapshot_id,baselineVersion:r.baseline_version,baselineManifestHmac:r.baseline_manifest_hmac});
  const hmac=this.secrets.fingerprint(fact);
  if(typeof r.rejection_hmac!=='string'||!hex.test(r.rejection_hmac)||!timingSafeEqual(Buffer.from(r.rejection_hmac,'hex'),Buffer.from(hmac,'hex'))
   ||fact.clusterId!==cid||fact.workspaceId!==wid||fact.ownerId!==ownerId||fact.idempotencyKey!==key||r.source_owner_id!==ownerId||r.has_registration!==false||r.has_job!==false
   ||!['cluster','workspace','services'].includes(r.scope_kind)||!Array.isArray(r.root_ids)||!hex.test(r.transport_scope??''))throw fail();
  return Object.freeze({fact,scopeKind:r.scope_kind,rootIds:[...r.root_ids],transportScope:r.transport_scope});
 }
}
