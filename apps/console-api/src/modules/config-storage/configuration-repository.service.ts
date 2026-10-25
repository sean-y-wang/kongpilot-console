import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { CONFIGURATION_LEASE_MS,CONFIGURATION_TIMEOUT_MS } from '../../infrastructure/kong/configuration-budget';
import { CONFIGURATION_ACCESS, type CaptureCollection, type CaptureGraph, type CaptureObject, type CaptureStage,
  type ConfigPlan, type ConfigurationAccessHandle, type ConfigurationAccessProof, type ConfigurationCaptureRepository,
  type ConfigurationJobSummary, type ConfigurationList, type ConfigurationPlanIdentity, type ConfigurationScope, type ConfigurationEvidenceWriter, type ConfigurationGitOpsSummary,
  type ConfigurationDownloadEvidence,type ConfigurationDeckEvidence,type ConfigurationDeckEvidenceWriter,
  type ConfigurationStorageAccessPolicy, type ConfigurationStoragePhase, type SnapshotSummary, type SnapshotScheduleSummary, type StagePageInput } from '../configuration/configuration.types';
import { SnapshotCryptoService, type ConfigurationMaterialIdentity } from './snapshot-crypto.service';
import {DURABLE_CONFIGURATION_PRESENCE_QUERY,isProvenLegacyConfigurationRow} from '../configuration/configuration-durable.repository';
import type { DeckPurpose,DeckSessionIssue,DeckSessionLocator,DeckSessionRepository } from '../deck-adapter/deck.types';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const hex = /^[a-f0-9]{64}$/;
const failure = (code: string, message = '配置存储状态或参数无效') => new ConflictException({code, message});
const invalid = (code = 'INVALID_CONFIGURATION_STORAGE') => new BadRequestException({code, message: '配置存储参数无效'});
const iso = (v: string | Date) => new Date(v).toISOString();
const hashToken = (token: string) => createHash('sha256').update(token, 'utf8').digest('hex');
const safeHashEqual = (a: string, b: string) => hex.test(a) && hex.test(b) && timingSafeEqual(Buffer.from(a,'hex'), Buffer.from(b,'hex'));
export const INITIALIZE_EXECUTION_PROGRESS_QUERY = `UPDATE configuration_jobs
 SET safe_progress=$2::jsonb,revision=revision+1,updated_at=now()
 WHERE id=$1 AND cluster_id=$3 AND workspace_id=$4 AND revision=$5 AND state='pending'
 AND kind IN('apply','rollback') AND plan_id=$6 AND plan_revision=$7 AND plan_hash=$8 RETURNING *`;
// A failed capture has no sealed version. Its root can retain 'capturing',
// while the original capture job records the failure. Only a unique terminal
// capture with the exact immutable owner/scope/material association can make
// that root archivable. This query never grants execution or restarts a job.
export const SNAPSHOT_TERMINAL_CAPTURE_QUERY = `SELECT j.id,j.state FROM config_snapshots s
 JOIN configuration_jobs j ON j.cluster_id=s.cluster_id AND j.workspace_id=s.workspace_id
 AND j.kind='capture' AND j.safe_progress->>'snapshotId'=s.id::text
 WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.id=$3 AND s.state='capturing' AND s.current_version IS NULL
 AND j.actor_id=s.created_by AND j.transport_scope=s.transport_scope AND j.scope_kind=s.scope_kind AND j.root_ids=s.root_ids
 AND j.state IN('failed','cancelled','expired')
 AND EXISTS(SELECT 1 FROM configuration_materials m WHERE m.cluster_id=j.cluster_id AND m.workspace_id=j.workspace_id AND m.job_id=j.id AND m.artifact_kind='snapshot')
 AND NOT EXISTS(SELECT 1 FROM configuration_jobs other WHERE other.cluster_id=s.cluster_id AND other.workspace_id=s.workspace_id
 AND other.kind='capture' AND other.safe_progress->>'snapshotId'=s.id::text AND other.id<>j.id)`;
const stepSelection=`SELECT s.id,s.execution_id,s.plan_step_id,s.step_order,s.object_workspace_id,s.state,s.recycle_entry_id,s.safe_result,s.error_code,s.revision,s.started_at,s.completed_at,
 p.entity_type AS type,p.mutation_action AS action,p.native_id AS original_id,p.allocated_native_id,s.effective_native_id,
 coalesce(s.operation_id,s.receipt_operation_id) AS recorded_operation_id,
 (s.state='succeeded' AND s.receipt_ciphertext IS NOT NULL AND s.after_hmac IS NOT NULL AND m.state='succeeded' AND m.remote_completed AND m.result_secret IS NOT NULL) AS verified
 FROM configuration_job_steps s JOIN configuration_plan_objects p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id AND p.plan_id=s.plan_id AND p.plan_revision=s.plan_revision AND p.plan_hash=s.plan_hash AND p.step_id=s.plan_step_id
 LEFT JOIN mutation_operations m ON m.cluster_id=s.cluster_id AND m.workspace_id=s.object_workspace_id AND m.id=coalesce(s.operation_id,s.receipt_operation_id)`;

export interface CreateConfigurationJobInput {
  id?: string; scope: ConfigurationScope; kind: 'capture'|'import'|'compare'|'export'|'apply'|'rollback'|'reconcile';
  idempotencyKey: string; input?: unknown; expiresAt: string; requestId?: string;
  originRef?: import('../configuration/configuration.types').ConfigurationOriginRef;
  writeEvidence: (tx:DbService,before:null,after:ConfigurationJobSummary)=>Promise<void>;
}
/** Bootstrap-only origin verifier. Every callback is SQL/decryption only; the
 * transport kernel performs fresh source reads outside storage transactions. */
export interface ConfigurationOriginStoragePolicy {
  bindJob(handle:ConfigurationAccessHandle,job:any,origin:import('../configuration/configuration.types').ConfigurationOriginRef,tx:DbService):Promise<void>;
  beforeFreeze(handle:ConfigurationAccessHandle,job:any,plan:ConfigPlan,tx:DbService):Promise<void>;
  bindPlan(handle:ConfigurationAccessHandle,job:any,plan:ConfigPlan,identity:import('../configuration/configuration.types').ConfigurationPlanIdentity,tx:DbService):Promise<void>;
  verifyPlan(handle:ConfigurationAccessHandle,row:any,plan:ConfigPlan,tx:DbService):Promise<void>;
}
/** Fixed bootstrap hook. Runs inside the actual execution INSERT transaction;
 * it neither supplies an execution ID nor substitutes for storage authority. */
export interface ConfigurationScheduledExecutionOriginPolicy {
  created(tx:DbService, originalAccessHandle:ConfigurationAccessHandle, executionId:string):Promise<void>;
}
export interface BeginCaptureInput {
  jobId?: string; snapshotId?: string; scope: ConfigurationScope; name: string; description?: string;
  idempotencyKey: string; expiresAt: string;
  writeEvidence?: (tx:DbService,before:null,after:ConfigurationJobSummary)=>Promise<void>;
}

@Injectable()
export class ConfigurationRepositoryService implements ConfigurationCaptureRepository, DeckSessionRepository {
  private evidenceWriter?: ConfigurationEvidenceWriter;
  private deckEvidenceWriter?:ConfigurationDeckEvidenceWriter;
  private originPolicy?:ConfigurationOriginStoragePolicy;
  private scheduledExecutionOriginPolicy?:ConfigurationScheduledExecutionOriginPolicy;
  constructor(private readonly db: DbService, private readonly secrets: SecretService,
    private readonly crypto: SnapshotCryptoService,
    @Inject(CONFIGURATION_ACCESS) private readonly access: ConfigurationStorageAccessPolicy) {}
  /** Installed exactly once by Root's bootstrap, never by an HTTP DTO. The
   * writer receives safe metadata only and cannot mint configuration authority. */
  installEvidenceWriter(writer:ConfigurationEvidenceWriter):void{
    if(this.evidenceWriter||!writer||typeof writer.jobCreated!=='function'||typeof writer.snapshotSealed!=='function'||typeof writer.metadataChanged!=='function')throw failure('CONFIGURATION_EVIDENCE_WRITER_INVALID');
    this.evidenceWriter=writer;
  }
  installOriginPolicy(policy:ConfigurationOriginStoragePolicy):void{
    if(this.originPolicy||!policy||['bindJob','beforeFreeze','bindPlan','verifyPlan'].some(k=>typeof(policy as any)[k]!=='function'))throw failure('CONFIGURATION_ORIGIN_POLICY_INVALID');
    this.originPolicy=Object.freeze(policy);
  }
  installScheduledExecutionOriginPolicy(policy:ConfigurationScheduledExecutionOriginPolicy):void{
    if(this.scheduledExecutionOriginPolicy||!policy||typeof policy.created!=='function')throw failure('CONFIGURATION_SCHEDULED_ORIGIN_POLICY_INVALID');
    this.scheduledExecutionOriginPolicy=Object.freeze({created:policy.created.bind(policy)});
  }
  private requiredOrigin(job:any,plan?:ConfigPlan):boolean{return job.required_origin_kind!=null||job.required_origin_id!=null||job.required_origin_hmac!=null||plan?.originRef!==undefined;}
  private metadataWriter():ConfigurationEvidenceWriter{
    if(!this.evidenceWriter)throw failure('CONFIGURATION_AUDIT_REQUIRED');return this.evidenceWriter;
  }
  installDeckEvidenceWriter(writer:ConfigurationDeckEvidenceWriter):void{
    if(this.deckEvidenceWriter||!writer||typeof writer.sessionChanged!=='function')throw failure('CONFIGURATION_EVIDENCE_WRITER_INVALID');this.deckEvidenceWriter=writer;
  }
  private deckWriter():ConfigurationDeckEvidenceWriter{if(!this.deckEvidenceWriter)throw failure('CONFIGURATION_AUDIT_REQUIRED');return this.deckEvidenceWriter;}
  private inTransaction<T>(transaction:DbService|undefined,work:(tx:DbService)=>Promise<T>):Promise<T>{
    if(transaction!==undefined&&!(transaction instanceof DbService))throw invalid('CONFIGURATION_TRANSACTION_INVALID');
    return(transaction??this.db).transaction(work);
  }

  private validateScope(scope: ConfigurationScope): void {
    if (!scope || !uuid.test(scope.clusterId) || !uuid.test(scope.workspaceId) || !hex.test(scope.transportScope)
      || !['cluster','workspace','services'].includes(scope.kind) || !Array.isArray(scope.rootIds) || scope.rootIds.length>100
      || scope.rootIds.some(id => !uuid.test(id)) || new Set(scope.rootIds).size!==scope.rootIds.length
      || (scope.kind==='services') !== (scope.rootIds.length>0)) throw invalid();
  }
  private scope(row: any): ConfigurationScope {
    return {clusterId: row.cluster_id, workspaceId: row.workspace_id, transportScope: row.transport_scope,
      kind: row.scope_kind, rootIds: row.root_ids};
  }
  private async authorize(handle: ConfigurationAccessHandle, scope: ConfigurationScope, phase: ConfigurationStoragePhase,
    tx: DbService, extra: {jobId?: string; artifactId?: string; planId?: string; planRevision?: number; planHash?: string; leaseGeneration?: number} = {}): Promise<ConfigurationAccessProof> {
    this.validateScope(scope);
    const proof = await this.access.assertStorage(handle, {scope, phase, ...extra}, tx);
    if (!proof || !uuid.test(proof.actorId) || proof.expiresAt<=Date.now() || canonicalJson(proof.scope)!==canonicalJson(scope)) throw failure('CONFIGURATION_AUTHORITY_CHANGED');
    return proof;
  }
  private async job(handle: ConfigurationAccessHandle, id: string, phase: ConfigurationStoragePhase, tx: DbService, lease?: number): Promise<any> {
    if (!uuid.test(id)) throw invalid();
    const row = await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 FOR UPDATE', [id]);
    if (!row) throw new NotFoundException({code:'CONFIGURATION_JOB_NOT_FOUND',message:'配置作业不存在'});
    await this.authorize(handle, this.scope(row), phase, tx, {jobId:id, leaseGeneration:lease});
    if (lease!==undefined && (row.lease_generation!==lease || row.expires_at<=new Date() || !['pending','running'].includes(row.state))) throw failure('CONFIGURATION_LEASE_CHANGED');
    return row;
  }
  private async assertArtifactScope(tx:DbService,scope:ConfigurationScope,jobId:string):Promise<void>{
    const row=await tx.one<any>('SELECT cluster_id,workspace_id,transport_scope,scope_kind,root_ids FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[scope.clusterId,scope.workspaceId,jobId]);
    if(!row||canonicalJson(this.scope(row))!==canonicalJson(scope))throw failure('CONFIGURATION_ARTIFACT_SCOPE_MISMATCH');
  }
  private identity(row: any): ConfigurationMaterialIdentity {
    return {clusterId:row.cluster_id, workspaceId:row.workspace_id, jobId:row.job_id, materialId:row.id,
      artifactId:row.artifact_id, artifactKind:row.artifact_kind};
  }
  private async captureMaterial(job: any, tx: DbService): Promise<any> {
    const row = await tx.one<any>("SELECT * FROM configuration_materials WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 AND artifact_kind='snapshot' FOR UPDATE", [job.cluster_id,job.workspace_id,job.id]);
    if (!row || row.state!=='available') throw failure('CONFIGURATION_MATERIAL_UNAVAILABLE');
    return row;
  }
  private objectSection(object: Pick<CaptureObject,'objectKey'|'entityType'|'nativeId'|'parentId'|'credentialKind'>) {
    return {section:'object' as const,key:object.objectKey,entityType:object.entityType,nativeId:object.nativeId,parentId:object.parentId??null,credentialKind:object.credentialKind??null};
  }
  private jobSummary(row: any): ConfigurationJobSummary {
    return {id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,kind:row.kind,state:row.state,revision:row.revision,
      safeProgress:this.secrets.redact(row.safe_progress),errorCode:row.error_code,createdAt:iso(row.created_at),completedAt:row.completed_at?iso(row.completed_at):null};
  }
  private isMetadataWrite(input:CreateConfigurationJobInput):boolean{
    const value=input.input as any;if(!value||typeof value!=='object'||value.action!=='metadata')return false;
    const operations:Record<string,readonly string[]>={config_snapshots:['archive','restore','purge'],config_snapshot_schedules:['create','update','archive','restore','purge'],configuration_gitops_runs:['create']};
    if(input.kind!=='compare'||Object.keys(value).length!==5||Object.keys(value).some(k=>!['action','resourceType','resourceId','operation','payload'].includes(k))
      ||!Object.hasOwn(operations,value.resourceType)||!operations[value.resourceType].includes(value.operation)||!uuid.test(value.resourceId)
      ||!value.payload||typeof value.payload!=='object'||Array.isArray(value.payload)||![Object.prototype,null].includes(Object.getPrototypeOf(value.payload)))throw invalid('CONFIGURATION_METADATA_JOB_INVALID');
    return true;
  }
  async createJob(handle: ConfigurationAccessHandle, input: CreateConfigurationJobInput,transaction?:DbService): Promise<ConfigurationJobSummary> {
    this.validateScope(input.scope);
    if (typeof input.writeEvidence!=='function'||!['capture','import','compare','export','apply','rollback','reconcile'].includes(input.kind) || typeof input.idempotencyKey!=='string'
      || input.idempotencyKey.length<8 || input.idempotencyKey.length>128 || !Number.isFinite(Date.parse(input.expiresAt)) || Date.parse(input.expiresAt)<=Date.now()) throw invalid();
    const metadataWrite=this.isMetadataWrite(input),id = input.id??randomUUID(); if (!uuid.test(id)) throw invalid();
    const origin=input.originRef;
    if(origin&&(!this.originPolicy||Object.keys(origin).sort().join(',')!=='kind,materialHmac,originId,version'||origin.version!==1||origin.kind!=='governance-promote'||!uuid.test(origin.originId)||!hex.test(origin.materialHmac)||!['import','apply','reconcile'].includes(input.kind)))throw invalid('CONFIGURATION_ORIGIN_INVALID');
    const requestHmac = this.secrets.fingerprint({scope:input.scope,kind:input.kind,input:input.input??null,...(origin?{originRef:origin}:{})});
    return this.inTransaction(transaction,async tx => {
      const proof = await this.authorize(handle,input.scope,metadataWrite?'metadata-write':'capture-page',tx);
      const scheduled=proof.origin==='schedule'&&input.kind==='capture'&&proof.scheduleRunId&&uuid.test(proof.scheduleRunId);
      if (!scheduled&&(!proof.sessionId || !uuid.test(proof.sessionId)) || scheduled&&proof.sessionId) throw failure('CONFIGURATION_SESSION_REQUIRED');
      await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-job:${proof.actorId}:${input.idempotencyKey}`]);
      const existing = await tx.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4', [input.scope.clusterId,input.scope.workspaceId,proof.actorId,input.idempotencyKey]);
      if (existing) {
        if (!safeHashEqual(existing.request_hmac,requestHmac)) throw failure('IDEMPOTENCY_CONFLICT');
        if((existing.required_origin_kind??null)!==(origin?.kind??null)||(existing.required_origin_id??null)!==(origin?.originId??null)||(existing.required_origin_hmac??null)!==(origin?.materialHmac??null))throw failure('CONFIGURATION_ORIGIN_CHANGED');
        await this.authorize(handle,input.scope,metadataWrite?'metadata-write':'capture-page',tx,{jobId:existing.id}); return this.jobSummary(existing);
      }
      const sourcePlanId=['apply','rollback'].includes(input.kind)?(input.input as any)?.planId:undefined;
      if(sourcePlanId!==undefined){
        if(typeof sourcePlanId!=='string'||!uuid.test(sourcePlanId))throw invalid('INVALID_CONFIGURATION_SOURCE_PLAN');
        await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-source-plan:${sourcePlanId.toLowerCase()}`]);
        const sourcePlan=await tx.one<any>('SELECT id FROM configuration_plans WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[sourcePlanId,input.scope.clusterId,input.scope.workspaceId]);
        if(!sourcePlan)throw failure('CONFIGURATION_SOURCE_PLAN_UNAVAILABLE');
        if(await tx.one('SELECT id FROM configuration_durable_issues WHERE source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3',[sourcePlanId,input.scope.clusterId,input.scope.workspaceId]))throw failure('CONFIGURATION_DURABLE_ALREADY_SUBMITTED');
        if(await tx.one('SELECT id FROM configuration_durable_rejections WHERE source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3',[sourcePlanId,input.scope.clusterId,input.scope.workspaceId]))throw failure('CONFIGURATION_DURABLE_SOURCE_REJECTED');
      }
      const cluster = await tx.one<any>('SELECT execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[input.scope.clusterId]);
      if (!cluster) throw failure('CONFIGURATION_CLUSTER_UNAVAILABLE');
      const expiry = new Date(Math.min(Date.parse(input.expiresAt),proof.expiresAt)).toISOString();
      const row = await tx.one<any>(`INSERT INTO configuration_jobs(id,cluster_id,workspace_id,transport_scope,actor_id,origin_session_id,
        authority_expires_at,kind,idempotency_key,request_hmac,request_id,scope_kind,root_ids,input_secret,permission_version,
        credential_epoch,cluster_revision,workspace_revision,capture_epoch,execution_mode,approval_required,expires_at,origin_type,required_origin_kind,required_origin_id,required_origin_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$7,$22,$23,$24,$25) RETURNING *`,
        [id,input.scope.clusterId,input.scope.workspaceId,input.scope.transportScope,proof.actorId,proof.sessionId,expiry,input.kind,input.idempotencyKey,
          requestHmac,input.requestId??null,input.scope.kind,input.scope.rootIds,input.input===undefined?null:this.secrets.encrypt(input.input,`configuration-job:${id}`),
          proof.permissionVersion,proof.credentialEpoch,proof.clusterRevision,proof.workspaceRevision,proof.captureEpoch,cluster.execution_mode,(['apply','rollback','reconcile'].includes(input.kind)||metadataWrite)&&cluster.execution_mode==='approval',scheduled?'schedule':proof.origin==='pipeline'?'pipeline':'http',origin?.kind??null,origin?.originId??null,origin?.materialHmac??null]);
      if(origin)await this.originPolicy!.bindJob(handle,row,origin,tx);
      const after=this.jobSummary(row);await input.writeEvidence(tx,null,after);
      await this.authorize(handle,input.scope,metadataWrite?'metadata-write':'capture-page',tx,{jobId:id}); return after;
    });
  }
  async beginCapture(handle: ConfigurationAccessHandle, input: BeginCaptureInput): Promise<CaptureStage> {
    if (typeof input.name!=='string' || !input.name.trim() || input.name.length>128 || (input.description?.length??0)>8192) throw invalid();
    if(!input.jobId&&typeof input.writeEvidence!=='function')throw invalid('CONFIGURATION_AUDIT_REQUIRED');
    const jobId = input.jobId??(await this.createJob(handle,{scope:input.scope,kind:'capture',idempotencyKey:input.idempotencyKey,input:{name:input.name,description:input.description??''},expiresAt:input.expiresAt,writeEvidence:input.writeEvidence!})).id;
    return this.db.transaction(async tx => {
      const job = await this.job(handle,jobId,'capture-page',tx);
      if (job.kind!=='capture' || canonicalJson(this.scope(job))!==canonicalJson(input.scope)) throw failure('CONFIGURATION_JOB_SCOPE_MISMATCH');
      // The material's artifact ID is the immutable version ID, not the root snapshot ID.
      const current = await tx.one<any>("SELECT m.*,j.safe_progress FROM configuration_materials m JOIN configuration_jobs j ON j.id=m.job_id WHERE m.job_id=$1 AND m.artifact_kind='snapshot'",[jobId]);
      if (current) {
        const snapshotId = current.safe_progress.snapshotId;
        if (!uuid.test(snapshotId)) throw failure('CONFIGURATION_CAPTURE_BINDING_INVALID');
        return {jobId,snapshotId,versionId:current.artifact_id,materialId:current.id,leaseGeneration:job.lease_generation};
      }
      const snapshotId=input.snapshotId??randomUUID(), versionId=randomUUID(), materialId=randomUUID();
      if (!uuid.test(snapshotId)) throw invalid();
      const identity: ConfigurationMaterialIdentity={clusterId:job.cluster_id,workspaceId:job.workspace_id,jobId,materialId,artifactId:versionId,artifactKind:'snapshot'};
      await tx.exec(`INSERT INTO config_snapshots(id,cluster_id,workspace_id,transport_scope,created_by,name,description,scope_kind,root_ids)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[snapshotId,job.cluster_id,job.workspace_id,job.transport_scope,job.actor_id,input.name,input.description??'',job.scope_kind,job.root_ids]);
      await tx.exec("INSERT INTO configuration_materials(id,cluster_id,workspace_id,job_id,artifact_kind,artifact_id,wrapped_key_secret) VALUES($1,$2,$3,$4,'snapshot',$5,$6)",[materialId,job.cluster_id,job.workspace_id,jobId,versionId,this.crypto.createWrappedKey(identity)]);
      await tx.exec("UPDATE configuration_jobs SET state='running',started_at=now(),safe_progress=$2::jsonb,revision=revision+1,updated_at=now() WHERE id=$1",[jobId,JSON.stringify({snapshotId,versionId,materialId})]);
      await this.authorize(handle,input.scope,'capture-page',tx,{jobId,leaseGeneration:job.lease_generation});
      return {jobId,snapshotId,versionId,materialId,leaseGeneration:job.lease_generation};
    });
  }
  async stagePage(handle: ConfigurationAccessHandle,input: StagePageInput): Promise<void> {
    if (!Number.isInteger(input.pageNo)||input.pageNo<1||input.pageNo>100||!hex.test(input.queryHmac)||!hex.test(input.cursorHmac)
      ||!Array.isArray(input.records)||input.records.length>100||!Number.isInteger(input.byteCount)||input.byteCount<0||input.byteCount>33554432
      || input.terminalObserved!==(input.nextCursor==null)) throw invalid();
    await this.db.transaction(async tx => {
      const job=await this.job(handle,input.jobId,'capture-page',tx,input.leaseGeneration), material=await this.captureMaterial(job,tx), identity=this.identity(material);
      const counts=await tx.one<any>('SELECT count(*)::integer AS pages,coalesce(sum(record_count),0)::integer AS records,coalesce(sum(byte_count),0)::bigint AS bytes FROM configuration_job_pages WHERE job_id=$1',[job.id]);
      if(counts.pages>=100||counts.records+input.records.length>10000||Number(counts.bytes)+input.byteCount>33554432) throw failure('CONFIGURATION_CAPTURE_BUDGET');
      const prior=await tx.one<any>('SELECT page_no,query_hmac,terminal_observed FROM configuration_job_pages WHERE job_id=$1 AND collection_key=$2 ORDER BY page_no DESC LIMIT 1',[job.id,input.collectionKey]);
      if(input.pageNo!==(prior?prior.page_no+1:1)||prior&&(prior.terminal_observed||prior.query_hmac!==input.queryHmac)) throw failure('CONFIGURATION_PAGE_CHAIN_INVALID');
      await this.crypto.withKey(identity,material.wrapped_key_secret,async key => {
        await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id,leaseGeneration:input.leaseGeneration});
        const page=this.crypto.encrypt(key,identity,{section:'page',key:`${input.collectionKey}:${input.pageNo}`},input.records);
        const cursor=input.nextCursor==null?null:this.crypto.encrypt(key,identity,{section:'cursor',key:`${input.collectionKey}:${input.pageNo}`},input.nextCursor);
        await tx.exec(`INSERT INTO configuration_job_pages(cluster_id,workspace_id,job_id,collection_key,page_no,query_hmac,cursor_hmac,next_cursor_ciphertext,page_ciphertext,record_count,byte_count,terminal_observed)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[job.cluster_id,job.workspace_id,job.id,input.collectionKey,input.pageNo,input.queryHmac,input.cursorHmac,cursor,page,input.records.length,input.byteCount,input.terminalObserved]);
      });
      await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id,leaseGeneration:input.leaseGeneration});
    });
  }
  async stageObject(handle: ConfigurationAccessHandle,input:{jobId:string;object:CaptureObject;leaseGeneration:number}):Promise<void>{
    const o=input.object;
    if(!o||!uuid.test(o.nativeId)||!uuid.test(o.objectWorkspaceId)||!hex.test(o.beforeHmac)||!hex.test(o.schemaHmac)||!o.objectKey||o.objectKey.length>256||!Array.isArray(o.dependencies))throw invalid();
    await this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'capture-page',tx,input.leaseGeneration),material=await this.captureMaterial(job,tx),identity=this.identity(material);
      const count=await tx.one<any>('SELECT count(*)::integer AS count FROM configuration_staged_objects WHERE job_id=$1',[job.id]);if(count.count>=10000)throw failure('CONFIGURATION_OBJECT_BUDGET');
      await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>{
        await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id,leaseGeneration:input.leaseGeneration});
        await tx.exec(`INSERT INTO configuration_staged_objects(cluster_id,workspace_id,job_id,object_key,entity_type,native_id,parent_type,parent_id,credential_kind,object_workspace_id,reference_only,affected,dependencies,payload_ciphertext,before_hmac,schema_hmac,recovery_state)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,[job.cluster_id,job.workspace_id,job.id,o.objectKey,o.entityType,o.nativeId,o.parentType??null,o.parentId??null,o.credentialKind??null,o.objectWorkspaceId,o.referenceOnly,o.affected,o.dependencies,this.crypto.encrypt(key,identity,this.objectSection(o),o),o.beforeHmac,o.schemaHmac,o.recovery.state]);
      });
      await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id,leaseGeneration:input.leaseGeneration});
    });
  }
  async collectionEOF(handle:ConfigurationAccessHandle,input:{jobId:string;collection:CaptureCollection;leaseGeneration:number}):Promise<void>{
    const c=input.collection;if(!c.terminalObserved||!hex.test(c.queryHmac)||!hex.test(c.cursorChainHmac)||!hex.test(c.coverageHmac))throw invalid();
    await this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'capture-page',tx,input.leaseGeneration);
      const pages=await tx.query<any>('SELECT page_no,query_hmac,record_count,terminal_observed FROM configuration_job_pages WHERE job_id=$1 AND collection_key=$2 ORDER BY page_no',[job.id,c.collectionKey]);
      if(pages.length!==c.pageCount||pages.reduce((n,p)=>n+p.record_count,0)!==c.recordCount||pages.some((p,i)=>p.page_no!==i+1||p.query_hmac!==c.queryHmac||p.terminal_observed!==(i===pages.length-1)))throw failure('CONFIGURATION_COLLECTION_INCOMPLETE');
      await tx.exec(`INSERT INTO configuration_staged_collections(cluster_id,workspace_id,job_id,collection_key,entity_type,parent_id,credential_kind,query_hmac,page_size,page_count,record_count,terminal_observed,cursor_chain_hmac,coverage_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,$12,$13)`,[job.cluster_id,job.workspace_id,job.id,c.collectionKey,c.entityType,c.parentId??null,c.credentialKind??null,c.queryHmac,c.pageSize,c.pageCount,c.recordCount,c.cursorChainHmac,c.coverageHmac]);
      await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id,leaseGeneration:input.leaseGeneration});
    });
  }
  async sealSnapshot(handle:ConfigurationAccessHandle,input:{jobId:string;graph:CaptureGraph;leaseGeneration:number}):Promise<SnapshotSummary>{
    const writer=this.evidenceWriter;if(!writer)throw failure('CONFIGURATION_EVIDENCE_WRITER_REQUIRED');
    const g=input.graph;
    if(g.completeness!=='complete'||g.consistency!=='console_fenced_best_effort'||g.objects.length>10000||g.pageCount>100||g.recordCount>10000||g.byteCount>33554432||g.nativeCallCount>500||Buffer.byteLength(canonicalJson(g),'utf8')>33554432||g.jobId!==input.jobId
      ||g.requiredCollections.length!==new Set(g.requiredCollections).size||!hex.test(g.schemaHmac)||Date.parse(g.observedUntil)-Date.parse(g.observedFrom)>120000)throw failure('CONFIGURATION_CAPTURE_INCOMPLETE');
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'seal',tx,input.leaseGeneration),beforeJob=this.jobSummary(job),material=await this.captureMaterial(job,tx),identity=this.identity(material);
      if(canonicalJson(this.scope(job))!==canonicalJson(g.scope)||g.materialId!==material.id||g.versionId!==material.artifact_id||g.snapshotId!==job.safe_progress.snapshotId
        ||job.permission_version!==g.permissionVersion||job.capture_epoch!==g.captureEpoch||job.cluster_revision!==g.clusterRevision||job.workspace_revision!==g.workspaceRevision||job.credential_epoch!==g.credentialEpoch)throw failure('CONFIGURATION_CAPTURE_AUTHORITY_CHANGED');
      const staged=await tx.query<any>('SELECT * FROM configuration_staged_objects WHERE job_id=$1 ORDER BY object_key',[job.id]);
      const cols=await tx.query<any>('SELECT * FROM configuration_staged_collections WHERE job_id=$1 ORDER BY collection_key',[job.id]);
      const pages=await tx.one<any>('SELECT count(*)::integer AS count,coalesce(sum(record_count),0)::integer AS records,coalesce(sum(byte_count),0)::bigint AS bytes FROM configuration_job_pages WHERE job_id=$1',[job.id]);
      if(staged.length!==g.objects.length||cols.length!==g.collections.length||pages.count>g.pageCount||pages.records>g.recordCount||Number(pages.bytes)>g.byteCount
        ||cols.reduce((n,c)=>n+c.page_count,0)!==pages.count||cols.reduce((n,c)=>n+c.record_count,0)!==pages.records)throw failure('CONFIGURATION_MANIFEST_COUNT_MISMATCH');
      const objectMap=new Map(g.objects.map(o=>[o.objectKey,o]));if(objectMap.size!==g.objects.length)throw failure('CONFIGURATION_DUPLICATE_OBJECT');
      const collectionMap=new Map(g.collections.map(c=>[c.collectionKey,c]));if(collectionMap.size!==g.collections.length||g.requiredCollections.some(k=>!collectionMap.get(k)?.terminalObserved))throw failure('CONFIGURATION_REQUIRED_EOF_MISSING');
      for(const o of g.objects)if(o.dependencies.some(d=>!objectMap.has(d)))throw failure('CONFIGURATION_REFERENCE_INCOMPLETE');
      const recovery={complete:0,requires_secret_input:0,requires_rotation:0,nonrestorable:0};for(const o of g.objects)recovery[o.recovery.state]++;
      await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>{
        const current=await this.authorize(handle,g.scope,'seal',tx,{jobId:job.id,artifactId:g.versionId,leaseGeneration:input.leaseGeneration});
        if(current.nativeUsage&&(current.nativeUsage.calls!==g.nativeCallCount||current.nativeUsage.pages!==g.pageCount||current.nativeUsage.records!==g.recordCount||current.nativeUsage.bytes!==g.byteCount))throw failure('CONFIGURATION_NATIVE_BUDGET_PROOF_CHANGED');
        for(const row of staged){const expected=objectMap.get(row.object_key)!;const actual=this.crypto.decrypt<CaptureObject>(key,identity,this.objectSection(expected),row.payload_ciphertext);if(!safeHashEqual(this.secrets.fingerprint(actual),this.secrets.fingerprint(expected)))throw failure('CONFIGURATION_STAGED_OBJECT_CHANGED');}
        for(const row of cols){const c=collectionMap.get(row.collection_key);if(!c||row.entity_type!==c.entityType||row.parent_id!==(c.parentId??null)||row.credential_kind!==(c.credentialKind??null)||row.query_hmac!==c.queryHmac||row.page_count!==c.pageCount||row.record_count!==c.recordCount||row.cursor_chain_hmac!==c.cursorChainHmac||row.coverage_hmac!==c.coverageHmac)throw failure('CONFIGURATION_STAGED_COLLECTION_CHANGED');}
        await tx.exec(`INSERT INTO config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version,version_id,source_job_id,material_id,manifest_hmac,manifest_ciphertext,completeness,consistency,
          observed_from,observed_until,kong_version,adapter_version,schema_hmac,permission_version,capture_epoch,object_count,secret_count,page_count,record_count,byte_count,native_call_count,required_collections,recovery_summary,warning_codes,stored_page_count,stored_record_count,stored_byte_count)
          VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,'complete','console_fenced_best_effort',$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24,$25,$26,$27)`,
          [job.cluster_id,job.workspace_id,g.snapshotId,g.versionId,job.id,material.id,this.secrets.fingerprint(g),this.crypto.encrypt(key,identity,{section:'manifest',key:'snapshot'},g),
            g.observedFrom,g.observedUntil,g.kongVersion,g.adapterVersion,g.schemaHmac,g.permissionVersion,g.captureEpoch,g.objects.length,g.objects.reduce((n,o)=>n+(o.secretCopies?.length??0),0),g.pageCount,g.recordCount,g.byteCount,g.nativeCallCount,g.requiredCollections,JSON.stringify(recovery),g.warningCodes,pages.count,pages.records,pages.bytes]);
        await tx.exec(`INSERT INTO config_snapshot_objects(cluster_id,workspace_id,version_id,object_key,entity_type,native_id,parent_type,parent_id,credential_kind,object_workspace_id,reference_only,affected,dependencies,payload_ciphertext,before_hmac,schema_hmac,recovery_state)
          SELECT cluster_id,workspace_id,$2,object_key,entity_type,native_id,parent_type,parent_id,credential_kind,object_workspace_id,reference_only,affected,dependencies,payload_ciphertext,before_hmac,schema_hmac,recovery_state FROM configuration_staged_objects WHERE job_id=$1`,[job.id,g.versionId]);
        await tx.exec(`INSERT INTO config_snapshot_collections(cluster_id,workspace_id,version_id,collection_key,entity_type,parent_id,credential_kind,query_hmac,page_size,page_count,record_count,terminal_observed,cursor_chain_hmac,coverage_hmac)
          SELECT cluster_id,workspace_id,$2,collection_key,entity_type,parent_id,credential_kind,query_hmac,page_size,page_count,record_count,terminal_observed,cursor_chain_hmac,coverage_hmac FROM configuration_staged_collections WHERE job_id=$1`,[job.id,g.versionId]);
      });
      await tx.exec("UPDATE config_snapshots SET current_version=1,state='ready',revision=revision+1,updated_at=now() WHERE id=$1 AND state='capturing'",[g.snapshotId]);
      const completed=await tx.one<any>("UPDATE configuration_jobs SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 RETURNING *",[job.id]);
      await tx.exec("UPDATE config_snapshot_schedule_runs SET state='succeeded',completed_at=now() WHERE job_id=$1 AND state='running'",[job.id]);
      await this.authorize(handle,g.scope,'seal',tx,{jobId:job.id,artifactId:g.versionId,leaseGeneration:input.leaseGeneration});
      const snapshot=this.snapshotSummary(await this.snapshotRow(tx,g.scope,g.snapshotId));
      await writer.snapshotSealed(tx,beforeJob,this.jobSummary(completed),snapshot);
      await this.authorize(handle,g.scope,'seal',tx,{jobId:job.id,artifactId:g.versionId,leaseGeneration:input.leaseGeneration});return snapshot;
    });
  }
  private async snapshotRow(tx:DbService,scope:ConfigurationScope,id:string):Promise<any>{
    const row=await tx.one<any>(`SELECT s.*,v.version_id,v.object_count,v.page_count,v.record_count,v.byte_count,v.completeness,v.consistency,v.recovery_summary,v.warning_codes
      FROM config_snapshots s LEFT JOIN config_snapshot_versions v ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.snapshot_id=s.id AND v.version=s.current_version
      WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.id=$3`,[scope.clusterId,scope.workspaceId,id]);if(!row)throw new NotFoundException({code:'SNAPSHOT_NOT_FOUND',message:'快照不存在'});return row;
  }
  private snapshotSummary(r:any):SnapshotSummary{return{id:r.id,clusterId:r.cluster_id,workspaceId:r.workspace_id,name:r.name,description:r.description,state:r.state,revision:r.revision,currentVersion:r.current_version,versionId:r.version_id??undefined,
    scopeKind:r.scope_kind,rootIds:r.root_ids,objectCount:r.object_count??0,pageCount:r.page_count??0,recordCount:r.record_count??0,byteCount:Number(r.byte_count??0),completeness:r.completeness??null,consistency:r.consistency??null,
    recovery:r.recovery_summary??{complete:0,requires_secret_input:0,requires_rotation:0,nonrestorable:0},warningCodes:r.warning_codes??[],createdAt:iso(r.created_at),updatedAt:iso(r.updated_at)};}
  async getJob(handle:ConfigurationAccessHandle,id:string):Promise<ConfigurationJobSummary>{return this.db.transaction(async tx=>this.jobSummary(await this.job(handle,id,'read',tx)));}
  async getSnapshotSummary(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;snapshotId:string}):Promise<SnapshotSummary>{
    if(!uuid.test(input.snapshotId))throw invalid();
    return this.db.transaction(async tx=>{
      await this.authorize(handle,input.scope,'read',tx,{artifactId:input.snapshotId});
      const root=await this.snapshotRow(tx,input.scope,input.snapshotId);
      if(canonicalJson(this.scope(root))!==canonicalJson(input.scope))throw failure('SOURCE_SCOPE_CHANGED');
      const summary=this.snapshotSummary(root);
      await this.authorize(handle,input.scope,'read',tx,{artifactId:input.snapshotId});return summary;
    });
  }
  async readSnapshot(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;snapshotId:string;version?:number}):Promise<CaptureGraph>{
    return this.db.transaction(async tx=>{
      await this.authorize(handle,input.scope,'read',tx,{artifactId:input.snapshotId});const root=await this.snapshotRow(tx,input.scope,input.snapshotId);
      if(canonicalJson(this.scope(root))!==canonicalJson(input.scope)||root.state==='deleted')throw failure('SOURCE_SCOPE_CHANGED');
      const version=await tx.one<any>(`SELECT v.*,m.id,m.cluster_id,m.workspace_id,m.job_id,m.artifact_id,m.artifact_kind,m.wrapped_key_secret,m.state AS material_state
        FROM config_snapshot_versions v JOIN configuration_materials m ON m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id AND m.id=v.material_id
        WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4`,[input.scope.clusterId,input.scope.workspaceId,input.snapshotId,input.version??root.current_version]);
      if(!version||version.material_state!=='available')throw failure('CONFIGURATION_MATERIAL_UNAVAILABLE');
      const identity=this.identity(version);return this.crypto.withKey(identity,version.wrapped_key_secret,async key=>{
        await this.authorize(handle,input.scope,'read',tx,{artifactId:version.version_id});const graph=this.crypto.decrypt<CaptureGraph>(key,identity,{section:'manifest',key:'snapshot'},version.manifest_ciphertext);
        if(!safeHashEqual(this.secrets.fingerprint(graph),version.manifest_hmac)||canonicalJson(graph.scope)!==canonicalJson(input.scope))throw failure('CONFIGURATION_MANIFEST_CHANGED');
        await this.authorize(handle,input.scope,'read',tx,{artifactId:version.version_id});return graph;
      });
    });
  }
  async listSnapshots(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;size?:number;cursor?:string;includeDeleted?:boolean;state?:SnapshotSummary['state'];search?:string}):Promise<ConfigurationList<SnapshotSummary>>{
    const size=input.size??20;if(!Number.isInteger(size)||size<1||size>100||input.state&&!['capturing','ready','incomplete','failed','deleted','expired'].includes(input.state)||input.search!==undefined&&(typeof input.search!=='string'||input.search.length>128))throw invalid();
    const includeDeleted=input.includeDeleted===true||input.state==='deleted',search=input.search?.trim()??'';
    return this.db.transaction(async tx=>{
      const proof=await this.authorize(handle,input.scope,'read',tx),binding={actorId:proof.actorId,permissionVersion:proof.permissionVersion,scope:input.scope,size,includeDeleted,state:input.state??null,search};
      let upper=new Date().toISOString(),lastTime:string|null=null,lastId:string|null=null;
      if(input.cursor){if(input.cursor.length>4096)throw invalid('INVALID_CONFIGURATION_CURSOR');try{const[coded,signature]=input.cursor.split('.');const p=JSON.parse(Buffer.from(coded,'base64url').toString('utf8'));if(!safeHashEqual(signature,this.secrets.fingerprint(p))||canonicalJson(p.binding)!==canonicalJson(binding)||!uuid.test(p.lastId)||!Number.isFinite(Date.parse(p.upper))||!Number.isFinite(Date.parse(p.lastTime)))throw Error();upper=p.upper;lastTime=p.lastTime;lastId=p.lastId;}catch{throw invalid('INVALID_CONFIGURATION_CURSOR');}}
      const rows=await tx.query<any>(`SELECT s.*,v.version_id,v.object_count,v.page_count,v.record_count,v.byte_count,v.completeness,v.consistency,v.recovery_summary,v.warning_codes
        FROM config_snapshots s LEFT JOIN config_snapshot_versions v ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.snapshot_id=s.id AND v.version=s.current_version
        WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.transport_scope=$3 AND s.created_at<=$4 AND($5 OR s.state<>'deleted')
        AND($6::timestamptz IS NULL OR(s.created_at,s.id)<($6::timestamptz,$7::uuid)) AND($9::text IS NULL OR s.state=$9)
        AND($10='' OR position(lower($10) in lower(s.name||' '||s.description))>0) AND s.scope_kind=$11 AND s.root_ids=$12::uuid[] ORDER BY s.created_at DESC,s.id DESC LIMIT $8`,[input.scope.clusterId,input.scope.workspaceId,input.scope.transportScope,upper,includeDeleted,lastTime,lastId,size+1,input.state??null,search,input.scope.kind,input.scope.rootIds]);
      const hasMore=rows.length>size,items=rows.slice(0,size).map(r=>this.snapshotSummary(r));let nextCursor:string|null=null;
      if(hasMore){const last=rows[size-1],p={binding,upper,lastTime:iso(last.created_at),lastId:last.id};nextCursor=Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+this.secrets.fingerprint(p);}
      await this.authorize(handle,input.scope,'read',tx);return{items,nextCursor,size,total:null};
    });
  }
  async archiveSnapshot(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;snapshotId:string;revision:number;restore?:boolean},transaction?:DbService):Promise<SnapshotSummary>{
    const writer=this.metadataWriter();
    return this.inTransaction(transaction,async tx=>{
      await this.authorize(handle,input.scope,input.restore?'metadata-write':'purge',tx,{artifactId:input.snapshotId});
      await tx.one('SELECT id FROM config_snapshots WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[input.scope.clusterId,input.scope.workspaceId,input.snapshotId]);
      const root=await this.snapshotRow(tx,input.scope,input.snapshotId);
      if(canonicalJson(this.scope(root))!==canonicalJson(input.scope))throw failure('SOURCE_SCOPE_CHANGED');
      if(!input.restore&&!['ready','failed','incomplete','expired'].includes(root.state)
        &&!(root.state==='capturing'&&await tx.one(SNAPSHOT_TERMINAL_CAPTURE_QUERY,[input.scope.clusterId,input.scope.workspaceId,input.snapshotId])))throw failure('CONFIGURATION_CAPTURE_NOT_TERMINAL');
      if(input.restore&&!await tx.one(`SELECT 1 FROM config_snapshot_versions v JOIN configuration_materials m ON m.id=v.material_id WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4 AND m.state='available'`,[input.scope.clusterId,input.scope.workspaceId,root.id,root.current_version]))throw failure('CONFIGURATION_MATERIAL_UNAVAILABLE');
      const count=await tx.exec(`UPDATE config_snapshots SET state=$4,deleted_at=$5::timestamptz,retention_until=$6::timestamptz,revision=revision+1,updated_at=now()
        WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND revision=$7 AND state=$8`,[input.scope.clusterId,input.scope.workspaceId,input.snapshotId,input.restore?'ready':'deleted',input.restore?null:new Date().toISOString(),input.restore?null:new Date(Date.now()+30*86400000).toISOString(),input.revision,input.restore?'deleted':root.state]);
      if(count!==1||canonicalJson(this.scope(root))!==canonicalJson(input.scope))throw failure('SNAPSHOT_REVISION_CONFLICT');
      const after=this.snapshotSummary(await this.snapshotRow(tx,input.scope,input.snapshotId));
      await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshots',resourceId:input.snapshotId,action:input.restore?'restore':'archive',before:this.snapshotSummary(root),after});
      await this.authorize(handle,input.scope,input.restore?'metadata-write':'purge',tx,{artifactId:input.snapshotId});return after;
    });
  }
  async freezePlan(handle:ConfigurationAccessHandle,input:{jobId:string;plan:ConfigPlan},transaction?:DbService):Promise<ConfigurationPlanIdentity>{
    const p=input.plan;if(p.steps.length>10000||p.steps.reduce((n,s)=>n+s.nativeRequests.length,0)>500||Buffer.byteLength(canonicalJson(p))>33554432)throw failure('CONFIGURATION_PLAN_BUDGET');
    const ids=new Set(p.steps.map(s=>s.stepId));if(ids.size!==p.steps.length||p.steps.some((s,i)=>s.stepOrder!==i+1||!uuid.test(s.stepId)||s.dependencies.some(d=>!ids.has(d)||p.steps.findIndex(x=>x.stepId===d)>=i)))throw failure('CONFIGURATION_DAG_INVALID');
    return this.inTransaction(transaction,async tx=>{
      const job=await this.job(handle,input.jobId,'plan',tx);if(canonicalJson(this.scope(job))!==canonicalJson(p.scope))throw failure('CONFIGURATION_PLAN_SCOPE_MISMATCH');
      if(this.requiredOrigin(job,p)){if(!this.originPolicy)throw failure('CONFIGURATION_ORIGIN_POLICY_REQUIRED');await this.originPolicy.beforeFreeze(handle,job,p,tx);}
      const planId=randomUUID(),artifactId=randomUUID(),materialId=randomUUID(),planHash=this.secrets.fingerprint(p),identity:ConfigurationMaterialIdentity={clusterId:job.cluster_id,workspaceId:job.workspace_id,jobId:job.id,materialId,artifactId,artifactKind:'plan'};
      await tx.exec("INSERT INTO configuration_materials(id,cluster_id,workspace_id,job_id,artifact_kind,artifact_id,wrapped_key_secret) VALUES($1,$2,$3,$4,'plan',$5,$6)",[materialId,job.cluster_id,job.workspace_id,job.id,artifactId,this.crypto.createWrappedKey(identity)]);
      await tx.exec("INSERT INTO configuration_plans(id,cluster_id,workspace_id,transport_scope,created_by,source_job_id,mode,state) VALUES($1,$2,$3,$4,$5,$6,$7,'draft')",[planId,job.cluster_id,job.workspace_id,job.transport_scope,job.actor_id,job.id,p.mode]);
      const material=await tx.one<any>('SELECT * FROM configuration_materials WHERE id=$1',[materialId]);
      await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>{
        await this.authorize(handle,p.scope,'plan',tx,{jobId:job.id});
        await tx.exec(`INSERT INTO configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,source_job_id,material_id,artifact_id,manifest_ciphertext,input_hmac,steps_hmac,source_manifest_hmac,baseline_manifest_hmac,
          cluster_revision,workspace_revision,permission_version,kong_version,schema_hmac,step_count,native_packet_count,delete_count,recovery_complete,expires_at)
          VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$4,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,[job.cluster_id,job.workspace_id,planId,planHash,job.id,materialId,artifactId,this.crypto.encrypt(key,identity,{section:'manifest',key:'plan'},p),this.secrets.fingerprint(p.steps),p.sourceManifestHmac,p.baselineManifestHmac,p.clusterRevision,p.workspaceRevision,p.permissionVersion,p.kongVersion,p.schemaHmac,p.steps.length,p.steps.reduce((n,s)=>n+s.nativeRequests.length,0),p.steps.filter(s=>s.mutationAction==='delete').length,p.recoveryComplete,p.expiresAt]);
        for(const s of p.steps)await tx.exec(`INSERT INTO configuration_plan_objects(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,step_id,step_order,object_key,entity_type,native_id,allocated_native_id,parent_type,parent_id,credential_kind,permission_action,mutation_action,body_hmac,before_hmac,dependencies,payload_ciphertext,native_requests,reference_only,blocker_codes,masked_diff,object_workspace_id)
          VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,$21,$22,$23::jsonb,$24)`,[job.cluster_id,job.workspace_id,planId,planHash,s.stepId,s.stepOrder,s.objectKey,s.entityType,s.nativeId??null,s.allocatedNativeId??null,s.parentType??null,s.parentId??null,s.credentialKind??null,s.permissionAction,s.mutationAction,s.bodyHmac,s.beforeHmac,s.dependencies,this.crypto.encrypt(key,identity,{section:'plan-step',key:s.stepId,entityType:s.entityType,nativeId:s.nativeId??s.allocatedNativeId??null,parentId:s.parentId??null,credentialKind:s.credentialKind??null},s),JSON.stringify(s.nativeRequests.map(n=>({method:n.method,path_hmac:this.secrets.fingerprint(n.canonicalPath),body_hmac:n.bodyHmac,before_hmac:n.beforeHmac}))),s.referenceOnly,s.blockerCodes,JSON.stringify(this.secrets.redact(s.maskedDiff)),s.objectWorkspaceId]);
      });
      if(this.requiredOrigin(job,p))await this.originPolicy!.bindPlan(handle,job,p,{planId,planRevision:1,planHash,jobId:job.id},tx);
      await tx.exec("UPDATE configuration_plans SET state='ready',revision=revision+1,updated_at=now() WHERE id=$1",[planId]);
      await tx.exec('UPDATE configuration_jobs SET plan_id=$2,plan_revision=1,plan_hash=$3,revision=revision+1,updated_at=now() WHERE id=$1',[job.id,planId,planHash]);
      await this.authorize(handle,p.scope,'plan',tx,{jobId:job.id,planId,planRevision:1,planHash});return{planId,planRevision:1,planHash,jobId:job.id};
    });
  }
  async readPlan(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;planId:string;planRevision:number;planHash:string}):Promise<ConfigPlan>{
    return this.db.transaction(async tx=>{
      await this.authorize(handle,input.scope,'plan',tx,input);const row=await tx.one<any>(`SELECT v.*,m.id,m.cluster_id,m.workspace_id,m.job_id,m.artifact_id,m.artifact_kind,m.wrapped_key_secret,m.state AS material_state,p.transport_scope,j.authority_domain,j.durable_issue_id
        FROM configuration_plan_versions v JOIN configuration_materials m ON m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id AND m.id=v.material_id JOIN configuration_plans p ON p.id=v.plan_id JOIN configuration_jobs j ON j.id=v.source_job_id AND j.cluster_id=v.cluster_id AND j.workspace_id=v.workspace_id
        WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.plan_id=$3 AND v.plan_revision=$4 AND v.plan_hash=$5`,[input.scope.clusterId,input.scope.workspaceId,input.planId,input.planRevision,input.planHash]);
      if(!row||row.material_state!=='available'||row.transport_scope!==input.scope.transportScope)throw failure('CONFIGURATION_PLAN_UNAVAILABLE');await this.assertArtifactScope(tx,input.scope,row.source_job_id);
      const identity=this.identity(row);return this.crypto.withKey(identity,row.wrapped_key_secret,async key=>{
        await this.authorize(handle,input.scope,'plan',tx,input);const plan=this.crypto.decrypt<ConfigPlan>(key,identity,{section:'manifest',key:'plan'},row.manifest_ciphertext);
        if(!safeHashEqual(this.secrets.fingerprint(plan),input.planHash)||canonicalJson(plan.scope)!==canonicalJson(input.scope))throw failure('CONFIGURATION_PLAN_CHANGED');
        if(this.access.verifyDurablePlan)await this.access.verifyDurablePlan(handle,row,plan,tx);else{
          if(plan.durableRef!==undefined||row.authority_domain!=null||row.durable_issue_id!=null)throw failure('CONFIGURATION_DURABLE_POLICY_UNAVAILABLE');
          const presence=await tx.one<any>(DURABLE_CONFIGURATION_PRESENCE_QUERY,[row.source_job_id,input.scope.clusterId,input.scope.workspaceId]);
          if(!isProvenLegacyConfigurationRow(presence))throw failure('CONFIGURATION_DURABLE_POLICY_UNAVAILABLE');
        }
        const job=await tx.one<any>('SELECT required_origin_kind,required_origin_id,required_origin_hmac FROM configuration_jobs WHERE id=$1',[row.source_job_id]);
        if(this.requiredOrigin(job??{},plan)){if(!this.originPolicy)throw failure('CONFIGURATION_ORIGIN_POLICY_REQUIRED');await this.originPolicy.verifyPlan(handle,row,plan,tx);}
        await this.authorize(handle,input.scope,'plan',tx,input);return plan;
      });
    });
  }
  /** Binds an execution baseline only to the once-frozen plan of a new job.
   * Current authority, the job row lock and revision CAS precede any claim or
   * native step. Existing terminal jobs are never reopened. */
  async initializeExecutionProgress(handle:ConfigurationAccessHandle,input:{identity:ConfigurationPlanIdentity;revision:number;safeProgress:Record<string,unknown>},transaction?:DbService):Promise<ConfigurationJobSummary>{
    const identity=input.identity;
    if(!identity||!uuid.test(identity.jobId)||!uuid.test(identity.planId)||!hex.test(identity.planHash)||identity.planRevision!==1
      ||!Number.isSafeInteger(input.revision)||input.revision<1||!input.safeProgress
      ||!uuid.test(String(input.safeProgress.baselineSnapshotId))||!Number.isSafeInteger(input.safeProgress.baselineVersion)||Number(input.safeProgress.baselineVersion)<1)throw invalid();
    const progress=this.secrets.redact({...input.safeProgress,...identity});
    if(Buffer.byteLength(canonicalJson(progress))>33554432)throw invalid();
    return this.inTransaction(transaction,async tx=>{
      const job=await this.job(handle,identity.jobId,'plan',tx);
      if(job.state!=='pending'||!['apply','rollback'].includes(job.kind)||job.revision!==input.revision
        ||job.plan_id!==identity.planId||job.plan_revision!==identity.planRevision||job.plan_hash!==identity.planHash)throw failure('CONFIGURATION_EXECUTION_PROGRESS_CONFLICT');
      const updated=await tx.one<any>(INITIALIZE_EXECUTION_PROGRESS_QUERY,[job.id,JSON.stringify(progress),job.cluster_id,job.workspace_id,input.revision,identity.planId,identity.planRevision,identity.planHash]);
      if(!updated)throw failure('CONFIGURATION_EXECUTION_PROGRESS_CONFLICT');
      await this.authorize(handle,this.scope(updated),'plan',tx,identity);return this.jobSummary(updated);
    });
  }
  async createExport(handle:ConfigurationAccessHandle,input:{jobId:string;content:string;mode:'review'|'deployment';format:'deck-1.1'|'review-json';expiresAt:string;sourceSnapshotId?:string;sourceVersion?:number}):Promise<{id:string;byteCount:number;expiresAt:string}>{
    const byteCount=Buffer.byteLength(input.content,'utf8');if(byteCount>33554432||Date.parse(input.expiresAt)<=Date.now())throw invalid('CONFIGURATION_EXPORT_BUDGET');
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'download',tx),id=randomUUID(),materialId=randomUUID(),artifactId=randomUUID();
      const identity:ConfigurationMaterialIdentity={clusterId:job.cluster_id,workspaceId:job.workspace_id,jobId:job.id,materialId,artifactId,artifactKind:'export'};
      const wrapped=this.crypto.createWrappedKey(identity),expiresAt=new Date(Math.min(Date.parse(input.expiresAt),new Date(job.expires_at).getTime())).toISOString();
      await tx.exec("INSERT INTO configuration_materials(id,cluster_id,workspace_id,job_id,artifact_kind,artifact_id,wrapped_key_secret) VALUES($1,$2,$3,$4,'export',$5,$6)",[materialId,job.cluster_id,job.workspace_id,job.id,artifactId,wrapped]);
      await this.crypto.withKey(identity,wrapped,async key=>{
        await this.authorize(handle,this.scope(job),'download',tx,{jobId:job.id,artifactId:id});
        await tx.exec(`INSERT INTO configuration_exports(id,cluster_id,workspace_id,job_id,artifact_id,material_id,source_snapshot_id,source_version,format,mode,manifest_hmac,payload_ciphertext,byte_count,expires_at,created_by)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[id,job.cluster_id,job.workspace_id,job.id,artifactId,materialId,input.sourceSnapshotId??null,input.sourceVersion??null,input.format,input.mode,this.secrets.fingerprint(input.content),this.crypto.encrypt(key,identity,{section:'export',key:id},input.content),byteCount,expiresAt,job.actor_id]);
      });await this.authorize(handle,this.scope(job),'download',tx,{jobId:job.id,artifactId:id});return{id,byteCount,expiresAt};
    });
  }
  async issueDownloadGrant(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;exportId:string;writeEvidence:(tx:DbService,evidence:ConfigurationDownloadEvidence)=>Promise<void>},transaction?:DbService):Promise<{id:string;token:string;expiresAt:string}>{
    if(typeof input.writeEvidence!=='function')throw invalid('CONFIGURATION_AUDIT_REQUIRED');
    return this.inTransaction(transaction,async tx=>{
      const proof=await this.authorize(handle,input.scope,'download',tx,{artifactId:input.exportId});if(!proof.sessionId)throw failure('CONFIGURATION_SESSION_REQUIRED');
      const row=await tx.one<any>("SELECT * FROM configuration_exports WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND state='ready' AND expires_at>now() FOR UPDATE",[input.scope.clusterId,input.scope.workspaceId,input.exportId]);if(!row)throw failure('CONFIGURATION_EXPORT_UNAVAILABLE');await this.assertArtifactScope(tx,input.scope,row.job_id);
      const id=randomUUID(),token=randomBytes(32).toString('base64url'),expiresAt=new Date(Math.min(Date.now()+60000,proof.expiresAt,new Date(row.expires_at).getTime())).toISOString();
      await tx.exec(`INSERT INTO configuration_download_grants(id,cluster_id,workspace_id,export_id,actor_id,session_id,artifact_hmac,permission_version,token_hash,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[id,input.scope.clusterId,input.scope.workspaceId,input.exportId,proof.actorId,proof.sessionId,row.manifest_hmac,proof.permissionVersion,hashToken(token),expiresAt]);
      await input.writeEvidence(tx,{scope:input.scope,grantId:id,exportId:row.id,actorId:proof.actorId,action:'issue',state:'ready',mode:row.mode,format:row.format,byteCount:row.byte_count,expiresAt});
      await this.authorize(handle,input.scope,'download',tx,{artifactId:input.exportId});return{id,token,expiresAt};
    });
  }
  /** Returns the content only to Root's current-authorized no-store stream. Root
   * must recheck its opaque authority before the first byte and every chunk. */
  async consumeDownloadGrant(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;grantId:string;token:string;writeEvidence:(tx:DbService,evidence:ConfigurationDownloadEvidence)=>Promise<void>},transaction?:DbService):Promise<{content:string;byteCount:number;format:string;exportId:string}>{
    if(typeof input.writeEvidence!=='function'||!uuid.test(input.grantId)||typeof input.token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.token))throw invalid('INVALID_CONFIGURATION_DOWNLOAD');
    return this.inTransaction(transaction,async tx=>{
      const grant=await tx.one<any>('SELECT * FROM configuration_download_grants WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[input.scope.clusterId,input.scope.workspaceId,input.grantId]);
      if(!grant||grant.state!=='ready'||new Date(grant.expires_at).getTime()<=Date.now()||!safeHashEqual(grant.token_hash,hashToken(input.token)))throw failure('CONFIGURATION_DOWNLOAD_UNAVAILABLE');
      const proof=await this.authorize(handle,input.scope,'download',tx,{artifactId:grant.export_id});
      if(proof.actorId!==grant.actor_id||proof.sessionId!==grant.session_id||proof.permissionVersion!==grant.permission_version)throw failure('CONFIGURATION_DOWNLOAD_AUTHORITY_CHANGED');
      const row=await tx.one<any>(`SELECT e.*,m.id,m.cluster_id,m.workspace_id,m.job_id,m.artifact_id,m.artifact_kind,m.wrapped_key_secret,m.state AS material_state FROM configuration_exports e
        JOIN configuration_materials m ON m.cluster_id=e.cluster_id AND m.workspace_id=e.workspace_id AND m.id=e.material_id WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.id=$3 AND e.state='ready' AND e.expires_at>now()`,[input.scope.clusterId,input.scope.workspaceId,grant.export_id]);
      if(!row||row.material_state!=='available'||row.manifest_hmac!==grant.artifact_hmac)throw failure('CONFIGURATION_EXPORT_UNAVAILABLE');await this.assertArtifactScope(tx,input.scope,row.job_id);
      const identity=this.identity(row);return this.crypto.withKey(identity,row.wrapped_key_secret,async key=>{
        await this.authorize(handle,input.scope,'download',tx,{artifactId:grant.export_id});const content=this.crypto.decrypt<string>(key,identity,{section:'export',key:grant.export_id},row.payload_ciphertext);
        if(typeof content!=='string'||!safeHashEqual(this.secrets.fingerprint(content),grant.artifact_hmac)||Buffer.byteLength(content,'utf8')!==row.byte_count)throw failure('CONFIGURATION_EXPORT_CHANGED');
        await tx.exec("UPDATE configuration_download_grants SET state='consumed',consumed_at=now() WHERE id=$1 AND state='ready'",[grant.id]);
        await input.writeEvidence(tx,{scope:input.scope,grantId:grant.id,exportId:grant.export_id,actorId:proof.actorId,action:'consume',state:'consumed',mode:row.mode,format:row.format,byteCount:row.byte_count,expiresAt:iso(grant.expires_at)});
        await this.authorize(handle,input.scope,'download',tx,{artifactId:grant.export_id});return{content,byteCount:row.byte_count,format:row.format,exportId:grant.export_id};
      });
    });
  }
  private deckLocator(row:any):DeckSessionLocator{return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,transportScope:row.transport_scope,actorId:row.actor_id,sessionId:row.session_id,jobId:row.job_id,purpose:row.purpose,
    credentialEpoch:row.credential_epoch,permissionVersion:row.permission_version,revision:row.revision,expiresAt:iso(row.expires_at),planId:row.plan_id??undefined,planRevision:row.plan_revision??undefined,planHash:row.plan_hash??undefined};}
  private deckEvidence(row:any,scope:ConfigurationScope):ConfigurationDeckEvidence{return{scope,id:row.id,jobId:row.job_id,actorId:row.actor_id,purpose:row.purpose,state:row.state,revision:row.revision,expiresAt:iso(row.expires_at),planId:row.plan_id??undefined,planRevision:row.plan_revision??undefined,planHash:row.plan_hash??undefined};}
  /** Only a hash-authenticated, active safe tuple can bootstrap Root's delegated
   * verifier. This method never reads/decrypts configuration or creates authority. */
  async locateDeckSession(input:{id:string;tokenHash:string}):Promise<DeckSessionLocator|null>{
    if(!uuid.test(input.id)||!hex.test(input.tokenHash))return null;
    const row=await this.db.one<any>("SELECT * FROM configuration_deck_sessions WHERE id=$1 AND token_hash=$2 AND state='active' AND expires_at>now()",[input.id,input.tokenHash]);return row?this.deckLocator(row):null;
  }
  async issueDeckSession(rawHandle:unknown,input:DeckSessionIssue&{expiresAt:string;credentialEpoch:number}):Promise<{id:string;token:string;expiresAt:string}>{
    const handle=rawHandle as ConfigurationAccessHandle;if(!['read','write'].includes(input.purpose))throw invalid();
    const writer=this.deckWriter();
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,input.purpose==='write'?'step':'read',tx),scope=this.scope(job);
      const proof=await this.authorize(handle,scope,input.purpose==='write'?'step':'read',tx,{jobId:job.id,planId:input.planId,planRevision:input.planRevision,planHash:input.planHash});
      if(!proof.sessionId||input.credentialEpoch!==proof.credentialEpoch||input.purpose==='write'&&(!input.planId||!input.planRevision||!input.planHash||job.plan_id!==input.planId||job.plan_revision!==input.planRevision||job.plan_hash!==input.planHash))throw failure('CONFIGURATION_DECK_AUTHORITY_CHANGED');
      if(input.purpose==='read'&&(input.planId||input.planRevision||input.planHash))throw invalid();
      const id=randomUUID(),token=randomBytes(32).toString('base64url'),expiresAt=new Date(Math.min(Date.now()+120000,Date.parse(input.expiresAt),proof.expiresAt,new Date(job.expires_at).getTime())).toISOString();
      if(Date.parse(expiresAt)<=Date.now())throw failure('CONFIGURATION_DECK_EXPIRED');
      await tx.exec(`INSERT INTO configuration_deck_sessions(id,cluster_id,workspace_id,transport_scope,actor_id,session_id,purpose,token_hash,credential_epoch,permission_version,job_id,plan_id,plan_revision,plan_hash,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[id,job.cluster_id,job.workspace_id,job.transport_scope,proof.actorId,proof.sessionId,input.purpose,hashToken(token),proof.credentialEpoch,proof.permissionVersion,job.id,input.planId??null,input.planRevision??null,input.planHash??null,expiresAt]);
      await writer.sessionChanged(tx,{action:'issue',before:null,after:this.deckEvidence(await tx.one('SELECT * FROM configuration_deck_sessions WHERE id=$1',[id]),scope)});
      await this.authorize(handle,scope,input.purpose==='write'?'step':'read',tx,{jobId:job.id,planId:input.planId,planRevision:input.planRevision,planHash:input.planHash});return{id,token,expiresAt};
    });
  }
  async readDeckSession(rawHandle:unknown,input:{id:string;token:string;purpose:DeckPurpose}):Promise<DeckSessionLocator>{
    const handle=rawHandle as ConfigurationAccessHandle;return this.db.transaction(async tx=>{
      const row=await tx.one<any>("SELECT * FROM configuration_deck_sessions WHERE id=$1 AND state='active' AND expires_at>now() FOR UPDATE",[input.id]);
      if(!row||row.purpose!==input.purpose||!safeHashEqual(row.token_hash,hashToken(input.token)))throw failure('CONFIGURATION_DECK_SESSION_UNAVAILABLE');
      const job=await this.job(handle,row.job_id,row.purpose==='write'?'step':'read',tx),proof=await this.authorize(handle,this.scope(job),row.purpose==='write'?'step':'read',tx,{jobId:job.id,planId:row.plan_id??undefined,planRevision:row.plan_revision??undefined,planHash:row.plan_hash??undefined});
      if(proof.actorId!==row.actor_id||proof.sessionId!==row.session_id||proof.permissionVersion!==row.permission_version||proof.credentialEpoch!==row.credential_epoch||job.transport_scope!==row.transport_scope)throw failure('CONFIGURATION_DECK_AUTHORITY_CHANGED');
      return this.deckLocator(row);
    });
  }
  async revokeDeckSession(rawHandle:unknown,id:string,revision:number):Promise<{revoked:true}>{
    const writer=this.deckWriter(),handle=rawHandle as ConfigurationAccessHandle;return this.db.transaction(async tx=>{
      const row=await tx.one<any>('SELECT * FROM configuration_deck_sessions WHERE id=$1 FOR UPDATE',[id]);if(!row)throw failure('CONFIGURATION_DECK_SESSION_UNAVAILABLE');
      const job=await this.job(handle,row.job_id,'read',tx);if(row.revision!==revision||row.state!=='active')throw failure('CONFIGURATION_DECK_REVISION_CONFLICT');
      await tx.exec("UPDATE configuration_deck_sessions SET state='revoked',revoked_at=now(),revision=revision+1 WHERE id=$1 AND revision=$2",[id,revision]);
      await writer.sessionChanged(tx,{action:'revoke',before:this.deckEvidence(row,this.scope(job)),after:this.deckEvidence({...row,state:'revoked',revision:row.revision+1},this.scope(job))});
      await this.authorize(handle,this.scope(job),'read',tx,{jobId:job.id});return{revoked:true};
    });
  }
  async chargeDeckSessionBudget(rawHandle:unknown,id:string,delta:{pages:number;records:number;bytes:number;calls?:number}):Promise<void>{
    if([delta.pages,delta.records,delta.bytes,delta.calls??0].some(n=>!Number.isSafeInteger(n)||n<0))throw invalid('CONFIGURATION_DECK_BUDGET_INVALID');
    const handle=rawHandle as ConfigurationAccessHandle,exceeded=await this.db.transaction(async tx=>{
      const row=await tx.one<any>("SELECT * FROM configuration_deck_sessions WHERE id=$1 AND state='active' FOR UPDATE",[id]);if(!row)throw failure('CONFIGURATION_DECK_SESSION_UNAVAILABLE');
      const job=await this.job(handle,row.job_id,row.purpose==='write'?'step':'read',tx),proof=await this.authorize(handle,this.scope(job),row.purpose==='write'?'step':'read',tx,{jobId:job.id});
      if(proof.actorId!==row.actor_id||proof.sessionId!==row.session_id||proof.permissionVersion!==row.permission_version||proof.credentialEpoch!==row.credential_epoch)throw failure('CONFIGURATION_DECK_AUTHORITY_CHANGED');
      const next={pages:row.budget_pages+delta.pages,records:row.budget_records+delta.records,bytes:Number(row.budget_bytes)+delta.bytes,calls:row.budget_calls+(delta.calls??0)};
      if(next.pages>100||next.records>10000||next.bytes>33554432||next.calls>500||Date.now()-new Date(row.created_at).getTime()>120000||new Date(row.expires_at).getTime()<=Date.now()){
        await tx.exec("UPDATE configuration_deck_sessions SET state='budget_exceeded',revision=revision+1 WHERE id=$1",[id]);
        await this.deckWriter().sessionChanged(tx,{action:'budget_exceeded',before:this.deckEvidence(row,this.scope(job)),after:this.deckEvidence({...row,state:'budget_exceeded',revision:row.revision+1},this.scope(job))});
        await this.authorize(handle,this.scope(job),row.purpose==='write'?'step':'read',tx,{jobId:job.id});return true;
      }
      await tx.exec('UPDATE configuration_deck_sessions SET budget_pages=$2,budget_records=$3,budget_bytes=$4,budget_calls=$5 WHERE id=$1',[id,next.pages,next.records,next.bytes,next.calls]);
      await this.authorize(handle,this.scope(job),row.purpose==='write'?'step':'read',tx,{jobId:job.id});return false;
    });if(exceeded)throw failure('CONFIGURATION_DECK_BUDGET_EXCEEDED');
  }
  async destroySnapshotMaterial(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;snapshotId:string;revision:number;confirmName:string},transaction?:DbService):Promise<{destroyed:true;backupCaveat:true}>{
    const writer=this.metadataWriter();
    return this.inTransaction(transaction,async tx=>{
      await this.authorize(handle,input.scope,'purge',tx,{artifactId:input.snapshotId});
      await tx.one('SELECT id FROM config_snapshots WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[input.scope.clusterId,input.scope.workspaceId,input.snapshotId]);
      const root=await this.snapshotRow(tx,input.scope,input.snapshotId);
      if(root.state!=='deleted'||root.revision!==input.revision||input.confirmName!==root.name||canonicalJson(this.scope(root))!==canonicalJson(input.scope))throw failure('SNAPSHOT_PURGE_CONFIRMATION_REQUIRED');
      const pin=await tx.one(`SELECT 1 FROM configuration_executions WHERE cluster_id=$1 AND workspace_id=$2 AND before_snapshot_id=$3 AND state IN('claimed','executing','partial','uncertain')
        UNION ALL SELECT 1 FROM configuration_exports e WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.source_snapshot_id=$3 AND e.state='ready' AND e.expires_at>now() LIMIT 1`,[input.scope.clusterId,input.scope.workspaceId,root.id]);
      if(pin)throw failure('SNAPSHOT_MATERIAL_PINNED');
      const count=await tx.exec(`UPDATE configuration_materials m SET wrapped_key_secret=NULL,state='destroyed',destroyed_at=now(),revision=revision+1
        FROM config_snapshot_versions v WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND m.id=v.material_id AND m.state='available'`,[input.scope.clusterId,input.scope.workspaceId,root.id]);
      if(!count)throw failure('CONFIGURATION_MATERIAL_UNAVAILABLE');
      await tx.exec('UPDATE config_snapshots SET revision=revision+1,updated_at=now() WHERE id=$1',[root.id]);
      await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshots',resourceId:root.id,action:'purge',before:this.snapshotSummary(root),after:this.snapshotSummary(await this.snapshotRow(tx,input.scope,root.id)),result:{destroyedMaterials:count,backupCopiesMayRetainKeys:true}});
      await this.authorize(handle,input.scope,'purge',tx,{artifactId:root.id});return{destroyed:true,backupCaveat:true};
    });
  }
  async claimJob(handle:ConfigurationAccessHandle,input:{jobId:string;revision?:number;leaseMs:number}):Promise<{jobId:string;revision:number;leaseGeneration:number;leaseUntil:string}>{
    if(!Number.isInteger(input.leaseMs)||input.leaseMs<1000||input.leaseMs>CONFIGURATION_LEASE_MS)throw invalid('CONFIGURATION_LEASE_INVALID');
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'step',tx);
      if(input.revision!==undefined&&job.revision!==input.revision||!['pending','running','waiting_approval'].includes(job.state)||job.remote_started&&!job.remote_completed)throw failure('CONFIGURATION_JOB_UNCERTAIN');
      if(job.lease_until&&new Date(job.lease_until).getTime()>Date.now())throw failure('CONFIGURATION_JOB_LEASE_HELD');
      const scope=this.scope(job),proof=await this.authorize(handle,scope,'step',tx,{jobId:job.id}),deadline=[Date.now()+input.leaseMs,new Date(job.expires_at).getTime(),new Date(job.authority_expires_at).getTime(),proof.expiresAt];
      if(job.plan_id){
        const version=await tx.one<any>('SELECT expires_at FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',[job.cluster_id,job.workspace_id,job.plan_id,job.plan_revision,job.plan_hash]);
        if(!version)throw failure('CONFIGURATION_EXECUTION_PLAN_CHANGED');
        deadline.push(new Date(version.expires_at).getTime());
      }
      const untilMs=Math.min(...deadline);
      if(!Number.isFinite(untilMs)||untilMs<=Date.now())throw failure('CONFIGURATION_AUTHORITY_CHANGED');
      const generation=job.lease_generation+1,until=new Date(untilMs).toISOString();
      await tx.exec("UPDATE configuration_jobs SET lease_generation=$2,lease_owner_hash=$3,lease_until=$4,state='running',started_at=coalesce(started_at,now()),revision=revision+1,updated_at=now() WHERE id=$1",[job.id,generation,this.secrets.fingerprint(randomBytes(32).toString('base64url')),until]);
      // Root reacquires a new handle after this committed generation change.
      // The old handle intentionally cannot pass the next job-bound check.
      await this.authorize(handle,this.scope(job),'step',tx);return{jobId:job.id,revision:job.revision+1,leaseGeneration:generation,leaseUntil:until};
    });
  }
  async createExecution(handle:ConfigurationAccessHandle,input:{jobId:string;planId:string;planRevision:number;planHash:string;beforeSnapshotId:string;beforeSnapshotVersion:number;workflowId?:string;approvedVersion?:number;claimHash:string}):Promise<{executionId:string;claimHash:string}>{
    if(!hex.test(input.claimHash))throw invalid('CONFIGURATION_EXECUTION_CLAIM_INVALID');
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'step',tx),scope=this.scope(job);
      const proof=await this.authorize(handle,scope,'step',tx,{jobId:job.id,planId:input.planId,planRevision:input.planRevision,planHash:input.planHash,leaseGeneration:job.lease_generation});
      if(job.plan_id!==input.planId||job.plan_revision!==input.planRevision||job.plan_hash!==input.planHash||job.expires_at<=new Date())throw failure('CONFIGURATION_EXECUTION_PLAN_CHANGED');
      const old=await tx.one<any>('SELECT id,claim_hash FROM configuration_executions WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3',[job.cluster_id,job.workspace_id,job.id]);
      if(old){if(!safeHashEqual(old.claim_hash,input.claimHash))throw failure('CONFIGURATION_EXECUTION_ALREADY_CLAIMED');return{executionId:old.id,claimHash:old.claim_hash};}
      const baseline=await tx.one<any>(`SELECT v.*,s.transport_scope FROM config_snapshot_versions v JOIN config_snapshots s ON s.id=v.snapshot_id
        WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4 AND s.state='ready'`,[job.cluster_id,job.workspace_id,input.beforeSnapshotId,input.beforeSnapshotVersion]);
      if(!baseline||baseline.transport_scope!==job.transport_scope||baseline.consistency!=='console_fenced_best_effort')throw failure('CONFIGURATION_BEFORE_SNAPSHOT_REQUIRED');
      let wrapper:any=null;
      if(job.execution_mode==='approval'){
        if(!input.workflowId||!input.approvedVersion)throw failure('APPROVAL_REQUIRED');
        wrapper=await tx.one<any>(`SELECT w.plan_hash FROM workflows w WHERE w.cluster_id=$1 AND w.workspace_id=$2 AND w.id=$3 AND w.plan_revision=$4
          AND w.kind='configuration_v2' AND w.subject_type='configuration_jobs' AND w.subject_id=$5 AND w.approval_required AND w.state IN('approved','executing')
          AND(SELECT count(*) FROM workflow_steps s WHERE s.workflow_id=w.id AND s.plan_revision=w.plan_revision)=1
          AND EXISTS(SELECT 1 FROM workflow_steps s WHERE s.workflow_id=w.id AND s.plan_revision=w.plan_revision AND s.plan_hash=w.plan_hash AND s.kind='metadata' AND s.handler='configuration_v2' AND s.entity_type='configuration_jobs' AND s.entity_id=$5 AND jsonb_array_length(s.native_requests)=0)`,[job.cluster_id,job.workspace_id,input.workflowId,input.approvedVersion,job.id]);
        if(!wrapper)throw failure('APPROVAL_REQUIRED');
      }else if(input.workflowId||input.approvedVersion)throw invalid('DIRECT_CONFIGURATION_CANNOT_BIND_APPROVAL');
      const executionId=randomUUID();
      // Material lifetime is not execution authority. A new durable source
      // retains an independently fixed short execution deadline.
      const executionExpiry=job.authority_domain==='durable-configuration-v1'?
        new Date(Math.min(new Date(job.expires_at).getTime(),proof.expiresAt,Date.now()+CONFIGURATION_TIMEOUT_MS)).toISOString():job.expires_at;
      await tx.exec(`INSERT INTO configuration_executions(id,cluster_id,workspace_id,job_id,plan_id,plan_revision,plan_hash,actor_id,workflow_id,approved_version,workflow_plan_hash,execution_mode,claim_hash,permission_version,before_snapshot_id,before_snapshot_version,lease_generation,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,[executionId,job.cluster_id,job.workspace_id,job.id,input.planId,input.planRevision,input.planHash,job.actor_id,input.workflowId??null,input.approvedVersion??null,wrapper?.plan_hash??null,job.execution_mode,input.claimHash,job.permission_version,input.beforeSnapshotId,input.beforeSnapshotVersion,job.lease_generation,executionExpiry]);
      await this.scheduledExecutionOriginPolicy?.created(tx,handle,executionId);
      await this.authorize(handle,scope,'step',tx,{jobId:job.id,planId:input.planId,planRevision:input.planRevision,planHash:input.planHash,leaseGeneration:job.lease_generation});return{executionId,claimHash:input.claimHash};
    });
  }
  async initializeSteps(handle:ConfigurationAccessHandle,input:{jobId:string;executionId:string}):Promise<Array<{id:string;planStepId:string;stepOrder:number;objectWorkspaceId:string;state:string}>>{
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'step',tx),e=await tx.one<any>('SELECT * FROM configuration_executions WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND job_id=$4 FOR UPDATE',[job.cluster_id,job.workspace_id,input.executionId,job.id]);
      if(!e)throw failure('CONFIGURATION_EXECUTION_UNAVAILABLE');
      const existing=await tx.query<any>('SELECT id,plan_step_id,step_order,object_workspace_id,state FROM configuration_job_steps WHERE execution_id=$1 ORDER BY step_order',[e.id]);
      if(existing.length)return existing.map(s=>({id:s.id,planStepId:s.plan_step_id,stepOrder:s.step_order,objectWorkspaceId:s.object_workspace_id,state:s.state}));
      const plans=await tx.query<any>('SELECT * FROM configuration_plan_objects WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5 ORDER BY step_order',[e.cluster_id,e.workspace_id,e.plan_id,e.plan_revision,e.plan_hash]);
      for(const p of plans)await tx.exec(`INSERT INTO configuration_job_steps(id,cluster_id,workspace_id,job_id,execution_id,plan_id,plan_revision,plan_hash,plan_step_id,step_order,object_workspace_id,approval_required,before_hmac,original_native_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,[randomUUID(),job.cluster_id,job.workspace_id,job.id,e.id,e.plan_id,e.plan_revision,e.plan_hash,p.step_id,p.step_order,p.object_workspace_id,e.execution_mode==='approval',p.before_hmac,p.native_id??p.allocated_native_id]);
      await this.authorize(handle,this.scope(job),'step',tx,{jobId:job.id,planId:e.plan_id,planRevision:e.plan_revision,planHash:e.plan_hash});
      const rows=await tx.query<any>('SELECT id,plan_step_id,step_order,object_workspace_id,state FROM configuration_job_steps WHERE execution_id=$1 ORDER BY step_order',[e.id]);return rows.map(s=>({id:s.id,planStepId:s.plan_step_id,stepOrder:s.step_order,objectWorkspaceId:s.object_workspace_id,state:s.state}));
    });
  }
  async readSteps(handle:ConfigurationAccessHandle,input:{jobId:string;executionId?:string}):Promise<Array<Record<string,unknown>>>{
    return this.db.transaction(async tx=>{const job=await this.job(handle,input.jobId,'read',tx);const rows=await tx.query<any>(stepSelection+' WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.job_id=$3 AND($4::uuid IS NULL OR s.execution_id=$4) ORDER BY s.step_order',[job.cluster_id,job.workspace_id,job.id,input.executionId??null]);await this.authorize(handle,this.scope(job),'read',tx,{jobId:job.id});return rows.map(s=>this.stepSummary(s));});
  }
  private stepSummary(s:any):Record<string,unknown>{return this.secrets.redact({id:s.id,executionId:s.execution_id,planStepId:s.plan_step_id,stepOrder:s.step_order,objectWorkspaceId:s.object_workspace_id,state:s.state,type:s.type,action:s.action,objectId:s.original_id??s.allocated_native_id,originalId:s.original_id,effectiveId:s.effective_native_id,operationId:s.recorded_operation_id,verified:s.verified===true,recycleEntryId:s.recycle_entry_id,result:s.safe_result,errorCode:s.error_code,revision:s.revision,startedAt:s.started_at?iso(s.started_at):null,completedAt:s.completed_at?iso(s.completed_at):null});}
  async listSteps(handle:ConfigurationAccessHandle,input:{jobId:string;size?:number;cursor?:string}):Promise<ConfigurationList<Record<string,unknown>>>{
    const size=input.size??20;if(!Number.isInteger(size)||size<1||size>100)throw invalid();
    return this.db.transaction(async tx=>{
      const job=await this.job(handle,input.jobId,'read',tx),scope=this.scope(job),proof=await this.authorize(handle,scope,'read',tx,{jobId:job.id}),binding={jobId:job.id,scope,actorId:proof.actorId,permissionVersion:proof.permissionVersion,size};let after=0;
      if(input.cursor){if(input.cursor.length>4096)throw invalid('INVALID_CONFIGURATION_CURSOR');try{const[a,b]=input.cursor.split('.'),p=JSON.parse(Buffer.from(a,'base64url').toString('utf8'));if(!safeHashEqual(b,this.secrets.fingerprint(p))||canonicalJson(p.binding)!==canonicalJson(binding)||!Number.isInteger(p.after)||p.after<0||p.after>10000)throw Error();after=p.after;}catch{throw invalid('INVALID_CONFIGURATION_CURSOR');}}
      const rows=await tx.query<any>(stepSelection+' WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.job_id=$3 AND s.step_order>$4 ORDER BY s.step_order LIMIT $5',[job.cluster_id,job.workspace_id,job.id,after,size+1]);
      const visible=rows.slice(0,size),links=visible.length?await tx.query<any>(`SELECT c.step_id,g.recycle_entry_id,g.object_workspace_id
        FROM configuration_recycle_components c JOIN configuration_recycle_graphs g ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.graph_id
        WHERE c.cluster_id=$1 AND c.workspace_id=$2 AND c.step_id=ANY($3::uuid[]) AND g.job_id=$4 AND g.actor_id=$5`,[job.cluster_id,job.workspace_id,visible.map(s=>s.id),job.id,job.actor_id]):[];
      const items=visible.map(s=>{const link=links.find(l=>l.step_id===s.id);return{...this.stepSummary(s),...(link?{completeRecycleEntryId:link.recycle_entry_id,recycleWorkspaceId:link.object_workspace_id}:{})};});
      await this.authorize(handle,scope,'read',tx,{jobId:job.id});const p=rows[size-1]?{binding,after:rows[size-1].step_order}:null;
      return{items,size,total:null,nextCursor:rows.length>size&&p?Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+this.secrets.fingerprint(p):null};
    });
  }
  async recordStepEvidence(handle:ConfigurationAccessHandle,input:{jobId:string;stepId:string;revision:number;state:'running'|'succeeded'|'failed'|'uncertain'|'skipped';receipt?:unknown;afterHmac?:string;safeResult?:unknown;errorCode?:string;recycleEntryId?:string;effectiveNativeId?:string}):Promise<void>{
    if(input.errorCode&&!/^[A-Z0-9_]{1,128}$/.test(input.errorCode)||input.state==='succeeded'&&(!input.receipt||!input.afterHmac||!hex.test(input.afterHmac)))throw invalid('CONFIGURATION_STEP_EVIDENCE_INVALID');
    await this.db.transaction(async tx=>{
      const phase=input.state==='running'?'step':'ledger';
      const job=await this.job(handle,input.jobId,phase,tx),s=await tx.one<any>('SELECT * FROM configuration_job_steps WHERE job_id=$1 AND id=$2 FOR UPDATE',[job.id,input.stepId]);
      if(!s||s.revision!==input.revision||['succeeded','skipped'].includes(s.state)||s.state==='uncertain'&&input.state==='running')throw failure('CONFIGURATION_STEP_REVISION_CONFLICT');
      let receiptOperationId:string|null=null;
      if(input.state==='succeeded'){
        const receipt=input.receipt as any;
        if(!receipt||!uuid.test(receipt.operationId)||receipt.state!=='succeeded'||receipt.remoteCompleted!==true)throw failure('CONFIGURATION_NATIVE_RECEIPT_MISSING');
        const operation=await tx.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND actor_id=$4 FOR SHARE',[job.cluster_id,s.object_workspace_id,receipt.operationId,job.actor_id]);
        const frozen=await tx.one<any>('SELECT * FROM configuration_plan_objects WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND step_id=$6',[s.cluster_id,s.workspace_id,s.plan_id,s.plan_revision,s.plan_hash,s.plan_step_id]);
        const expectedId=frozen?.entity_type==='targets'&&frozen.mutation_action==='update'?frozen.allocated_native_id:frozen?.native_id??frozen?.allocated_native_id;
        if(!operation||!frozen||operation.state!=='succeeded'||!operation.remote_started||!operation.remote_completed||!operation.result_secret
          ||operation.entity_type!==frozen.entity_type||operation.action!==frozen.mutation_action||operation.entity_id!==expectedId
          ||operation.parent_id!==(frozen.parent_id??null)||operation.credential_kind!==(frozen.credential_kind??null)||operation.transport_scope!==job.transport_scope
          ||operation.idempotency_key!==`configuration-${job.id}-${s.id}`||receipt.entityId!==operation.entity_id||input.effectiveNativeId!==undefined&&input.effectiveNativeId!==operation.entity_id
          ||!operation.before_secret||!operation.payload_secret)throw failure('CONFIGURATION_NATIVE_RECEIPT_MISMATCH');
        if(s.approval_required){
          if(s.operation_id!==operation.id||operation.configuration_job_id!==job.id||operation.configuration_step_id!==s.id||operation.configuration_execution_id!==s.execution_id||operation.configuration_plan_revision!==s.plan_revision||operation.configuration_plan_hash!==s.plan_hash)throw failure('CONFIGURATION_NATIVE_RECEIPT_MISMATCH');
        }else if([operation.workflow_id,operation.workflow_execution_id,operation.workflow_plan_revision,operation.workflow_plan_hash,operation.workflow_step_id,operation.configuration_job_id,operation.configuration_execution_id,operation.configuration_step_id,operation.configuration_plan_revision,operation.configuration_plan_hash].some(v=>v!==null))throw failure('CONFIGURATION_NATIVE_RECEIPT_MISMATCH');
        if(!safeHashEqual(this.secrets.fingerprint(this.secrets.decrypt(operation.before_secret,`mutation:${operation.id}:before`)),frozen.before_hmac)
          ||!safeHashEqual(this.secrets.fingerprint(this.secrets.decrypt(operation.payload_secret,`mutation:${operation.id}:payload`)),frozen.body_hmac))throw failure('CONFIGURATION_NATIVE_RECEIPT_MISMATCH');
        receiptOperationId=operation.id;
      }
      const material=await tx.one<any>(`SELECT m.* FROM configuration_plan_versions v JOIN configuration_materials m ON m.id=v.material_id
        WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.plan_id=$3 AND v.plan_revision=$4 AND v.plan_hash=$5`,[s.cluster_id,s.workspace_id,s.plan_id,s.plan_revision,s.plan_hash]);if(!material||material.state!=='available')throw failure('CONFIGURATION_PLAN_UNAVAILABLE');
      const identity=this.identity(material);await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>{
        await this.authorize(handle,this.scope(job),phase,tx,{jobId:job.id,planId:s.plan_id,planRevision:s.plan_revision,planHash:s.plan_hash});
        const receipt=input.receipt===undefined?null:this.crypto.encrypt(key,identity,{section:'receipt',key:`${s.execution_id}:${s.id}`},input.receipt);
        await tx.exec(`UPDATE configuration_job_steps SET state=$3,receipt_ciphertext=coalesce($4,receipt_ciphertext),after_hmac=coalesce($5,after_hmac),safe_result=$6::jsonb,error_code=$7,
          recycle_entry_id=coalesce($8,recycle_entry_id),effective_native_id=coalesce($9,effective_native_id),receipt_operation_id=coalesce($11,receipt_operation_id),revision=revision+1,started_at=coalesce(started_at,now()),completed_at=CASE WHEN $3='running' THEN NULL ELSE now() END WHERE job_id=$1 AND id=$2 AND revision=$10`,[job.id,s.id,input.state,receipt,input.afterHmac??null,JSON.stringify(this.secrets.redact(input.safeResult??{})),input.errorCode??null,input.recycleEntryId??null,input.effectiveNativeId??null,input.revision,receiptOperationId]);
      });
      await tx.exec('INSERT INTO configuration_job_attempts(id,cluster_id,workspace_id,job_id,execution_id,step_id,attempt_no,lease_generation,phase,result,error_code) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[randomUUID(),job.cluster_id,job.workspace_id,job.id,s.execution_id,s.id,s.revision,job.lease_generation,'step_evidence',input.state==='running'?'started':input.state==='skipped'?'succeeded':input.state,input.errorCode??null]);
      await this.authorize(handle,this.scope(job),phase,tx,{jobId:job.id,planId:s.plan_id,planRevision:s.plan_revision,planHash:s.plan_hash});
    });
  }
  async finishJob(handle:ConfigurationAccessHandle,input:{jobId:string;state:'succeeded'|'partial'|'failed'|'uncertain'|'cancelled';safeProgress?:unknown;errorCode?:string;leaseGeneration?:number;writeEvidence:(tx:DbService,before:ConfigurationJobSummary,after:ConfigurationJobSummary)=>Promise<void>},transaction?:DbService):Promise<ConfigurationJobSummary>{
    if(typeof input.writeEvidence!=='function'||input.errorCode&&!/^[A-Z0-9_]{1,128}$/.test(input.errorCode))throw invalid('CONFIGURATION_AUDIT_REQUIRED');
    return this.inTransaction(transaction,async tx=>{
      const job=await this.job(handle,input.jobId,'ledger',tx),before=this.jobSummary(job);
      if(input.leaseGeneration!==undefined&&job.lease_generation!==input.leaseGeneration||['succeeded','cancelled','expired'].includes(job.state))throw failure('CONFIGURATION_JOB_TERMINAL');
      if(input.state==='succeeded'&&await tx.one("SELECT 1 FROM configuration_job_steps WHERE job_id=$1 AND state NOT IN('succeeded','skipped') LIMIT 1",[job.id]))throw failure('CONFIGURATION_STEPS_INCOMPLETE');
      if(input.state==='succeeded'&&job.plan_id&&['apply','rollback'].includes(job.kind)){const count=await tx.one<any>('SELECT (SELECT count(*)::integer FROM configuration_job_steps WHERE job_id=$1) AS actual,(SELECT step_count FROM configuration_plan_versions WHERE cluster_id=$2 AND workspace_id=$3 AND plan_id=$4 AND plan_revision=$5) AS expected',[job.id,job.cluster_id,job.workspace_id,job.plan_id,job.plan_revision]);if(count.actual!==count.expected)throw failure('CONFIGURATION_STEPS_INCOMPLETE');}
      const row=await tx.one<any>(`UPDATE configuration_jobs SET state=$2,safe_progress=$3::jsonb,error_code=$4,remote_completed=CASE WHEN $2='uncertain' THEN false ELSE remote_started END,
        completed_at=now(),revision=revision+1,updated_at=now(),lease_until=NULL WHERE id=$1 RETURNING *`,[job.id,input.state,JSON.stringify(this.secrets.redact(input.safeProgress??job.safe_progress)),input.errorCode??null]);
      await tx.exec('UPDATE configuration_executions SET state=$2,revision=revision+1,completed_at=now() WHERE job_id=$1 AND state IN(\'claimed\',\'executing\')',[job.id,input.state==='cancelled'?'failed':input.state]);
      await tx.exec("UPDATE config_snapshot_schedule_runs SET state=$2,completed_at=now() WHERE job_id=$1 AND state='running'",[job.id,input.state==='succeeded'?'succeeded':'failed']);
      const after=this.jobSummary(row);await input.writeEvidence(tx,before,after);await this.authorize(handle,this.scope(job),'read',tx,{jobId:job.id});return after;
    });
  }
  async findByOriginalKey(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;idempotencyKey:string}):Promise<ConfigurationJobSummary|null>{
    return this.db.transaction(async tx=>{const proof=await this.authorize(handle,input.scope,'read',tx);const row=await tx.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4 AND transport_scope=$5 AND scope_kind=$6 AND root_ids=$7::uuid[]',[input.scope.clusterId,input.scope.workspaceId,proof.actorId,input.idempotencyKey,input.scope.transportScope,input.scope.kind,input.scope.rootIds]);await this.authorize(handle,input.scope,'read',tx);return row?this.jobSummary(row):null;});
  }
  async listJobs(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;size?:number;cursor?:string}):Promise<ConfigurationList<ConfigurationJobSummary>>{
    const size=input.size??20;if(!Number.isInteger(size)||size<1||size>100)throw invalid();
    return this.db.transaction(async tx=>{const proof=await this.authorize(handle,input.scope,'read',tx),binding={actorId:proof.actorId,permissionVersion:proof.permissionVersion,scope:input.scope,size};let upper=new Date().toISOString(),lastTime:string|null=null,lastId:string|null=null;
      if(input.cursor){try{const[a,b]=input.cursor.split('.'),p=JSON.parse(Buffer.from(a,'base64url').toString('utf8'));if(!safeHashEqual(b,this.secrets.fingerprint(p))||canonicalJson(p.binding)!==canonicalJson(binding)||!uuid.test(p.lastId))throw Error();upper=p.upper;lastTime=p.lastTime;lastId=p.lastId;}catch{throw invalid('INVALID_CONFIGURATION_CURSOR');}}
      const rows=await tx.query<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND transport_scope=$4 AND created_at<=$5 AND($6::timestamptz IS NULL OR(created_at,id)<($6::timestamptz,$7::uuid)) AND scope_kind=$9 AND root_ids=$10::uuid[] ORDER BY created_at DESC,id DESC LIMIT $8',[input.scope.clusterId,input.scope.workspaceId,proof.actorId,input.scope.transportScope,upper,lastTime,lastId,size+1,input.scope.kind,input.scope.rootIds]);
      const last=rows[size-1],p=last?{binding,upper,lastTime:iso(last.created_at),lastId:last.id}:null;await this.authorize(handle,input.scope,'read',tx);return{items:rows.slice(0,size).map(r=>this.jobSummary(r)),size,total:null,nextCursor:rows.length>size&&p?Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+this.secrets.fingerprint(p):null};});
  }
  async freezeImport(handle:ConfigurationAccessHandle,input:{jobId:string;document:unknown}):Promise<{artifactId:string}>{
    if(Buffer.byteLength(canonicalJson(input.document),'utf8')>8388608)throw invalid('CONFIGURATION_IMPORT_BUDGET');
    return this.db.transaction(async tx=>{const job=await this.job(handle,input.jobId,'plan',tx);if(job.kind!=='import'&&job.kind!=='rollback')throw failure('CONFIGURATION_IMPORT_JOB_REQUIRED');const artifactId=randomUUID(),materialId=randomUUID(),identity:ConfigurationMaterialIdentity={clusterId:job.cluster_id,workspaceId:job.workspace_id,jobId:job.id,materialId,artifactId,artifactKind:'import'},wrapped=this.crypto.createWrappedKey(identity);
      await tx.exec("INSERT INTO configuration_materials(id,cluster_id,workspace_id,job_id,artifact_kind,artifact_id,wrapped_key_secret) VALUES($1,$2,$3,$4,'import',$5,$6)",[materialId,job.cluster_id,job.workspace_id,job.id,artifactId,wrapped]);
      await this.crypto.withKey(identity,wrapped,async key=>{const ciphertext=this.crypto.encrypt(key,identity,{section:'manifest',key:'import'},input.document);await tx.exec('INSERT INTO configuration_imports(cluster_id,workspace_id,job_id,artifact_id,material_id,manifest_hmac,payload_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)',[job.cluster_id,job.workspace_id,job.id,artifactId,materialId,this.secrets.fingerprint(input.document),ciphertext]);});await this.authorize(handle,this.scope(job),'plan',tx,{jobId:job.id,artifactId});return{artifactId};});
  }
  async readImport<T=unknown>(handle:ConfigurationAccessHandle,input:{jobId:string;artifactId:string}):Promise<T>{
    return this.db.transaction(async tx=>{const job=await this.job(handle,input.jobId,'plan',tx),row=await tx.one<any>(`SELECT i.*,m.id,m.cluster_id,m.workspace_id,m.job_id,m.artifact_id,m.artifact_kind,m.wrapped_key_secret,m.state FROM configuration_imports i JOIN configuration_materials m ON m.id=i.material_id WHERE i.cluster_id=$1 AND i.workspace_id=$2 AND i.job_id=$3 AND i.artifact_id=$4`,[job.cluster_id,job.workspace_id,job.id,input.artifactId]);if(!row||row.state!=='available')throw failure('CONFIGURATION_IMPORT_UNAVAILABLE');const identity=this.identity(row);
      return this.crypto.withKey(identity,row.wrapped_key_secret,async key=>{await this.authorize(handle,this.scope(job),'plan',tx,{jobId:job.id,artifactId:input.artifactId});const value=this.crypto.decrypt<T>(key,identity,{section:'manifest',key:'import'},row.payload_ciphertext);if(!safeHashEqual(this.secrets.fingerprint(value),row.manifest_hmac))throw failure('CONFIGURATION_IMPORT_CHANGED');await this.authorize(handle,this.scope(job),'plan',tx,{jobId:job.id,artifactId:input.artifactId});return value;});});
  }
  async readPlanSummary(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;planId:string;planRevision?:number}):Promise<Record<string,unknown>>{
    return this.db.transaction(async tx=>{await this.authorize(handle,input.scope,'read',tx,{planId:input.planId});const row=await tx.one<any>(`SELECT p.*,v.plan_hash,v.step_count,v.native_packet_count,v.delete_count,v.recovery_complete,v.expires_at
      FROM configuration_plans p JOIN configuration_plan_versions v ON v.cluster_id=p.cluster_id AND v.workspace_id=p.workspace_id AND v.plan_id=p.id AND v.plan_revision=coalesce($4,p.current_revision)
      WHERE p.cluster_id=$1 AND p.workspace_id=$2 AND p.id=$3 AND p.transport_scope=$5`,[input.scope.clusterId,input.scope.workspaceId,input.planId,input.planRevision??null,input.scope.transportScope]);if(!row)throw failure('CONFIGURATION_PLAN_UNAVAILABLE');await this.assertArtifactScope(tx,input.scope,row.source_job_id);await this.authorize(handle,input.scope,'read',tx,{planId:input.planId});return{id:row.id,planId:row.id,planRevision:input.planRevision??row.current_revision,planHash:row.plan_hash,jobId:row.source_job_id,state:row.state,revision:row.revision,mode:row.mode,stepCount:row.step_count,nativePacketCount:row.native_packet_count,deleteCount:row.delete_count,recoveryComplete:row.recovery_complete,expiresAt:iso(row.expires_at)};});
  }
  async listChanges(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;planId:string;planRevision:number;planHash:string;size?:number;cursor?:string;afterOrder?:number}):Promise<ConfigurationList<Record<string,unknown>>>{
    const size=input.size??20;if(!Number.isInteger(size)||size<1||size>100)throw invalid();
    return this.db.transaction(async tx=>{const proof=await this.authorize(handle,input.scope,'read',tx,input),source=await tx.one<any>('SELECT source_job_id FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[input.scope.clusterId,input.scope.workspaceId,input.planId]);if(!source)throw failure('CONFIGURATION_PLAN_UNAVAILABLE');await this.assertArtifactScope(tx,input.scope,source.source_job_id);const binding={scope:input.scope,actorId:proof.actorId,permissionVersion:proof.permissionVersion,planId:input.planId,planRevision:input.planRevision,planHash:input.planHash,size};let after=input.afterOrder??0;
      if(input.cursor){if(input.cursor.length>4096)throw invalid('INVALID_CONFIGURATION_CURSOR');try{const[a,b]=input.cursor.split('.'),p=JSON.parse(Buffer.from(a,'base64url').toString('utf8'));if(!safeHashEqual(b,this.secrets.fingerprint(p))||canonicalJson(p.binding)!==canonicalJson(binding)||!Number.isInteger(p.after)||p.after<0||p.after>10000)throw Error();after=p.after;}catch{throw invalid('INVALID_CONFIGURATION_CURSOR');}}
      if(!Number.isInteger(after)||after<0||after>10000)throw invalid('INVALID_CONFIGURATION_CURSOR');const rows=await tx.query<any>('SELECT step_id,step_order,object_key,entity_type,object_workspace_id,native_id,allocated_native_id,parent_type,parent_id,credential_kind,permission_action,mutation_action,reference_only,blocker_codes,masked_diff FROM configuration_plan_objects WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND step_order>$6 ORDER BY step_order LIMIT $7',[input.scope.clusterId,input.scope.workspaceId,input.planId,input.planRevision,input.planHash,after,size+1]);await this.authorize(handle,input.scope,'read',tx,input);const p=rows[size-1]?{binding,after:rows[size-1].step_order}:null;return{items:rows.slice(0,size).map(r=>this.secrets.redact({id:r.step_id,stepId:r.step_id,stepOrder:r.step_order,objectKey:r.object_key,entityType:r.entity_type,objectWorkspaceId:r.object_workspace_id,nativeId:r.native_id,allocatedNativeId:r.allocated_native_id,parentType:r.parent_type,parentId:r.parent_id,credentialKind:r.credential_kind,permissionAction:r.permission_action,mutationAction:r.mutation_action,referenceOnly:r.reference_only,blockerCodes:r.blocker_codes,diff:r.masked_diff})),size,total:null,nextCursor:rows.length>size&&p?Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+this.secrets.fingerprint(p):null};});
  }
  private gitOpsSummary(r:any):ConfigurationGitOpsSummary{return{id:r.id,clusterId:r.cluster_id,workspaceId:r.workspace_id,jobId:r.job_id,createdBy:r.created_by,repositoryLabel:r.repository_label,commitSha:r.commit_sha,pipelineReference:r.pipeline_reference,state:r.job_state,createdAt:iso(r.created_at)};}
  async createGitOpsRun(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;jobId:string;repositoryLabel:string;commitSha:string;pipelineReference:string;id?:string},transaction?:DbService):Promise<ConfigurationGitOpsSummary>{
    if(input.id!==undefined&&!uuid.test(input.id)||!uuid.test(input.jobId)||typeof input.repositoryLabel!=='string'||!/^[A-Za-z0-9_. /-]{1,128}$/.test(input.repositoryLabel)||!input.repositoryLabel.trim()
      ||typeof input.commitSha!=='string'||!/^([a-f0-9]{40}|[a-f0-9]{64})$/.test(input.commitSha)
      ||typeof input.pipelineReference!=='string'||!/^[A-Za-z0-9_. /:#-]{1,256}$/.test(input.pipelineReference)||!input.pipelineReference.trim()
      ||/(?:[a-z][a-z0-9+.-]*:\/\/|https?:|@|[?&=]|(?:token|password|secret|authorization|api[_-]?key)[:=])/i.test(input.pipelineReference))throw invalid('INVALID_CONFIGURATION_GITOPS_METADATA');
    const writer=this.metadataWriter();return this.inTransaction(transaction,async tx=>{
      const proof=await this.authorize(handle,input.scope,'metadata-write',tx);
      // Referencing an old job never reacquires that job's execution capability.
      // The opaque handle remains bound to Root's current metadata ledger job.
      await this.authorize(handle,input.scope,'read',tx);
      const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND actor_id=$4 FOR SHARE',[input.scope.clusterId,input.scope.workspaceId,input.jobId,proof.actorId]);
      if(!job||canonicalJson(this.scope(job))!==canonicalJson(input.scope))throw failure('CONFIGURATION_GITOPS_JOB_SCOPE_CHANGED');
      const id=input.id??randomUUID(),row=await tx.one<any>(`INSERT INTO configuration_gitops_runs(id,cluster_id,workspace_id,job_id,created_by,repository_label,commit_sha,pipeline_reference)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[id,input.scope.clusterId,input.scope.workspaceId,job.id,proof.actorId,input.repositoryLabel,input.commitSha,input.pipelineReference]);
      const after=this.gitOpsSummary({...row,job_state:job.state});await writer.metadataChanged(tx,{scope:input.scope,resourceType:'configuration_gitops_runs',resourceId:id,action:'create',before:null,after});
      await this.authorize(handle,input.scope,'metadata-write',tx);return after;
    });
  }
  async listGitOpsRuns(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;size?:number;cursor?:string}):Promise<ConfigurationList<ConfigurationGitOpsSummary>>{
    const size=input.size??20;if(!Number.isInteger(size)||size<1||size>100)throw invalid();
    return this.db.transaction(async tx=>{
      const proof=await this.authorize(handle,input.scope,'read',tx),binding={scope:input.scope,actorId:proof.actorId,permissionVersion:proof.permissionVersion,size};let upper=new Date().toISOString(),lastTime:string|null=null,lastId:string|null=null;
      if(input.cursor){if(input.cursor.length>4096)throw invalid('INVALID_CONFIGURATION_CURSOR');try{const[a,b]=input.cursor.split('.'),p=JSON.parse(Buffer.from(a,'base64url').toString('utf8'));if(!safeHashEqual(b,this.secrets.fingerprint(p))||canonicalJson(p.binding)!==canonicalJson(binding)||!uuid.test(p.lastId)||!Number.isFinite(Date.parse(p.upper))||!Number.isFinite(Date.parse(p.lastTime)))throw Error();upper=p.upper;lastTime=p.lastTime;lastId=p.lastId;}catch{throw invalid('INVALID_CONFIGURATION_CURSOR');}}
      const rows=await tx.query<any>(`SELECT g.*,j.state AS job_state FROM configuration_gitops_runs g JOIN configuration_jobs j ON j.cluster_id=g.cluster_id AND j.workspace_id=g.workspace_id AND j.id=g.job_id
        WHERE g.cluster_id=$1 AND g.workspace_id=$2 AND g.created_by=$3 AND j.transport_scope=$4 AND g.created_at<=$5
        AND($6::timestamptz IS NULL OR(g.created_at,g.id)<($6::timestamptz,$7::uuid)) AND j.scope_kind=$9 AND j.root_ids=$10::uuid[] ORDER BY g.created_at DESC,g.id DESC LIMIT $8`,[input.scope.clusterId,input.scope.workspaceId,proof.actorId,input.scope.transportScope,upper,lastTime,lastId,size+1,input.scope.kind,input.scope.rootIds]);
      const last=rows[size-1],p=last?{binding,upper,lastTime:iso(last.created_at),lastId:last.id}:null;
      await this.authorize(handle,input.scope,'read',tx);return{items:rows.slice(0,size).map(r=>this.gitOpsSummary(r)),size,total:null,nextCursor:rows.length>size&&p?Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+this.secrets.fingerprint(p):null};
    });
  }
  private schedulePolicy(input:{scope:ConfigurationScope;intervalMinutes:number;timezone:string;retentionDays:number}):void{
    this.validateScope(input.scope);if(!Number.isInteger(input.intervalMinutes)||input.intervalMinutes<5||input.intervalMinutes>10080||!Number.isInteger(input.retentionDays)||input.retentionDays<1||input.retentionDays>3650||typeof input.timezone!=='string'||input.timezone.length>100)throw invalid('INVALID_SNAPSHOT_SCHEDULE');
    try{new Intl.DateTimeFormat('en',{timeZone:input.timezone}).format(new Date());}catch{throw invalid('INVALID_SNAPSHOT_TIMEZONE');}
  }
  private scheduleSummary(r:any):SnapshotScheduleSummary{return{id:r.id,clusterId:r.cluster_id,workspaceId:r.workspace_id,name:r.name,ownerUserId:r.owner_user_id,state:r.state,revision:r.revision,currentVersion:r.current_version,scopeKind:r.scope_kind,rootIds:r.root_ids,intervalMinutes:r.interval_minutes,timezone:r.timezone,retentionDays:r.retention_days,nextRunAt:iso(r.next_run_at),purgedAt:r.purged_at?iso(r.purged_at):null,createdAt:iso(r.created_at),updatedAt:iso(r.updated_at)};}
  private async scheduleRow(tx:DbService,scope:ConfigurationScope,id:string):Promise<any>{const row=await tx.one<any>(`SELECT s.*,v.scope_kind,v.root_ids,v.interval_minutes,v.timezone,v.retention_days,v.policy_hmac FROM config_snapshot_schedules s
    JOIN config_snapshot_schedule_versions v ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=s.current_version WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.id=$3`,[scope.clusterId,scope.workspaceId,id]);if(!row||canonicalJson(this.scope(row))!==canonicalJson(scope))throw failure('SNAPSHOT_SCHEDULE_NOT_FOUND');return row;}
  async createSchedule(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;name:string;intervalMinutes:number;timezone:string;retentionDays:number;id?:string},transaction?:DbService):Promise<SnapshotScheduleSummary>{
    this.schedulePolicy(input);if(input.id!==undefined&&!uuid.test(input.id)||typeof input.name!=='string'||!input.name.trim()||input.name.length>128)throw invalid('INVALID_SNAPSHOT_SCHEDULE');
    const writer=this.metadataWriter();
    return this.inTransaction(transaction,async tx=>{const proof=await this.authorize(handle,input.scope,'metadata-write',tx),id=input.id??randomUUID();await tx.exec(`INSERT INTO config_snapshot_schedules(id,cluster_id,workspace_id,transport_scope,name,owner_user_id,next_run_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,[id,input.scope.clusterId,input.scope.workspaceId,input.scope.transportScope,input.name,proof.actorId,new Date(Date.now()+input.intervalMinutes*60000).toISOString()]);
      await tx.exec('INSERT INTO config_snapshot_schedule_versions(cluster_id,workspace_id,schedule_id,version,scope_kind,root_ids,interval_minutes,timezone,retention_days,policy_hmac,created_by) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10)',[input.scope.clusterId,input.scope.workspaceId,id,input.scope.kind,input.scope.rootIds,input.intervalMinutes,input.timezone,input.retentionDays,this.secrets.fingerprint(input),proof.actorId]);
      const after=this.scheduleSummary(await this.scheduleRow(tx,input.scope,id));await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshot_schedules',resourceId:id,action:'create',before:null,after});
      await this.authorize(handle,input.scope,'metadata-write',tx,{artifactId:id});return after;});
  }
  async updateSchedule(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;scheduleId:string;revision:number;name:string;intervalMinutes:number;timezone:string;retentionDays:number;paused?:boolean},transaction?:DbService):Promise<SnapshotScheduleSummary>{
    this.schedulePolicy(input);if(typeof input.name!=='string'||!input.name.trim()||input.name.length>128)throw invalid();
    const writer=this.metadataWriter();
    return this.inTransaction(transaction,async tx=>{const proof=await this.authorize(handle,input.scope,'metadata-write',tx,{artifactId:input.scheduleId});await tx.one('SELECT id FROM config_snapshot_schedules WHERE id=$1 FOR UPDATE',[input.scheduleId]);const old=await this.scheduleRow(tx,input.scope,input.scheduleId);if(old.revision!==input.revision||old.state==='deleted')throw failure('SNAPSHOT_SCHEDULE_REVISION_CONFLICT');const version=old.current_version+1;
      await tx.exec('INSERT INTO config_snapshot_schedule_versions(cluster_id,workspace_id,schedule_id,version,scope_kind,root_ids,interval_minutes,timezone,retention_days,policy_hmac,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[input.scope.clusterId,input.scope.workspaceId,old.id,version,input.scope.kind,input.scope.rootIds,input.intervalMinutes,input.timezone,input.retentionDays,this.secrets.fingerprint({scope:input.scope,intervalMinutes:input.intervalMinutes,timezone:input.timezone,retentionDays:input.retentionDays}),proof.actorId]);
      await tx.exec('UPDATE config_snapshot_schedules SET current_version=$2,name=$3,state=$4,next_run_at=$5,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$6',[old.id,version,input.name,input.paused?'paused':'active',new Date(Date.now()+input.intervalMinutes*60000).toISOString(),input.revision]);
      const after=this.scheduleSummary(await this.scheduleRow(tx,input.scope,old.id));await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshot_schedules',resourceId:old.id,action:'update',before:this.scheduleSummary(old),after});
      await this.authorize(handle,input.scope,'metadata-write',tx,{artifactId:old.id});return after;});
  }
  async archiveSchedule(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;scheduleId:string;revision:number;restore?:boolean},transaction?:DbService):Promise<SnapshotScheduleSummary>{
    const writer=this.metadataWriter();
    return this.inTransaction(transaction,async tx=>{await this.authorize(handle,input.scope,input.restore?'metadata-write':'purge',tx,{artifactId:input.scheduleId});
      await tx.one('SELECT id FROM config_snapshot_schedules WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[input.scope.clusterId,input.scope.workspaceId,input.scheduleId]);const old=await this.scheduleRow(tx,input.scope,input.scheduleId);
      const n=await tx.exec(`UPDATE config_snapshot_schedules SET state=$4,deleted_at=$5::timestamptz,revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 AND revision=$6 AND purged_at IS NULL AND(($7 AND state='deleted') OR(NOT $7 AND state IN('active','paused')))`,[input.scope.clusterId,input.scope.workspaceId,input.scheduleId,input.restore?'paused':'deleted',input.restore?null:new Date().toISOString(),input.revision,input.restore===true]);if(n!==1)throw failure('SNAPSHOT_SCHEDULE_REVISION_CONFLICT');
      const after=this.scheduleSummary(await this.scheduleRow(tx,input.scope,input.scheduleId));await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshot_schedules',resourceId:input.scheduleId,action:input.restore?'restore':'archive',before:this.scheduleSummary(old),after});
      await this.authorize(handle,input.scope,input.restore?'metadata-write':'purge',tx,{artifactId:input.scheduleId});return after;});
  }
  async purgeSchedule(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;scheduleId:string;revision:number;confirmName:string},transaction?:DbService):Promise<SnapshotScheduleSummary>{
    const writer=this.metadataWriter();return this.inTransaction(transaction,async tx=>{
      await this.authorize(handle,input.scope,'purge',tx,{artifactId:input.scheduleId});
      await tx.one('SELECT id FROM config_snapshot_schedules WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3 FOR UPDATE',[input.scope.clusterId,input.scope.workspaceId,input.scheduleId]);const old=await this.scheduleRow(tx,input.scope,input.scheduleId);
      if(old.state!=='deleted'||old.purged_at||old.revision!==input.revision||input.confirmName!==old.name)throw failure('SNAPSHOT_SCHEDULE_PURGE_CONFIRMATION_REQUIRED');
      if(await tx.one("SELECT 1 FROM config_snapshot_schedule_runs WHERE cluster_id=$1 AND workspace_id=$2 AND schedule_id=$3 AND state IN('pending','running') LIMIT 1",[input.scope.clusterId,input.scope.workspaceId,old.id]))throw failure('SNAPSHOT_SCHEDULE_RUN_PINNED');
      await tx.exec('UPDATE config_snapshot_schedules SET purged_at=now(),revision=revision+1,updated_at=now() WHERE id=$1',[old.id]);const after=this.scheduleSummary(await this.scheduleRow(tx,input.scope,old.id));
      await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshot_schedules',resourceId:old.id,action:'purge',before:this.scheduleSummary(old),after});
      await this.authorize(handle,input.scope,'purge',tx,{artifactId:old.id});return after;
    });
  }
  async listSchedules(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;size?:number;cursor?:string;includeDeleted?:boolean;state?:SnapshotScheduleSummary['state'];search?:string}):Promise<ConfigurationList<SnapshotScheduleSummary>>{
    const size=input.size??20;if(!Number.isInteger(size)||size<1||size>100||input.state&&!['active','paused','deleted'].includes(input.state)||input.search!==undefined&&(typeof input.search!=='string'||input.search.length>128))throw invalid();const includeDeleted=input.includeDeleted===true||input.state==='deleted',search=input.search?.trim()??'';return this.db.transaction(async tx=>{
      const proof=await this.authorize(handle,input.scope,'read',tx),binding={scope:input.scope,actorId:proof.actorId,permissionVersion:proof.permissionVersion,size,includeDeleted,state:input.state??null,search};let upper=new Date().toISOString(),lastTime:string|null=null,lastId:string|null=null;
      if(input.cursor){try{const[a,b]=input.cursor.split('.'),p=JSON.parse(Buffer.from(a,'base64url').toString('utf8'));if(!safeHashEqual(b,this.secrets.fingerprint(p))||canonicalJson(p.binding)!==canonicalJson(binding)||!uuid.test(p.lastId))throw Error();upper=p.upper;lastTime=p.lastTime;lastId=p.lastId;}catch{throw invalid('INVALID_CONFIGURATION_CURSOR');}}
      const rows=await tx.query<any>(`SELECT s.*,v.scope_kind,v.root_ids,v.interval_minutes,v.timezone,v.retention_days FROM config_snapshot_schedules s JOIN config_snapshot_schedule_versions v ON v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.schedule_id=s.id AND v.version=s.current_version
        WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.transport_scope=$3 AND s.purged_at IS NULL AND s.created_at<=$4 AND($5 OR s.state<>'deleted') AND($6::timestamptz IS NULL OR(s.created_at,s.id)<($6::timestamptz,$7::uuid))
        AND($9::text IS NULL OR s.state=$9) AND($10='' OR position(lower($10) in lower(s.name))>0) AND v.scope_kind=$11 AND v.root_ids=$12::uuid[] ORDER BY s.created_at DESC,s.id DESC LIMIT $8`,[input.scope.clusterId,input.scope.workspaceId,input.scope.transportScope,upper,includeDeleted,lastTime,lastId,size+1,input.state??null,search,input.scope.kind,input.scope.rootIds]);const last=rows[size-1],p=last?{binding,upper,lastTime:iso(last.created_at),lastId:last.id}:null;
      await this.authorize(handle,input.scope,'read',tx);return{items:rows.slice(0,size).map(r=>this.scheduleSummary(r)),size,total:null,nextCursor:rows.length>size&&p?Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+this.secrets.fingerprint(p):null};});
  }
  /** Minimal scheduler locators are not capture authority. Root re-verifies the
   * current owner, scope and policy before minting a schedule-only handle. */
  async peekDueSchedules(limit=20):Promise<Array<{scheduleId:string;clusterId:string;workspaceId:string;ownerUserId:string;version:number;revision:number;scheduledAt:string}>>{
    if(!Number.isInteger(limit)||limit<1||limit>100)throw invalid();const rows=await this.db.query<any>("SELECT id,cluster_id,workspace_id,owner_user_id,current_version,revision,next_run_at FROM config_snapshot_schedules WHERE state='active' AND next_run_at<=now() ORDER BY next_run_at,id LIMIT $1",[limit]);return rows.map(r=>({scheduleId:r.id,clusterId:r.cluster_id,workspaceId:r.workspace_id,ownerUserId:r.owner_user_id,version:r.current_version,revision:r.revision,scheduledAt:iso(r.next_run_at)}));
  }
  async claimDue(handle:ConfigurationAccessHandle,input:{scope:ConfigurationScope;scheduleId:string;version:number;revision:number;scheduledAt:string;runId:string},transaction?:DbService):Promise<{runId:string;scope:ConfigurationScope;retentionDays:number}>{
    const writer=this.metadataWriter();
    if(!uuid.test(input.runId)||!Number.isFinite(Date.parse(input.scheduledAt)))throw invalid();return this.inTransaction(transaction,async tx=>{
      const proof=await this.authorize(handle,input.scope,'capture-page',tx,{artifactId:input.scheduleId});if(proof.origin!=='schedule'||proof.scheduleRunId!==input.runId||proof.sessionId)throw failure('SNAPSHOT_SCHEDULE_AUTHORITY_REQUIRED');
      await tx.one('SELECT id FROM config_snapshot_schedules WHERE id=$1 FOR UPDATE',[input.scheduleId]);const row=await this.scheduleRow(tx,input.scope,input.scheduleId);
      if(row.state!=='active'||row.revision!==input.revision||row.current_version!==input.version||row.owner_user_id!==proof.actorId||iso(row.next_run_at)!==input.scheduledAt||Date.parse(input.scheduledAt)>Date.now())throw failure('SNAPSHOT_SCHEDULE_CHANGED');
      await tx.exec(`INSERT INTO config_snapshot_schedule_runs(id,cluster_id,workspace_id,schedule_id,schedule_version,scheduled_at,creator_id,state,permission_version) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8)`,[input.runId,input.scope.clusterId,input.scope.workspaceId,row.id,row.current_version,input.scheduledAt,proof.actorId,proof.permissionVersion]);
      await tx.exec('UPDATE config_snapshot_schedules SET next_run_at=$2,revision=revision+1,updated_at=now() WHERE id=$1',[row.id,new Date(Date.now()+row.interval_minutes*60000).toISOString()]);
      await writer.metadataChanged(tx,{scope:input.scope,resourceType:'config_snapshot_schedules',resourceId:row.id,action:'update',before:this.scheduleSummary(row),after:this.scheduleSummary(await this.scheduleRow(tx,input.scope,row.id))});
      await this.authorize(handle,input.scope,'capture-page',tx,{artifactId:row.id});return{runId:input.runId,scope:input.scope,retentionDays:row.retention_days};});
  }
  async bindScheduleRunJob(handle:ConfigurationAccessHandle,input:{jobId:string;runId:string},transaction?:DbService):Promise<void>{
    await this.inTransaction(transaction,async tx=>{const job=await this.job(handle,input.jobId,'capture-page',tx),proof=await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id});if(proof.origin!=='schedule'||proof.scheduleRunId!==input.runId||job.origin_type!=='schedule')throw failure('SNAPSHOT_SCHEDULE_AUTHORITY_REQUIRED');const n=await tx.exec("UPDATE config_snapshot_schedule_runs SET job_id=$2,state='running' WHERE id=$1 AND cluster_id=$3 AND workspace_id=$4 AND creator_id=$5 AND state='pending' AND job_id IS NULL",[input.runId,job.id,job.cluster_id,job.workspace_id,proof.actorId]);if(n!==1)throw failure('SNAPSHOT_SCHEDULE_RUN_ALREADY_BOUND');await this.authorize(handle,this.scope(job),'capture-page',tx,{jobId:job.id});});
  }
}
