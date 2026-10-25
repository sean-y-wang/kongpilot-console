import { configurationJobSubjectMaterial } from './workflow-configuration-job-subject';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';
import { isIP } from 'node:net';
import { DbService, withVerificationReadMemo } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { sortByFreshFingerprint } from './workflow-fresh-fingerprint-sort';
import { assertKongPath, entityForPath } from '../../infrastructure/kong/policy';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { kong15SchemaValidationEquivalent } from '../config-transfer/schema-comparison';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { normalizeEntityAuthorizationView } from '../entities/entity-reference';
import { SnapshotCryptoService } from '../config-storage/snapshot-crypto.service';
import type { ConfigPlan } from '../configuration/configuration.types';
import { ConfigurationDurableRepository,configurationDurableMarker } from '../configuration/configuration-durable.repository';
import { grantMatchesEntity, inheritedTagMatches, validGrant } from '../authorization/grant-policy';
import type { EffectiveGrant, PermissionAction } from '../../common/authorization.types';
import { configurationOriginMarker, normalizedNativeRequests } from './approved-execution.types';
import { assertConfigurationWorkflowPlan, type ConfigurationWorkflowPayload } from './configuration-workflow';
import { assertEntityAnnotationPlan } from '../annotations/entity-annotation-workflow-plan';
import { isMetadataScheduledKind, type MetadataScheduledKind } from './metadata-schedule.guard';
import { METADATA_SCHEDULE_FEATURE, metadataSubjectSealSource } from './metadata-schedule.registry';
import { validateWorkflowPlan } from './workflow-validation';
import { planAad, type WorkflowPlanV1 } from './workflow.types';
import type { WorkflowBusinessSubjectSealV1, WorkflowScheduledPlanV1, WorkflowScheduleDraft } from './workflow-schedule.contract';
import type { WorkflowScheduledBusinessKind } from './workflow-scheduled-authority.types';
import type { WorkflowScheduledConfigurationMaterial, WorkflowScheduledConfigurationPromoteSqlMaterial } from './workflow-scheduled-configuration-origin.types';
import type { WorkflowScheduleCandidateReadInput as ReadInput, WorkflowScheduleCandidateReadResource as Resource,
 WorkflowScheduleCandidateReadScope as ReadScope, WorkflowScheduleCandidateBusinessPolicy as ReadPolicy } from './workflow-schedule-candidate-read.types';
import { decodePublicationProof, portalKeyAad } from '../portal/portal-proof';
import { isPortalCredentialScheduleKind } from '../portal/portal-credential-lifecycle-contract';
import { decryptComparisonMaterial, governanceComparisonEnvelope } from '../governance/governance-comparison-material';
import { isPortalCredentialBusinessMaterial, type WorkflowBusinessMaterial, type WorkflowBusinessPortalMaterial, type WorkflowBusinessAnnotationMaterial, type WorkflowBusinessMetadataMaterial, type WorkflowBusinessPromotionMaterial } from './workflow-business-material.types';
import type { WorkflowBusinessScopedReadBridge, WorkflowBusinessScopedSubject } from './workflow-business-scoped-read.types';
import { isServiceHostReferencePoint, validServiceHostReference } from './workflow-service-host-reference';

const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i, hex = /^[a-f\d]{64}$/;
const deny = (code = 'WORKFLOW_BUSINESS_MATERIAL_INVALID') => new ForbiddenException({ code });
const time = (value: unknown): number => new Date(value as any).getTime();
const iso = (value: unknown): string => { if (!Number.isFinite(time(value))) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_TIME_INVALID'); return new Date(value as any).toISOString(); };
const int = (value: unknown): number => { const n = typeof value === 'number' ? value : typeof value === 'string' && /^[1-9][0-9]{0,9}$/.test(value) ? Number(value) : NaN;
 if (!Number.isSafeInteger(n) || n < 1 || n > 2_147_483_647) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_EPOCH_INVALID'); return n; };
const roots = new Set(['services','routes','consumers','upstreams','plugins','certificates','ca_certificates','snis']);
const credentials = new Set(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
const limits = Object.freeze({ maxCalls:500, maxPages:100, maxRecords:10000, maxBytes:33554432 });
interface Proposed { type:string; id:string; parentId?:string; credentialKind?:string; workspaceId:string; body:any; before:any; action:PermissionAction; create:boolean;appendAllocatedId?:string }
interface Witness { type:string; entity:any; workspaceId:string; resource:Readonly<Resource> }
interface ResponseScope { active:boolean; failed:boolean; expiresAt:number; binding?:string; bytes:number; planningFutureParents:boolean;
 readonly witnesses:Map<string,Witness>; readonly serviceHostParents:Map<string,Witness>; readonly futureParents:Map<string,Witness>; readonly completed:Set<string>; readonly seen:Set<string>; readonly absent:Set<string>; }

/** Fixed business material compiler. Storage/current callbacks are SQL-only;
 * actual native data enters solely through Root's installed GET response
 * callback. No callback executes Kong, creates a claim or manufactures a SID.
 * New scheduled plans must be sealed before approval; old deadlines remain
 * immutable. This provider is intentionally not auto-registered in a module. */
@Injectable()
export class WorkflowBusinessMaterialService {
 private readonly crypto:SnapshotCryptoService;
 private readonly responses = new AsyncLocalStorage<ResponseScope>();
 private scoped?:Readonly<WorkflowBusinessScopedReadBridge>;
 constructor(private readonly db:DbService, private readonly secrets:SecretService) { this.crypto=new SnapshotCryptoService(secrets); }
 installScopedReadBridge(bridge:WorkflowBusinessScopedReadBridge):void{
  if(this.scoped||!bridge||typeof bridge.assertSubject!=='function'||typeof bridge.resolveReadScope!=='function')throw deny('WORKFLOW_BUSINESS_SCOPED_POLICY_ALREADY_INSTALLED');
  this.scoped=Object.freeze({assertSubject:bridge.assertSubject.bind(bridge),resolveReadScope:bridge.resolveReadScope.bind(bridge)});
 }
 private scopedInput(input:ReadInput):boolean{return!!this.scoped&&input.principal.user.superAdmin!==true;}
 private same(a:unknown,b:unknown):void { if(this.secrets.fingerprint(a??null)!==this.secrets.fingerprint(b??null)) throw deny('WORKFLOW_BUSINESS_MATERIAL_CHANGED'); }

  async configurationMaterial(jobId: string, tx: DbService = this.db): Promise<Readonly<WorkflowScheduledConfigurationMaterial>> {
    if (!uuid.test(jobId)) throw deny();
    const job = await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1', [jobId]);
    if (!job || !uuid.test(job.actor_id) || !uuid.test(job.origin_session_id ?? '') || job.origin_type !== 'http'
      || !['apply', 'rollback'].includes(job.kind) || job.execution_mode !== 'approval' || job.approval_required !== true
      || !uuid.test(job.plan_id ?? '') || !uuid.test(job.workflow_id ?? '') || !hex.test(job.plan_hash ?? '')
      || !hex.test(job.transport_scope ?? '') || !hex.test(job.request_hmac ?? '') || !Array.isArray(job.root_ids)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_JOB_INVALID');
    const keys = [job.cluster_id, job.workspace_id], planRow = await tx.one<any>('SELECT * FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [...keys, job.plan_id]);
    const version = await tx.one<any>('SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4', [...keys, job.plan_id, job.plan_revision]);
    const material = version && await tx.one<any>('SELECT * FROM configuration_materials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [...keys, version.material_id]);
    if (!planRow || planRow.current_revision !== job.plan_revision || planRow.transport_scope !== job.transport_scope || !version
      || version.plan_hash !== job.plan_hash || !material || material.state !== 'available' || !material.wrapped_key_secret
      || material.job_id !== version.source_job_id || material.artifact_kind !== 'plan' || material.artifact_id !== version.artifact_id) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PLAN_INVALID');
    const identity = { clusterId: keys[0], workspaceId: keys[1], jobId: version.source_job_id, materialId: material.id, artifactId: version.artifact_id, artifactKind: 'plan' as const };
    const plan = await this.crypto.withKey(identity, material.wrapped_key_secret, async key => this.crypto.decrypt<ConfigPlan>(key, identity, { section: 'manifest', key: 'plan' }, version.manifest_ciphertext));
    if (this.secrets.fingerprint(plan) !== job.plan_hash || version.input_hmac !== job.plan_hash || this.secrets.fingerprint(plan.steps) !== version.steps_hmac
      || plan.scope.clusterId !== job.cluster_id || plan.scope.workspaceId !== job.workspace_id || plan.scope.transportScope !== job.transport_scope
      || plan.scope.kind !== job.scope_kind || this.secrets.fingerprint(plan.scope.rootIds) !== this.secrets.fingerprint(job.root_ids)
      || plan.permissionVersion !== job.permission_version || plan.clusterRevision !== job.cluster_revision || plan.workspaceRevision !== job.workspace_revision
      || !/^1\.5\.\d+$/.test(plan.kongVersion) || !plan.recoveryComplete || !Array.isArray(plan.steps) || plan.steps.length > 10000
      || version.step_count !== plan.steps.length || version.schema_hmac !== plan.schemaHmac || version.source_manifest_hmac !== plan.sourceManifestHmac
      || version.baseline_manifest_hmac !== plan.baselineManifestHmac) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PLAN_HMAC_INVALID');
    if(configurationDurableMarker(job)||plan.durableRef!==undefined)await new ConfigurationDurableRepository(this.secrets).verify(job,tx,true,plan);
    const objects = await tx.query<any>('SELECT * FROM configuration_plan_objects WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 ORDER BY step_order', [...keys, job.plan_id, job.plan_revision]);
    if (objects.length !== plan.steps.length) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_OBJECTS_INCOMPLETE');
    let packets = 0; const seen = new Set<string>();
    await this.crypto.withKey(identity, material.wrapped_key_secret, async key => {
      for (const [i, step] of plan.steps.entries()) {
        const object = objects[i];
        if (!uuid.test(step.stepId) || seen.has(step.stepId) || step.stepOrder !== i + 1 || step.referenceOnly || step.blockerCodes.length
          || step.bodyHmac !== this.secrets.fingerprint(step.body) || step.beforeHmac !== this.secrets.fingerprint(step.before ?? null)
          || !uuid.test(step.objectWorkspaceId) || !Array.isArray(step.nativeRequests) || !step.nativeRequests.length
          || object.step_id !== step.stepId || object.step_order !== step.stepOrder || object.object_workspace_id !== step.objectWorkspaceId
          || object.entity_type !== step.entityType || object.mutation_action !== step.mutationAction || object.body_hmac !== step.bodyHmac || object.before_hmac !== step.beforeHmac
          || object.reference_only !== false || object.blocker_codes?.length) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_STEP_INVALID');
        this.same(object.dependencies, step.dependencies);
        this.same(object.native_id ?? null, step.nativeId ?? null); this.same(object.allocated_native_id ?? null, step.allocatedNativeId ?? null);
        this.same(object.parent_id ?? null, step.parentId ?? null); this.same(object.credential_kind ?? null, step.credentialKind ?? null);
        for (const request of step.nativeRequests) { assertKongPath(request.method, request.canonicalPath);
          if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) || !hex.test(request.bodyHmac) || !hex.test(request.beforeHmac)) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PACKET_INVALID'); packets++; }
        this.same(object.native_requests, step.nativeRequests.map(request => ({ method: request.method, path_hmac: this.secrets.fingerprint(request.canonicalPath), body_hmac: request.bodyHmac, before_hmac: request.beforeHmac })));
        const decoded = this.crypto.decrypt(key, identity, { section: 'plan-step', key: step.stepId, entityType: step.entityType,
          nativeId: step.nativeId ?? step.allocatedNativeId ?? null, parentId: step.parentId ?? null, credentialKind: step.credentialKind ?? null }, object.payload_ciphertext);
        this.same(decoded, step); seen.add(step.stepId);
      }
    });
    if (packets > 500 || version.native_packet_count !== packets) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PACKET_BUDGET');
    let marker; try { marker = configurationOriginMarker(job); } catch { throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_MARKER_INVALID'); }
    let sourceOrigin: Record<string, any> | null = null;
    if (marker) {
      if (!plan.originRef || plan.originRef.version !== 1 || plan.originRef.kind !== marker.kind || plan.originRef.originId !== marker.id || plan.originRef.materialHmac !== marker.hmac) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_MARKER_INVALID');
      const jobOrigin = await tx.one<any>('SELECT * FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3', [...keys, job.id]);
      const planOrigin = await tx.one<any>('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5', [...keys, job.plan_id, job.plan_revision, job.plan_hash]);
      if (!jobOrigin || !planOrigin || jobOrigin.origin_kind !== marker.kind || jobOrigin.origin_id !== marker.id || jobOrigin.material_hmac !== marker.hmac
        || planOrigin.origin_kind !== marker.kind || planOrigin.origin_id !== marker.id || planOrigin.material_hmac !== marker.hmac
        || planOrigin.job_id !== version.source_job_id || !uuid.test(jobOrigin.source_cluster_id) || !uuid.test(jobOrigin.source_workspace_id)
        || jobOrigin.source_cluster_id === job.cluster_id && jobOrigin.source_workspace_id === job.workspace_id) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_BINDING_INVALID');
      sourceOrigin = { marker, jobOrigin, planOrigin };
    } else if (plan.originRef !== undefined || await tx.one('SELECT 1 FROM configuration_job_origin_bindings WHERE job_id=$1', [job.id])
      || await tx.one('SELECT 1 FROM configuration_plan_origin_bindings WHERE plan_id=$1 AND plan_revision=$2 AND plan_hash=$3', [job.plan_id, job.plan_revision, job.plan_hash])) throw deny('WORKFLOW_SCHEDULE_CONFIGURATION_FOREIGN_PROMOTE_ORIGIN');
    const subjectSeal = { version: 1 as const, driver: marker ? 'governance-promote' as const : job.kind === 'rollback' ? 'configuration-rollback' as const : 'configuration-apply' as const,
      subjectId: job.id, materialHmac: this.secrets.fingerprint({ version: 1, origin: 'workflow-scheduled-configuration', job: configurationJobSubjectMaterial(job),
        planVersion: { sourceJobId: version.source_job_id, planId: version.plan_id, revision: version.plan_revision, hash: version.plan_hash, inputHmac: version.input_hmac,
          materialId: version.material_id, artifactId: version.artifact_id, stepsHmac: version.steps_hmac, sourceManifestHmac: version.source_manifest_hmac,
          baselineManifestHmac: version.baseline_manifest_hmac, schemaHmac: version.schema_hmac, createdAt: iso(version.created_at), expiresAt: iso(version.expires_at) },
        material: { id: material.id, jobId: material.job_id, artifactId: material.artifact_id, artifactKind: material.artifact_kind, wrappedKey: material.wrapped_key_secret }, sourceOrigin }),
      nativeManifestHmac: this.secrets.fingerprint(plan), sourceScopes: sourceOrigin ? [{ clusterId: sourceOrigin.jobOrigin.source_cluster_id,
        workspaceId: sourceOrigin.jobOrigin.source_workspace_id, materialHmac: marker!.hmac }] : [] };
    return immutableJson({ job, version, planRow, material, plan, sourceOrigin, subjectSeal });
  }
 /** Real SQL plan/version/step facts; callers cannot replace encrypted source
  * material with a plan-shaped HTTP object. No deadline is amended here. */
 private async persistedPlan(plan:Readonly<WorkflowPlanV1>,tx:DbService):Promise<any> {
  validateWorkflowPlan(plan as WorkflowPlanV1);
  const keys=[plan.clusterId,plan.workspaceId,plan.workflowId],hash=this.secrets.fingerprint(plan);
  const workflow=await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',keys);
  const version=await tx.one<any>('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[...keys,plan.planRevision]);
  if(!workflow||!version||workflow.plan_revision!==plan.planRevision||workflow.plan_hash!==hash||version.plan_hash!==hash
   ||workflow.kind!==plan.kind||workflow.subject_type!==plan.subject.type||workflow.subject_id!==plan.subject.id
   ||workflow.requester_type!==plan.requester.type||(plan.requester.type==='console'?workflow.requester_user_id:workflow.requester_developer_id)!==plan.requester.id
   ||workflow.definition_id!==plan.definition.id||workflow.definition_version!==plan.definition.version||version.policy_version!==plan.definition.version
   ||workflow.approval_required!==true||version.approval_required!==true||plan.approvalRequired!==true
   ||workflow.execution_mode!==plan.executionMode||version.execution_mode!==plan.executionMode
   ||version.step_count!==plan.steps.length||version.native_request_count!==plan.steps.reduce((n,s)=>n+s.nativeRequests.length,0)
   ||version.steps_hash!==this.secrets.fingerprint(plan.steps))throw deny('WORKFLOW_BUSINESS_PLAN_STORAGE_CHANGED');
  const decoded=this.secrets.decrypt(version.payload_secret,planAad(plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision));this.same(decoded,plan);
  const rows=await tx.query<any>('SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order',[...keys,plan.planRevision]);
  if(rows.length!==plan.steps.length)throw deny('WORKFLOW_BUSINESS_STEPS_INCOMPLETE');
  for(const [i,s]of plan.steps.entries()) { const r=rows[i];
   if(r.id!==s.id||r.step_order!==s.order||r.plan_hash!==hash||r.step_key!==s.key||r.kind!==s.kind||r.entity_type!==s.entityType
    ||(r.entity_id??null)!==(s.entityId??null)||(r.parent_id??null)!==(s.parentId??null)||(r.credential_kind??null)!==(s.credentialKind??null)
    ||r.permission_action!==s.permissionAction||(r.mutation_action??null)!==(s.mutationAction??null)||(r.handler??null)!==(s.handler??null)
    ||(r.mutation_payload_hmac??null)!==(s.mutationPayloadHmac??null)||(r.mutation_idempotency_key??null)!==(s.mutationIdempotencyKey??null)
    ||(r.before_fingerprint??null)!==(s.beforeFingerprint??null)||(r.metadata_before_hmac??null)!==(s.metadataBeforeHmac??null)
    ||(r.metadata_revision??null)!==(s.metadataRevision??null)||(r.metadata_payload_hmac??null)!==(s.metadataPayloadHmac??null)
    ||r.execution_mode!==plan.executionMode||r.approval_required!==true)throw deny('WORKFLOW_BUSINESS_STEP_STORAGE_CHANGED');
   this.same(r.dependencies,s.dependencies);this.same(r.native_requests,normalizedNativeRequests(s.nativeRequests,this.secrets));
  }
  return workflow;
 }
 /** The real pending Portal issue graph has exactly three native POSTs and
  * one metadata activation. Developer and console executor stay distinct. */
 async portalMaterial(plan:Readonly<WorkflowPlanV1>,tx:DbService=this.db):Promise<Readonly<WorkflowBusinessPortalMaterial>> {
  if(plan.kind!=='portal-credential-issue'||plan.subject.type!=='portal_application_grants'||plan.requester.type!=='developer')throw deny('WORKFLOW_BUSINESS_PORTAL_KIND_INVALID');
  await this.persistedPlan(plan,tx);
  const keys=[plan.clusterId,plan.workspaceId],grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,plan.subject.id]);
  if(!grant||grant.developer_id!==plan.requester.id||grant.workflow_id!==plan.workflowId||grant.transport_scope!==plan.scope.transportScope
   ||!uuid.test(grant.consumer_id)||!uuid.test(grant.acl_id)||grant.reservation_released_at)throw deny('WORKFLOW_BUSINESS_PORTAL_GRANT_CHANGED');
  const credential=await tx.one<any>('SELECT * FROM portal_credentials WHERE cluster_id=$1 AND workspace_id=$2 AND grant_id=$3 AND generation=1',[...keys,grant.id]);
  const application=await tx.one<any>('SELECT * FROM portal_applications WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,grant.application_id]);
  const developer=await tx.one<any>('SELECT * FROM portal_developers WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,grant.developer_id]);
  const publication=await tx.one<any>('SELECT * FROM portal_publications WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,grant.publication_id]);
  if(!credential||credential.workflow_id!==plan.workflowId||credential.developer_id!==grant.developer_id||credential.consumer_id!==grant.consumer_id
   ||credential.credential_kind!=='key-auth'||credential.generation!==1||credential.previous_credential_id!==null||!uuid.test(credential.kong_id)
   ||!application||application.status!=='active'||application.deleted_at||application.developer_id!==grant.developer_id
   ||!developer||developer.status!=='active'||developer.deleted_at||developer.must_change_password||!publication||publication.state!=='published'
   ||publication.transport_scope!==grant.transport_scope||publication.acl_group!==grant.acl_group||!uuid.test(publication.service_id))throw deny('WORKFLOW_BUSINESS_PORTAL_SUBJECT_REVOKED');
  const proofRow=await tx.one<any>(`SELECT p.* FROM portal_publication_proofs p JOIN workflow_executions e ON e.id=p.workflow_execution_id
   JOIN workflows w ON w.id=p.workflow_id WHERE p.cluster_id=$1 AND p.workspace_id=$2 AND p.publication_id=$3 AND p.publication_revision=$4
   AND e.state='succeeded' AND w.state='succeeded'`,[...keys,publication.id,publication.published_revision]);
  if(!proofRow)throw deny('WORKFLOW_BUSINESS_PORTAL_PUBLICATION_PROOF_REQUIRED');
  const proof=decodePublicationProof(proofRow,this.secrets);
  if(proof.serviceId!==publication.service_id||proof.aclPluginId!==publication.acl_plugin_id||proof.keyAuthPluginId!==publication.key_auth_plugin_id
   ||proof.aclGroup!==grant.acl_group||proof.transportScope!==plan.scope.transportScope||proof.clusterRevision!==plan.scope.clusterRevision
   ||proof.workspaceRevision!==plan.scope.workspaceRevision||proof.executionMode!==plan.executionMode)throw deny('WORKFLOW_BUSINESS_PORTAL_PUBLICATION_CHANGED');
  const key=this.secrets.decrypt<any>(credential.key_secret,portalKeyAad(plan.clusterId,plan.workspaceId,credential.id,1));
  if(typeof key?.key!=='string'||!key.key||this.secrets.fingerprint(key.key)!==credential.key_fingerprint
   ||!plan.generated||plan.generated.key!==key.key||plan.generated.consumerId!==grant.consumer_id||plan.generated.aclId!==grant.acl_id
   ||plan.generated.credentialId!==credential.kong_id||plan.steps.length!==4||plan.prerequisites.length!==1
   ||plan.prerequisites[0].type!=='services'||plan.prerequisites[0].id!==proof.serviceId||plan.prerequisites[0].path!==`/services/${proof.serviceId}`
   ||plan.prerequisites[0].fingerprint!==this.secrets.fingerprint(plan.prerequisites[0].before))throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
  this.same(plan.prerequisites[0].before,proof.service);
  for(const [i,s]of plan.steps.entries()) {
   if(i<3) { const kind=i===1?'acls':i===2?'key-auth':undefined,nativeId=i===0?grant.consumer_id:i===1?grant.acl_id:credential.kong_id,r=s.nativeRequests[0];
    if(s.kind!=='native'||s.entityType!==(i?'credentials':'consumers')||s.mutationAction!=='create'||s.permissionAction!=='write'
     ||s.entityId!=null||s.parentId!==(i?grant.consumer_id:undefined)||s.credentialKind!==kind||s.before!=null
     ||s.beforeFingerprint!==this.secrets.fingerprint(null)||s.nativeRequests.length!==1||!r||r.method!=='POST'||r.nativeId!==nativeId
     ||r.nativeType!==(kind??'consumers')||r.parentId!==s.parentId||r.credentialKind!==kind
     ||r.canonicalPath!==(i?`/consumers/${grant.consumer_id}/${kind}`:'/consumers')||(r.body as any)?.id!==nativeId
     ||s.mutationPayloadHmac!==this.secrets.fingerprint(s.mutationPayload)||r.bodyHmac!==s.mutationPayloadHmac)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
    this.same(s.dependencies,i?[plan.steps[i-1].id]:[]);this.same(r.body,s.mutationPayload);
    if(i===1&&(r.body as any)?.group!==grant.acl_group||i===2&&(r.body as any)?.key!==key.key)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
   } else { const m=s.metadata as any;
    if(s.kind!=='metadata'||s.handler!=='portal.credential.activate'||s.entityType!=='portal_application_grants'||s.entityId!==grant.id
     ||s.permissionAction!=='write'||s.nativeRequests.length||s.metadataRevision!==(s.before as any)?.revision
     ||s.metadataBeforeHmac!==this.secrets.fingerprint(s.before)||s.metadataPayloadHmac!==this.secrets.fingerprint(m)
     ||m?.action!=='issue'||m.retireConsumer!==false||m.oldCredentialId!==null||m.generation!==1||m.credentialId!==credential.id||m.kongId!==credential.kong_id
     ||m.consumerId!==grant.consumer_id||m.aclId!==grant.acl_id||m.keyFingerprint!==credential.key_fingerprint)throw deny('WORKFLOW_BUSINESS_PORTAL_ACTIVATION_MANIFEST_CHANGED');
    this.same(s.dependencies,[plan.steps[2].id]);
   }
  }
  const immutableGrant={id:grant.id,clusterId:grant.cluster_id,workspaceId:grant.workspace_id,transportScope:grant.transport_scope,
   applicationId:grant.application_id,publicationId:grant.publication_id,developerId:grant.developer_id,consumerId:grant.consumer_id,
   aclId:grant.acl_id,aclGroup:grant.acl_group,workflowId:grant.workflow_id,createdAt:iso(grant.created_at)};
  const immutableCredential={id:credential.id,grantId:credential.grant_id,developerId:credential.developer_id,consumerId:credential.consumer_id,
   nativeId:credential.kong_id,generation:credential.generation,keyCiphertext:credential.key_secret,keyFingerprint:credential.key_fingerprint,
   workflowId:credential.workflow_id,createdAt:iso(credential.created_at)};
  const subjectSeal:WorkflowBusinessSubjectSealV1={version:1,driver:'portal-credential-issue',subjectId:grant.id,
   materialHmac:this.secrets.fingerprint({version:1,origin:'workflow-scheduled-portal-issue',grant:immutableGrant,credential:immutableCredential,
    application:{id:application.id,developerId:application.developer_id,createdAt:iso(application.created_at)},
    developer:{id:developer.id,credentialEpoch:String(developer.credential_epoch)},publicationProofHmac:proofRow.publication_proof_hmac}),
   nativeManifestHmac:this.secrets.fingerprint({version:1,workflowId:plan.workflowId,planRevision:plan.planRevision,requester:plan.requester,
    scope:plan.scope,definition:plan.definition,prerequisites:plan.prerequisites,steps:plan.steps,generated:plan.generated}),sourceScopes:[]};
  return immutableJson({kind:'portal-credential-issue',grant,credential,previousCredential:null,application,publication,developer,publicationProof:proof,
   publicationProofRow:proofRow,plan,subjectSeal});
 }
 /** Scheduled rotate/revoke material. Fail-closed on grant state, workflow
  * binding, credential graph and native/metadata manifest shape. No Kong I/O. */
 async portalChangeMaterial(plan:Readonly<WorkflowPlanV1>,tx:DbService=this.db):Promise<Readonly<WorkflowBusinessPortalMaterial>> {
  if(!isPortalCredentialScheduleKind(plan.kind)||plan.kind==='portal-credential-issue'
   ||plan.subject.type!=='portal_application_grants'||plan.requester.type!=='developer')throw deny('WORKFLOW_BUSINESS_PORTAL_KIND_INVALID');
  await this.persistedPlan(plan,tx);
  const keys=[plan.clusterId,plan.workspaceId],grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,plan.subject.id]);
  const expectState=plan.kind==='portal-credential-rotate'?'rotating':'revoking';
  if(!grant||grant.developer_id!==plan.requester.id||grant.workflow_id!==plan.workflowId||grant.state!==expectState
   ||grant.transport_scope!==plan.scope.transportScope||!uuid.test(grant.consumer_id)||!uuid.test(grant.acl_id)
   ||grant.reservation_released_at)throw deny('WORKFLOW_BUSINESS_PORTAL_GRANT_CHANGED');
  const application=await tx.one<any>('SELECT * FROM portal_applications WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,grant.application_id]);
  const developer=await tx.one<any>('SELECT * FROM portal_developers WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,grant.developer_id]);
  const publication=await tx.one<any>('SELECT * FROM portal_publications WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,grant.publication_id]);
  if(!application||application.status!=='active'||application.deleted_at||application.developer_id!==grant.developer_id
   ||!developer||developer.status!=='active'||developer.deleted_at||developer.must_change_password||!publication||publication.state!=='published'
   ||publication.transport_scope!==grant.transport_scope||publication.acl_group!==grant.acl_group||!uuid.test(publication.service_id))throw deny('WORKFLOW_BUSINESS_PORTAL_SUBJECT_REVOKED');
  const proofRow=await tx.one<any>(`SELECT p.* FROM portal_publication_proofs p JOIN workflow_executions e ON e.id=p.workflow_execution_id
   JOIN workflows w ON w.id=p.workflow_id WHERE p.cluster_id=$1 AND p.workspace_id=$2 AND p.publication_id=$3 AND p.publication_revision=$4
   AND e.state='succeeded' AND w.state='succeeded'`,[...keys,publication.id,publication.published_revision]);
  if(!proofRow)throw deny('WORKFLOW_BUSINESS_PORTAL_PUBLICATION_PROOF_REQUIRED');
  const proof=decodePublicationProof(proofRow,this.secrets);
  if(proof.serviceId!==publication.service_id||proof.aclPluginId!==publication.acl_plugin_id||proof.keyAuthPluginId!==publication.key_auth_plugin_id
   ||proof.aclGroup!==grant.acl_group||proof.transportScope!==plan.scope.transportScope||proof.clusterRevision!==plan.scope.clusterRevision
   ||proof.workspaceRevision!==plan.scope.workspaceRevision||proof.executionMode!==plan.executionMode)throw deny('WORKFLOW_BUSINESS_PORTAL_PUBLICATION_CHANGED');
  const metaStep=plan.steps.find(s=>s.kind==='metadata');
  const meta:any=metaStep?.metadata;
  const handler=plan.kind==='portal-credential-rotate'?'portal.credential.rotate':'portal.credential.revoke';
  if(!metaStep||metaStep.handler!==handler||metaStep.entityType!=='portal_application_grants'||metaStep.entityId!==grant.id
   ||meta?.action!==(plan.kind==='portal-credential-rotate'?'rotate':'revoke')||!uuid.test(meta?.credentialId??'')
   ||meta.consumerId!==grant.consumer_id||meta.aclId!==grant.acl_id)throw deny('WORKFLOW_BUSINESS_PORTAL_ACTIVATION_MANIFEST_CHANGED');
  const natives=plan.steps.filter(s=>s.kind==='native');
  if(!natives.length||plan.steps[plan.steps.length-1]!==metaStep)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
  let credential:any,previousCredential:any=null;
  if(plan.kind==='portal-credential-rotate'){
   if(meta.oldCredentialId==null||!uuid.test(meta.oldCredentialId)||meta.generation<2||plan.generated==null
    ||plan.generated.consumerId!==grant.consumer_id||plan.generated.aclId!==grant.acl_id||plan.generated.credentialId!==meta.kongId
    ||typeof plan.generated.key!=='string'||!plan.generated.key)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
   credential=await tx.one<any>('SELECT * FROM portal_credentials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,meta.credentialId]);
   previousCredential=await tx.one<any>('SELECT * FROM portal_credentials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,meta.oldCredentialId]);
   if(!credential||credential.grant_id!==grant.id||credential.workflow_id!==plan.workflowId||credential.state!=='pending'
    ||credential.generation!==meta.generation||credential.previous_credential_id!==meta.oldCredentialId||credential.kong_id!==meta.kongId
    ||credential.key_fingerprint!==meta.keyFingerprint||!previousCredential||previousCredential.grant_id!==grant.id
    ||previousCredential.state!=='active'||previousCredential.id!==grant.current_credential_id
    ||this.secrets.fingerprint(plan.generated.key)!==credential.key_fingerprint)throw deny('WORKFLOW_BUSINESS_PORTAL_SUBJECT_REVOKED');
   const create=natives.find(s=>s.mutationAction==='create'&&s.credentialKind==='key-auth');
   const del=natives.find(s=>s.mutationAction==='delete'&&s.credentialKind==='key-auth');
   if(!create||!del||natives.length!==2||create.nativeRequests[0]?.nativeId!==meta.kongId
    ||del.nativeRequests[0]?.nativeId!==previousCredential.kong_id)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
  }else{
   if(plan.generated!==undefined||meta.oldCredentialId!==null&&meta.oldCredentialId!==meta.credentialId)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
   credential=await tx.one<any>('SELECT * FROM portal_credentials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,meta.credentialId]);
   if(!credential||credential.grant_id!==grant.id||credential.id!==grant.current_credential_id||credential.state!=='active'
    ||credential.kong_id!==meta.kongId||credential.key_fingerprint!==meta.keyFingerprint
    ||credential.generation!==meta.generation)throw deny('WORKFLOW_BUSINESS_PORTAL_SUBJECT_REVOKED');
   previousCredential=credential;
   const delKey=natives.find(s=>s.mutationAction==='delete'&&s.credentialKind==='key-auth');
   if(!delKey||delKey.nativeRequests[0]?.nativeId!==credential.kong_id)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
   if(meta.retireConsumer===true){
    if(natives.length!==3||!natives.some(s=>s.mutationAction==='delete'&&s.credentialKind==='acls')
     ||!natives.some(s=>s.mutationAction==='delete'&&s.entityType==='consumers'))throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
   }else if(natives.length!==1)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
  }
  if(plan.prerequisites.length<1||plan.prerequisites[0].type!=='services'||plan.prerequisites[0].id!==proof.serviceId)throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_MANIFEST_CHANGED');
  const immutableGrant={id:grant.id,clusterId:grant.cluster_id,workspaceId:grant.workspace_id,transportScope:grant.transport_scope,
   applicationId:grant.application_id,publicationId:grant.publication_id,developerId:grant.developer_id,consumerId:grant.consumer_id,
   aclId:grant.acl_id,aclGroup:grant.acl_group,workflowId:grant.workflow_id,createdAt:iso(grant.created_at),state:grant.state};
  const immutableCredential={id:credential.id,grantId:credential.grant_id,developerId:credential.developer_id,consumerId:credential.consumer_id,
   nativeId:credential.kong_id,generation:credential.generation,keyCiphertext:credential.key_secret,keyFingerprint:credential.key_fingerprint,
   workflowId:credential.workflow_id,createdAt:iso(credential.created_at),state:credential.state};
  const origin=plan.kind==='portal-credential-rotate'?'workflow-scheduled-portal-rotate':'workflow-scheduled-portal-revoke';
  const subjectSeal:WorkflowBusinessSubjectSealV1={version:1,driver:plan.kind,subjectId:grant.id,
   materialHmac:this.secrets.fingerprint({version:1,origin,grant:immutableGrant,credential:immutableCredential,
    previousCredentialId:previousCredential&&plan.kind==='portal-credential-rotate'?previousCredential.id:null,
    application:{id:application.id,developerId:application.developer_id,createdAt:iso(application.created_at)},
    developer:{id:developer.id,credentialEpoch:String(developer.credential_epoch)},publicationProofHmac:proofRow.publication_proof_hmac}),
   nativeManifestHmac:this.secrets.fingerprint({version:1,workflowId:plan.workflowId,planRevision:plan.planRevision,requester:plan.requester,
    scope:plan.scope,definition:plan.definition,prerequisites:plan.prerequisites,steps:plan.steps,generated:plan.generated??null}),sourceScopes:[]};
  return immutableJson({kind:plan.kind,grant,credential,previousCredential:plan.kind==='portal-credential-rotate'?previousCredential:null,
   application,publication,developer,publicationProof:proof,publicationProofRow:proofRow,plan,subjectSeal});
 }
 /** Promotion parents retain the import J0/P0. apply freezes the identical
  * manifest under a new J1/P1; UUID equality would reject every genuine fork.
  * Both immutable SQL origins and the authenticated original apply request
  * must instead close that exact two-job/two-plan graph. */
 private async promotionConfigurationLineage(m:Readonly<WorkflowScheduledConfigurationMaterial>,row:any,tx:DbService):Promise<WorkflowBusinessPromotionMaterial['configurationLineage']>{
  const bad=()=>{throw deny('WORKFLOW_BUSINESS_PROMOTION_STORAGE_CHANGED');};
  const {marker,jobOrigin,planOrigin}=m.sourceOrigin!,j=m.job,v=m.version,p=m.planRow,keys=[j.cluster_id,j.workspace_id];
  if(!uuid.test(row.configuration_job_id??'')||!uuid.test(row.plan_id??'')||!int(row.plan_revision)||!hex.test(row.plan_hash??'')
   ||j.kind!=='apply'||j.id===row.configuration_job_id||j.plan_id===row.plan_id||v.source_job_id!==j.id||p.source_job_id!==j.id
   ||p.created_by!==j.actor_id||p.cluster_id!==j.cluster_id||p.workspace_id!==j.workspace_id
   ||v.plan_id!==j.plan_id||v.plan_revision!==j.plan_revision||v.plan_hash!==j.plan_hash||row.plan_hash!==j.plan_hash
   ||!m.plan.originRef||m.plan.originRef.kind!==marker.kind||m.plan.originRef.originId!==marker.id||m.plan.originRef.materialHmac!==marker.hmac)bad();
  const original=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[row.configuration_job_id]);
  const originalPlan=await tx.one<any>('SELECT * FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,row.plan_id]);
  const originalVersion=await tx.one<any>('SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4',[...keys,row.plan_id,row.plan_revision]);
  const originalJobOrigin=await tx.one<any>('SELECT * FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3',[...keys,row.configuration_job_id]);
  const originalPlanOrigin=await tx.one<any>('SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5',[...keys,row.plan_id,row.plan_revision,row.plan_hash]);
  const binding=(job:any,jobBinding:any,planBinding:any)=>!!jobBinding&&!!planBinding
   &&jobBinding.cluster_id===j.cluster_id&&jobBinding.workspace_id===j.workspace_id&&jobBinding.job_id===job.id
   &&jobBinding.origin_kind===marker.kind&&jobBinding.origin_id===row.id&&jobBinding.material_hmac===marker.hmac
   &&jobBinding.source_cluster_id===row.cluster_id&&jobBinding.source_workspace_id===row.workspace_id&&jobBinding.comparison_id===row.comparison_id
   &&planBinding.cluster_id===j.cluster_id&&planBinding.workspace_id===j.workspace_id&&planBinding.job_id===job.id
   &&planBinding.plan_id===job.plan_id&&planBinding.plan_revision===job.plan_revision&&planBinding.plan_hash===job.plan_hash
   &&planBinding.origin_kind===marker.kind&&planBinding.origin_id===row.id&&planBinding.material_hmac===marker.hmac;
  if(!original||original.id!==row.configuration_job_id||original.kind!=='import'||original.state!=='succeeded'
   ||original.idempotency_key!==`governance-promote-${row.id}`||original.origin_type!=='http'||!uuid.test(original.origin_session_id??'')
   ||original.cluster_id!==j.cluster_id||original.workspace_id!==j.workspace_id||original.actor_id!==j.actor_id||original.transport_scope!==j.transport_scope
   ||original.scope_kind!==m.plan.scope.kind||this.secrets.fingerprint(original.root_ids)!==this.secrets.fingerprint(m.plan.scope.rootIds)
   ||original.plan_id!==row.plan_id||original.plan_revision!==row.plan_revision||original.plan_hash!==row.plan_hash
   ||original.required_origin_kind!==marker.kind||original.required_origin_id!==row.id||original.required_origin_hmac!==marker.hmac
   ||!originalPlan||originalPlan.id!==row.plan_id||originalPlan.cluster_id!==j.cluster_id||originalPlan.workspace_id!==j.workspace_id
   ||originalPlan.created_by!==original.actor_id||originalPlan.source_job_id!==original.id||originalPlan.current_revision!==row.plan_revision||originalPlan.transport_scope!==j.transport_scope
   ||!originalVersion||originalVersion.cluster_id!==j.cluster_id||originalVersion.workspace_id!==j.workspace_id||originalVersion.plan_id!==row.plan_id
   ||originalVersion.plan_revision!==row.plan_revision||originalVersion.source_job_id!==original.id||originalVersion.plan_hash!==row.plan_hash||originalVersion.input_hmac!==row.plan_hash
   ||!binding(j,jobOrigin,planOrigin)||!binding(original,originalJobOrigin,originalPlanOrigin))bad();
  for(const field of ['steps_hmac','schema_hmac','source_manifest_hmac','baseline_manifest_hmac','step_count','native_packet_count','recovery_complete'])
   if(originalVersion[field]!==v[field])bad();
  const deadlines=[original.authority_expires_at,original.expires_at,originalVersion.expires_at,m.plan.expiresAt].map(time);
  if(deadlines.some(value=>!Number.isFinite(value)||value<=Date.now())||time(originalVersion.expires_at)!==time(v.expires_at)
   ||time(originalVersion.expires_at)!==time(m.plan.expiresAt))bad();
  const originalMaterial=await tx.one<any>('SELECT * FROM configuration_materials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,originalVersion.material_id]);
  if(!originalMaterial||originalMaterial.state!=='available'||originalMaterial.job_id!==original.id||originalMaterial.artifact_kind!=='plan'
   ||originalMaterial.artifact_id!==originalVersion.artifact_id||!originalMaterial.wrapped_key_secret)bad();
  const identity={clusterId:j.cluster_id,workspaceId:j.workspace_id,jobId:original.id,materialId:originalMaterial.id,artifactId:originalVersion.artifact_id,artifactKind:'plan' as const};
  await this.crypto.withKey(identity,originalMaterial.wrapped_key_secret,async key=>{
   const manifest=this.crypto.decrypt<ConfigPlan>(key,identity,{section:'manifest',key:'plan'},originalVersion.manifest_ciphertext);
   if(this.secrets.fingerprint(manifest)!==row.plan_hash||this.secrets.fingerprint(manifest)!==this.secrets.fingerprint(m.plan))bad();
  });
  if(!j.input_secret)bad();
  const input=this.secrets.decrypt<any>(j.input_secret,`configuration-job:${j.id}`);
  if(!input||Object.keys(input).sort().join(',')!=='confirm_deletes,confirmed,driver,planHash,planId,planRevision'
   ||input.planId!==row.plan_id||input.planRevision!==row.plan_revision||input.planHash!==row.plan_hash||input.driver!=='bff'
   ||input.confirmed!==true||typeof input.confirm_deletes!=='boolean'||m.plan.steps.some(step=>step.mutationAction==='delete')&&!input.confirm_deletes
   ||this.secrets.fingerprint({scope:m.plan.scope,kind:j.kind,input,originRef:m.plan.originRef})!==j.request_hmac)bad();
  return Object.freeze({importJobId:original.id,importPlanId:row.plan_id,authorityExpiresAt:iso(original.authority_expires_at),
   expiresAt:iso(original.expires_at),planExpiresAt:iso(originalVersion.expires_at)});
 }
 async promotionMaterial(material:Readonly<WorkflowScheduledConfigurationMaterial>,tx:DbService=this.db):Promise<Readonly<WorkflowBusinessPromotionMaterial>|null> {
  if(!material.sourceOrigin)return null;
  const {marker,jobOrigin}=material.sourceOrigin;
  const row=await tx.one<any>('SELECT * FROM governance_promotions WHERE id=$1',[marker.id]);
  const comparison=row&&await tx.one<any>('SELECT * FROM governance_comparisons WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[row.comparison_id,row.cluster_id,row.workspace_id]);
  if(!row||!comparison||comparison.quality!=='complete'||comparison.target_cluster_id!==row.target_cluster_id||comparison.target_workspace_id!==row.target_workspace_id||row.state!=='ready'||row.actor_id!==material.job.actor_id||row.cluster_id!==jobOrigin.source_cluster_id||row.workspace_id!==jobOrigin.source_workspace_id
   ||row.comparison_id!==jobOrigin.comparison_id||row.target_cluster_id!==material.job.cluster_id||row.target_workspace_id!==material.job.workspace_id
   ||row.source_inventory_hmac!==comparison.source_inventory_hmac||row.target_inventory_hmac!==comparison.target_inventory_hmac
   ||this.secrets.fingerprint(comparison.policy)!==comparison.policy_hmac)throw deny('WORKFLOW_BUSINESS_PROMOTION_STORAGE_CHANGED');
  const configurationLineage=await this.promotionConfigurationLineage(material,row,tx);
  const decoded=decryptComparisonMaterial(comparison,this.secrets),source=decoded.source.inventory,target=decoded.target.inventory;
  const selection=this.secrets.decrypt<Record<string,any>>(row.selection_secret,`governance:promotion-selection:${row.id}`);
  if(!decoded.source.nativeFingerprints||!decoded.target.nativeFingerprints||source.completeness!=='complete'||target.completeness!=='complete'
   ||source.projection||target.projection||!/^1\.5\.\d+$/.test(source.version)||source.version!==target.version
   ||source.scope.clusterId!==row.cluster_id||source.scope.workspaceId!==row.workspace_id||target.scope.clusterId!==row.target_cluster_id
   ||target.scope.workspaceId!==row.target_workspace_id||source.scope.transportScope===target.scope.transportScope
   ||this.secrets.fingerprint(selection)!==row.selection_hmac)throw deny('WORKFLOW_BUSINESS_PROMOTION_MATERIAL_CHANGED');
  const recovery=await tx.one<any>('SELECT * FROM promotion_recovery_bindings WHERE promotion_id=$1',[row.id]);
  if((selection.includeSecrets||selection.includeCredentials)&&(!recovery||recovery.source_cluster_id!==source.scope.clusterId
   ||recovery.source_workspace_id!==source.scope.workspaceId||!hex.test(recovery.manifest_hmac??'')||!hex.test(recovery.recovery_hmac??'')))throw deny('WORKFLOW_BUSINESS_PROMOTION_RECOVERY_REQUIRED');
  const sourceManifest={scope:source.scope,version:source.version,adapterVersion:(source as any).adapterVersion??'kong-1.5',schemas:source.schemas,
   pluginSchemas:source.pluginSchemas,enabledPlugins:[...source.enabledPlugins].sort(),nativeFingerprints:governanceComparisonEnvelope(source,decoded.source.nativeFingerprints).nativeFingerprints,
   completeness:source.completeness,projection:source.projection,consistency:source.consistency??'console_fenced_best_effort',
   objects:source.objects.map(o=>({entityType:o.entityType,nativeId:o.nativeId,parentId:o.parentId??null,credentialKind:(o as any).credentialKind??null,
    objectWorkspaceId:o.objectWorkspaceId??null,payload:o.payload,sensitiveFields:[...(o.sensitiveFields??[])].sort(),referenceOnly:o.referenceOnly===true,
    managedBoundary:o.managedBoundary??'none',certificate:o.certificate??null})).sort((a,b)=>`${a.entityType}:${a.nativeId}`.localeCompare(`${b.entityType}:${b.nativeId}`))};
  const originMaterial={version:1,kind:'governance-promote',originId:row.id,comparisonId:comparison.id,actorId:row.actor_id,sourceScope:source.scope,targetScope:target.scope,
   requestHmac:row.request_hmac,selectionHmac:row.selection_hmac,sourceInventoryHmac:row.source_inventory_hmac,targetInventoryHmac:row.target_inventory_hmac,
   sourceManifest,policyHmac:comparison.policy_hmac,recovery:recovery?{sourceJobId:recovery.source_job_id,snapshotId:recovery.snapshot_id,version:recovery.snapshot_version,
    manifestHmac:recovery.manifest_hmac,recoveryHmac:recovery.recovery_hmac}:null};
  if(this.secrets.fingerprint(originMaterial)!==marker.hmac)throw deny('WORKFLOW_BUSINESS_PROMOTION_ORIGIN_HMAC_CHANGED');
  return immutableJson({row,comparison,source,target,sourceNativeFingerprints:decoded.source.nativeFingerprints,
   targetNativeFingerprints:decoded.target.nativeFingerprints,selection,recovery,configurationLineage});
 }
 /** Fixed bootstrap-only SQL observer. Ordinary configuration does not enter
  * this path. Native source/target response checks remain in their original
  * reader; these facts only close its authenticated material/registry window. */
 async promoteClosedSqlMaterial(plan:Readonly<WorkflowScheduledPlanV1>,draft:Readonly<WorkflowScheduleDraft>,tx:DbService):Promise<Readonly<WorkflowScheduledConfigurationPromoteSqlMaterial>> {
  const m=await this.materialForPlan(plan,tx);
  if(m.kind!=='configuration_v2'||!m.promotion||!m.sourceOrigin||m.job.kind!=='apply'
   ||m.subjectSeal.driver!=='governance-promote'||m.subjectSeal.sourceScopes.length!==1)throw deny('WORKFLOW_BUSINESS_PROMOTION_SQL_MATERIAL_REQUIRED');
  this.same(m.subjectSeal,draft.binding.subjectSeal);
  const {marker}=m.sourceOrigin,promotion=m.promotion,source=m.subjectSeal.sourceScopes[0];
  if(marker.kind!=='governance-promote'||marker.id!==promotion.row.id||marker.hmac!==m.job.required_origin_hmac
   ||source.clusterId!==promotion.source.scope.clusterId||source.workspaceId!==promotion.source.scope.workspaceId||source.materialHmac!==marker.hmac
   ||promotion.target.scope.clusterId!==plan.clusterId||promotion.target.scope.workspaceId!==plan.workspaceId
   ||promotion.source.scope.transportScope===promotion.target.scope.transportScope)throw deny('WORKFLOW_BUSINESS_PROMOTION_SQL_MATERIAL_REQUIRED');
  const registries:WorkflowScheduledConfigurationPromoteSqlMaterial['registries'][number][]=[];
  for(const inventory of [promotion.source,promotion.target]) {
   const scope=inventory.scope,c=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL',[scope.clusterId]);
   const w=await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',[scope.clusterId,scope.workspaceId]);
   if(!c||!w||c.id!==scope.clusterId||w.id!==scope.workspaceId||w.cluster_id!==scope.clusterId||w.deleted_at
    ||w.status!=='active'||['disabled','incompatible'].includes(c.status)||!/^1\.5\.\d+$/.test(c.version??'')||c.version!==inventory.version
    ||transportScopeFor(c.admin_url,c.transport_scope)!==scope.transportScope
    ||inventory===promotion.target&&(c.revision!==plan.scope.clusterRevision||w.revision!==plan.scope.workspaceRevision
      ||c.execution_mode!==plan.executionMode||w.code!==promotion.selection.targetWorkspaceCode))throw deny('WORKFLOW_BUSINESS_PROMOTION_REGISTRY_CHANGED');
   // Same projection as canonical target closure. Probe health/timestamps and
   // lease progress are not immutable connection or workspace identity.
   registries.push({cluster:{id:c.id,version:c.version,revision:c.revision,executionMode:c.execution_mode,deletedAt:c.deleted_at,
    adminUrl:c.admin_url,transportScope:c.transport_scope,connectionSecret:c.connection_secret},
    workspace:{id:w.id,clusterId:w.cluster_id,revision:w.revision,status:w.status,deletedAt:w.deleted_at,code:w.code}});
  }
  const lineage=promotion.configurationLineage,deadlines={importAuthority:lineage.authorityExpiresAt,importJob:lineage.expiresAt,importPlan:lineage.planExpiresAt,
   applyAuthority:iso(m.job.authority_expires_at),applyJob:iso(m.job.expires_at),applyVersion:iso(m.version.expires_at),configurationPlan:iso(m.plan.expiresAt),
   wrapperPlan:iso(plan.expiresAt),delegation:iso(draft.delegation.expiresAt),windowEnd:iso(draft.spec.windowEnd)};
  const clock=await tx.one<any>('SELECT clock_timestamp() AS observed_at');
  if(!clock||!Number.isFinite(time(clock.observed_at))||Object.values(deadlines).some(value=>!Number.isFinite(time(value))||time(value)<=time(clock.observed_at))
   ||[lineage.authorityExpiresAt,lineage.expiresAt,lineage.planExpiresAt,m.job.authority_expires_at,m.job.expires_at,m.version.expires_at,m.plan.expiresAt]
     .some(value=>time(draft.spec.windowEnd)>time(value))||time(m.plan.expiresAt)>time(m.job.authority_expires_at))throw deny('WORKFLOW_BUSINESS_OLD_DEADLINE_NOT_RENEWABLE');
  return immutableJson({version:1 as const,jobId:m.job.id,marker,subjectSeal:m.subjectSeal,sourceOrigin:m.sourceOrigin,
   configurationLineage:lineage,registries,deadlines,observedAt:iso(clock.observed_at)});
 }
 private async annotationMaterial(plan:Readonly<WorkflowPlanV1>,tx:DbService):Promise<Readonly<WorkflowBusinessAnnotationMaterial>> {
  await this.persistedPlan(plan,tx);
  const step=assertEntityAnnotationPlan(plan as WorkflowPlanV1),payload=step.metadata as {intentId:string;materialHmac:string};
  const request=await tx.one<any>('SELECT * FROM entity_annotation_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
  const intent=await tx.one<any>('SELECT * FROM annotation_change_intents WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
  if(!request||!intent||request.workflow_id!==plan.workflowId||intent.workflow_id!==plan.workflowId||request.actor_id!==plan.requester.id
   ||intent.actor_id!==plan.requester.id||request.material_hmac!==payload.materialHmac||intent.material_hmac!==payload.materialHmac
   ||payload.intentId!==plan.subject.id||request.id!==plan.subject.id)throw deny('WORKFLOW_BUSINESS_ANNOTATION_WRAPPER_CHANGED');
  const subjectSeal:WorkflowBusinessSubjectSealV1={version:1,driver:'entity-annotation',subjectId:request.id,
   materialHmac:request.material_hmac,
   nativeManifestHmac:this.secrets.fingerprint({version:1,origin:'workflow-scheduled-entity-annotation',workflowId:request.workflow_id}),
   sourceScopes:[]};
  return immutableJson({kind:'entity-annotation',request,intent,plan,subjectSeal});
 }
 private async metadataMaterial(plan:Readonly<WorkflowPlanV1>,tx:DbService):Promise<Readonly<WorkflowBusinessMetadataMaterial>> {
  if(!isMetadataScheduledKind(plan.kind)||plan.kind==='entity-annotation')throw deny('WORKFLOW_BUSINESS_KIND_INVALID');
  await this.persistedPlan(plan,tx);
  const kind=plan.kind as Exclude<MetadataScheduledKind,'entity-annotation'>;
  const src=metadataSubjectSealSource(plan.subject.type);
  let materialHmac:string; let request:Record<string,any>|null=null; let entity:Record<string,any>|null=null;
  if(src.style==='request'){
    request=await tx.one<any>(`SELECT * FROM ${src.table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[plan.subject.id,plan.clusterId,plan.workspaceId]);
    if(!request||request.workflow_id!==plan.workflowId||request.actor_id!==plan.requester.id)throw deny('WORKFLOW_BUSINESS_METADATA_WRAPPER_CHANGED');
    materialHmac=String(request[src.materialColumn]);
  }else{
    entity=await tx.one<any>(`SELECT * FROM ${src.table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[plan.subject.id,plan.clusterId,plan.workspaceId]);
    if(!entity)throw deny('WORKFLOW_BUSINESS_METADATA_WRAPPER_CHANGED');
    materialHmac=this.secrets.fingerprint({id:entity.id,revision:entity.revision,clusterId:entity.cluster_id,workspaceId:entity.workspace_id});
  }
  const subjectSeal:WorkflowBusinessSubjectSealV1={version:1,driver:kind as any,subjectId:plan.subject.id,materialHmac,
   nativeManifestHmac:this.secrets.fingerprint({version:1,origin:`workflow-scheduled-${kind}`,workflowId:plan.workflowId}),sourceScopes:[]};
  return immutableJson({kind,subjectType:plan.subject.type,request,entity,plan,subjectSeal});
 }
 async materialForPlan(plan:Readonly<WorkflowPlanV1>,tx:DbService=this.db):Promise<Readonly<WorkflowBusinessMaterial>> {
  if(plan.kind==='portal-credential-issue')return this.portalMaterial(plan,tx);
  if(plan.kind==='portal-credential-rotate'||plan.kind==='portal-credential-revoke')return this.portalChangeMaterial(plan,tx);
  if((plan.kind as string)==='entity-annotation')return this.annotationMaterial(plan,tx);
  if(isMetadataScheduledKind(plan.kind))return this.metadataMaterial(plan,tx);
  if(plan.kind!=='configuration_v2')throw deny('WORKFLOW_BUSINESS_KIND_INVALID');
  // Within one verification read (withReadMemo scope) the identical SQL rows
  // yield the identical verified material; outside a scope this recomputes.
  if(tx instanceof DbService)return tx.memoizedRead(`workflow-business-material:configuration_v2:${this.secrets.fingerprint(plan)}`,()=>this.configurationPlanMaterial(plan,tx));
  return this.configurationPlanMaterial(plan,tx);
 }
 private async configurationPlanMaterial(plan:Readonly<WorkflowPlanV1>,tx:DbService):Promise<Readonly<WorkflowBusinessMaterial>> {
  await this.persistedPlan(plan,tx);
  const step=assertConfigurationWorkflowPlan(plan as WorkflowPlanV1),payload=step.metadata as ConfigurationWorkflowPayload;
  const m=await this.configurationMaterial(payload.jobId,tx);
  if(m.job.workflow_id!==plan.workflowId||m.job.actor_id!==plan.requester.id||payload.planId!==m.job.plan_id
   ||payload.planRevision!==m.job.plan_revision||payload.planHash!==m.job.plan_hash||m.job.execution_mode!==plan.executionMode
   ||m.job.cluster_revision!==plan.scope.clusterRevision||m.job.workspace_revision!==plan.scope.workspaceRevision
   ||m.job.transport_scope!==plan.scope.transportScope)throw deny('WORKFLOW_BUSINESS_CONFIGURATION_WRAPPER_CHANGED');
  return immutableJson({...m,kind:'configuration_v2',promotion:await this.promotionMaterial(m,tx)});
 }
 async subjectSealForPlan(plan:Readonly<WorkflowPlanV1>,tx:DbService=this.db):Promise<Readonly<WorkflowBusinessSubjectSealV1>> {
  return (await this.materialForPlan(plan,tx)).subjectSeal;
 }
 /** Root reconstructs this SQL-only input from a verified original read
  * handle's plan/schedule/actor/role. The returned DTO is neither a handle nor
  * authority; only the original Context/GET provider may observe responses. */
 async currentReadInput(plan:Readonly<WorkflowScheduledPlanV1>,draft:Readonly<WorkflowScheduleDraft>,actorId:string,
  role:'executor'|'reviewer',transaction:DbService=this.db):Promise<Readonly<ReadInput>> {
  if(!uuid.test(actorId)||!['executor','reviewer'].includes(role))throw deny('WORKFLOW_BUSINESS_READ_PRINCIPAL_CHANGED');
  const row=await transaction.one<any>('SELECT * FROM users WHERE id=$1',[actorId]),epoch=await transaction.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!row||!epoch||row.status!=='active'||row.deleted_at||row.force_password_change)throw deny('WORKFLOW_BUSINESS_READ_PRINCIPAL_CHANGED');
  const grants=sortByFreshFingerprint((await transaction.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[actorId])).filter(validGrant),
   row=>this.secrets.fingerprint(row));
  const principal=immutableJson({user:{id:row.id,username:row.username,superAdmin:row.super_admin===true,forcePasswordChange:false,
   displayName:row.display_name,locale:row.locale,timezone:row.timezone,revision:row.revision},credentialEpoch:String(row.credential_epoch),
   permissionVersion:`${row.id}:${row.permissions_epoch}:${epoch.version}`,grants});
  const input:ReadInput=Object.freeze({plan:immutableJson(plan),draft:immutableJson(draft),role,principal,transaction});
  await this.assertCurrent(input);return input;
 }
 /** The same complete fixed callbacks serve preclaim candidate reads and live
  * namespace validation reads. Missing registration in either remains closed. */
 businessReadPolicy(kind:WorkflowScheduledBusinessKind,observeAbsence=false):Readonly<ReadPolicy> {
  if(!['configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(kind))throw deny('WORKFLOW_BUSINESS_KIND_INVALID');
  const exact=(input:ReadInput)=>{if(input.plan.kind!==kind)throw deny('WORKFLOW_BUSINESS_KIND_INVALID');};
  return Object.freeze({resolveReadScope:async(input:ReadInput)=>{exact(input);return observeAbsence?this.resolveAbsenceReadScope(input):this.resolveReadScope(input);},
   assertCurrent:async(input:ReadInput)=>{exact(input);await this.assertCurrent(input);},
   authorizeResponse:async(input:ReadInput&{resource:Readonly<Resource>;response:unknown;status:number})=>{exact(input);await this.authorizeResponse(input);}});
 }
 /** Optional point reads belong only to sealed creates/Target allocations or
  * exact Service.host relations. They supplement the
  * same real collection/parent observations and never replace complete EOF.
  * Root must opt its fixed policy into this SDK-observer capability. */
 async resolveAbsenceReadScope(input:ReadInput):Promise<Readonly<ReadScope>> {
  const base=await this.resolveReadScope(input),m=await this.materialForPlan(input.plan,input.transaction),cid=input.plan.clusterId;
  const resources=[...base.resources],proposed=this.proposed(m);
  const additions:Resource[]=[];
  for(const p of this.scopedInput(input)?[]:this.allocations(proposed)){
   const path=p.type==='targets'?`/upstreams/${p.parentId}/targets/${p.id}`:credentials.has(p.type)?`/consumers/${p.parentId}/${p.type}/${p.id}`:`/${p.type}/${p.id}`;
   assertKongPath('GET',path);
   if(resources.some(r=>r.clusterId===cid&&r.workspaceId===p.workspaceId&&r.path===path))continue;
   additions.push({clusterId:cid,workspaceId:p.workspaceId,path,kind:'point',entityType:entityForPath(path)??p.type,entityId:p.id,
    ...(p.parentId?{parentId:p.parentId}:{}),secrets:credentials.has(p.type)||['plugins','certificates'].includes(p.type),allowAbsent:true,required:false});
  }
  for(const resource of this.serviceHostResources(m,cid)){
   const existing=[...resources,...additions].find(r=>this.resourceKey(r)===this.resourceKey(resource));
   if(existing)this.same(existing,resource);else additions.push(resource);
  }
  const current=this.responses.getStore();
  if(current){const state=this.state(input);
   for(const parent of state.serviceHostParents.values()){
    const resource=this.serviceTargetResource(parent.resource,parent.entity),existing=[...resources,...additions].find(r=>this.resourceKey(r)===this.resourceKey(resource));
    if(existing){if(existing.kind!=='collection'||existing.entityType!=='targets'||existing.parentId!==resource.parentId||existing.query?.tags!==undefined||existing.query?.size!==100)
      throw deny('WORKFLOW_BUSINESS_SERVICE_TARGET_RESOURCE_CONFLICT');}
    else additions.push(resource);
   }
  }
  additions.sort((a,b)=>a.path.split('/').length-b.path.split('/').length||a.path.localeCompare(b.path));
  if(resources.length+additions.length>500)throw deny('WORKFLOW_BUSINESS_READ_RESOURCE_BUDGET');
  return immutableJson({...base,resources:[...resources,...additions]});
 }
 /** Only authenticated configuration steps select a name. Repeated Service
  * hosts share one canonical resource instead of requesting unrelated rows. */
 private serviceHostResources(m:Readonly<WorkflowBusinessMaterial>,cid:string):Resource[]{
  if(m.kind!=='configuration_v2')return[];
  const refs=new Map<string,{workspaceId:string;host:string;ids:Set<string>}>();
  for(const step of m.plan.steps){
   if(step.entityType!=='services'||step.mutationAction==='delete')continue;
   const effective={...(step.before as any??{}),...(step.body as any??{})},host=effective.host,id=step.nativeId??step.allocatedNativeId;
   if(typeof host!=='string'||!host.length)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_INVALID');
   if(isIP(host)||host.startsWith('[')&&host.endsWith(']')&&isIP(host.slice(1,-1)))continue;
   if(!id||!uuid.test(id))throw deny('WORKFLOW_BUSINESS_NATIVE_ID_INVALID');
   const key=`${step.objectWorkspaceId}:${host}`,entry=refs.get(key)??{workspaceId:step.objectWorkspaceId,host,ids:new Set<string>()};
   entry.ids.add(id);refs.set(key,entry);
  }
  return[...refs.values()].map(ref=>{
   const serviceHostReference={host:ref.host,serviceIds:[...ref.ids].sort()};
   if(!validServiceHostReference(serviceHostReference))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_LOOKUP_AMBIGUOUS');
   return{clusterId:cid,workspaceId:ref.workspaceId,path:`/upstreams/${encodeURIComponent(ref.host)}`,kind:'point' as const,entityType:'upstreams',
    serviceHostReference,secrets:false,allowAbsent:true,required:false};
  }).sort((a,b)=>a.workspaceId.localeCompare(b.workspaceId)||a.path.localeCompare(b.path));
 }
 private serviceTargetResource(parent:Readonly<Resource>,raw:any):Resource{
  if(!isServiceHostReferencePoint(parent)||!raw||!uuid.test(raw.id??'')||raw.name!==parent.serviceHostReference!.host)
   throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_INVALID');
  return immutableJson({clusterId:parent.clusterId,workspaceId:parent.workspaceId,path:`/upstreams/${raw.id}/targets`,kind:'collection',entityType:'targets',
   parentId:raw.id,serviceHostReference:parent.serviceHostReference,secrets:false,required:false,query:{size:100}});
 }
 /** A fixed Runtime may request the child descriptor only after this exact
  * principal's live response scope accepted the original current parent row.
  * Caller-provided IDs, historical snapshots and copied parent DTOs confer no
  * child scope. The SDK provider separately authenticates transport truth. */
 async resolveServiceHostTargetResource(input:ReadInput,parentResource:Readonly<Resource>,parentRaw:unknown):Promise<Readonly<Resource>>{
  const state=this.state(input);try{
   await this.assertCurrent(input);
   const material=await this.materialForPlan(input.plan,input.transaction),expected=this.serviceHostResources(material,input.plan.clusterId)
    .find(r=>this.resourceKey(r)===this.resourceKey(parentResource));
   if(!expected)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_REQUIRED');this.same(expected,parentResource);
   const observed=state.serviceHostParents.get(this.resourceKey(expected));
   if(!observed||!state.completed.has(this.resourceKey(expected))||state.absent.has(this.resourceKey(expected)))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_REQUIRED');
   this.same(observed.resource,expected);this.same(observed.entity,parentRaw);
   const wid=await this.workspaceFor(input,expected.clusterId,'upstreams',observed.entity);
   if(wid!==expected.workspaceId||observed.workspaceId!==wid||!this.permits(input,expected.clusterId,wid,'upstreams','read',observed.entity))
    throw deny('WORKFLOW_BUSINESS_RESPONSE_READ_DENIED');
   await this.assertCurrent(input);this.state(input);
   const candidate=this.serviceTargetResource(expected,observed.entity),scope=await this.resolveAbsenceReadScope(input),actual=scope.resources.find(r=>this.resourceKey(r)===this.resourceKey(candidate));
   if(!actual||actual.kind!=='collection'||actual.entityType!=='targets'||actual.parentId!==candidate.parentId||actual.query?.tags!==undefined||actual.query?.size!==100)
    throw deny('WORKFLOW_BUSINESS_SERVICE_TARGET_RESOURCE_CONFLICT');
   return immutableJson(actual);
  }catch(error){state.failed=true;throw error;}
 }
 /** Closes only the fixed destination relation profile. The original SDK
  * provider authenticates each observation before invoking this policy in a
  * separate current-principal scope. This does not replace the complete plan
  * or Native checkpoints, acknowledge a write, or grant a second SDK send. */
 async assertServiceHostReadComplete(input:ReadInput,parentResource:Readonly<Resource>,parentRaw:unknown,includeTargets:boolean):Promise<void>{
  const state=this.state(input);try{
   if(typeof includeTargets!=='boolean')throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_REQUIRED');
   await this.assertCurrent(input);
   const material=await this.materialForPlan(input.plan,input.transaction),expected=this.serviceHostResources(material,input.plan.clusterId)
    .find(r=>this.resourceKey(r)===this.resourceKey(parentResource));
   if(!expected)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_REQUIRED');this.same(expected,parentResource);
   if(!state.completed.has(this.resourceKey(expected)))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_READ_INCOMPLETE');
   if(parentRaw===null){
    if(!state.absent.has(this.resourceKey(expected))||state.serviceHostParents.has(this.resourceKey(expected)))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_REQUIRED');
   }else{
    const parent=state.serviceHostParents.get(this.resourceKey(expected));
    if(!parent||state.absent.has(this.resourceKey(expected)))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_PARENT_REQUIRED');
    this.same(parent.entity,parentRaw);
    const wid=await this.workspaceFor(input,expected.clusterId,'upstreams',parent.entity);
    if(wid!==expected.workspaceId||!this.permits(input,expected.clusterId,wid,'upstreams','read',parent.entity))throw deny('WORKFLOW_BUSINESS_RESPONSE_READ_DENIED');
    if(includeTargets){
     const target=await this.resolveServiceHostTargetResource(input,expected,parent.entity);
     if(!state.completed.has(this.resourceKey(target)))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_TARGET_EOF_REQUIRED');
     for(const witness of state.witnesses.values())if(this.resourceKey(witness.resource)===this.resourceKey(target)){
      const currentWid=await this.workspaceFor(input,target.clusterId,'targets',witness.entity);
      if(currentWid!==target.workspaceId||witness.workspaceId!==currentWid||!this.permits(input,target.clusterId,currentWid,'targets','read',witness.entity))
       throw deny('WORKFLOW_BUSINESS_RESPONSE_READ_DENIED');
     }
    }
   }
   await this.assertCurrent(input);this.state(input);
  }catch(error){state.failed=true;throw error;}
 }
 /** Fixed participant policy only: no caller callback, GET, SDK certificate,
  * Namespace or Native authority is created here. Runtime must first bind all
  * raw observations to its original private SDK round. Each participant gets
  * a new short-lived Material state, including when called inside the fixed
  * executor's live-read scope; the outer state is restored without mutation. */
 async assertServiceHostParticipant(input:ReadInput,parentResource:Readonly<Resource>,originalRaw:unknown,status:200|404,
  pages:readonly unknown[],includeTargets:boolean,serviceObservation?:Readonly<{serviceId:string;before:unknown}>):Promise<void>{
  const outer=this.responses.getStore();
  if(outer&&(!outer.active||outer.failed||outer.expiresAt<=Date.now()))throw deny('WORKFLOW_BUSINESS_ORIGINAL_READ_SCOPE_REQUIRED');
  if(![200,404].includes(status)||typeof includeTargets!=='boolean'||!Array.isArray(pages)||pages.length>5
   ||(status===404||!includeTargets)&&pages.length){if(outer)outer.failed=true;throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_OBSERVATIONS_INVALID');}
  const parent=immutableJson(originalRaw),observedPages=immutableJson(pages),selected=immutableJson(parentResource),subject=immutableJson(serviceObservation??null),state=this.newResponseScope();
  try{await this.responses.run(state,async()=>{
   if(status===404&&!subject)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
   if(subject)await this.assertServiceHostCurrentService(input,selected,subject);
   await this.authorizeResponse({...input,resource:selected,response:parent,status});
   if(status===200&&includeTargets){
    const target=await this.resolveServiceHostTargetResource(input,selected,parent),ids=new Set<string>();let records=0;
    if(!observedPages.length)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_TARGET_EOF_REQUIRED');
    for(const [index,raw]of observedPages.entries()){
     const page=raw as any;
     if(!page||typeof page!=='object'||Array.isArray(page)||!Array.isArray(page.data)||page.data.length>100
      ||!Object.hasOwn(page,'next')||(index===observedPages.length-1?page.next!==null:typeof page.next!=='string'||!page.next.length))
      throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_TARGET_EOF_REQUIRED');
     for(const row of page.data){if(!row||!uuid.test(row.id??'')||ids.has(row.id)||++records>500)throw deny('WORKFLOW_BUSINESS_READ_RECORD_BUDGET');ids.add(row.id);}
     await this.authorizeResponse({...input,resource:target,response:page,status:200});
    }
   }
   await this.assertServiceHostReadComplete(input,selected,status===404?null:parent,includeTargets);
   if(state.failed||!state.active||state.expiresAt<=Date.now())throw deny('WORKFLOW_BUSINESS_READ_SCOPE_FAILED');
  });
   // A promise's final continuation is a separate liveness boundary. A late
   // descendant or queued expiry cannot revive a closed outer/inner scope.
   if(!state.active||state.failed||state.expiresAt<=Date.now()||outer&&(!outer.active||outer.failed||outer.expiresAt<=Date.now()))
    throw deny('WORKFLOW_BUSINESS_READ_SCOPE_FAILED');
  }catch(error){if(outer)outer.failed=true;throw error;}finally{this.closeResponseScope(state);}
 }
 /** The fixed Runtime binds this value to the original current primary SDK
  * observation. A missing upstream does not invent an Upstream READ scope;
  * the actual Service subject still needs its current complete permissions. */
 private async assertServiceHostCurrentService(input:ReadInput,parent:Readonly<Resource>,observation:Readonly<{serviceId:string;before:unknown}>):Promise<void>{
  if(!isServiceHostReferencePoint(parent)||!uuid.test(observation.serviceId??'')||!parent.serviceHostReference!.serviceIds.includes(observation.serviceId))
   throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
  await this.assertServiceCurrentSubject(input,observation,parent);
 }
 private async assertServiceCurrentSubject(input:ReadInput,observation:Readonly<{serviceId:string;before:unknown}>,parent?:Readonly<Resource>):Promise<{material:Readonly<WorkflowBusinessMaterial>;proposed:Proposed;scope:Readonly<ReadScope>}>{
  if(!uuid.test(observation.serviceId??''))throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
  await this.assertCurrent(input);
  const cid=input.plan.clusterId;
  const material=await this.materialForPlan(input.plan,input.transaction),proposed=this.proposed(material),matches=proposed.filter(p=>p.type==='services'&&p.id===observation.serviceId&&p.action==='write'&&(!parent||p.workspaceId===parent.workspaceId)),p=matches[0];
  if(material.kind!=='configuration_v2'||matches.length!==1||!p)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
  if(parent){const expected=this.serviceHostResources(material,cid).find(r=>this.resourceKey(r)===this.resourceKey(parent));
   if(!expected)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');this.same(expected,parent);}
  this.same(observation.before,p.before);
  const scope=await this.resolveAbsenceReadScope(input),resource=scope.resources.find(r=>r.kind==='point'&&r.entityType==='services'
   &&r.clusterId===cid&&r.workspaceId===p.workspaceId&&r.entityId===p.id&&r.path===`/services/${p.id}`);
  if(!resource)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
  if(p.create){
   if(observation.before!==null||resource.allowAbsent!==true)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
   // This is a prospective-subject grant check, not a second SDK absence
   // certificate. The caller must retain the original primary SDK404 proof.
   await this.authorizeScopedAbsentSubject(input,resource,p,proposed,scope);
  }else{
   if(!observation.before||(observation.before as any).id!==p.id)throw deny('WORKFLOW_BUSINESS_SERVICE_HOST_CURRENT_SERVICE_REQUIRED');
   await this.authorizeResponse({...input,resource,response:observation.before,status:200});
   if(input.role==='executor'&&!this.permits(input,cid,p.workspaceId,'services',p.action,observation.before))
    throw deny('WORKFLOW_BUSINESS_CURRENT_SUBJECT_ACTION_DENIED');
  }
  const raw=normalizeEntityAuthorizationView('services',{...(observation.before as any??{}),...p.body,id:p.id}),wid=await this.workspaceFor(input,cid,'services',raw);
  if(wid!==p.workspaceId||!this.permits(input,cid,wid,'services','read',raw)
   ||input.role==='executor'&&!this.permits(input,cid,wid,'services',p.action,raw))throw deny('WORKFLOW_BUSINESS_SUBJECT_ACTION_DENIED');
  if(this.scopedInput(input))await this.scoped!.assertSubject(input,material,proposed,[{entityType:'services',entity:raw,clusterId:cid,workspaceId:wid}]);
  await this.assertCurrent(input);this.state(input);return{material,proposed:p,scope};
 }
 /** Fixed TLS relation participant, independent of whether Service.host is
  * a literal IP. Runtime binds these raw rows to the original same-round SDK
  * observations; this method creates no transport proof or Native authority. */
 async assertServiceTlsParticipant(input:ReadInput,observation:Readonly<{serviceId:string;before:unknown;
  references:readonly Readonly<{resource:Readonly<Resource>;entity:unknown}>[]}>):Promise<void>{
  const outer=this.responses.getStore();
  if(outer&&(!outer.active||outer.failed||outer.expiresAt<=Date.now()))throw deny('WORKFLOW_BUSINESS_ORIGINAL_READ_SCOPE_REQUIRED');
  if(!observation||!Array.isArray(observation.references)||observation.references.length>500){if(outer)outer.failed=true;throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_OBSERVATIONS_INVALID');}
  const selected=immutableJson(observation),state=this.newResponseScope();
  try{await this.responses.run(state,async()=>{
   const {material,proposed:p,scope}=await this.assertServiceCurrentSubject(input,selected);
   if(p.create||!selected.before)throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_UPDATE_REQUIRED');
   const effective=normalizeEntityAuthorizationView('services',{...(p.before as any??{}),...p.body}),ids=new Map<string,{type:string;id:string}>();
   const add=(type:string,id:unknown)=>{if(typeof id!=='string'||!uuid.test(id))throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_REFERENCE_INVALID');ids.set(`${type}:${id}`,{type,id});};
   if(effective.client_certificate!==undefined&&effective.client_certificate!==null)add('certificates',effective.client_certificate.id);
   if(effective.ca_certificates!==undefined&&effective.ca_certificates!==null){
    if(!Array.isArray(effective.ca_certificates))throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_REFERENCE_INVALID');
    for(const ca of effective.ca_certificates)add('ca_certificates',typeof ca==='string'?ca:ca?.id);
   }
   if(selected.references.length!==ids.size)throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_REFERENCES_INCOMPLETE');
   const seen=new Set<string>();
   for(const reference of selected.references){
    const resource=reference?.resource,key=`${resource?.entityType}:${resource?.entityId}`,expected=ids.get(key);
    if(!expected||seen.has(key))throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_REFERENCE_INVALID');
    const compiled=scope.resources.find(r=>r.kind==='point'&&r.clusterId===input.plan.clusterId&&r.workspaceId===p.workspaceId
     &&r.entityType===expected.type&&r.entityId===expected.id&&r.path===`/${expected.type}/${expected.id}`);
    if(!compiled)throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_REFERENCE_INVALID');this.same(compiled,resource);
    await this.authorizeResponse({...input,resource:compiled,response:reference.entity,status:200});seen.add(key);
   }
   if(seen.size!==ids.size||material.kind!=='configuration_v2')throw deny('WORKFLOW_BUSINESS_SERVICE_TLS_REFERENCES_INCOMPLETE');
   await this.assertCurrent(input);this.state(input);
  });
   if(!state.active||state.failed||state.expiresAt<=Date.now()||outer&&(!outer.active||outer.failed||outer.expiresAt<=Date.now()))throw deny('WORKFLOW_BUSINESS_READ_SCOPE_FAILED');
  }catch(error){if(outer)outer.failed=true;throw error;}finally{this.closeResponseScope(state);}
 }
 private completeGrant(input:ReadInput,cid:string,wid:string,module:string,action:PermissionAction):boolean {
  return input.principal.user.superAdmin===true||input.principal.grants.some(g=>validGrant(g)&&g.module===module&&g.action===action
   &&(g.cluster_id===null||g.cluster_id===cid)&&(g.workspace_id===null||g.workspace_id===wid)
   &&(g.scope_type==='global'||g.scope_type==='workspace'&&g.cluster_id===cid&&g.workspace_id===wid&&g.scope_values.length===1&&g.scope_values[0]===wid));
 }
 async assertCurrent(input:ReadInput):Promise<void> {
  const material=await this.assertStoredCurrent(input,!this.scopedInput(input));
  if(this.scopedInput(input))await this.scoped!.assertSubject(input,material,this.proposed(material));
 }
 /** SQL/AEAD/identity/registry/deadline verification only. Omitting broad
  * feature grants here grants no READ or Native capability: the once-installed
  * scoped policy and real response/action checks remain mandatory. */
 private async assertStoredCurrent(input:ReadInput,wholeFeature:boolean):Promise<Readonly<WorkflowBusinessMaterial>> {
  const {plan:p,draft:d,principal:u,transaction:tx}=input;
  if(!p?.scheduling||!['executor','reviewer'].includes(input.role)||p.kind!==d.binding.kind||p.subject.type!==d.binding.subjectType
   ||p.subject.id!==d.binding.subjectId||p.clusterId!==d.binding.clusterId||p.workspaceId!==d.binding.workspaceId||p.workflowId!==d.binding.workflowId
   ||p.planRevision!==d.binding.workflowPlanRevision||this.secrets.fingerprint(p)!==d.binding.workflowPlanHash
   ||p.requester.type!==d.binding.requester.type||p.requester.id!==d.binding.requester.id
   ||time(p.expiresAt)<=Date.now()||time(d.spec.windowEnd)>time(p.expiresAt)||d.delegation.ownerId!==d.delegation.executorId
   ||input.role==='executor'&&u.user.id!==d.delegation.executorId||input.role==='reviewer'&&u.user.id===d.delegation.executorId)throw deny('WORKFLOW_BUSINESS_READ_BINDING_CHANGED');
  const user=await tx.one<any>('SELECT * FROM users WHERE id=$1',[u.user.id]),epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  const grants=sortByFreshFingerprint((await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[u.user.id])).filter(validGrant),
   row=>this.secrets.fingerprint(row));
  if(!user||!epoch||user.status!=='active'||user.deleted_at||user.force_password_change||String(user.credential_epoch)!==u.credentialEpoch
   ||`${user.id}:${user.permissions_epoch}:${epoch.version}`!==u.permissionVersion||user.super_admin!==u.user.superAdmin)throw deny('WORKFLOW_BUSINESS_READ_PRINCIPAL_CHANGED');
  this.same(grants,sortByFreshFingerprint(u.grants,row=>this.secrets.fingerprint(row)));
  const m=await this.materialForPlan(p,tx);this.same(m.subjectSeal,d.binding.subjectSeal);
  if(wholeFeature&&(!this.completeGrant(input,p.clusterId,p.workspaceId,'workflows',input.role==='reviewer'?'approve':'write')
   ||!this.completeGrant(input,p.clusterId,p.workspaceId,m.kind==='configuration_v2'?'snapshots':isPortalCredentialScheduleKind(m.kind)?'portal':(METADATA_SCHEDULE_FEATURE as Record<string,string>)[m.kind]??'workflows',input.role==='reviewer'?'read':'write')))throw deny('WORKFLOW_BUSINESS_SUBJECT_GRANT_REQUIRED');
  const target=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL',[p.clusterId]);
  const ws=await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',[p.clusterId,p.workspaceId]);
  if(!target||!ws||!/^1\.5\.\d+$/.test(target.version??'')||['disabled','incompatible'].includes(target.status)||ws.status!=='active'
   ||target.revision!==p.scope.clusterRevision||ws.revision!==p.scope.workspaceRevision||target.execution_mode!==p.executionMode
   ||transportScopeFor(target.admin_url,target.transport_scope)!==p.scope.transportScope)throw deny('WORKFLOW_BUSINESS_REGISTRY_CHANGED');
  if(m.kind==='configuration_v2') {
   const deadlines=[m.job.authority_expires_at,m.job.expires_at,m.version.expires_at,m.plan.expiresAt,
    ...(m.promotion?[m.promotion.configurationLineage.authorityExpiresAt,m.promotion.configurationLineage.expiresAt,m.promotion.configurationLineage.planExpiresAt]:[])].map(time);
   if(deadlines.some(v=>!Number.isFinite(v)||v<=Date.now()||time(d.spec.windowEnd)>v)||time(m.plan.expiresAt)>time(m.job.authority_expires_at))throw deny('WORKFLOW_BUSINESS_OLD_DEADLINE_NOT_RENEWABLE');
   if(m.job.actor_id!==d.delegation.executorId||String(m.job.credential_epoch)!==d.delegation.executorCredentialEpoch
    ||m.job.permission_version!==`${m.job.actor_id}:${(await tx.one<any>('SELECT permissions_epoch FROM users WHERE id=$1',[m.job.actor_id]))?.permissions_epoch}:${epoch.version}`)throw deny('WORKFLOW_BUSINESS_CONFIGURATION_OWNER_CHANGED');
   if(m.promotion)for(const inv of [m.promotion.source,m.promotion.target]) {
    const c=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL',[inv.scope.clusterId]);
    const w=await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',[inv.scope.clusterId,inv.scope.workspaceId]);
    if(!c||!w||w.status!=='active'||['disabled','incompatible'].includes(c.status)||c.version!==inv.version
     ||transportScopeFor(c.admin_url,c.transport_scope)!==inv.scope.transportScope)throw deny('WORKFLOW_BUSINESS_PROMOTION_REGISTRY_CHANGED');
    if(wholeFeature&&!this.completeGrant(input,c.id,w.id,'promote',input.role==='executor'?'write':'read'))throw deny('WORKFLOW_BUSINESS_PROMOTION_READ_REQUIRED');
    if(wholeFeature&&(m.promotion.selection.includeSecrets||m.promotion.selection.includeCredentials)&&!this.completeGrant(input,c.id,w.id,'secrets','read'))throw deny('WORKFLOW_BUSINESS_PROMOTION_SECRET_REQUIRED');
   }
  } else if(isPortalCredentialBusinessMaterial(m)) {
   if(m.kind==='portal-credential-issue'){
    if(d.binding.requester.type!=='developer'||d.binding.requester.id!==m.developer.id||String(m.developer.credential_epoch)!==d.binding.requester.credentialEpoch
     ||d.delegation.executorId===m.developer.id||m.grant.state!=='pending'||m.grant.current_generation!==0||m.grant.current_credential_id!==null
     ||m.grant.acl_credential_ref_id!==null||m.credential.state!=='pending')throw deny('WORKFLOW_BUSINESS_PORTAL_REQUESTER_OR_RESERVATION_CHANGED');
    const activation=m.plan.steps[3];if(activation.metadataRevision!==m.grant.revision||activation.metadataBeforeHmac!==this.secrets.fingerprint(m.grant))throw deny('WORKFLOW_BUSINESS_PORTAL_ACTIVATION_BEFORE_CHANGED');
   }else{
    const expect=m.kind==='portal-credential-rotate'?'rotating':'revoking';
    if(d.binding.requester.type!=='developer'||d.binding.requester.id!==m.developer.id||String(m.developer.credential_epoch)!==d.binding.requester.credentialEpoch
     ||d.delegation.executorId===m.developer.id||m.grant.state!==expect||m.grant.workflow_id!==m.plan.workflowId)throw deny('WORKFLOW_BUSINESS_PORTAL_REQUESTER_OR_RESERVATION_CHANGED');
    const meta=m.plan.steps.find(s=>s.kind==='metadata');
    if(!meta||meta.metadataRevision!==m.grant.revision||meta.metadataBeforeHmac!==this.secrets.fingerprint(m.grant))throw deny('WORKFLOW_BUSINESS_PORTAL_ACTIVATION_BEFORE_CHANGED');
   }
  } else if(m.kind==='entity-annotation') {
   if(d.binding.requester.type!=='console'||d.binding.requester.id!==m.intent.actor_id||d.binding.requester.id!==m.request.actor_id
    ||String(m.intent.credential_epoch)!==d.binding.requester.credentialEpoch||m.request.material_hmac!==m.intent.material_hmac
    ||time(m.intent.expires_at)<=Date.now()||time(d.spec.windowEnd)>time(m.intent.expires_at)
    ||m.intent.permission_version!==`${m.intent.actor_id}:${(await tx.one<any>('SELECT permissions_epoch FROM users WHERE id=$1',[m.intent.actor_id]))?.permissions_epoch}:${epoch.version}`)
    throw deny('WORKFLOW_BUSINESS_ANNOTATION_REQUESTER_OR_MATERIAL_CHANGED');
  } else if(isMetadataScheduledKind(m.kind)) {
   if(d.binding.requester.type!=='console'||d.binding.requester.id!==p.requester.id)throw deny('WORKFLOW_BUSINESS_METADATA_REQUESTER_CHANGED');
   if(m.request&&(m.request.actor_id!==p.requester.id||String(m.request.workflow_id)!==p.workflowId))throw deny('WORKFLOW_BUSINESS_METADATA_WRAPPER_CHANGED');
   if(m.entity&&(m.entity.cluster_id!==p.clusterId||m.entity.workspace_id!==p.workspaceId))throw deny('WORKFLOW_BUSINESS_METADATA_WRAPPER_CHANGED');
  } else throw deny('WORKFLOW_BUSINESS_KIND_INVALID');
  return m;
 }
 private proposed(m:Readonly<WorkflowBusinessMaterial>):Proposed[] {
  if(isPortalCredentialBusinessMaterial(m))return m.plan.steps.filter(s=>s.kind==='native').map(s=>({type:s.credentialKind??s.entityType,
   id:s.nativeRequests[0].nativeId!,parentId:s.parentId,credentialKind:s.credentialKind,workspaceId:m.plan.workspaceId,
   body:s.mutationPayload,before:s.before??null,action:s.permissionAction,create:s.mutationAction==='create'}));
  if(m.kind!=='configuration_v2')return [];
  return m.plan.steps.map(s=>({type:s.entityType==='credentials'?s.credentialKind!:s.entityType,id:(s.nativeId??s.allocatedNativeId)!,
   parentId:s.parentId??undefined,credentialKind:s.credentialKind??undefined,workspaceId:s.objectWorkspaceId,
   body:s.body,before:s.before??null,action:s.permissionAction,create:s.mutationAction==='create',
   ...(s.entityType==='targets'&&s.mutationAction==='update'&&s.allocatedNativeId&&s.allocatedNativeId!==s.nativeId?{appendAllocatedId:s.allocatedNativeId}:{})}));
 }
 private allocations(proposed:readonly Proposed[]):Proposed[]{return proposed.flatMap(p=>p.create?[p]:p.appendAllocatedId?
  [{...p,id:p.appendAllocatedId,body:{...p.body,id:p.appendAllocatedId},before:null,create:true,appendAllocatedId:undefined}]:[]);}
 /** Server-owned paths come from authenticated complete native material.
  * The legacy domain keeps full EOF; the fixed scoped bridge uses exact
  * allocated points and the provider's genuine SDK404 association. */
 async resolveReadScope(input:ReadInput):Promise<Readonly<ReadScope>> {
  const original=await this.fullReadScope(input);
  if(!this.scoped)return original;
  const material=await this.materialForPlan(input.plan,input.transaction);
  // Point compilation is independent of role authorization. Ordinary sealed
  // manifests need only their fixed UUIDs even for a super-admin. Promote
  // retains its original complete coverage/EOF contract for every role.
  if(input.principal.user.superAdmin===true&&material.kind==='configuration_v2'&&material.promotion)return original;
  return this.scoped.resolveReadScope(input,material,this.proposed(material),original);
 }
 private async fullReadScope(input:ReadInput):Promise<Readonly<ReadScope>> {
  const m=await this.materialForPlan(input.plan,input.transaction),cid=input.plan.clusterId,wid=input.plan.workspaceId;
  const resources=new Map<string,Resource>(),proposed=this.proposed(m),createParents=new Set(proposed.filter(p=>p.create&&['consumers','upstreams'].includes(p.type)).map(p=>`${p.type}:${p.id}`));
  const add=(r:Resource)=>{assertKongPath('GET',r.path);const key=`${r.clusterId}:${r.workspaceId}:${r.path}`,old=resources.get(key);
   if(old){if(old.kind!==r.kind||old.entityType!==r.entityType||(old.parentId??null)!==(r.parentId??null))throw deny('WORKFLOW_BUSINESS_READ_RESOURCE_CONFLICT');
    resources.set(key,{...old,secrets:old.secrets||r.secrets,required:old.required||r.required});return;}resources.set(key,r);};
  const schema=(clusterId:string,workspaceId:string,name:string,plugin=false)=>{if(!/^[a-z][a-z0-9_-]{0,127}$/.test(name))throw deny('WORKFLOW_BUSINESS_SCHEMA_INVALID');
   add({clusterId,workspaceId,path:plugin?`/plugins/schema/${name}`:`/schemas/${name}`,kind:'schema',entityType:name,secrets:false,required:true});};
  const point=(clusterId:string,workspaceId:string,type:string,id:string,parentId?:string)=>{
   if(!uuid.test(id)||parentId!==undefined&&!uuid.test(parentId))throw deny('WORKFLOW_BUSINESS_NATIVE_ID_INVALID');
   const path=type==='targets'?`/upstreams/${parentId}/targets/${id}`:credentials.has(type)?`/consumers/${parentId}/${type}/${id}`:`/${type}/${id}`;
   add({clusterId,workspaceId,path,kind:'point',entityType:entityForPath(path)??type,entityId:id,...(parentId?{parentId}:{}),
    secrets:credentials.has(type)||['plugins','certificates'].includes(type),required:true});};
  const collection=(clusterId:string,workspaceId:string,type:string,parentId?:string)=>{
   if(parentId!==undefined&&!uuid.test(parentId))throw deny('WORKFLOW_BUSINESS_NATIVE_ID_INVALID');
   const path=type==='targets'?`/upstreams/${parentId}/targets`:credentials.has(type)?`/consumers/${parentId}/${type}`:`/${type}`;
   add({clusterId,workspaceId,path,kind:'collection',entityType:entityForPath(path)??type,...(parentId?{parentId}:{}),
    secrets:credentials.has(type)||['plugins','certificates'].includes(type),required:true,query:{size:100}});};
  const parentRefs=(clusterId:string,workspaceId:string,type:string,raw:any)=>{
   const entity=normalizeEntityAuthorizationView(type,raw);if(!entity||typeof entity!=='object')return;
   const refs:Array<[string,unknown]>=type==='plugins'?[['services',entity.service?.id],['routes',entity.route?.id],['consumers',entity.consumer?.id]]
    :type==='routes'?[['services',entity.service?.id]]:type==='snis'?[['certificates',entity.certificate?.id]]
    :type==='services'?[['certificates',entity.client_certificate?.id],...(Array.isArray(entity.ca_certificates)?entity.ca_certificates.map((v:any)=>['ca_certificates',typeof v==='string'?v:v?.id] as [string,unknown]):[])]
    :type==='targets'?[['upstreams',entity.upstream?.id]]:credentials.has(type)?[['consumers',entity.consumer?.id]]:[];
   for(const [parentType,id]of refs)if(id!==undefined&&id!==null){if(!uuid.test(String(id)))throw deny('WORKFLOW_BUSINESS_NATIVE_PARENT_INVALID');
    if(!createParents.has(`${parentType}:${id}`))point(clusterId,workspaceId,parentType,String(id));}
  };
  if(isPortalCredentialBusinessMaterial(m)) {
   point(cid,wid,'services',m.publicationProof.serviceId);
   for(const id of [m.publicationProof.aclPluginId,m.publicationProof.keyAuthPluginId])point(cid,wid,'plugins',id);
   collection(cid,wid,'consumers');schema(cid,wid,'consumers');schema(cid,wid,'acls');schema(cid,wid,'keyauth_credentials');
  } else if(m.kind==='configuration_v2') {
   for(const s of m.plan.steps) {
    const p=proposed.find(p=>p.id===(s.nativeId??s.allocatedNativeId)&&p.workspaceId===s.objectWorkspaceId)!;
    if(!p||!uuid.test(p.id)||!roots.has(p.type)&&p.type!=='targets'&&!credentials.has(p.type))throw deny('WORKFLOW_BUSINESS_NATIVE_STEP_INVALID');
    for(const raw of [s.before,s.body])parentRefs(cid,p.workspaceId,p.type,raw);
    if(p.parentId&&!createParents.has(`${p.type==='targets'?'upstreams':'consumers'}:${p.parentId}`))point(cid,p.workspaceId,p.type==='targets'?'upstreams':'consumers',p.parentId);
    if(p.create) {
     // An absent allocated Consumer/Upstream cannot already own FK children.
     // Never issue a nested GET against that absent parent and call its 404 EOF.
     if(p.parentId&&createParents.has(`${p.type==='targets'?'upstreams':'consumers'}:${p.parentId}`))collection(cid,p.workspaceId,p.type==='targets'?'upstreams':'consumers');
     else collection(cid,p.workspaceId,p.type,p.parentId);
    } else point(cid,p.workspaceId,p.type,p.id,p.parentId);
    const schemaType=p.type==='targets'?'targets':p.type==='key-auth'?'keyauth_credentials':p.type==='basic-auth'?'basicauth_credentials'
     :p.type==='jwt'?'jwt_secrets':p.type==='oauth2'?'oauth2_credentials':p.type==='hmac-auth'?'hmacauth_credentials':p.type;
    schema(cid,p.workspaceId,schemaType);
    if(p.type==='plugins')for(const raw of [s.before,s.body])if((raw as any)?.name)schema(cid,p.workspaceId,(raw as any).name,true);
   }
   if(m.promotion)for(const inv of [m.promotion.source,m.promotion.target]) {
    const scid=inv.scope.clusterId,swid=inv.scope.workspaceId;
    for(const [type,c]of Object.entries(inv.coverage)) {
     if(c.state!=='complete'||!c.eof)throw deny('WORKFLOW_BUSINESS_PROMOTION_EOF_REQUIRED');
     if(type.startsWith('targets:'))collection(scid,swid,'targets',type.slice(8));
     else if(roots.has(type))collection(scid,swid,type);else throw deny('WORKFLOW_BUSINESS_PROMOTION_COLLECTION_INVALID');
    }
    for(const o of inv.objects) {parentRefs(scid,o.objectWorkspaceId??swid,o.entityType,o.payload);
     if(o.entityType==='targets')point(scid,o.objectWorkspaceId??swid,'upstreams',o.parentId!);
     point(scid,o.objectWorkspaceId??swid,o.entityType,o.nativeId,o.parentId);
    }
    for(const type of Object.keys(inv.schemas))schema(scid,swid,type);
    for(const name of Object.keys(inv.pluginSchemas))schema(scid,swid,name,true);
   }
  } else {
   // entity-annotation + eight metadata kinds: no Kong native GET scope.
  }
  // A sealed no-op configuration still verifies its actual 1.5 schema and
  // SQL subject/grants; it does not invent a native packet or list statistic.
  if(!resources.size)schema(cid,wid,'services');
  const order=(r:Resource)=>r.kind==='schema'?100:r.entityType==='routes'?10:r.entityType==='services'?20:r.entityType==='consumers'?30
   :r.entityType==='upstreams'?40:r.entityType==='certificates'?50:r.entityType==='ca_certificates'?60:r.entityType==='snis'?70:r.entityType==='plugins'?80:90;
  const values=[...resources.values()].sort((a,b)=>order(a)-order(b)||a.clusterId.localeCompare(b.clusterId)||a.path.localeCompare(b.path));
  if(!values.length||values.length>500)throw deny('WORKFLOW_BUSINESS_READ_RESOURCE_BUDGET');return immutableJson({version:1,resources:values,limits});
 }
 /** Root must wrap each original candidate/validation read run separately.
  * Cached parents cannot escape or be reused by the next packet/actor/window. */
 async runResponseScope<T>(fn:()=>Promise<T>):Promise<T> {
  if(this.responses.getStore()||typeof fn!=='function')throw deny('WORKFLOW_BUSINESS_READ_SCOPE_REENTRY');
  const state=this.newResponseScope();
  try{return await this.responses.run(state,async()=>{const result=await fn();if(state.failed||!state.active||state.expiresAt<=Date.now())throw deny('WORKFLOW_BUSINESS_READ_SCOPE_FAILED');return result;});}
  finally{this.closeResponseScope(state);}
 }
 private newResponseScope():ResponseScope{return{active:true,failed:false,expiresAt:Math.min(Date.now()+30000,this.responses.getStore()?.expiresAt??Infinity),bytes:0,planningFutureParents:false,witnesses:new Map(),serviceHostParents:new Map(),futureParents:new Map(),completed:new Set(),seen:new Set(),absent:new Set()};}
 private closeResponseScope(state:ResponseScope):void{state.active=false;state.witnesses.clear();state.serviceHostParents.clear();state.futureParents.clear();state.completed.clear();state.seen.clear();state.absent.clear();}
 private state(input:ReadInput):ResponseScope {
  const state=this.responses.getStore();if(!state?.active||state.failed||state.expiresAt<=Date.now())throw deny('WORKFLOW_BUSINESS_ORIGINAL_READ_SCOPE_REQUIRED');
  const binding=this.secrets.fingerprint({plan:input.plan,draft:input.draft,actorId:input.principal.user.id,role:input.role,
   credentialEpoch:input.principal.credentialEpoch,permissionVersion:input.principal.permissionVersion,grants:input.principal.grants});
  if(state.binding&&state.binding!==binding){state.failed=true;throw deny('WORKFLOW_BUSINESS_READ_SCOPE_CHANGED');}state.binding=binding;return state;
 }
 private witnessKey(cid:string,type:string,id:string):string{return `${cid}:${type}:${id}`;}
 private resourceKey(r:Readonly<Resource>):string{return `${r.clusterId}:${r.workspaceId}:${r.path}`;}
 private async workspaceFor(input:ReadInput,cid:string,type:string,raw:any):Promise<string> {
  const entity=normalizeEntityAuthorizationView(type,raw),state=this.state(input);let owner=entity;
  if(type==='targets'||credentials.has(type)||type==='credentials') {
   const parentType=type==='targets'?'upstreams':'consumers',parentId=type==='targets'?entity.upstream?.id:entity.consumer?.id;
   if(!uuid.test(parentId??''))throw deny('WORKFLOW_BUSINESS_RESPONSE_PARENT_INVALID');
   const parent=state.witnesses.get(this.witnessKey(cid,parentType,parentId))??(state.planningFutureParents?state.futureParents.get(this.witnessKey(cid,parentType,parentId)):undefined);if(!parent)throw deny('WORKFLOW_BUSINESS_CURRENT_PARENT_READ_REQUIRED');owner=parent.entity;
  }
  if(owner.tags!==undefined&&owner.tags!==null&&(!Array.isArray(owner.tags)||owner.tags.length>1000||owner.tags.some((t:any)=>typeof t!=='string'||!t.length||t.length>128)))throw deny('WORKFLOW_BUSINESS_RESPONSE_TAG_INVALID');
  const tags:string[]=owner.tags??[],reserved=tags.filter(t=>t.startsWith('kos-ws-'));
  if(reserved.length>1)throw deny('WORKFLOW_BUSINESS_RESPONSE_WORKSPACE_AMBIGUOUS');
  const code=reserved.length?reserved[0].slice(7):'default';if(!/^[a-z][a-z0-9_-]{0,47}$/.test(code))throw deny('WORKFLOW_BUSINESS_RESPONSE_WORKSPACE_INVALID');
  const ws=await input.transaction.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND code=$2',[cid,code]);
  if(!ws||ws.status!=='active'||ws.deleted_at||!uuid.test(ws.id??''))throw deny('WORKFLOW_BUSINESS_RESPONSE_WORKSPACE_INVALID');
  return ws.id;
 }
 private direct(input:ReadInput,cid:string,wid:string,type:string,action:PermissionAction,entity:any):EffectiveGrant[] {
  return input.principal.grants.filter(g=>grantMatchesEntity(g,type,action,{clusterId:cid,workspaceId:wid,entityType:type,entity}));
 }
 private parentGrants(input:ReadInput,cid:string,wid:string,type:string,id:string,action:PermissionAction,child:any,depth=0):EffectiveGrant[] {
  if(depth>2)throw deny('WORKFLOW_BUSINESS_PARENT_CYCLE');const state=this.state(input),w=state.witnesses.get(this.witnessKey(cid,type,id))??(state.planningFutureParents?state.futureParents.get(this.witnessKey(cid,type,id)):undefined);
  if(!w||w.workspaceId!==wid)return [];const raw=normalizeEntityAuthorizationView(type,w.entity),direct=this.direct(input,cid,wid,type,action,raw).filter(g=>inheritedTagMatches(g,child));
  if(direct.length)return direct;
  if(type==='routes'&&action!=='read'&&raw.service?.id)return this.parentGrants(input,cid,wid,'services',raw.service.id,action,raw,depth+1).filter(g=>inheritedTagMatches(g,child));
  return [];
 }
 private secretPermits(input:ReadInput,cid:string,wid:string,type:string,entity:any):boolean {
  entity=this.authorizationEntity(input,cid,type,entity);
  return input.principal.user.superAdmin===true||input.principal.grants.some(g=>grantMatchesEntity(g,'secrets','read',{clusterId:cid,workspaceId:wid,entityType:type,entity}));
 }
 private authorizationEntity(input:ReadInput,cid:string,type:string,raw:any):any{
  const entity=normalizeEntityAuthorizationView(type,raw);
  if(this.scopedInput(input)&&credentials.has(type)&&!Array.isArray(raw?.tags)&&entity.consumer?.id){
   const state=this.state(input),parent=state.witnesses.get(this.witnessKey(cid,'consumers',entity.consumer.id))??state.futureParents.get(this.witnessKey(cid,'consumers',entity.consumer.id));
   if(parent)return{...entity,tags:[...(parent.entity.tags??[])]};
  }
  return entity;
 }
 private permits(input:ReadInput,cid:string,wid:string,type:string,action:PermissionAction,raw:any):boolean {
  const entity=this.authorizationEntity(input,cid,type,raw),state=this.state(input);if(input.principal.user.superAdmin)return true;
  const direct=this.direct(input,cid,wid,type,action,entity);
  if(type==='plugins') {const parents:Array<[string,string]>=[];for(const [field,t]of [['service','services'],['route','routes'],['consumer','consumers']])if(entity[field]?.id)parents.push([t,entity[field].id]);
   return parents.length?parents.every(([t,id])=>this.parentGrants(input,cid,wid,t,id,action,entity).length>0):action==='read'&&direct.length>0;
  }
  if(direct.length)return true;
  if(type==='routes'&&action!=='read'&&entity.service?.id)return this.parentGrants(input,cid,wid,'services',entity.service.id,action,entity).length>0;
  if(type==='services'&&action==='read')return [...state.witnesses.values()].some(w=>w.type==='routes'&&w.workspaceId===wid&&w.resource.clusterId===cid
   &&normalizeEntityAuthorizationView('routes',w.entity).service?.id===entity.id&&input.principal.grants.some(g=>grantMatchesEntity(g,'routes',g.action,{clusterId:cid,workspaceId:wid,entityType:'routes',entity:w.entity})));
  if(type==='targets'&&entity.upstream?.id)return this.parentGrants(input,cid,wid,'upstreams',entity.upstream.id,action,entity).length>0;
  if(credentials.has(type)&&entity.consumer?.id)return this.parentGrants(input,cid,wid,'consumers',entity.consumer.id,action,entity).length>0;
  return false;
 }
 /** Every raw row is checked. Broad collections never turn a planned object's
  * write grant into authority over unrelated returned objects. */
 async authorizeResponse(input:ReadInput&{resource:Readonly<Resource>;response:unknown;status:number}):Promise<void> {
  // One response authorization is one verification read: its repeated
  // identical SQL/material layers share one result; epoch probes stay live.
  return withVerificationReadMemo(input.transaction,()=>this.authorizeResponseRead(input));
 }
 private async authorizeResponseRead(input:ReadInput&{resource:Readonly<Resource>;response:unknown;status:number}):Promise<void> {
  const state=this.state(input);try{
   await this.assertCurrent(input);const scope=await this.resolveReadScope(input),r=input.resource;
   const expected=scope.resources.find(x=>this.resourceKey(x)===this.resourceKey(r))
    ??(await this.resolveAbsenceReadScope(input)).resources.find(x=>this.resourceKey(x)===this.resourceKey(r));
   if(!expected)throw deny('WORKFLOW_BUSINESS_RESPONSE_PATH_FORBIDDEN');this.same(expected,r);
   if(input.status===404){
    if(isServiceHostReferencePoint(r)){
     // Transport provenance is established by the provider's opaque SDK404
     // observer, not by this status argument. This branch accepts only the
     // exact compiled name resource; denied/foreign real rows never enter it.
     if(state.serviceHostParents.has(this.resourceKey(r)))throw deny('WORKFLOW_BUSINESS_CURRENT_OBJECT_CHANGED');
     state.absent.add(this.resourceKey(r));state.seen.add(this.resourceKey(r));state.completed.add(this.resourceKey(r));return;
    }
    const m=await this.materialForPlan(input.plan,input.transaction),p=this.allocations(this.proposed(m)).find(p=>{
     const path=p.type==='targets'?`/upstreams/${p.parentId}/targets/${p.id}`:credentials.has(p.type)?`/consumers/${p.parentId}/${p.type}/${p.id}`:`/${p.type}/${p.id}`;
     return p.create&&p.id===r.entityId&&p.workspaceId===r.workspaceId&&(p.parentId??null)===(r.parentId??null)&&path===r.path&&entityForPath(path)===r.entityType;});
    const scoped=scope.domain==='scoped-points-v1';
    if(r.kind!=='point'||r.allowAbsent!==true||(!scoped&&r.required!==false)||r.clusterId!==input.plan.clusterId||!p)throw deny('WORKFLOW_BUSINESS_RESPONSE_STATUS_INVALID');
    // The fixed SDK provider has already authenticated its opaque transport
    // observation and EOF/parent witness. Recheck the complete current domain
    // material/grants; an HTTP error body is never a native entity or permit.
    // Live validation may see an earlier authentic create already present.
    // This is permission review, not prefix acknowledgement; the candidate
    // runner still invokes assertReadComplete for its preclaim collision test.
    if(scoped)await this.authorizeScopedAbsentSubject(input,r,p,this.proposed(m),scope);
    else await this.verifyObservedGrants(input,false,true);
    state.seen.add(this.resourceKey(r));state.completed.add(this.resourceKey(r));return;
   }
   if(input.status!==200)throw deny('WORKFLOW_BUSINESS_RESPONSE_STATUS_INVALID');
   const response=immutableJson(input.response);state.bytes+=Buffer.byteLength(JSON.stringify(response??null));if(state.bytes>limits.maxBytes)throw deny('WORKFLOW_BUSINESS_READ_BYTE_BUDGET');
   if(r.kind==='schema'){if(!response||typeof response!=='object'||Array.isArray(response))throw deny('WORKFLOW_BUSINESS_SCHEMA_RESPONSE_INVALID');
    const m=await this.materialForPlan(input.plan,input.transaction),parts=r.path.split('/').filter(Boolean);
    if(m.kind==='portal-credential-issue'){const expectedSchema=parts[1]==='consumers'?m.publicationProof.schemas.consumers:parts[1]==='acls'?m.publicationProof.schemas.acls
      :parts[1]==='keyauth_credentials'?m.publicationProof.schemas.keyAuth:undefined;
      const cluster=await input.transaction.one<any>('SELECT version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[r.clusterId]);
      if(!expectedSchema||!kong15SchemaValidationEquivalent(stripSensitiveSchemaDefaults(response,this.secrets),
        stripSensitiveSchemaDefaults(expectedSchema,this.secrets),cluster?.version))throw deny('WORKFLOW_BUSINESS_SCHEMA_RESPONSE_INVALID');}
    else if(m.kind==='configuration_v2'&&m.promotion){const inv=r.clusterId===m.promotion.source.scope.clusterId&&r.workspaceId===m.promotion.source.scope.workspaceId?m.promotion.source:m.promotion.target,
      expectedSchema=parts[0]==='schemas'?inv.schemas[parts[1]]:inv.pluginSchemas[parts[2]];if(expectedSchema)this.same(stripSensitiveSchemaDefaults(response,this.secrets),stripSensitiveSchemaDefaults(expectedSchema,this.secrets));}
    state.seen.add(this.resourceKey(r));return;}
   const rows=r.kind==='collection'?(response as any)?.data:[response];
   if(!Array.isArray(rows)||r.kind==='collection'&&(!Object.hasOwn(response as object,'next')||(response as any).next===undefined))throw deny('WORKFLOW_BUSINESS_RESPONSE_EOF_INVALID');
   for(const raw of rows){if(!raw||typeof raw!=='object'||Array.isArray(raw)||!uuid.test(raw.id??'')||r.kind==='point'&&!(isServiceHostReferencePoint(r)?raw.name===r.serviceHostReference!.host:raw.id===r.entityId))throw deny('WORKFLOW_BUSINESS_RESPONSE_ID_INVALID');
    const parts=r.path.split('/').filter(Boolean),type=parts[0]==='consumers'&&credentials.has(parts[2])?parts[2]:r.entityType;
    const entity=normalizeEntityAuthorizationView(type,raw);
    if(r.parentId&&(type==='targets'?entity.upstream?.id:entity.consumer?.id)!==r.parentId)throw deny('WORKFLOW_BUSINESS_RESPONSE_PARENT_INVALID');
    const wid=await this.workspaceFor(input,r.clusterId,type,entity);
    // Unrelated full-EOF rows may belong to another current workspace, but each
    // needs that real workspace's READ grant; point subjects stay exact.
    if(r.kind==='point'&&wid!==r.workspaceId)throw deny('WORKFLOW_BUSINESS_RESPONSE_WORKSPACE_MISMATCH');
    if(!this.permits(input,r.clusterId,wid,type,'read',entity))throw deny('WORKFLOW_BUSINESS_RESPONSE_READ_DENIED');
    const sensitive=this.secrets.fingerprint(this.secrets.redact(raw))!==this.secrets.fingerprint(raw);
    if(sensitive&&(!r.secrets||!this.secretPermits(input,r.clusterId,wid,type,entity)))throw deny('WORKFLOW_BUSINESS_RESPONSE_SECRET_DENIED');
    if(isServiceHostReferencePoint(r)){
     if(state.absent.has(this.resourceKey(r)))throw deny('WORKFLOW_BUSINESS_CURRENT_OBJECT_CHANGED');
     state.serviceHostParents.set(this.resourceKey(r),{type,entity:raw,workspaceId:wid,resource:r});
    }
    const key=this.witnessKey(r.clusterId,type,raw.id),old=state.witnesses.get(key);
    if(old&&this.secrets.fingerprint(old.entity)!==this.secrets.fingerprint(raw))throw deny('WORKFLOW_BUSINESS_CURRENT_OBJECT_CHANGED');
    state.witnesses.set(key,{type,entity:raw,workspaceId:wid,resource:r});if(state.witnesses.size>limits.maxRecords)throw deny('WORKFLOW_BUSINESS_READ_RECORD_BUDGET');
   }
   state.seen.add(this.resourceKey(r));if(r.kind!=='collection'||(response as any).next===null)state.completed.add(this.resourceKey(r));
  }catch(error){state.failed=true;throw error;}
 }
 /** Fixed provider callback for an original absent FK parent. This method
  * does not accept a status/error response, invent a Kong observation or
  * certify a packet. The provider verifies the private witness separately. */
 async authorizeScopedParentAbsence(input:ReadInput,child:Readonly<Resource>,parent:Readonly<Resource>):Promise<void>{
  const state=this.state(input);try{
   await this.assertCurrent(input);const scope=await this.resolveReadScope(input);
   if(scope.domain!=='scoped-points-v1')throw deny('WORKFLOW_BUSINESS_SCOPED_PARENT_ABSENCE_REQUIRED');
   for(const selected of [parent,child]){const expected=scope.resources.find(r=>this.resourceKey(r)===this.resourceKey(selected));
    if(!expected)throw deny('WORKFLOW_BUSINESS_RESPONSE_PATH_FORBIDDEN');this.same(expected,selected);}
   const material=await this.materialForPlan(input.plan,input.transaction),proposed=this.proposed(material),p=proposed.find(p=>p.create&&p.id===child.entityId
    &&p.workspaceId===child.workspaceId&&p.parentId===parent.entityId),parts=child.path.split('/').filter(Boolean),parentType=p?.type==='targets'?'upstreams':'consumers';
   if(!p||child.kind!=='point'||child.allowAbsent!==true||parent.kind!=='point'||parent.allowAbsent!==true||parent.parentId!==undefined
    ||parent.clusterId!==child.clusterId||parent.workspaceId!==child.workspaceId||child.parentId!==parent.entityId
    ||parts.length!==4||parts[0]!==parentType||parts[1]!==parent.entityId||parts[2]!==p.type||parts[3]!==p.id
    ||parent.path!==`/${parentType}/${parent.entityId}`||!state.absent.has(this.resourceKey(parent))||!state.completed.has(this.resourceKey(parent))
    ||state.seen.has(this.resourceKey(child))||!(p.type==='targets'||credentials.has(p.type)))throw deny('WORKFLOW_BUSINESS_SCOPED_PARENT_ABSENCE_REQUIRED');
   await this.authorizeScopedAbsentSubject(input,child,p,proposed,scope);
   state.seen.add(this.resourceKey(child));state.completed.add(this.resourceKey(child));
  }catch(error){state.failed=true;throw error;}
 }
 private async authorizeScopedAbsentSubject(input:ReadInput,r:Readonly<Resource>,p:Proposed,proposed:readonly Proposed[],scope:Readonly<ReadScope>):Promise<void>{
  const state=this.state(input);state.planningFutureParents=true;
  try{
   const raw=normalizeEntityAuthorizationView(p.type,{...p.body,id:p.id});
   if(p.parentId){raw[p.type==='targets'?'upstream':'consumer']={id:p.parentId};this.futureParent(input,p,proposed,scope);}
   const wid=await this.workspaceFor(input,r.clusterId,p.type,raw);
   if(wid!==p.workspaceId||!this.permits(input,r.clusterId,wid,p.type,'read',raw)||input.role==='executor'&&!this.permits(input,r.clusterId,wid,p.type,p.action,raw))throw deny('WORKFLOW_BUSINESS_ABSENT_SUBJECT_READ_DENIED');
   if(this.secrets.fingerprint(this.secrets.redact(raw))!==this.secrets.fingerprint(raw)&&!this.secretPermits(input,r.clusterId,wid,p.type,raw))throw deny('WORKFLOW_BUSINESS_SUBJECT_SECRET_DENIED');
   state.absent.add(this.resourceKey(r));
  }finally{state.planningFutureParents=false;state.futureParents.clear();}
 }
 /** Call after genuine fixed GET scope completion. This check uses current
  * observed parents and actual source HMACs, never historical tags as current
  * ownership. It does not acknowledge or permit a native packet. */
 async assertReadComplete(input:ReadInput):Promise<void> { return this.verifyObservedGrants(input,true); }
 /** Live permission verification inside Root's genuine original Namespace.
  * Existence is only a READ observation: it never certifies a successful
  * prefix or replaces the execution Kernel's native preconditions/results. */
 async assertCurrentReadGrants(input:ReadInput):Promise<void> { return this.verifyObservedGrants(input,false); }
 private futureParent(input:ReadInput,p:Proposed,proposed:readonly Proposed[],scope:Readonly<ReadScope>):void{
  if(!p.parentId)return;const state=this.state(input),cid=input.plan.clusterId,parentType=p.type==='targets'?'upstreams':'consumers';
  if(state.witnesses.has(this.witnessKey(cid,parentType,p.parentId)))return;
  const parent=proposed.find(x=>x.type===parentType&&x.id===p.parentId&&x.create),resource=scope.resources.find(r=>r.clusterId===cid&&r.workspaceId===p.workspaceId
   &&(r.kind==='collection'&&r.path===`/${parentType}`||scope.domain==='scoped-points-v1'&&r.kind==='point'&&r.entityId===p.parentId&&r.path===`/${parentType}/${p.parentId}`&&state.absent.has(this.resourceKey(r))));
  if(!parent||!resource||!state.completed.has(this.resourceKey(resource))||input.role==='executor'&&!this.permits(input,cid,parent.workspaceId,parent.type,'write',parent.body)
   ||!this.permits(input,cid,parent.workspaceId,parent.type,'read',parent.body))throw deny('WORKFLOW_BUSINESS_CURRENT_PARENT_READ_REQUIRED');
  state.futureParents.set(this.witnessKey(cid,parentType,parent.id),{type:parentType,entity:parent.body,workspaceId:parent.workspaceId,resource});
 }
 private async verifyObservedGrants(input:ReadInput,preclaim:boolean,readCreates=false):Promise<void> {
  const state=this.state(input);try{
   await this.assertCurrent(input);const scope=await this.resolveReadScope(input),m=await this.materialForPlan(input.plan,input.transaction);
   if(scope.resources.some(r=>r.required&&(r.kind==='schema'?!state.seen.has(this.resourceKey(r)):!state.completed.has(this.resourceKey(r)))))throw deny('WORKFLOW_BUSINESS_READ_INCOMPLETE');
   const proposed=this.proposed(m),cid=input.plan.clusterId;state.planningFutureParents=true;
   if(m.kind==='portal-credential-issue')for(const [type,id,raw]of [['services',m.publicationProof.serviceId,m.publicationProof.service],
     ['plugins',m.publicationProof.aclPluginId,m.publicationProof.aclPlugin],['plugins',m.publicationProof.keyAuthPluginId,m.publicationProof.keyAuthPlugin]]as const){
    const actual=state.witnesses.get(this.witnessKey(cid,type,id));if(!actual||actual.workspaceId!==input.plan.workspaceId
     ||this.secrets.fingerprint(actual.entity)!==this.secrets.fingerprint(raw))throw deny('WORKFLOW_BUSINESS_PORTAL_NATIVE_PUBLICATION_CHANGED');
   }
   for(const p of proposed) {
    const type=p.type,current=state.witnesses.get(this.witnessKey(cid,type,p.id));
    const raw=normalizeEntityAuthorizationView(type,p.create?{...p.body,id:p.id}:{...current?.entity,...(p.action==='delete'?{}:p.body),id:p.id});
    if(preclaim&&p.create&&current)throw deny('WORKFLOW_BUSINESS_CREATE_ID_ALREADY_EXISTS');
    if(current&&current.workspaceId!==p.workspaceId)throw deny('WORKFLOW_BUSINESS_SUBJECT_WORKSPACE_CHANGED');
    if(current&&input.role==='executor'&&!this.permits(input,cid,current.workspaceId,type,p.action,current.entity))throw deny('WORKFLOW_BUSINESS_CURRENT_SUBJECT_ACTION_DENIED');
    if(!p.create&&!current)throw deny('WORKFLOW_BUSINESS_CURRENT_SUBJECT_MISSING');
    if(!raw||typeof raw!=='object'||raw.id!==p.id)throw deny('WORKFLOW_BUSINESS_SUBJECT_BODY_INVALID');
    if(p.parentId){const field=type==='targets'?'upstream':'consumer';raw[field]={id:p.parentId};}
    // A future parent is usable only after its authentic root collection EOF
    // proves its allocated ID absent, and its own proposed create is allowed.
    if(p.parentId&&!state.witnesses.has(this.witnessKey(cid,type==='targets'?'upstreams':'consumers',p.parentId))) {
     this.futureParent(input,p,proposed,scope);
    }
    const wid=await this.workspaceFor(input,cid,type,raw);if(wid!==p.workspaceId)throw deny('WORKFLOW_BUSINESS_SUBJECT_WORKSPACE_CHANGED');
    if((readCreates||scope.domain==='scoped-points-v1')&&p.create&&!this.permits(input,cid,wid,type,'read',raw))throw deny('WORKFLOW_BUSINESS_ABSENT_SUBJECT_READ_DENIED');
    if(input.role==='executor'&&!this.permits(input,cid,wid,type,p.action,raw))throw deny('WORKFLOW_BUSINESS_SUBJECT_ACTION_DENIED');
    if(!input.principal.user.superAdmin&&this.secrets.fingerprint(this.secrets.redact(raw))!==this.secrets.fingerprint(raw)
     &&!this.secretPermits(input,cid,wid,type,raw))throw deny('WORKFLOW_BUSINESS_SUBJECT_SECRET_DENIED');
   }
   if(scope.domain==='scoped-points-v1')for(const p of this.allocations(proposed).filter(p=>!proposed.some(original=>original.id===p.id))){
    const actual=state.witnesses.get(this.witnessKey(cid,p.type,p.id));if(preclaim&&actual)throw deny('WORKFLOW_BUSINESS_CREATE_ID_ALREADY_EXISTS');
    const raw={...p.body,id:p.id,upstream:{id:p.parentId}},wid=await this.workspaceFor(input,cid,p.type,raw);
    if(wid!==p.workspaceId||!this.permits(input,cid,wid,p.type,'read',raw)||input.role==='executor'&&!this.permits(input,cid,wid,p.type,'write',raw))throw deny('WORKFLOW_BUSINESS_SUBJECT_ACTION_DENIED');
   }
   if(this.scopedInput(input)){
    const observed:WorkflowBusinessScopedSubject[]=m.kind==='portal-credential-issue'?[{entityType:'services',entity:state.witnesses.get(this.witnessKey(cid,'services',m.publicationProof.serviceId))?.entity,clusterId:cid,workspaceId:input.plan.workspaceId}]
     :proposed.map(p=>({entityType:p.type,entity:this.authorizationEntity(input,cid,p.type,{...(state.witnesses.get(this.witnessKey(cid,p.type,p.id))?.entity??p.body),id:p.id,...(p.parentId?{[p.type==='targets'?'upstream':'consumer']:{id:p.parentId}}:{})}),clusterId:cid,workspaceId:p.workspaceId}));
    if(m.kind==='configuration_v2'&&m.promotion)for(const inventory of [m.promotion.source,m.promotion.target])for(const object of inventory.objects)
     observed.push({entityType:object.entityType,entity:state.witnesses.get(this.witnessKey(inventory.scope.clusterId,object.entityType,object.nativeId))?.entity,
      clusterId:inventory.scope.clusterId,workspaceId:object.objectWorkspaceId??inventory.scope.workspaceId});
    if(observed.some(s=>!s.entity))throw deny('WORKFLOW_BUSINESS_SCOPED_SUBJECT_UNOBSERVED');await this.scoped!.assertSubject(input,m,proposed,observed);
   }
   if(m.kind==='configuration_v2'&&m.promotion)for(const inv of [m.promotion.source]) {
    for(const object of inv.objects){const key=`${object.entityType}:${object.nativeId}`,observed=state.witnesses.get(this.witnessKey(inv.scope.clusterId,object.entityType,object.nativeId));
     if(!observed||observed.workspaceId!==object.objectWorkspaceId||this.secrets.fingerprint(observed.entity)!==m.promotion.sourceNativeFingerprints[key])throw deny('WORKFLOW_BUSINESS_PROMOTION_RAW_SOURCE_CHANGED');}
    const expectedKeys=new Set(inv.objects.map(o=>`${o.entityType}:${o.nativeId}`)),rootServices=new Set(inv.scope.rootIds),routeIds=new Set<string>();
    for(const w of state.witnesses.values())if(w.resource.clusterId===inv.scope.clusterId&&w.type==='routes'&&rootServices.has(normalizeEntityAuthorizationView('routes',w.entity).service?.id))routeIds.add(w.entity.id);
    for(const w of state.witnesses.values())if(w.resource.clusterId===inv.scope.clusterId){const raw=normalizeEntityAuthorizationView(w.type,w.entity);
     const selected=inv.scope.kind==='cluster'||inv.scope.kind==='workspace'&&w.workspaceId===inv.scope.workspaceId
      ||inv.scope.kind==='services'&&(w.type==='services'&&rootServices.has(raw.id)||w.type==='routes'&&routeIds.has(raw.id)
       ||w.type==='plugins'&&(rootServices.has(raw.service?.id)||routeIds.has(raw.route?.id)));
     if(selected&&!expectedKeys.has(`${w.type}:${raw.id}`))throw deny('WORKFLOW_BUSINESS_PROMOTION_SOURCE_MEMBERSHIP_CHANGED');
    }
    for(const [type,coverage]of Object.entries(inv.coverage)) {const path=type.startsWith('targets:')?`/upstreams/${type.slice(8)}/targets`:`/${type}`;
     const r=scope.resources.find(r=>r.clusterId===inv.scope.clusterId&&r.workspaceId===inv.scope.workspaceId&&r.path===path&&r.kind==='collection');
     if(!r||!coverage.eof||!state.completed.has(this.resourceKey(r)))throw deny('WORKFLOW_BUSINESS_PROMOTION_EOF_REQUIRED');
    }
   }
  }catch(error){state.failed=true;throw error;}
  finally{state.planningFutureParents=false;state.futureParents.clear();}
 }
 /** Pure budget calculation only. Root supplies measured raw usage from its
  * genuine current read handle, not a client DTO. Each future native send
  * reserves two source fences and all three transport GET attempts. */
 assertExecutionReadBudget(nativePackets:number,currentUsage:Readonly<{calls:number;pages:number;records:number;bytes:number}>,privateUsage?:Readonly<{calls:number;pages:number;records:number;bytes:number}>):void {
  const cap={calls:limits.maxCalls,pages:limits.maxPages,records:limits.maxRecords,bytes:limits.maxBytes};
  if(!Number.isSafeInteger(nativePackets)||nativePackets<0||nativePackets>500)throw deny('WORKFLOW_BUSINESS_EXECUTION_BUDGET_INVALID');
  const usages=[currentUsage,...(privateUsage?[privateUsage]:[])],rounds=nativePackets*2;
  for(const usage of usages)if(!usage||Object.keys(cap).some(k=>!Number.isSafeInteger((usage as any)[k])||(usage as any)[k]<0))throw deny('WORKFLOW_BUSINESS_EXECUTION_BUDGET_INVALID');
  for(const key of Object.keys(cap) as Array<keyof typeof cap>){const base=usages.reduce((n,u)=>n+u[key],0),estimated=base*(key==='calls'?rounds*3+1:rounds+1);
   if(estimated>cap[key])throw deny('WORKFLOW_BUSINESS_EXECUTION_BUDGET_EXCEEDED');}
 }
}
