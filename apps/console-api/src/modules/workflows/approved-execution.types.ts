import type { WorkflowScheduledNamespaceCheckpoint, WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';
import type { AuthUser } from '../../common/auth';
import type { DbService } from '../../infrastructure/db.service';
import type { KongExecutionFrame, KongPolicyCluster } from '../../infrastructure/kong/execution-context.service';
import type { MutationContext } from '../mutations/mutation.service';
import type { WorkflowNativeRequest, WorkflowPlanV1 } from './workflow.types';
import type { WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import type { WorkflowScheduledConfigurationCheckpoint, WorkflowScheduledConfigurationExecutionHandle,
  WorkflowScheduledConfigurationExecutionProof, WorkflowScheduledConfigurationJobHandle } from './workflow-scheduled-configuration-origin.types';

export const APPROVED_PORTAL_STEP_POLICY = 'APPROVED_PORTAL_STEP_POLICY';
export const APPROVED_WORKFLOW_METADATA_POLICY = 'APPROVED_WORKFLOW_METADATA_POLICY';
export const PORTAL_AUTH_BOUNDARY = 'PORTAL_AUTH_BOUNDARY';
declare const executionHandleBrand: unique symbol;
declare const portalPermitBrand: unique symbol;
declare const issueRecoveryBrand: unique symbol;
export type ApprovedExecutionHandle = Readonly<{ [executionHandleBrand]: true }>;
export type PortalBoundaryReadPermit = Readonly<{ [portalPermitBrand]: true }>;
/** Only the private SQL verifier can mint this metadata-only handle. */
export type IssueActivationRecoveryHandle = Readonly<{ [issueRecoveryBrand]: true }>;
export interface IssueActivationRecoveryProof {
  executionId: string; workflowId: string; clusterId: string; workspaceId: string;
  transportScope: string; actorId: string; sessionId: string; permissionVersion: string;
  stepId: string; expiresAt: number;
}

/** Server-derived packet. A shape, workflow ID or boolean never grants access. */
export interface PortalNativePacket {
  clusterId: string; transportScope: string; workspaceId: string; operationId: string;
  method: string; canonicalPath: string; body: unknown; before: unknown;
  /** Actual durable action, including migration and target health operations. */
  mutationAction: MutationContext['action']; parentId?: string; credentialKind?: string;
}
/** Read-only prospective facts. No operation, claim or native permit exists. */
export type PortalPreparedPacket = Omit<PortalNativePacket, 'operationId'> & { nativeId: string };
export interface PortalAuthBoundaryPolicy {
  assertBeforeNativeSend(input: Readonly<PortalNativePacket>, permit: PortalBoundaryReadPermit): Promise<void>;
  assertCurrentIssueRecoveryBoundary(): Promise<void>;
  assertPreparedChange?(input: Readonly<PortalPreparedPacket>): Promise<void>;
}
export interface ApprovedPortalStepPolicy { assertNativeWrite(input: Readonly<PortalNativePacket>): Promise<void>; }
export interface ApprovedMetadataInput {
  handler: string; actor: AuthUser; clusterId: string; workspaceId: string;
  entityType: string; entityId: string; before: unknown; revision: number; payload: unknown;
}
export interface ApprovedMetadataStepPolicy { assertStep(input: Readonly<ApprovedMetadataInput>, tx: DbService): Promise<void>; }
export interface ApprovedMutationBindingV1 {
  workflowId: string; executionId: string; planRevision: number; planHash: string;
  stepId: string; beforeHmac: string;
}
export interface ApprovedMutationBindingV2 {
  version: 2; workflowId: string; configurationJobId: string; configurationExecutionId: string;
  configurationStepId: string; configurationPlanRevision: number; configurationPlanHash: string; beforeHmac: string;
}
export interface ApprovedMutationBindingV3 {
  version:3;workflowId:string;executionId:string;planRevision:number;planHash:string;stepId:string;
  sourceId:string;baselineId:string;attemptId:string;packetKey:string;nativeId:string;beforeHmac:string;
}
export type ApprovedMutationBinding = ApprovedMutationBindingV1 | ApprovedMutationBindingV2 | ApprovedMutationBindingV3;
export const isConfigurationBinding = (binding: ApprovedMutationBinding | null): binding is ApprovedMutationBindingV2 => !!binding && 'version' in binding && binding.version === 2;
/** Only Root's private job authority can verify its original claim. The
 * approved service additionally checks SQL, cryptographic plans and grants. */
export interface ConfigurationApprovedClaim {
  claimHash: string; jobId: string; actorId: string; sessionId: string | null; leaseGeneration: number;
  permissionVersion: string; expiresAt: number; workflowExecutionId: string;
  /** Produced only by the private original configuration-job verifier. The
   * persisted authoring SID remains on SQL011; it is never adopted here. */
  scheduledOrigin?: Readonly<WorkflowScheduledConfigurationExecutionProof>;
}
export interface ConfigurationApprovedDelegate {
  verifyExecution(executionId: string, tx: DbService): Promise<ConfigurationApprovedClaim>;
  /** Fixed server callback; source-origin jobs fail closed without it. The
   * actor remains the real current executor/reviewer, never a adopted SID. */
  assertOrigin?(plan: WorkflowPlanV1, actorId: string, action: 'read' | 'write' | 'approve', tx?: DbService): Promise<void>;
  /** SQL/crypto immutable origin binding only; no adopted actor or network IO. */
  assertStoredOrigin?(plan: WorkflowPlanV1, tx?: DbService): Promise<void>;
  /** One load = one step/packet checkpoint occurrence per party. */
  runLoad?<T>(fn: () => Promise<T>): Promise<T>;
}
export type ConfigurationOriginDelegate=Pick<ConfigurationApprovedDelegate,'assertOrigin'|'assertStoredOrigin'>;
export interface ConfigurationOriginMarker {kind:'governance-promote';id:string;hmac:string}
/** Values come only from the exact durable configuration job. A partial,
 * malformed or foreign marker never becomes an unmarked legacy job. */
export function configurationOriginMarker(job:Record<string,unknown>):ConfigurationOriginMarker|null{
  const kind=job.required_origin_kind,id=job.required_origin_id,hmac=job.required_origin_hmac;
  if([kind,id,hmac].every(value=>value===undefined||value===null))return null;
  if(kind!=='governance-promote'||typeof id!=='string'||!/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(id)||typeof hmac!=='string'||!/^[a-f\d]{64}$/.test(hmac))throw new Error('CONFIGURATION_ORIGIN_MARKER_INVALID');
  return{kind,id,hmac};
}
/** Bootstrap-only governance authority. It verifies immutable intent SQL and
 * live complete grants without supplying a native capability or impersonating
 * the independent reviewer in the executor's session. */
export interface GovernanceMetadataApprovedDelegate {
  verifyIntent(plan: WorkflowPlanV1, tx?: DbService): Promise<void>;
  assertSubject(plan: WorkflowPlanV1, actorId: string, action: 'read' | 'write' | 'approve', tx?: DbService): Promise<void>;
  verifyReviewer(userId: string, plan: WorkflowPlanV1, tx?: DbService): Promise<void>;
}
export interface WorkflowPolicyMetadataApprovedDelegate extends GovernanceMetadataApprovedDelegate {}
/** Bootstrap-only bridge for the original business namespace. Its read runner
 * retains the genuine namespace ancestor and independently checks current SQL
 * principals, claim/window/lease and votes without recursively entering the
 * full business verifier. Paths are requests to a fixed provider whitelist,
 * never a client-controlled expansion of read or write authority. */
export interface ApprovedWorkflowScheduledDelegate {
  /** Checkpoint-scoped configuration_v2 party round; see business runtime. */
  runConfigurationPartyCheckpoint?<T>(originalNamespaceHandle:object,phase:WorkflowScheduledNamespaceCheckpoint,tx:DbService,fn:()=>Promise<T>):Promise<T>;
  readConfigurationNativeBefore?(originalReadHandle:ConfigurationNativeBeforeReadHandle):Promise<Readonly<ConfigurationNativeBeforeReadResult>>;
  runValidationRead<T>(originalNamespaceHandle: object, clusterId: string, paths: readonly string[], tx: DbService, fn: () => Promise<T>,
    options?: Readonly<{ role: 'reviewer'; userId: string }>): Promise<T>;
  assertConfigurationOrigin(originalNamespaceHandle: object, plan: WorkflowPlanV1, actorId: string, action: 'read' | 'write' | 'approve', tx: DbService): Promise<void>;
}
/** Fixed bootstrap-only background reviewer reader. Plan JSON is only an
 * immutable selector: Root revalidates its original stored draft, current
 * reviewer and grants inside a private Candidate GET-only capsule. */
export interface ApprovedWorkflowScheduledReviewerReadPolicy {
  verifyCurrent(reviewerId: string, plan: Readonly<WorkflowScheduledPlanV1>, tx: DbService): Promise<void>;
}
/** Bootstrap-only bridge to the original job/execution WeakMaps. This method
 * accepts an opaque original execution handle, never an execution-proof DTO.
 * Missing registration keeps NULL-SID V2 mutations unavailable. */
export interface ApprovedWorkflowScheduledConfigurationDelegate {
  verifyExecution(originalExecutionHandle: WorkflowScheduledConfigurationExecutionHandle,
    checkpoint: WorkflowScheduledConfigurationCheckpoint, tx: DbService): Promise<Readonly<WorkflowScheduledConfigurationExecutionProof>>;
}
declare const configurationBeforeReadBrand:unique symbol;
export type ConfigurationNativeBeforeReadHandle=Readonly<{[configurationBeforeReadBrand]:true}>;
/** Private selector returned only after the original Approved step, complete
 * configuration SQL/AEAD and reciprocal operation binding were checked. This
 * projection is never an executable permission or an HTTP request DTO. */
export interface ConfigurationNativeBeforeReadIntent {
 readonly namespaceHandle:object;readonly namespace:Readonly<WorkflowScheduledNamespaceProof>;
 readonly clusterId:string;readonly workspaceId:string;readonly actorId:string;readonly workflowId:string;
 readonly jobId:string;readonly executionId:string;readonly jobStepId:string;readonly planStepId:string;
 readonly planId:string;readonly planRevision:number;readonly planHash:string;readonly operationId:string;
 readonly observation?:'service-destination';
 readonly method:string;readonly canonicalPath:string;readonly beforePath:string;readonly allocatedPath?:string;
 readonly entityType:string;readonly nativeId?:string;readonly allocatedNativeId?:string;readonly parentId?:string;readonly credentialKind?:string;
 readonly bodyHmac:string;readonly beforeHmac:string;readonly mutationAction:string;readonly expiresAt:number;
}
/** Observed values only. They never acknowledge a mutation or grant a send. */
export interface ConfigurationNativeBeforeReadResult {readonly before:unknown;readonly allocatedAbsent?:boolean;readonly serviceHostUpstream?:unknown|null;readonly serviceTargets?:readonly unknown[];readonly serviceReferences?:readonly Readonly<{entityType:'certificates'|'ca_certificates';entity:unknown}>[];}
export type ConfigurationNativeBeforeInput=Omit<ApprovedNativeRequest,'before'|'result'>;
export type ApprovedNativeStage = 'authorize' | 'prepare' | 'before-send' | 'response';
export interface ApprovedExecutionProof {
  executionId: string; workflowId: string; clusterId: string; workspaceId: string;
  actorId: string; sessionId: string | null; permissionVersion: string; expiresAt: number;
  /** These facts do not confer authority. A NULL SID is accepted only behind
   * the service's private execution/namespace association and SQL026 origin. */
  origin?: 'scheduled-workflow' | 'scheduled-configuration'; scheduleClaimId?: string; workflowOriginId?: string;
  configurationOriginId?: string;
  /** V2 approvals bind the complete immutable set; legacy V1 proofs retain
   * their existing single-decision checks and may omit these fields. */
  approvalFormat?: 1 | 2; approvalSetId?: string | null; approvalSetHmac?: string | null;
}
export interface ApprovedStepProof { execution: ApprovedExecutionProof; stepId: string; kind: 'native' | 'metadata'; }
export interface ApprovedNativeRequest extends PortalNativePacket {
  frame: KongExecutionFrame; cluster: KongPolicyCluster; query: Readonly<Record<string, string | number>>;
  result?: unknown;
}
/** Installed once by the approved service. Context never injects Engine. */
export interface ApprovedExecutionPolicy {
  verifyExecution(handle: ApprovedExecutionHandle): Promise<ApprovedExecutionProof>;
  /** Context's explicit NULL-SID branch must verify the original proof and
   * namespace identities. Missing implementation keeps that branch closed. */
  verifyWorkflowScheduledExecution?(execution: ApprovedExecutionProof, originalNamespaceHandle: object): Promise<void>;
  /** Distinct V2 namespace: validates the private job and nested execution,
   * not the enclosing wrapper's V1 native authority. */
  verifyWorkflowScheduledConfigurationExecution?(execution: ApprovedExecutionProof, originalNamespaceHandle: object,
    originalJobHandle: WorkflowScheduledConfigurationJobHandle): Promise<void>;
  verifyStep(execution: ApprovedExecutionProof, stepId: string): Promise<ApprovedStepProof>;
  mutationBinding(step: ApprovedStepProof, context: Readonly<MutationContext>): Promise<ApprovedMutationBinding>;
  bindOperation(step: ApprovedStepProof, context: Readonly<MutationContext>, binding: ApprovedMutationBinding, operationId: string, tx: DbService): Promise<void>;
  readConfigurationNativeBefore?(step:ApprovedStepProof,input:Readonly<ConfigurationNativeBeforeInput>,observation?:'service-destination'):Promise<Readonly<ConfigurationNativeBeforeReadResult>>;
  assertNative(step: ApprovedStepProof, input: Readonly<ApprovedNativeRequest>, stage: ApprovedNativeStage): Promise<void>;
  assertMetadata(step: ApprovedStepProof, input: Readonly<ApprovedMetadataInput>, tx: DbService): Promise<void>;
  /** An absent implementation never grants a recovery read or write. */
  verifyIssueActivationRecovery?(handle: IssueActivationRecoveryHandle): Promise<IssueActivationRecoveryProof>;
}

export function normalizedNativeRequests(requests: readonly WorkflowNativeRequest[], secrets: { fingerprint(value: unknown): string }): Array<Record<string, unknown>> {
  return requests.map(request => ({ method: request.method, path_hash: secrets.fingerprint(request.canonicalPath), native_type: request.nativeType,
    native_id: request.nativeId ?? null, parent_id: request.parentId ?? null, credential_kind: request.credentialKind ?? null,
    body_hmac: request.bodyHmac, before_hmac: request.beforeHmac ?? null }));
}
