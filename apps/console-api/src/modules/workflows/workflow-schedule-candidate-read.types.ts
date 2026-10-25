import type { AuthUser } from '../../common/auth';
import type { EffectiveGrant } from '../../common/authorization.types';
import type { DbService } from '../../infrastructure/db.service';
import type { WorkflowScheduledPlanV1, WorkflowScheduleDraft } from './workflow-schedule.contract';
import type { KongExecutionFrame } from '../../infrastructure/kong/execution-context.service';

/** Fixed Root admission for an original authenticated metadata HTTP ancestor.
 * It authorizes only a linked readonly candidate capsule, never a browser SID
 * identity for its reader, a scheduled Namespace or a Native permit. */
export interface WorkflowCandidateHttpAdmissionPolicy {
  verifyParent(originalReadHandle: object, actualHttpActorFrame: Readonly<KongExecutionFrame>): Promise<void>;
}

export type WorkflowScheduleCandidateRole = 'executor' | 'reviewer';
export interface WorkflowScheduleCandidatePrincipal {
  readonly user: Readonly<AuthUser>;
  readonly credentialEpoch: string;
  readonly permissionVersion: string;
  readonly grants: readonly Readonly<EffectiveGrant>[];
}
export interface WorkflowScheduleCandidateReadResource {
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly path: string;
  readonly kind: 'point' | 'collection' | 'schema';
  /** This is a server-selected read descriptor, never an HTTP allowlist. */
  readonly entityType: string;
  readonly entityId?: string;
  readonly parentId?: string;
  /** Fixed AEAD-derived Service.host lookup. This selector grants no READ or
   * absence proof; only the original validation SDK observer may establish a
   * 404, and a 200 must match this exact name and the current workspace. */
  readonly serviceHostReference?: Readonly<{ host: string; serviceIds: readonly string[] }>;
  readonly secrets: boolean;
  readonly allowAbsent?: boolean;
  readonly required?: boolean;
  /** Collection offsets are generated only from the preceding authentic
   * response. Size/tags remain fixed for the complete collection EOF. */
  readonly query?: Readonly<{ size: number; tags?: string }>;
}
export interface WorkflowScheduleCandidateReadScope {
  readonly version: 1;
  /** Fixed provider output only; ordinary / full EOF scopes omit this field. */
  readonly domain?: 'scoped-points-v1';
  readonly resources: readonly Readonly<WorkflowScheduleCandidateReadResource>[];
  readonly limits: Readonly<{ maxCalls: number; maxPages: number; maxRecords: number; maxBytes: number }>;
}
export interface WorkflowScheduleCandidateReadInput {
  readonly plan: Readonly<WorkflowScheduledPlanV1>;
  readonly draft: Readonly<WorkflowScheduleDraft>;
  readonly role: WorkflowScheduleCandidateRole;
  readonly principal: Readonly<WorkflowScheduleCandidatePrincipal>;
  readonly transaction: DbService;
}
/** Fixed material compiler. Providers invoke this only for a private original
 * SDK404 parent witness in the same live read capsule. The callback verifies
 * compiled creates and the actual principal's current READ/write/secret scope;
 * it cannot fabricate a transport observation or grant Native permission. */
export interface WorkflowScheduledParentAbsencePolicy {
  assertChild(input: WorkflowScheduleCandidateReadInput, child: Readonly<WorkflowScheduleCandidateReadResource>,
    parent: Readonly<WorkflowScheduleCandidateReadResource>): Promise<void>;
}
/** Metadata projection of a Kong 1.5 FK fact, never an SDK404 certificate. */
export interface WorkflowScheduledFutureChildAbsenceWitness {
  readonly kind: 'parent-FK-absence';
  readonly nativeRequestsSent: 0;
}
/** Every callback is installed once for the actual business kind. Scope
 * resolution/current metadata must perform no Kong read. The response
 * callback checks each real object's current scope, READ and secret grants;
 * it cannot replace a response with a caller-selected filtered subset. */
export interface WorkflowScheduleCandidateBusinessPolicy {
  resolveReadScope(input: WorkflowScheduleCandidateReadInput): Promise<Readonly<WorkflowScheduleCandidateReadScope>>;
  assertCurrent(input: WorkflowScheduleCandidateReadInput): Promise<void>;
  authorizeResponse(input: WorkflowScheduleCandidateReadInput & {
    readonly resource: Readonly<WorkflowScheduleCandidateReadResource>;
    readonly response: unknown;
    readonly status: number;
  }): Promise<void>;
}
export interface WorkflowScheduleCandidateContextRunner {
  assertNoFrame(): void;
  run<T>(originalReadHandle: object, fn: () => Promise<T>): Promise<T>;
}
/** Bootstrap-only Root implementation. Neither its handle, input, transaction,
 * observations nor responses are returned by the private group closure. */
export interface WorkflowScheduleCandidateFixedReader {
  read(originalReadHandle: object, proof: Readonly<WorkflowScheduleCandidateReadProof>,
    input: Readonly<WorkflowScheduleCandidateReadInput>): Promise<void>;
}
export type WorkflowScheduleCandidateFixedGroup = (plan: WorkflowScheduledPlanV1, actorId: string,
  role: WorkflowScheduleCandidateRole, transaction: DbService) => Promise<void>;
/** This projection is not a handle, actor identity, browser session, claim,
 * write Namespace or native permission. Root recognizes only its original
 * private frame-to-handle association and the fixed GET policy below. */
export interface WorkflowScheduleCandidateReadProof {
  readonly version: 1;
  readonly origin: 'workflow-schedule-candidate-read';
  readonly readOnly: true;
  readonly actor: Readonly<AuthUser>;
  readonly sessionId: null;
  readonly credentialEpoch: string;
  readonly permissionVersion: string;
  readonly workflowId: string;
  readonly workflowPlanRevision: number;
  readonly workflowPlanHash: string;
  readonly scheduleId: string;
  readonly role: WorkflowScheduleCandidateRole;
  readonly expiresAt: string;
  readonly scope: Readonly<WorkflowScheduleCandidateReadScope>;
  readonly registries: readonly Readonly<{ clusterId: string; workspaceId: string; transportScope: string; clusterRevision: number; workspaceRevision: number; endpointHmac: string }>[];
}
export interface WorkflowScheduleCandidateRequest {
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly method: string;
  readonly path: string;
  readonly body?: unknown;
  readonly query: Readonly<Record<string, string | number>>;
}
/** Root Context/NativePolicy adapter only. A copied proof/source/frame cannot
 * stand in for originalReadHandle or originalRequestToken. */
export interface WorkflowScheduleCandidateReadPolicy {
  verifyHandle(originalReadHandle: object): Promise<Readonly<WorkflowScheduleCandidateReadProof>>;
  assertLive(originalReadHandle: object): void;
  authorizeRequest(originalReadHandle: object, request: WorkflowScheduleCandidateRequest): Promise<object>;
  verifyRequest(originalRequestToken: object): Promise<Readonly<WorkflowScheduleCandidateReadProof>>;
  authorizeResponse(originalRequestToken: object, response: unknown, originalAbsenceObservation?: 200 | object): Promise<unknown>;
}
