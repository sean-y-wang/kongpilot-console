import type { AuthUser } from '../../common/auth';
import type { DbService } from '../../infrastructure/db.service';

export const CONFIGURATION_ACCESS = 'CONFIGURATION_ACCESS';
export const CONFIGURATION_CAPTURE_REPOSITORY = 'CONFIGURATION_CAPTURE_REPOSITORY';
declare const accessBrand: unique symbol;
/** A runtime WeakMap-owned handle. This TypeScript shape never grants authority. */
export type ConfigurationAccessHandle = Readonly<{ [accessBrand]: true }>;
export type ConfigurationScopeKind = 'cluster' | 'workspace' | 'services';
export interface ConfigurationScope {
  clusterId: string; workspaceId: string; transportScope: string;
  kind: ConfigurationScopeKind; rootIds: readonly string[];
}
export type ConfigurationEntityType = 'services' | 'routes' | 'consumers' | 'plugins' | 'upstreams'
  | 'targets' | 'certificates' | 'ca_certificates' | 'snis' | 'credentials';
export type ConfigurationCredentialKind = 'key-auth' | 'basic-auth' | 'jwt' | 'oauth2' | 'hmac-auth' | 'acls';
export type ConfigurationRecoveryState = 'complete' | 'requires_secret_input' | 'requires_rotation' | 'nonrestorable';
export interface ConfigurationRecovery {
  state: ConfigurationRecoveryState; blockerCodes: readonly string[];
  /** Immutable private copy, never a mutable CredentialStore reference. */
  restorePayload?: Record<string, unknown>; absoluteExpiresAt?: string | null;
  sourceCredentialRefId?: string; sourceHashHmac?: string;
}
export interface FrozenSecretMaterial {
  kind: ConfigurationCredentialKind; consumerId: string; nativeId: string;
  sourceCredentialRefId?: string; sourceHashHmac?: string;
  restorePayload: Record<string, unknown>; verifiedAt: string;
}
export interface CapturedSchemaBundle {
  entities: Readonly<Record<string, unknown>>; plugins: Readonly<Record<string, unknown>>;
  enabledPlugins: readonly string[]; kongVersion: string; adapterVersion: string; schemaHmac: string;
}
export interface CaptureObject {
  objectKey: string; entityType: ConfigurationEntityType; nativeId: string;
  parentType?: ConfigurationEntityType | null; parentId?: string | null;
  credentialKind?: ConfigurationCredentialKind | null; objectWorkspaceId: string;
  ownershipTags: readonly string[]; affected: boolean; referenceOnly: boolean;
  dependencies: readonly string[]; payload: Record<string, unknown>;
  beforeHmac: string; schemaHmac: string; observedAt: string;
  recovery: ConfigurationRecovery; managedBoundary?: 'none' | 'portal' | 'metrics';
  workspaceRevision?: number; secretCopies?: readonly FrozenSecretMaterial[];
}
export interface CaptureCollection {
  collectionKey: string; entityType: ConfigurationEntityType; parentId?: string | null;
  credentialKind?: ConfigurationCredentialKind | null; queryHmac: string; pageSize: number;
  pageCount: number; recordCount: number; terminalObserved: boolean;
  cursorChainHmac: string; coverageHmac: string;
}
export interface CaptureGraph {
  scope: ConfigurationScope; objects: readonly CaptureObject[]; collections: readonly CaptureCollection[];
  completeness: 'complete' | 'incomplete'; consistency: 'console_fenced_best_effort' | 'changed' | 'unverified';
  kongVersion: string; adapterVersion: string; schemaHmac: string; permissionVersion: string;
  captureEpoch: string; observedFrom: string; observedUntil: string;
  pageCount: number; recordCount: number; byteCount: number; nativeCallCount: number;
  warningCodes: readonly string[];
  requiredCollections: readonly string[]; schemas: CapturedSchemaBundle;
  credentialEpoch: number; clusterRevision: number; workspaceRevision: number; nodeId?: string;
  jobId: string; snapshotId: string; versionId: string; materialId: string;
}
export type ConfigurationStoragePhase = 'capture-page' | 'seal' | 'read' | 'plan' | 'step' | 'ledger' | 'download' | 'purge' | 'metadata-write';
export interface ConfigurationStorageAccess {
  scope: ConfigurationScope; phase: ConfigurationStoragePhase; jobId?: string; artifactId?: string;
  planId?: string; planRevision?: number; planHash?: string; leaseGeneration?: number;
}
export interface ConfigurationAccessProof {
  actorId: string; sessionId?: string | null; permissionVersion: string;
  scope: ConfigurationScope; expiresAt: number;
  captureEpoch: string; clusterRevision: number; workspaceRevision: number; credentialEpoch: number;
  nativeUsage?: {calls: number; pages: number; records: number; bytes: number};
  /** Minted only by Root's schedule-run verifier, never a caller-origin DTO. */
  origin?: 'http' | 'schedule' | 'pipeline'; scheduleRunId?: string;
}
/** Root provides the implementation; repositories do not mint or deserialize handles. */
export interface ConfigurationStorageAccessPolicy {
  verifyDurablePlan?(handle:ConfigurationAccessHandle,row:any,plan:ConfigPlan,tx:DbService):Promise<void>;
  assertStorage(handle: ConfigurationAccessHandle, input: Readonly<ConfigurationStorageAccess>, tx: DbService): Promise<ConfigurationAccessProof>;
}
export interface ConfigurationAccessAcquireInput {
  actor: AuthUser; clusterId: string; workspaceId?: string; kind: ConfigurationScopeKind;
  rootIds?: readonly string[]; purpose: 'capture' | 'compare' | 'export' | 'import' | 'apply' | 'rollback';
}
export interface CaptureFence extends ConfigurationAccessProof {
  kongVersion: string; nodeId?: string; adapterVersion: string;
  enabledPlugins: readonly string[]; jobId?: string; leaseGeneration?: number;
  nativeUsage?: { calls: number; pages: number; records: number; bytes: number };
}
export interface CaptureReadBudget { calls: number; pages: number; records: number; bytes: number; startedAt: number; }
export interface ConfigurationAccessPolicy extends ConfigurationStorageAccessPolicy {
  acquire(jobId: string): Promise<ConfigurationAccessHandle>;
  acquireJob(input: ConfigurationAccessAcquireInput & { kindOfJob: string; idempotencyKey: string }): Promise<ConfigurationAccessHandle>;
  assertCurrent(handle: ConfigurationAccessHandle, input: { phase: string; jobId?: string; scope?: ConfigurationScope; manifestHash?: string }, tx?: DbService): Promise<CaptureFence>;
  runRead<T>(handle: ConfigurationAccessHandle, paths: readonly string[], fn: (usage: () => CaptureReadBudget) => Promise<T>): Promise<T>;
  resolveOwnership(handle: ConfigurationAccessHandle, input: { entityType: ConfigurationEntityType; nativeId: string; payload: Record<string, unknown>; parent?: CaptureObject; parentId?: string; credentialKind?: ConfigurationCredentialKind; referenceOnly: boolean }): Promise<CaptureOwnership>;
  assertObject(handle: ConfigurationAccessHandle, input: { entityType: ConfigurationEntityType; nativeId: string; payload: Record<string, unknown>; parentId?: string; credentialKind?: ConfigurationCredentialKind; secrets: boolean }): Promise<void>;
  freezeRecovery(handle: ConfigurationAccessHandle, input: { entityType: ConfigurationEntityType; nativeId: string; payload: Record<string, unknown>; parentId?: string; credentialKind?: ConfigurationCredentialKind; observedAt: string }): Promise<ConfigurationRecovery>;
}
export interface CaptureOwnership { workspaceId: string; workspaceRevision: number; physicalTags: readonly string[]; managedBoundary?: 'none' | 'portal' | 'metrics'; }
export type ConfigurationCaptureAccessPolicy = ConfigurationAccessPolicy;
export type ConfigurationClaim = ConfigurationAccessHandle;
export interface CaptureStage {
  jobId: string; snapshotId: string; versionId: string; materialId: string; leaseGeneration: number;
}
export interface StagePageInput {
  jobId: string; collectionKey: string; pageNo: number; queryHmac: string; cursorHmac: string;
  nextCursor?: string | null; records: readonly Record<string, unknown>[];
  terminalObserved: boolean; byteCount: number; leaseGeneration: number;
}
export interface SnapshotSummary {
  id: string; clusterId: string; workspaceId: string; name: string; description: string;
  state: 'capturing' | 'ready' | 'incomplete' | 'failed' | 'deleted' | 'expired'; revision: number;
  currentVersion: number | null; versionId?: string; scopeKind: ConfigurationScopeKind; rootIds:readonly string[];
  objectCount: number; pageCount: number; recordCount: number; byteCount: number;
  completeness: 'complete' | 'incomplete' | null; consistency: CaptureGraph['consistency'] | null;
  recovery: Readonly<Record<ConfigurationRecoveryState, number>>; warningCodes: readonly string[];
  createdAt: string; updatedAt: string;
}
export interface ConfigurationNativeRequest {
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE'; canonicalPath: string;
  body: unknown; bodyHmac: string; beforeHmac: string;
}
export interface ConfigurationPlanStep {
  stepId: string; stepOrder: number; objectKey: string; entityType: ConfigurationEntityType;
  objectWorkspaceId: string; clearMap: readonly string[];
  nativeId?: string | null; allocatedNativeId?: string | null;
  parentType?: ConfigurationEntityType | null; parentId?: string | null;
  credentialKind?: ConfigurationCredentialKind | null;
  permissionAction: 'write' | 'delete'; mutationAction: 'create' | 'update' | 'delete';
  dependencies: readonly string[]; body: Record<string, unknown> | null; before: unknown;
  /** Compiler-owned SDK envelope, encrypted and covered by the immutable plan
   * HMAC. Native writes always use the sealed delta, never this envelope. */
  deckWirePayload?: Record<string, unknown>;
  /** Only top-level fields proven to be sets by the captured entity schema.
   * This metadata is covered by the same immutable plan HMAC. */
  deckWireSetFields?: readonly string[];
  bodyHmac: string; beforeHmac: string; nativeRequests: readonly ConfigurationNativeRequest[];
  referenceOnly: boolean; blockerCodes: readonly string[]; maskedDiff: readonly unknown[];
}
export interface ConfigPlan {
  /** Present only on newly issued durable material; never an import DTO. */
  durableRef?: Readonly<{version:1;domain:'durable-configuration-v1';issueId:string}>;
  /** Required persistent provenance; never accepted from a public import DTO. */
  originRef?: ConfigurationOriginRef;
  scope: ConfigurationScope; mode: 'merge' | 'sync' | 'rollback'; steps: readonly ConfigurationPlanStep[];
  sourceManifestHmac: string; baselineManifestHmac: string; schemaHmac: string;
  permissionVersion: string; clusterRevision: number; workspaceRevision: number;
  kongVersion: string; recoveryComplete: boolean; expiresAt: string;
}
export interface ConfigurationOriginRef {version:1;kind:'governance-promote';originId:string;materialHmac:string;}
export interface ConfigurationPromotionSourcePolicy {
  acquire(promotionId:string,actor:import('../entities/entities.types').EntityActor):Promise<{
    source:import('../governance/comparison-types').ComparisonInventory;target:import('../governance/comparison-types').ComparisonInventory;
    sourceNativeFingerprints:Readonly<Record<string,string>>;targetNativeFingerprints:Readonly<Record<string,string>>;
    options:import('../governance/comparison-types').PromoteOptions;handle:object;
  }>;
  refresh(promotionId:string,handle:object,actor:import('../entities/entities.types').EntityActor):Promise<import('../governance/comparison-types').ComparisonInventory>;
  fingerprints(promotionId:string,handle:object,inventory:import('../governance/comparison-types').ComparisonInventory):Promise<Readonly<Record<string,string>>>;
  /** Per-packet fence: re-read only the selected source objects' private fingerprints. */
  selectedFingerprints?(promotionId:string,handle:object,actor:import('../entities/entities.types').EntityActor,selected:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]):Promise<Readonly<Record<string,string>>>;
  assertCurrent(promotionId:string,handle:object):Promise<void>;
  /** SQL-only private job verifier boundary; never starts a native read or
   * adopts a caller's ambient actor context. */
  assertVerifierCurrent(promotionId:string,handle:object,origin:{actorId:string;sessionId:string;frame:import('../../infrastructure/kong/execution-context.service').KongExecutionFrame},tx?:DbService):Promise<void>;
  assertGrants(promotionId:string,actorId:string,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
}
export interface ConfigurationPromotionRecoveryDelegate {
  read(binding:Record<string,any>,source:import('../governance/comparison-types').ComparisonInventory,actor:import('../entities/entities.types').EntityActor):Promise<{graph:CaptureGraph;handle:ConfigurationAccessHandle}>;
  verify(handle:ConfigurationAccessHandle,graph:CaptureGraph):Promise<CaptureFence>;
}
export interface ConfigurationPlanIdentity {
  planId: string; planRevision: number; planHash: string; jobId: string;
}
export interface ConfigurationJobSummary {
  id: string; clusterId: string; workspaceId: string; kind: string; state: string; revision: number;
  safeProgress: Record<string, unknown>; errorCode: string | null; createdAt: string; completedAt: string | null;
}
export interface ConfigurationList<T> { items: T[]; nextCursor: string | null; size: number; total: null; }
export interface ConfigurationCaptureRepository {
  stagePage(handle: ConfigurationAccessHandle, input: StagePageInput): Promise<void>;
  stageObject(handle: ConfigurationAccessHandle, input: {jobId: string; object: CaptureObject; leaseGeneration: number}): Promise<void>;
  collectionEOF(handle: ConfigurationAccessHandle, input: {jobId: string; collection: CaptureCollection; leaseGeneration: number}): Promise<void>;
  sealSnapshot(handle: ConfigurationAccessHandle, input: {jobId: string; graph: CaptureGraph; leaseGeneration: number}): Promise<SnapshotSummary>;
}
export interface SnapshotScheduleSummary {
  id: string; clusterId: string; workspaceId: string; name: string; ownerUserId: string;
  state: 'active'|'paused'|'deleted'; revision: number; currentVersion: number;
  scopeKind: ConfigurationScopeKind; rootIds: readonly string[]; intervalMinutes: number;
  timezone: string; retentionDays: number; nextRunAt: string; purgedAt:string|null; createdAt: string; updatedAt: string;
}
export interface ConfigurationEvidenceWriter {
  jobCreated(tx:DbService,before:null,after:ConfigurationJobSummary):Promise<void>;
  snapshotSealed(tx:DbService,before:ConfigurationJobSummary,after:ConfigurationJobSummary,snapshot:SnapshotSummary):Promise<void>;
  metadataChanged(tx:DbService,evidence:ConfigurationMetadataEvidence):Promise<void>;
}
export interface ConfigurationGitOpsSummary {
  id:string;clusterId:string;workspaceId:string;jobId:string;createdBy:string;
  repositoryLabel:string;commitSha:string;pipelineReference:string;
  state:ConfigurationJobSummary['state'];createdAt:string;
}
export type ConfigurationMetadataEvidence = {
  scope:ConfigurationScope;resourceId:string;action:'create'|'update'|'archive'|'restore'|'purge';
} & ({resourceType:'config_snapshots';before:SnapshotSummary|null;after:SnapshotSummary;
  result?:{destroyedMaterials:number;backupCopiesMayRetainKeys:true}}
  | {resourceType:'config_snapshot_schedules';before:SnapshotScheduleSummary|null;after:SnapshotScheduleSummary}
  | {resourceType:'configuration_gitops_runs';before:null;after:ConfigurationGitOpsSummary});
export interface ConfigurationDownloadEvidence {
  scope:ConfigurationScope;grantId:string;exportId:string;actorId:string;
  action:'issue'|'consume';state:'ready'|'consumed';mode:'review'|'deployment';
  format:'deck-1.1'|'review-json';byteCount:number;expiresAt:string;
}
export interface ConfigurationDeckEvidence {
  scope:ConfigurationScope;id:string;jobId:string;actorId:string;purpose:'read'|'write';
  state:'active'|'revoked'|'expired'|'budget_exceeded';revision:number;expiresAt:string;
  planId?:string;planRevision?:number;planHash?:string;
}
export interface ConfigurationDeckEvidenceWriter {
  sessionChanged(tx:DbService,evidence:{action:'issue'|'revoke'|'expire'|'budget_exceeded';before:ConfigurationDeckEvidence|null;after:ConfigurationDeckEvidence}):Promise<void>;
}
