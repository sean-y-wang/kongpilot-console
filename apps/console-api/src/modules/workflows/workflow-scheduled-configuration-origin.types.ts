import type { DbService } from '../../infrastructure/db.service';
import type { ConfigurationJobExecutionProof } from '../../infrastructure/kong/execution-context.service';
import type { ConfigPlan } from '../configuration/configuration.types';
import type { WorkflowBusinessSubjectSealV1, WorkflowScheduledPlanV1, WorkflowScheduleDraft } from './workflow-schedule.contract';
import type { WorkflowScheduledNamespaceProof } from './workflow-scheduled-authority.types';

/** These checkpoints never certify an outcome or acknowledge a response.
 * Actual post-wire facts belong to the independent original failure ledger. */
export type WorkflowScheduledConfigurationCheckpoint = 'claim' | 'capture' | 'ledger' | 'step' | 'packet' | 'before-send';
export type WorkflowScheduledConfigurationExecutionCheckpoint = Extract<WorkflowScheduledConfigurationCheckpoint, 'step' | 'packet' | 'before-send'>;
declare const scheduledJobBrand: unique symbol;
declare const scheduledConfigurationExecutionBrand: unique symbol;
export type WorkflowScheduledConfigurationJobHandle = Readonly<{ [scheduledJobBrand]: true }>;
export type WorkflowScheduledConfigurationExecutionHandle = Readonly<{ [scheduledConfigurationExecutionBrand]: true }>;

/** Server-only authenticated material. Raw plans and native secrets must
 * never be projected to an HTTP response, log, audit or candidate DTO. */
export interface WorkflowScheduledConfigurationMaterial {
  readonly job: Readonly<Record<string, any>>;
  readonly version: Readonly<Record<string, any>>;
  readonly planRow: Readonly<Record<string, any>>;
  readonly material: Readonly<Record<string, any>>;
  readonly plan: Readonly<ConfigPlan>;
  readonly sourceOrigin: Readonly<Record<string, any>> | null;
  readonly subjectSeal: Readonly<WorkflowBusinessSubjectSealV1>;
}

/** Private SQL comparison evidence only. The fixed Material provider authenticates
 * both import/apply materials before constructing this value. It grants no read,
 * principal, Native permit or reusable authority and is never a public DTO. */
export interface WorkflowScheduledConfigurationPromoteSqlMaterial {
  readonly version: 1;
  readonly jobId: string;
  readonly marker: Readonly<{ kind: 'governance-promote'; id: string; hmac: string }>;
  readonly subjectSeal: Readonly<WorkflowBusinessSubjectSealV1>;
  readonly sourceOrigin: Readonly<Record<string, any>>;
  readonly configurationLineage: Readonly<{ importJobId: string; importPlanId: string; authorityExpiresAt: string; expiresAt: string; planExpiresAt: string }>;
  readonly registries: readonly Readonly<{ cluster: Readonly<Record<string, unknown>>; workspace: Readonly<Record<string, unknown>> }>[];
  readonly deadlines: Readonly<{ importAuthority: string; importJob: string; importPlan: string;
    applyAuthority: string; applyJob: string; applyVersion: string; configurationPlan: string; wrapperPlan: string;
    delegation: string; windowEnd: string }>;
  /** Sampled database wall time is used for expiry, never compared as material. */
  readonly observedAt: string;
}
export interface WorkflowScheduledConfigurationPromoteSqlPolicy {
  observe(plan: Readonly<WorkflowScheduledPlanV1>, draft: Readonly<WorkflowScheduleDraft>, tx: DbService): Promise<Readonly<WorkflowScheduledConfigurationPromoteSqlMaterial>>;
}
export interface WorkflowScheduledConfigurationInspection extends WorkflowScheduledConfigurationMaterial {
  readonly originalNamespaceHandle: object;
  readonly namespace: Readonly<WorkflowScheduledNamespaceProof>;
  readonly wrapper: Readonly<WorkflowScheduledPlanV1>;
  readonly wrapperOrigin: Readonly<Record<string, any>>;
  readonly wrapperExecution: Readonly<Record<string, any>>;
  readonly configurationExecution?: Readonly<Record<string, any>>;
  readonly configurationOrigin?: Readonly<Record<string, any>>;
  readonly rows?: readonly Readonly<Record<string, any>>[];
}

/** Bootstrap installs one fixed private verifier. It returns no principal,
 * grant, permit, handle or caller-selected policy. Candidate handles must be
 * independently issued by Root's real readonly provider. Live verification
 * keeps the original scheduled namespace ancestor and uses a separate private
 * validation-read brand; it must not clear ALS or reenter full Authority/NS
 * verification while checking reviewers or Promote source entities. */
export interface WorkflowScheduledConfigurationRootVerifier {
  assertCandidateRead(originalCandidateHandle: object, jobId: string, actorId: string, tx: DbService): Promise<void>;
  assertCandidateMaterial(originalCandidateHandle: object, material: Readonly<WorkflowScheduledConfigurationMaterial>, actorId: string, tx: DbService): Promise<void>;
  /** SQL-only identity observation for an existing original ledger. It must
   * retain the actual Namespace proof reference and cannot issue a capability. */
  assertLedgerCurrent(originalNamespaceHandle: object, originalNamespace: Readonly<WorkflowScheduledNamespaceProof>, tx: DbService): Promise<void>;
  /** Optional: one checkpoint occurrence's shared party observation round. */
  runLiveCheckpoint?<T>(originalNamespaceHandle: object, checkpoint: Exclude<WorkflowScheduledConfigurationCheckpoint, 'ledger'>, tx: DbService, fn: () => Promise<T>): Promise<T>;
  assertLiveMaterial(inspection: Readonly<WorkflowScheduledConfigurationInspection>, checkpoint: WorkflowScheduledConfigurationCheckpoint, tx: DbService): Promise<void>;
  /** Fixed canonical SQL closing observation for one original nested checkpoint.
   * It repeats the canonical approval/candidate/grant policy in the exact old
   * Namespace and cannot read Native, create authority or extend a deadline. */
  openClosedCheckpoint(originalNamespaceHandle: object, originalNamespaceProof: Readonly<WorkflowScheduledNamespaceProof>,
    checkpoint: WorkflowScheduledConfigurationCheckpoint, tx: DbService): Promise<object>;
  assertClosedCheckpoint(originalObservation: object, originalNamespaceHandle: object, originalNamespaceProof: Readonly<WorkflowScheduledNamespaceProof>,
    checkpoint: WorkflowScheduledConfigurationCheckpoint, tx: DbService): Promise<void>;
  /** Final synchronous original/deadline/lease fence after async close. The
   * sealed comparison stays private until release and grants no capability. */
  assertClosedCheckpointLive(originalObservation: object, originalNamespaceHandle: object, originalNamespaceProof: Readonly<WorkflowScheduledNamespaceProof>,
    checkpoint: WorkflowScheduledConfigurationCheckpoint, tx: DbService): void;
  releaseClosedCheckpoint(originalObservation: object): void;
}

/** Evidence only. Core must recognize the original WeakMap job handle and
 * retain its actual scheduled namespace ancestor before allowing NULL SID.
 * The author's persisted HTTP SID is preserved, never adopted or renewed. */
export interface WorkflowScheduledConfigurationJobProof extends ConfigurationJobExecutionProof {
  readonly origin: 'workflow-scheduled-configuration';
  readonly sessionId: null;
  readonly readOnly: false;
  readonly module: 'snapshots';
  readonly purpose: 'apply' | 'rollback';
  readonly namespaceHandle: object;
  readonly claimId: string;
  readonly wrapperOriginId: string;
  readonly wrapperExecutionId: string;
  readonly planId: string;
  readonly planRevision: number;
  readonly planHash: string;
  readonly subjectSealHmac: string;
}
export interface WorkflowScheduledConfigurationExecutionProof {
  readonly origin: 'workflow-scheduled-configuration';
  readonly sessionId: null;
  readonly jobHandle: WorkflowScheduledConfigurationJobHandle;
  readonly namespaceHandle: object;
  readonly claimId: string;
  readonly wrapperOriginId: string;
  readonly wrapperExecutionId: string;
  readonly configurationOriginId: string;
  readonly configurationExecutionId: string;
  readonly configurationJobId: string;
  readonly configurationPlanId: string;
  readonly configurationPlanRevision: number;
  readonly configurationPlanHash: string;
  readonly configurationClaimHash: string;
  readonly workflowId: string;
  readonly workflowPlanRevision: number;
  readonly workflowPlanHash: string;
  readonly actorId: string;
  readonly clusterId: string;
  readonly workspaceId: string;
  readonly permissionVersion: string;
  readonly credentialEpoch: number;
  readonly leaseGeneration: number;
  readonly expiresAt: number;
}

/** Evidence from one closed original nested observation; neither proof is authority. */
export interface WorkflowScheduledConfigurationExecutionAndJobProof {
  readonly job: Readonly<WorkflowScheduledConfigurationJobProof>;
  readonly execution: Readonly<WorkflowScheduledConfigurationExecutionProof>;
}
