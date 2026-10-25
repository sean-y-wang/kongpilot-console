import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';

export const WORKFLOW_KINDS = ['portal-publication', 'portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke', 'portal-developer-review', 'portal-metadata', 'event-metadata', 'configuration_v2', 'configuration-metadata', 'toolbox-operation', 'workspace-migration', 'governance-metadata', 'workflow-policy-metadata', 'native-change', 'iam-metadata', 'metrics-setup', 'control-metadata', 'entity-annotation'] as const;
export type WorkflowKind = typeof WORKFLOW_KINDS[number];
export type WorkflowSubjectType = 'portal_settings' | 'portal_developers' | 'portal_applications' | 'portal_publications' | 'portal_content' | 'portal_application_grants' | 'notification_channels' | 'event_subscriptions' | 'event_deliveries' | 'configuration_jobs' | 'config_snapshots' | 'config_snapshot_schedules' | 'configuration_gitops_runs' | 'toolbox_operations' | 'workspace_migration_plans' | 'governance_metadata_requests' | 'workflow_policy_requests' | 'entity_change_intents' | 'iam_metadata_requests' | 'metrics_setup_requests' | 'control_metadata_requests' | 'entity_annotation_requests';
export interface WorkflowNativeRequest {
  method: 'POST' | 'PATCH' | 'DELETE'; canonicalPath: string; nativeType: string;
  nativeId?: string; parentId?: string; credentialKind?: string;
  body?: unknown; bodyHmac: string; beforeHmac?: string;
}
export interface WorkflowStep {
  id: string; key: string; order: number; kind: 'native' | 'metadata'; handler?: string;
  entityType: string; entityId?: string; parentId?: string; credentialKind?: string;
  permissionAction: 'write' | 'delete'; dependencies: string[];
  mutationAction?: 'create' | 'update' | 'delete' | 'restore' | 'migrate';
  mutationPayload?: unknown; mutationPayloadHmac?: string; mutationIdempotencyKey?: string;
  nativeRequests: WorkflowNativeRequest[]; before?: unknown; beforeFingerprint?: string;
  metadata?: unknown; metadataBeforeHmac?: string; metadataRevision?: number; metadataPayloadHmac?: string;
}
export interface WorkflowPlanV1 {
  version: 1; clusterId: string; workspaceId: string; workflowId: string; planRevision: number; kind: WorkflowKind;
  executionMode: 'direct' | 'approval'; approvalRequired: boolean;
  subject: { type: WorkflowSubjectType; id: string };
  requester: { type: 'developer' | 'console'; id: string };
  definition: { id: string; version: number; policyHash: string };
  issuedAt: string; expiresAt: string;
  scope: { transportScope: string; clusterRevision: number; workspaceRevision: number };
  prerequisites: Array<{ type: string; id: string; path: string; fingerprint: string; before: any }>;
  steps: WorkflowStep[];
  generated?: { consumerId: string; aclId: string; credentialId: string; key: string };
  /** Present only for the fixed tag migration compiler; never supplied by HTTP. */
  migration?: { sourceWorkspaceId: string; targetWorkspaceId: string; targetWorkspaceRevision: number; materialHmac: string };
}
export interface WorkflowSnapshotV1 {
  version: 1; workflowId: string; executionId: string; clusterId: string; workspaceId: string;
  planRevision: number; planHash: string; capturedAt: string;
  objects: Array<{ type: string; id: string; path: string; before: any | null; absent: boolean; fingerprint: string }>;
}
/** Both digests use SecretService.fingerprint; no public SHA of plaintext keys. */
export const planAad = (cid: string, wid: string, id: string, revision: number) => `workflow:${cid}:${wid}:${id}:${revision}:plan`;
export const snapshotAad = (cid: string, wid: string, workflowId: string, executionId: string) => `workflow:${cid}:${wid}:${workflowId}:${executionId}:snapshot`;
export interface WorkflowHandlerInput { plan: WorkflowPlanV1; step: WorkflowStep; actor: EntityActor; executionId: string; transaction: DbService; }
export interface WorkflowHandler {
  authorize(plan: WorkflowPlanV1, actor: EntityActor, action: 'read' | 'write' | 'approve'): Promise<void>;
  prepare?(input: Omit<WorkflowHandlerInput, 'transaction'>): Promise<void>;
  inspect(input: Omit<WorkflowHandlerInput, 'transaction'>, tx: DbService): Promise<{ before: unknown; revision: number }>;
  apply(input: WorkflowHandlerInput): Promise<Record<string, unknown>>;
}
/** Fixed Root-owned adapter. Capability projections return booleans only;
 * none of these DTOs is an execution handle or a native authorization. */
export interface EntityChangeExecutorDelegate {
  canExecute(plan: WorkflowPlanV1, actor: EntityActor): Promise<boolean>;
  canPreflight(plan: WorkflowPlanV1, actor: EntityActor): Promise<boolean>;
  canRollback(plan: WorkflowPlanV1, actor: EntityActor): Promise<boolean>;
  execute(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<any>;
  historical(plan: WorkflowPlanV1, actor: EntityActor): Promise<Record<string, unknown>>;
  rollbackPrepare(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<Record<string, unknown>>;
  preflight(plan: WorkflowPlanV1, actor: EntityActor): Promise<Record<string, unknown>>;
  closeUnsent(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<Record<string, unknown>>;
  reconcileNoSend(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<Record<string, unknown>>;
  /** Missing adapter stays closed; no generic/native recovery fallback. */
  reconcileTerminalMetadata?(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<Record<string, unknown>>;
  reconcilePartialRestoreNoSend?(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<Record<string, unknown>>;
  reconcileTargetResult?(plan: WorkflowPlanV1, body: unknown, actor: EntityActor): Promise<Record<string, unknown>>;
}
export interface EntityChangeIntentCapabilities { readonly submit: boolean; }
export interface WorkflowSummary {
  id: string; kind: WorkflowKind; clusterId: string; workspaceId: string; name: string;
  /** A fixed Control metadata read selector; the actual plan anchor stays workspaceId. */
  scopeSelectorWorkspaceId?:string;
  revision: number; planRevision: number; planHash: string; state: string;
  executionMode: 'direct' | 'approval'; approvalRequired: boolean;
  createdAt: string; expiresAt: string; capabilities: Readonly<{ approve: boolean; reject: boolean; cancel: boolean; execute: boolean; reconcileMetadata?: boolean; abandonRejectedIssue?: boolean;
    /** Missing fields in historical or non-entity DTOs always mean false. */
    entityPreflight?: boolean; rollbackPrepare?: boolean }>;
  approval?: Record<string, unknown>;
  scheduled?:true;
}
export interface WorkflowReceipt {
  id: string; workflowId: string | null; executionId: string | null; clusterId: string; workspaceId: string;
  kind?:'control-metadata';scopeSelectorWorkspaceId?:string;
  idempotencyKey: string; state: string; revision: number | null; planHash: string | null;
  executionMode?: 'direct' | 'approval'; approvalRequired?: boolean;
  steps: Array<{ id: string; name: string; state: string; operationId: string | null;
    remoteStarted: boolean; remoteCompleted: boolean; recycleEntryId: string | null; errorCode: string | null }>;
  action?: 'submit' | 'approve' | 'reject' | 'execute' | 'cancel'; decisionCompleted?: boolean; submissionCompleted?: boolean; executionRequested?: boolean;
  metadataRecovery?: { eligible: boolean; kind: 'portal-credential-issue'; executionId: string; originalExecutionKeyRequired: true }
    | { eligible: boolean; kind: 'workspace-migration'; executionId:string; originalExecutionKeyRequired:true; knownNativeComplete:true; completed?:true };
  issueAbandonment?: { eligible: boolean; completed: boolean; kind: 'portal-credential-issue'; executionId: string; grantId: string; certificateId?: string; reservationReleased: boolean; originalExecutionKeyRequired: true };
  propagation: 'not_started' | 'pending' | 'acknowledged';
}
