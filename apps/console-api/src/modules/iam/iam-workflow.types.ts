import type { DbService } from '../../infrastructure/db.service';
import type { IamActor, IamScope } from './iam.types';
import type { IamMutation } from './iam-mutations.service';
import type { EffectiveGrant } from '../../common/authorization.types';
import type { WorkflowPlanV1,WorkflowHandlerInput,WorkflowReceipt } from '../workflows/workflow.types';

export const IAM_CHANGE_OPERATIONS=['create','update','status','archive','restore','permissions','clone','binding.grant','binding.revoke','binding.restore','member.add','member.revoke','member.restore'] as const;
export type IamChangeOperation=typeof IAM_CHANGE_OPERATIONS[number];
export type IamChangeResource='users'|'teams'|'roles';
export interface IamChangeRequest {
 readonly resource:IamChangeResource;readonly operation:IamChangeOperation;readonly resourceId?:string;readonly relatedId?:string;readonly input:Readonly<Record<string,unknown>>;
}
/** Actual SQL rows, including permission/binding/member dependencies. These
 * facts stay encrypted; public previews use SecretService.redact. */
export interface IamChangeBeforeGraph {
 readonly resource:unknown|null;readonly permissions:readonly unknown[];readonly bindings:readonly unknown[];readonly members:readonly unknown[];
 readonly related:readonly unknown[];
}
export interface IamCapturedChange {
 readonly request:Readonly<IamChangeRequest>;readonly mutation:Readonly<Omit<IamMutation,'actor'>>;
 readonly before:Readonly<IamChangeBeforeGraph>;readonly delegatedGrants:readonly Readonly<EffectiveGrant>[];
 readonly affectedScopes:readonly Readonly<IamScope>[];readonly allocatedIds:readonly string[];
}
export interface IamWorkflowScope {
 readonly clusterId:string;readonly workspaceId:string;readonly transportScope:string;readonly clusterRevision:number;readonly workspaceRevision:number;
 readonly executionMode:'approval';readonly clusterScopes:readonly Readonly<{clusterId:string;revision:number;executionMode:'direct'|'approval';workspaceId:string|null;workspaceRevision:number|null;transportScope:string}>[];
}
export interface IamWorkflowIntent {
 readonly version:1;readonly id:string;readonly workflowId:string;readonly actorId:string;readonly authoringSessionId:string;
 readonly credentialEpoch:string;readonly permissionVersion:string;readonly idempotencyKey:string;readonly workflowKey:string;readonly requestHmac:string;
 readonly issuedAt:string;readonly expiresAt:string;readonly capture:Readonly<IamCapturedChange>;readonly scope:Readonly<IamWorkflowScope>;
}
export interface IamMetadataPayload {readonly intentId:string;readonly resource:IamChangeResource;readonly operation:IamChangeOperation;readonly materialHmac:string;}
export interface IamWorkflowApiDelegate {
 prepare(request:unknown,actor:IamActor):Promise<Record<string,unknown>>;
 submit(intentId:string,request:unknown,actor:IamActor):Promise<Record<string,unknown>>;
 receipt(intentId:string,actor:IamActor):Promise<Record<string,unknown>>;
 receiptByKey(key:string,actor:IamActor):Promise<Record<string,unknown>>;
 assertDirectMutation(context:Readonly<IamMutation>,tx?:DbService):Promise<void>;
}
/** Fixed once-installed provider. Only an original private execution handle
 * can authorize the explicit metadata transaction; no shape grants access. */
export interface IamApprovedMutationPolicy {
 verify(originalHandle:object,context:Readonly<IamMutation>,phase:'before'|'after',tx:DbService,result?:unknown):Promise<Readonly<IamApprovedMutationBinding>>;
}
export interface IamApprovedChangePolicy {verifyCapture(originalHandle:object,capture:Readonly<IamCapturedChange>,actor:IamActor,tx:DbService):Promise<void>;}
export interface IamApprovedMutationBinding {readonly intentId:string;readonly workflowId:string;readonly executionId:string;readonly stepId:string;readonly planRevision:number;
 readonly planHash:string;readonly clusterId:string;readonly workspaceId:string;readonly actorId:string;readonly sessionId:string;readonly frameSessionId:string|null;readonly scheduledClaimId:string|null;readonly permissionVersion:string;readonly iamEpoch:string;}
export interface IamMetadataApprovedDelegate {
 verifyIntent(plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 assertSubject(plan:WorkflowPlanV1,userId:string,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
 verifyReviewer(userId:string,plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
}
/** Fixed WorkflowService tail adapter. A metadata result is recognized by
 * identity in the issuer's private WeakMap, never by its public fields. */
export interface IamMetadataCompletionDelegate {
 verifyMetadataCompletion(input:WorkflowHandlerInput,originalResult:Record<string,unknown>,beforePermissionVersion:string):Promise<void>;
 terminalReceipt(plan:WorkflowPlanV1,actor:IamActor):Promise<WorkflowReceipt>;
 reviewPreview(plan:WorkflowPlanV1,actor:IamActor):Promise<Record<string,unknown>>;
}
