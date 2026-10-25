import type { DbService } from '../../infrastructure/db.service';
import type { EntityActor } from '../entities/entities.types';
import type { IamMutation } from '../iam/iam-mutations.service';
import type { WorkflowHandlerInput, WorkflowPlanV1, WorkflowReceipt } from '../workflows/workflow.types';

export const CONTROL_CHANGE_RESOURCES=['clusters','data-sources','workspaces','recycle-bin'] as const;
export const CONTROL_CHANGE_OPERATIONS=['create','update','deactivate','archive','restore','purge'] as const;
export type ControlChangeResource=typeof CONTROL_CHANGE_RESOURCES[number];
export type ControlChangeOperation=typeof CONTROL_CHANGE_OPERATIONS[number];
export interface ControlChangeRequest {
 readonly resource:ControlChangeResource;readonly operation:ControlChangeOperation;
 readonly resourceId?:string;readonly input:Readonly<Record<string,unknown>>;
}
export interface ControlBusinessMutation {
 readonly resource:ControlChangeResource;readonly operation:ControlChangeOperation;readonly clusterId:string;readonly resourceId:string;
 readonly module:string;readonly action:'write'|'delete';readonly workspaceId:string|null;readonly actor:EntityActor;readonly payload:unknown;
}
/** The original services install these server functions once. No request may
 * select a transaction, an execution handle, or an approval bypass. */
export interface ControlBusinessBridge {
 currentTransaction():DbService|undefined;
 allocateId():string;
 execute<T>(mutation:ControlBusinessMutation,fn:(tx:DbService)=>Promise<T>,direct:()=>Promise<T>):Promise<T>;
 completed<T>(context:IamMutation):Promise<{result:T}|null>;
}
export interface ControlCapturedChange {
 readonly request:Readonly<ControlChangeRequest>;readonly mutation:Readonly<Omit<ControlBusinessMutation,'actor'>>;
 readonly before:Readonly<Record<string,unknown>>|null;readonly allocatedIds:readonly string[];
}
export interface ControlWorkflowScope {
 readonly clusterId:string;readonly workspaceId:string;readonly targetWorkspaceId:string|null;readonly transportScope:string;
 readonly clusterRevision:number;readonly workspaceRevision:number;readonly executionMode:'approval';
}
export interface ControlWorkflowIntent {
 readonly version:1;readonly id:string;readonly workflowId:string;readonly actorId:string;readonly authoringSessionId:string;
 readonly credentialEpoch:string;readonly permissionVersion:string;readonly idempotencyKey:string;readonly workflowKey:string;readonly requestHmac:string;
 readonly issuedAt:string;readonly expiresAt:string;readonly capture:Readonly<ControlCapturedChange>;readonly scope:Readonly<ControlWorkflowScope>;
}
export interface ControlMetadataPayload {readonly intentId:string;readonly resource:ControlChangeResource;readonly operation:ControlChangeOperation;readonly materialHmac:string;}
export interface ControlApprovedMutationPolicy {
 verifyCapture(originalHandle:object,capture:Readonly<ControlCapturedChange>,actor:EntityActor,tx:DbService):Promise<void>;
 verifyMutation(originalHandle:object,mutation:Readonly<ControlBusinessMutation>,phase:'before'|'after',tx:DbService,result?:unknown,after?:Readonly<Record<string,unknown>>|null):Promise<void>;
}
export interface ControlMetadataApprovedDelegate {
 verifyIntent(plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 assertSubject(plan:WorkflowPlanV1,userId:string,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
 verifyReviewer(userId:string,plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 assertWorkflowAdmission(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
}
export interface ControlMetadataCompletionDelegate {
 verifyMetadataCompletion(input:WorkflowHandlerInput,originalResult:Record<string,unknown>,beforePermissionVersion:string):Promise<void>;
 terminalReceipt(plan:WorkflowPlanV1,actor:EntityActor):Promise<WorkflowReceipt>;
 reviewPreview(plan:WorkflowPlanV1,actor:EntityActor):Promise<Record<string,unknown>>;
}
