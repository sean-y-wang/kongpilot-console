import type {DbService} from '../../infrastructure/db.service';
import type {AuditEvent,AuditOutboxReceipt} from '../audit/audit.service';
import type {EntityActor,EntityType} from '../entities/entities.types';
import type {EntityAnnotationRow} from '../workspaces/entity-annotations.service';
import type {WorkflowHandlerInput,WorkflowPlanV1,WorkflowReceipt} from '../workflows/workflow.types';

export const ANNOTATION_CHANGE_OPERATIONS=['set','remove','restore'] as const;
export type AnnotationChangeOperation=typeof ANNOTATION_CHANGE_OPERATIONS[number];
export interface AnnotationChangeRequest {readonly entityType:EntityType;readonly entityId:string;readonly operation:AnnotationChangeOperation;readonly input:Readonly<Record<string,unknown>>;}
export interface AnnotationNativeNode {readonly entityType:EntityType;readonly entity:Readonly<Record<string,unknown>>;readonly workspaceId:string;}
export interface AnnotationNativeProof {readonly root:Readonly<AnnotationNativeNode>;readonly parents:readonly Readonly<AnnotationNativeNode>[];readonly serviceRoutes:readonly Readonly<AnnotationNativeNode>[];readonly routesComplete:boolean;}
export interface AnnotationBusinessMutation {readonly clusterId:string;readonly workspaceId:string;readonly entityType:EntityType;readonly entityId:string;readonly operation:AnnotationChangeOperation;readonly action:'write'|'delete';readonly actor:EntityActor;readonly input:Readonly<Record<string,unknown>>;readonly entity:Readonly<Record<string,unknown>>;readonly retentionDays:number|null;}
export interface AnnotationOriginalSource {
 observe(clusterId:string,entityType:EntityType,entityId:string,actor:EntityActor,action:'read'|'write'|'delete',workspaceId:string):Promise<Readonly<{entity:Readonly<Record<string,unknown>>;workspaceId:string}>>;
 readAnnotation(clusterId:string,entityType:EntityType,entityId:string,tx:DbService):Promise<EntityAnnotationRow|null>;
}
/** Once-installed, fixed original metadata closures only. Neither request
 * selectors nor this bridge grant a Kong native write or an IAM permission. */
export interface AnnotationBusinessBridge {
 currentTransaction():DbService|undefined;
 execute<T>(mutation:AnnotationBusinessMutation,inspect:(tx:DbService)=>Promise<EntityAnnotationRow|null>,apply:(tx:DbService,before:EntityAnnotationRow|null)=>Promise<T>,direct:()=>Promise<T>):Promise<T>;
 appendAudit(event:AuditEvent,tx:DbService):Promise<AuditOutboxReceipt>;
}
export interface AnnotationCapturedChange {readonly request:Readonly<AnnotationChangeRequest>;readonly mutation:Readonly<Omit<AnnotationBusinessMutation,'actor'>>;readonly before:Readonly<EntityAnnotationRow>|null;readonly nativeProof:Readonly<AnnotationNativeProof>;}
export interface AnnotationWorkflowScope {readonly clusterId:string;readonly workspaceId:string;readonly transportScope:string;readonly clusterRevision:number;readonly workspaceRevision:number;readonly executionMode:'approval';}
export interface AnnotationWorkflowIntent {readonly version:1;readonly id:string;readonly workflowId:string;readonly actorId:string;readonly authoringSessionId:string;readonly credentialEpoch:string;readonly permissionVersion:string;readonly idempotencyKey:string;readonly workflowKey:string;readonly requestHmac:string;readonly issuedAt:string;readonly expiresAt:string;readonly capture:Readonly<AnnotationCapturedChange>;readonly scope:Readonly<AnnotationWorkflowScope>;}
export interface AnnotationMetadataPayload {readonly intentId:string;readonly entityType:EntityType;readonly entityId:string;readonly operation:AnnotationChangeOperation;readonly materialHmac:string;}
export interface AnnotationApprovedMutationPolicy {
 verifyCapture(originalHandle:object,capture:Readonly<AnnotationCapturedChange>,actor:EntityActor,tx:DbService):Promise<Readonly<{workflowId:string}>>;
 verifyMutation(originalHandle:object,mutation:Readonly<AnnotationBusinessMutation>,phase:'before'|'after',tx:DbService,result?:unknown,after?:Readonly<EntityAnnotationRow>|null,audit?:Readonly<AuditOutboxReceipt>):Promise<void>;
}
export interface EntityAnnotationApprovedDelegate {
 verifyIntent(plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 assertSubject(plan:WorkflowPlanV1,userId:string,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
 verifyReviewer(userId:string,plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 assertWorkflowAdmission(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
}
export interface EntityAnnotationCompletionDelegate {
 verifyMetadataCompletion(input:WorkflowHandlerInput,originalResult:Record<string,unknown>,beforePermissionVersion:string):Promise<void>;
 terminalReceipt(plan:WorkflowPlanV1,actor:EntityActor):Promise<WorkflowReceipt>;
 reviewPreview(plan:WorkflowPlanV1,actor:EntityActor):Promise<Record<string,unknown>>;
}
