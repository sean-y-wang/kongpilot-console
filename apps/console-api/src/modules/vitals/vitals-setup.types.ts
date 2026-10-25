import type {DbService} from '../../infrastructure/db.service';
import type {WorkflowPlanV1,WorkflowStep} from '../workflows/workflow.types';
import type {EntityActor} from '../entities/entities.types';
import type {MetricsSourceConnection} from './providers/metrics-source.service';

export type MetricsSetupMode='native_prometheus'|'collector';
export interface MetricsSetupControl {readonly revision:number;readonly activeSourceId:string|null;readonly enabled:boolean;readonly collectorEnabled:boolean;
 readonly credentialGeneration:number;readonly maxAgeMs:number;readonly capabilities:Readonly<Record<string,unknown>>;}
export interface MetricsSetupPlugin {readonly name:'prometheus'|'http-log';readonly workspaceId:string;readonly workspaceRevision:number;readonly nativeId:string;
 readonly action:'create'|'update';readonly before:unknown|null;readonly payload:Readonly<Record<string,unknown>>;readonly schemaHmac:string;}
export interface MetricsSetupIntent {readonly version:1;readonly id:string;readonly workflowId:string;readonly actorId:string;readonly authoringSessionId:string;
 readonly credentialEpoch:string;readonly permissionVersion:string;readonly idempotencyKey:string;readonly workflowKey:string;readonly requestHmac:string;
 readonly clusterId:string;readonly workspaceId:string;readonly clusterName:string;readonly clusterRevision:number;readonly workspaceRevision:number;readonly transportScope:string;
 readonly definition:Readonly<{id:string;version:number;policyHash:string}>;readonly mode:MetricsSetupMode;readonly source:Readonly<MetricsSourceConnection>;readonly settings:Readonly<MetricsSetupControl>;
 readonly ingest:Readonly<{generation:number;fingerprint:string}>|null;readonly plugins:readonly Readonly<MetricsSetupPlugin>[];readonly issuedAt:string;readonly expiresAt:string;}
export interface MetricsSetupMetadata {readonly intentId:string;readonly mode:MetricsSetupMode;readonly sourceId:string;readonly materialHmac:string;}
/** Fixed providers authenticate the original private Approved execution. The
 * public execution ID or a copied plan is never itself an execution permit. */
export interface MetricsSetupExecutionBridge {verify(plan:WorkflowPlanV1,executionId:string,phase:'native'|'metadata',tx?:DbService):Promise<void>;}
export interface MetricsSetupApprovedDelegate {verifyIntent(plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 assertSubject(plan:WorkflowPlanV1,userId:string,action:'read'|'write'|'approve',tx?:DbService):Promise<void>;
 verifyReviewer(userId:string,plan:WorkflowPlanV1,tx?:DbService):Promise<void>;
 nativeWorkspace(plan:WorkflowPlanV1,step:WorkflowStep,tx?:DbService):Promise<string>;}
export interface MetricsSetupExecutionDelegate {runManagedNative<T>(plan:WorkflowPlanV1,executionId:string,fn:()=>Promise<T>):Promise<T>;
 nativeWorkspace(plan:WorkflowPlanV1,step:WorkflowStep,tx?:DbService):Promise<string>;
 reviewPreview(plan:WorkflowPlanV1,actor:EntityActor):Promise<Record<string,unknown>>;}
export const metricsSetupAad=(id:string)=>`metrics-setup:${id}:intent`;
