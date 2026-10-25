import type { EntityActor } from '../entities/entities.types';

export type GovernanceModuleName='governance'|'lint'|'drift'|'promote';
export type GovernanceMetadataResource='governance_rules'|'governance_schedules'|'entity_annotations';
export type GovernanceMetadataOperation='create'|'update'|'archive'|'restore';
export interface GovernanceScopeSnapshot {clusterId:string;workspaceId:string;transportScope:string;clusterRevision:number;workspaceRevision:number;executionMode:'direct'|'approval';permissionVersion:string;originalRequest?:{type:GovernanceMetadataResource;target:string|null;operation:GovernanceMetadataOperation;input:Record<string,any>};}
export interface GovernanceReceipt {
 id:string;actorId:string;clusterId:string;workspaceId:string;idempotencyKey:string;
 domain:'governance'|'iam'|'workflow';kind:'inspection'|'comparison'|'promotion-plan'|'fix-plan'|'rule-change'|'schedule-change';
 state:string;registrationCompleted:boolean;submissionCompleted:boolean;executionCompleted:boolean;nativeExecutionRequested:false;
 configurationCommitted?:boolean;workflowId?:string;jobId?:string;planId?:string;targetClusterId?:string;targetWorkspaceId?:string;entity?:Record<string,unknown>;result?:Record<string,unknown>;
}
export interface GovernanceMetadataIntent {
 id:string;clusterId:string;workspaceId:string;actorId:string;resourceType:GovernanceMetadataResource;resourceId:string;
 operation:GovernanceMetadataOperation;idempotencyKey:string;requestHmac:string;payload:Record<string,any>;before:Record<string,any>|null;scope:GovernanceScopeSnapshot;workflowId:string;
}
export interface GovernanceScheduleLocator {scheduleId:string;clusterId:string;workspaceId:string;ownerUserId:string;version:number;revision:number;scheduledAt:string;runId:string;leaseGeneration:number;}
export interface GovernanceFixedMetadataPayload {intentId:string;resourceType:GovernanceMetadataResource;resourceId:string;operation:GovernanceMetadataOperation;payloadHmac:string;}
export type GovernanceActor=EntityActor;
