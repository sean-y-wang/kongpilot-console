import type { DeliveryChannelAuth, DeliveryProviderType, DeliverySafeSummary, ValidatedDeliveryChannel } from '../event-delivery/delivery.types';
import type { EventWorkflowHandlerName } from '../workflows/event-workflow';
import type { WorkflowSummary } from '../workflows/workflow.types';

export type SharedEventStatus = 'pending'|'active'|'disabled'|'deleted';
export interface EventScopeSnapshot {executionMode:'direct'|'approval';clusterRevision:number;workspaceRevision:number;transportScope:string}
export interface SafeChannel extends DeliverySafeSummary {
  id:string;clusterId:string;workspaceId:string;name:string;type:DeliveryProviderType;
  status:SharedEventStatus;revision:number;credentialGeneration:number;configured:boolean;
  options:Readonly<Record<string,never>>;createdAt:string;
  capabilities:{write:boolean;delete:boolean;restore:boolean;test:boolean};
}
export interface SafeSubscription {
  id:string;clusterId:string;workspaceId:string;channelId:string;name:string;status:SharedEventStatus;
  revision:number;eventTypes:string[];nativeType:string|null;nativeIds:string[];tags:string[];createdAt:string;
  capabilities:{write:boolean;delete:boolean;restore:boolean};
}
export interface CreateChannelInput {
  name:string;type:DeliveryProviderType;endpoint:string|{recipients:string[]};auth?:DeliveryChannelAuth;
  options?:Record<string,never>;status?:'active'|'disabled';
}
export interface UpdateChannelInput {
  revision:number;endpoint?:string|{recipients:string[]};auth?:DeliveryChannelAuth;
  options?:Record<string,never>;status?:'active'|'disabled';
}
export interface CreateSubscriptionInput {name:string;channelId:string;eventTypes:string[];nativeType?:string;nativeIds?:string[];tags?:string[];status?:'active'|'disabled'}
export interface UpdateSubscriptionInput {revision:number;eventTypes?:string[];nativeType?:string|null;nativeIds?:string[];tags?:string[];status?:'active'|'disabled'}
export interface EventRequestIdentity {
  handler:EventWorkflowHandlerName;createOrUpdate:'create'|'update'|'action';
  targetIdOrCollection:string;originalRequestHmac:string;
}
/** Only the sealed plan / encrypted IAM payload contains desiredConfigSecret. */
export interface EventMetadataPayload extends EventRequestIdentity {
  desiredConfigSecret?:ValidatedDeliveryChannel;
  desiredStatus?:'active'|'disabled';
  eventTypes?:string[];nativeType?:string|null;nativeIds?:string[];physicalTags?:string[];
  channelId?:string;name?:string;type?:DeliveryProviderType;
}
export interface EventMutationResult {
  entity?:SafeChannel|SafeSubscription;
  queued?:{eventId:string;deliveryId:string;replayGeneration?:number};
}
export interface EventOperationReceipt {
  domain:'iam'|'workflow';id:string;clusterId:string;workspaceId:string;idempotencyKey:string;
  handler:EventWorkflowHandlerName;state:string;configurationCommitted:boolean;submissionCompleted:boolean;
  executionCompleted:boolean;queued:boolean;deliverySucceeded:false;
  workflowId?:string;executionId?:string|null;revision?:number|null;planHash?:string|null;
  entity?:WorkflowSummary|SafeChannel|SafeSubscription;result?:EventMutationResult;errorCode?:string|null;
}
