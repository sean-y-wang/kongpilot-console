import type {AuthUser} from '../../common/auth';
import type {AuditEvent,AuditOutboxReceipt} from '../audit/audit.service';
export type {AuditOutboxReceipt};
export const EVENT_PAYLOAD_MAX_BYTES=8192,EVENT_SCOPE_MAX_BYTES=65536,EVENT_FANOUT_PAGE_SIZE=50;
export const DELIVERY_CLAIM_LIMIT=20,DELIVERY_CONCURRENCY=2,DELIVERY_MAX_ATTEMPTS=8,DELIVERY_MAX_AGE_MS=86400000;
export const DELIVERY_LEASE_MS=30000,DELIVERY_HEARTBEAT_MS=5000,NOTIFICATION_BATCH_LIMIT=100,LIST_MAX_SIZE=100;
export const EVENT_TYPES=['entity.created','entity.updated','entity.deleted','entity.restored','workflow.submitted','workflow.approval.progress','workflow.approved','workflow.rejected','workflow.cancelled','workflow.executed','workflow.failed','certificate.expiring','upstream.health.changed','config.drift','channel.test','delivery.replay'] as const;
export type EventPhase='requested'|'node'|'aggregate'|'terminal'|'observation';
export type EventSourceKind='audit'|'workflow'|'mutation'|'iam'|'portal'|'observation';
export interface HistoricalEventScope {
 version:1;quality:'verified'|'legacy_unknown';module:string;nativeType?:string;nativeId?:string;parentId?:string;credentialKind?:string;
 before:{workspaceId:string|null;physicalTags:readonly string[]}|null;after:{workspaceId:string|null;physicalTags:readonly string[]}|null;
 subject?:{type:string;id:string};
}
export interface TrustedAuditScopeHints {
 quality:'verified'|'legacy_unknown';module:string;nativeType?:string;nativeId?:string;
 beforeTags?:readonly string[];afterTags?:readonly string[];beforeExists?:boolean;afterExists?:boolean;
 beforeWorkspaceId?:string|null;afterWorkspaceId?:string|null;
 parentContext?:{nativeType:string;nativeId:string;credentialKind?:string};subject?:{type:string;id:string};
}
export type SafeHealth='healthy'|'unhealthy'|'degraded'|'checks_off';
export type ExpiryBucket='normal'|'30d'|'7d'|'1d'|'expired';
export interface EventPayload {
 version:1;title:string;summary:string;eventType:string;phase:EventPhase;result:string;subject:{type:string;id:string}|null;
 observedAt?:string;quality?:ObservationQuality;expiry?:{expiresAt:string;bucket:ExpiryBucket};health?:{before:SafeHealth;after:SafeHealth};
}
export interface EventRecord {
 id:string;clusterId:string|null;workspaceId:string|null;eventType:string;phase:EventPhase;sourceKind:EventSourceKind;sourceId:string;
 actorType:'user'|'developer'|'system';actorId:string|null;developerId:string|null;occurredAt:string;
 sourceScope:HistoricalEventScope;sourceScopeHmac:string;payloadSafe:EventPayload;payloadDigest:string;
 auditEventId?:string|null;auditEventHash?:string|null;observationId?:string|null;observationHmac?:string|null;
}
export interface SafeEventView {id:string;clusterId:string|null;workspaceId:string|null;eventType:string;phase:EventPhase;actorId:string|null;actorType:string;occurredAt:string;payload:EventPayload}
export interface EventListQuery {clusterId?:string;workspaceId?:string;eventType?:string;nativeType?:string;nativeId?:string;from?:string;to?:string;size?:number|string;cursor?:string}
export interface Page<T> {items:T[];nextCursor:string|null;size:number;total:null;scanIncomplete?:boolean}
export interface EventOperationEnvelope {
 version:1;handler:'event.channel.test'|'event.delivery.replay';requestHmac:string;beforeHmac:string;payloadHmac:string;
 iamOperationId?:string;workflow?:{id:string;executionId:string;planRevision:number;planHash:string;stepId:string};
}
export interface QueueMetadataReceipt {actorId:string;clusterId:string;workspaceId:string;auditReceipt:AuditOutboxReceipt;iamOperationId?:string;workflow?:{id:string;executionId:string;planRevision:number;planHash:string;stepId:string}}
export interface EnqueueTestInput extends QueueMetadataReceipt {channelId:string;channelRevision:number;credentialGeneration:number}
export interface EnqueueReplayInput extends QueueMetadataReceipt {deliveryId:string;expectedRevision:number}
export interface QueueReceipt {eventId:string;deliveryId:string;replayGeneration?:number}
export interface OutboxClaim {readonly outboxId:string;readonly eventId:string;readonly leaseOwner:string;readonly leaseGeneration:number;readonly leaseUntil:string;readonly revision:number}
export type DeliveryState='pending'|'claimed'|'sending'|'retrying'|'uncertain'|'paused_authority'|'succeeded'|'exhausted'|'cancelled';
export interface DeliveryClaim {
 readonly deliveryId:string;readonly eventId:string;readonly occurredAt:string;readonly sourceId:string;readonly clusterId:string;readonly workspaceId:string;readonly deliveryKind:'subscription'|'test';
 readonly subscriptionId:string|null;readonly subscriptionRevision:number|null;readonly channelId:string;readonly channelRevision:number;
 readonly credentialGeneration:number;readonly creatorId:string;readonly leaseOwner:string;readonly leaseGeneration:number;readonly leaseUntil:string;
 readonly attemptNo:number;readonly idempotencyKey:string;readonly payloadSafe:EventPayload;readonly payloadDigest:string;
}
export interface DeliveryOutcome {outcome:'succeeded'|'failed'|'uncertain';sendStarted:boolean;httpStatus?:number;durationMs:number;errorCode?:string;retryable:boolean;retryAfterMs?:number}
export type ChannelAuth={type:'none'}|{type:'bearer';token:string}|{type:'basic';username:string;password:string}|{type:'feishu-signature';secret:string};
export type ChannelEndpoint={url:string}|{recipients:readonly string[]};
/** Trusted worker RAM only. Never included in HTTP DTOs, claims or audit. */
export interface ChannelMaterials {type:'webhook'|'email'|'slack'|'feishu';endpoint:ChannelEndpoint;auth:ChannelAuth;optionsSafe:Readonly<Record<string,never>>}
export interface SafeDelivery {id:string;clusterId:string;workspaceId:string;eventId:string;deliveryKind:string;channelId:string;subscriptionId:string|null;state:DeliveryState;revision:number;attemptCount:number;replayGeneration:number;errorCode:string|null;createdAt:string}
export type DetectorKey='certificate.expiry.v1'|'upstream.health.v1';
export type DetectorSubject='certificates'|'ca_certificates'|'upstreams';
export type ObservationQuality='verified'|'partial'|'unavailable'|'invalid'|'stale';
export type SafeObservation={kind:'certificate_expiry';expiresAt:string}|{kind:'upstream_health';health:SafeHealth};
export interface TrustedObservationProof {readonly __trustedObservation:unique symbol}
export interface DetectorObservationInput {
 observationId:string;actorType:'system';actorId:null;clusterId:string;workspaceId:string;detectorKey:DetectorKey;subjectType:DetectorSubject;subjectId:string;
 transportScope:string;observedNodeId:string|null;clusterRevision:number;workspaceRevision:number;configFingerprint:string;scopeEpoch:string;
 observedAt:string;quality:ObservationQuality;sourceScope:HistoricalEventScope;observationSafe:SafeObservation|null;beforeBaselineRevision:number|null;sourceProof:TrustedObservationProof;
}
export interface ObservationReceipt {observationId:string;baselineRevision:number;disposition:'baseline_created'|'baseline_reset'|'unchanged'|'candidate'|'event_queued'|'quality_only'|'duplicate';eventId:string|null;outboxId:string|null}
export interface SafeNotification {id:string;clusterId:string|null;workspaceId:string|null;eventId:string;title:string;summary:string;link:{kind:string;id:string}|null;revision:number;readAt:string|null;dismissedAt:string|null;createdAt:string;capabilities:{read:boolean;write:boolean}}
export interface NotificationQuery {clusterId?:string;workspaceId?:string;size?:number|string;cursor?:string;unreadOnly?:boolean|string;dismissed?:boolean|string}
export interface PreferenceInput {clusterId:string;workspaceId:string;name:string;eventTypes:string[];nativeType?:string;nativeIds?:string[];tags?:string[];inAppEnabled:boolean;revision?:number}
export interface NotificationActor {user:AuthUser;idempotencyKey:string;requestId?:string;ip?:string}
export interface EventOperationAudit {append(event:AuditEvent,tx:import('../../infrastructure/db.service').DbService):Promise<AuditOutboxReceipt>}
