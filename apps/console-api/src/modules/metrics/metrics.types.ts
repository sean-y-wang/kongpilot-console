export const METRICS_PURPOSES = ['native_scrape','collector_scrape','collector_catalog','collector_ingest'] as const;
export type MetricsPurpose = typeof METRICS_PURPOSES[number];
export type MetricsAudience = 'bff' | 'collector';
export const METRICS_AUDIENCE: Record<MetricsPurpose,MetricsAudience> = {
  native_scrape:'bff',collector_catalog:'bff',collector_scrape:'collector',collector_ingest:'collector',
};
export type MetricsQuality = 'verified'|'unknown'|'ambiguous'|'stale'|'blocked';
export interface MetricsCredentialIdentity {
  readonly id:string; readonly clusterId:string; readonly purpose:MetricsPurpose;
  readonly audience:MetricsAudience; readonly generation:number;
}
export interface MetricsEnrollment {
  clusterId:string; generation:number;
  credentials:Array<{purpose:MetricsPurpose;audience:MetricsAudience;token:string}>;
}
export interface MetricsServiceInput {id:string;name?:string|null;host:string;tags?:string[]|null}
export interface MetricsRouteInput {id:string;name?:string|null;service:{id:string}|null;tags?:string[]|null}
export interface MetricsConsumerInput {id:string;username?:string|null;custom_id?:string|null;tags?:string[]|null}
export interface MetricsCatalogInput {
  cid:string;nodeId:string;transportScope:string;expectedCatalogRevision:number;
  observedKongNodeId?:string|null;observedAt:string|number;complete:boolean;
  routePairs:Array<{service:MetricsServiceInput;route:MetricsRouteInput|null}>;
  consumers:MetricsConsumerInput[];
}
/** Immutable attribution labels. No current-configuration join may relabel this row. */
export interface MetricsAssignment {
  epoch_id:string;cluster_id:string;node_id:string;entity_type:'services'|'routes'|'consumers';entity_id:string;
  workspace_id:string;service_id:string|null;route_id:string|null;consumer_id:string|null;
  tags:string[];service_label:string|null;route_label:string|null;
  valid_from:string;verified_until:string;closed_at:string|null;quality:'verified';
}
export type MetricsResolution = {quality:'verified';assignment:MetricsAssignment;catalogRevision:number}
  |{quality:Exclude<MetricsQuality,'verified'>;assignment:null;reasonCode:string;catalogRevision:number};
export interface MetricsCatalogPage {
  clusterId:string;catalogRevision:number;credentialGeneration:number;generatedAt:string;validUntil:string|null;
  blocked:boolean;complete:boolean;items:MetricsAssignment[];nextCursor:string|null;warnings:string[];
}
export interface MetricsAllowedEpochOptions {
  expectedCatalogRevision?:number;workspaceId?:string;authorizedServiceIds?:string[];authorizedRouteIds?:string[];
  authorizedConsumerIds?:string[];platformHistory?:boolean;
  /** Trusted inventory only; never an HTTP authorization option. Explicit consumer IDs still narrow it. */
  includeConsumerCandidates?:boolean;
}
export interface MetricsEventBindingInput {
  credentialGeneration:number;
  items:Array<{index:number;serviceId?:string;routeId?:string;consumerId?:string;startedAt:string|number;endedAt:string|number;epochIds?:string[]}>;
}
export interface MetricsEventBindingResult {
  catalogRevision:number;credentialGeneration:number;
  items:Array<{index:number;quality:MetricsQuality;reasonCode?:string;serviceEpoch?:MetricsAssignment;
    routeEpoch?:MetricsAssignment;consumerEpoch?:MetricsAssignment}>;
}
export interface MetricsWriteInput {
  cid:string;transportScope:string;operationId:string;requestFingerprint:string;
  entityType:string;entityId?:string;method:string;path:string;before?:unknown;body?:unknown;
}
export interface MetricsFenceReceipt {
  id:string;operationId:string;transportScope:string;requestFingerprint:string;closed:number;clusterIds:string[];
}
export interface MetricsSettingsView {
  clusterId:string;activeSourceId:string|null;provider:'prometheus';state:string;revision:number;
  catalogRevision:number;credentialGeneration:number;maxAgeMs:number;lastVerifiedAt:string|null;
  enabled:boolean;collectorEnabled:boolean;capabilities:Record<string,unknown>;
}
