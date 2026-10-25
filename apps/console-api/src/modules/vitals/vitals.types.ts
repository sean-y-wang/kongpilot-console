export type VitalsAvailability = 'available' | 'unavailable' | 'insufficient_samples' | 'unsupported' | 'partial';
export interface VitalsPoint { ts: number; value: number | null; }
export interface VitalsMetric { value: number | null; availability: VitalsAvailability; reasonCode?: string; }
export interface VitalsTimeWindow { start: string; end: string; step: number; rateWindowSeconds: number; }
export interface VitalsSource { id: string; name: string; type: 'prometheus' | 'loki'; status: string; availability: VitalsAvailability; }
export const VITALS_SERIES = ['qps', 'status2xx', 'status4xx', 'status5xx', 'latencyRequestP50', 'latencyRequestP95', 'latencyRequestP99', 'latencyUpstreamP50', 'latencyUpstreamP95', 'latencyUpstreamP99', 'latencyKongP50', 'latencyKongP95', 'latencyKongP99', 'bandwidthIngress', 'bandwidthEgress'] as const;
export type VitalsSeriesKey = typeof VITALS_SERIES[number];
export interface VitalsOverview {
  clusterId: string; workspaceId: string; scope: 'workspace' | 'cluster'; source: VitalsSource | null; evaluationAt: string;
  timeWindow: VitalsTimeWindow;
  requestedWindow?: VitalsTimeWindow;
  cards: { qps: VitalsMetric; p50: VitalsMetric; p95: VitalsMetric; p99: VitalsMetric; ingressBytesPerSecond: VitalsMetric; egressBytesPerSecond: VitalsMetric; onlineNodes: VitalsMetric; };
  series: Record<VitalsSeriesKey, VitalsPoint[]>;
  topN: { services: Array<{ id: string; name: string; value: number }>; consumers: Array<{ id: string; name: string; value: number }> };
  nodes: Array<{ id: string; online: number | null; datastoreReachable: number | null }>;
  units: { throughput: 'requests/second'; latency: 'milliseconds'; bandwidth: 'bytes/second' };
  availability: Record<string, VitalsAvailability>;
  quality: { complete: boolean; reasonCodes: string[]; catalogRevision: number; historicalScope: 'current_epoch' | 'platform_all_epochs'; sourceMetricVersion: string; gaps: string[] };
}
export interface VitalsCapabilities {
  clusterId: string; workspaceId: string; scope: 'workspace' | 'cluster'; source: VitalsSource | null; sources: VitalsSource[];
  nativeVersion: string | null; pluginVersion: '0.6.0'; provider: 'prometheus' | 'loki' | null;
  configured: boolean; collectorEnabled: boolean; catalogRevision: number; credentialGeneration: number;
  permissions: { setup: boolean; nodeMetrics: boolean; clusterMetrics: boolean };
  capabilities: { qps: boolean; statusCodes: boolean; latency: boolean; bandwidth: boolean; serviceTopN: boolean; consumerTopN: boolean; nodes: boolean; routeDrilldown: boolean };
  limitations: string[]; setupModes: ['native_prometheus', 'collector']; executionMode: 'direct' | 'approval';
}
export interface VitalsIdentityPage { items: Array<{ id: string; name: string; parentName?: string }>; nextCursor: string | null; size: number; total: null; scan_budget_exhausted: boolean; }
export interface VitalsQuery { workspaceId?: string; scope?: 'workspace' | 'cluster'; sourceId?: string; serviceId?: string; routeId?: string; start?: string; end?: string; step?: string | number; }
export interface VitalsSetup { sourceId: string; mode: 'native_prometheus' | 'collector'; confirmed: true; confirm_name: string; }
