import type { PreparedEntityChange } from '../entities/entity-change.types';
import type { VitalsMetric, VitalsOverview, VitalsQuery } from '../vitals/vitals.types';

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const record = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): string | null => typeof value === 'string' && uuid.test(value) ? value.toLowerCase() : null;
const reference = (value: unknown): string | null => id(record(value) ? value.id : value);
const invalid = () => new Error('WORKFLOW_IMPACT_MATERIAL_INVALID');
export const WORKFLOW_IMPACT_ROUTE_LIMIT = 200;
export const WORKFLOW_IMPACT_TRAFFIC_LIMIT = 8;

export interface WorkflowRelatedRoute {
  readonly id: string; readonly name: string | null; readonly serviceIds: readonly string[];
}
export interface WorkflowRelatedRoutes {
  readonly items: readonly WorkflowRelatedRoute[];
  readonly coverage: 'direct_routes' | 'complete_service_closure' | 'partial' | 'not_captured';
  readonly reasonCodes: readonly string[]; readonly truncated: boolean;
}
export interface WorkflowTrafficTarget { readonly type: 'services' | 'routes'; readonly id: string; }
export interface WorkflowTrafficQueryPlan {
  readonly clusterId: string; readonly workspaceId: string;
  /** Independently displayed measurements; overlapping Service/Route scopes
   * must never be added together into an alleged total affected traffic. */
  readonly aggregation: 'separate'; readonly targets: readonly WorkflowTrafficTarget[];
  readonly reasonCodes: readonly string[];
}

/** Authenticated, whole-subject-authorized compiler material only. This pure
 * projection performs no enumeration and supplies no permissions. It emits
 * business identities, never a private graph, config, header or credential. */
export function workflowRelatedRoutes(material: Readonly<PreparedEntityChange>): WorkflowRelatedRoutes {
  if (!material || !id(material.clusterId) || !id(material.workspaceId) || !Array.isArray(material.packets)
    || material.packets.length > 1000 || !Array.isArray(material.prerequisites) || material.prerequisites.length > 10000
    || !Array.isArray(material.metadataObligations) || material.metadataObligations.length > 2000) throw invalid();
  const routes = new Map<string, { id: string; name: string | null; services: Set<string> }>();
  const services = new Set<string>(), completeServices = new Set<string>(), reasons = new Set<string>();
  let observations = 0, broadRelation = false;
  const add = (routeId: unknown, data?: unknown) => {
    if (++observations > 10000) throw invalid();
    const route = id(routeId); if (!route) throw invalid();
    if (data !== undefined && data !== null && (!record(data) || data.id !== undefined && id(data.id) !== route)) throw invalid();
    const value = routes.get(route) ?? { id: route, name: null, services: new Set<string>() };
    if (record(data)) {
      if (typeof data.name === 'string') value.name = data.name.slice(0, 256);
      const service = reference(data.service); if (service) value.services.add(service);
    }
    routes.set(route, value);
  };
  const plugin = (data: any) => {
    const route = reference(data.route), service = reference(data.service), consumer = reference(data.consumer);
    if (route) add(route);
    if (service) services.add(service);
    if (!route && (!service || consumer)) { broadRelation = true; reasons.add(consumer ? 'CONSUMER_ROUTE_RELATIONS_NOT_CAPTURED' : 'GLOBAL_PLUGIN_ROUTE_RELATIONS_NOT_CAPTURED'); }
  };
  for (const packet of material.packets) {
    if (!id(packet.nativeId)) throw invalid();
    const before = record(packet.before) ? packet.before : {}, after = { ...before, ...(record(packet.body) ? packet.body : {}) };
    if (packet.nativeType === 'routes') { if (packet.before !== null) add(packet.nativeId, before); if (packet.method !== 'DELETE') add(packet.nativeId, after); }
    else if (packet.nativeType === 'services') services.add(packet.nativeId.toLowerCase());
    else if (packet.nativeType === 'plugins') { if (packet.before !== null) plugin(before); if (packet.method !== 'DELETE') plugin(after); }
    else { broadRelation = true; reasons.add('RELATED_ROUTES_NOT_CAPTURED'); }
  }
  for (const prerequisite of material.prerequisites) if (prerequisite.type === 'routes' && !prerequisite.absent && record(prerequisite.before)) add(prerequisite.nativeId ?? prerequisite.before.id, prerequisite.before);
  for (const obligation of material.metadataObligations) if (obligation.kind === 'recycle-archive' || obligation.kind === 'recycle-restore') {
    const graph = obligation.graph;
    if (!graph || !Array.isArray(graph.nodes) || graph.nodes.length > 1000) throw invalid();
    const root = graph.nodes.find(node => node.key === graph.rootKey);
    if (graph.complete && graph.purpose === 'recycle' && root?.type === 'services' && id(root.id)) completeServices.add(root.id.toLowerCase());
    for (const node of graph.nodes) if (node.type === 'routes') add(node.id, node.data);
  }
  if ([...services].some(service => !completeServices.has(service))) reasons.add('SERVICE_ROUTE_COLLECTION_NOT_CAPTURED');
  const sorted = [...routes.values()].sort((a, b) => a.id.localeCompare(b.id)), truncated = sorted.length > WORKFLOW_IMPACT_ROUTE_LIMIT;
  if (truncated) reasons.add('RELATED_ROUTE_DISPLAY_BUDGET');
  const incomplete = broadRelation || [...services].some(service => !completeServices.has(service)) || truncated;
  return { items: sorted.slice(0, WORKFLOW_IMPACT_ROUTE_LIMIT).map(value => ({ id: value.id, name: value.name, serviceIds: [...value.services].sort() })),
    coverage: incomplete ? sorted.length ? 'partial' : 'not_captured' : services.size ? 'complete_service_closure' : sorted.length ? 'direct_routes' : 'not_captured',
    reasonCodes: [...reasons].sort(), truncated };
}

/** UUID selectors only. Vitals must independently authorize the current
 * identity, workspace and membership epochs before executing this plan. */
export function workflowTrafficQueryPlan(material: Readonly<PreparedEntityChange>, related = workflowRelatedRoutes(material)): WorkflowTrafficQueryPlan {
  const targets = new Map<string, WorkflowTrafficTarget>();
  const add = (type: 'services' | 'routes', value: unknown) => { const parsed = id(value); if (!parsed) throw invalid(); targets.set(`${type}:${parsed}`, { type, id: parsed }); };
  for (const packet of material.packets) {
    if (packet.nativeType === 'services') add('services', packet.nativeId);
    if (packet.nativeType === 'plugins') for (const data of [packet.before, { ...(record(packet.before) ? packet.before : {}), ...(record(packet.body) ? packet.body : {}) }]) if (record(data) && reference(data.service)) add('services', reference(data.service));
  }
  for (const route of related.items) add('routes', route.id);
  const sorted = [...targets.values()].sort((a, b) => `${a.type}:${a.id}`.localeCompare(`${b.type}:${b.id}`)), reasonCodes: string[] = [];
  if (sorted.length > WORKFLOW_IMPACT_TRAFFIC_LIMIT) reasonCodes.push('WORKFLOW_TRAFFIC_QUERY_BUDGET');
  if (!sorted.length) reasonCodes.push('WORKFLOW_TRAFFIC_SCOPE_NOT_CAPTURED');
  return { clusterId: material.clusterId, workspaceId: material.workspaceId, aggregation: 'separate', targets: sorted.slice(0, WORKFLOW_IMPACT_TRAFFIC_LIMIT), reasonCodes };
}

export function workflowVitalsQuery(plan: WorkflowTrafficQueryPlan, target: WorkflowTrafficTarget, start: string, end: string): VitalsQuery {
  if (!id(plan.clusterId) || !id(plan.workspaceId) || !id(target.id) || !['services', 'routes'].includes(target.type)
    || !plan.targets.some(item => item.type === target.type && item.id === target.id)) throw invalid();
  return { workspaceId: plan.workspaceId, scope: 'workspace', ...(target.type === 'services' ? { serviceId: target.id } : { routeId: target.id }), start, end };
}

/** A zero is only a real available sample. Missing sources, empty epochs and
 * incomplete measurements retain null; they cannot certify zero impact. */
export function workflowTrafficMeasurement(plan: WorkflowTrafficQueryPlan, target: WorkflowTrafficTarget, overview: Readonly<VitalsOverview>, query: Readonly<VitalsQuery>): {
  target: WorkflowTrafficTarget; qps: VitalsMetric; evaluationAt: string; reasonCodes: readonly string[];
} {
  if (overview.clusterId !== plan.clusterId || overview.workspaceId !== plan.workspaceId || overview.scope !== 'workspace'
    || !plan.targets.some(item => item.type === target.type && item.id === target.id)
    || query.workspaceId !== plan.workspaceId || query.scope !== 'workspace'
    || (target.type === 'services' ? query.serviceId !== target.id || query.routeId !== undefined : query.routeId !== target.id || query.serviceId !== undefined)) throw invalid();
  const metric = overview.cards.qps, complete = overview.quality.complete;
  const valid = typeof metric.value === 'number' && Number.isFinite(metric.value) && metric.value >= 0;
  const available = complete && metric.availability === 'available' && valid;
  return { target: { type: target.type, id: target.id }, qps: available ? { value: metric.value, availability: 'available' }
    : { value: null, availability: !complete ? 'partial' : metric.availability === 'available' ? 'unavailable' : metric.availability,
      ...(metric.reasonCode ? { reasonCode: metric.reasonCode } : {}) }, evaluationAt: overview.evaluationAt, reasonCodes: [...overview.quality.reasonCodes] };
}

/** Newly persisted reviews describe planning facts. Current executable and
 * rollback actions belong exclusively to WorkflowService.summary.capabilities. */
export function nativeWorkflowImpact(material: Readonly<PreparedEntityChange>, subject: Readonly<{ type: string; id: string }>, intentRevision: number, fullDiffIncluded: boolean) {
  const relatedRoutes = workflowRelatedRoutes(material);
  return { subject: { type: subject.type, id: subject.id }, nativeRequests: 0, nativeRequestsScope: 'metadata_wrapper', plannedNativePackets: material.packets.length,
    objectCount: material.packets.length, relatedRoutes, traffic: null, trafficAvailability: 'unavailable' as const, trafficReasonCode: 'WORKFLOW_TRAFFIC_NOT_QUERIED',
    trafficQueryPlan: workflowTrafficQueryPlan(material, relatedRoutes), recovery: { state: material.recovery.state, blockerCodes: [...material.recovery.blockerCodes] },
    detailSource: { type: 'entity_change_intents', id: subject.id, revision: intentRevision }, fullDiffIncluded,
    rollback: '执行前建立受保护基线；可用恢复操作以当前工单能力为准，恢复须新建工单并按集群模式审批' };
}
