import { ApiError, api, getApiActorId } from '../api/client';
import { canonicalId } from '../api/workspace-scope';
import { MAX_VITALS_POINTS, sameVitalsScope, type VitalsScope } from './vitals-model';
import { VITALS_SERIES, type VitalsCapabilities, type VitalsOverview } from './vitals.types';

export function validateVitalsCapabilities(value: VitalsCapabilities, scope: VitalsScope): VitalsCapabilities {
  if (!value || value.clusterId !== scope.clusterId || value.workspaceId !== scope.workspaceId || value.scope !== (scope.metricsScope ?? 'workspace') || scope.sourceId && value.source && value.source.id !== scope.sourceId) throw new ApiError('监控能力的范围已变化，请刷新。', 0, 'METRICS_SCOPE_CHANGED');
  if (!Array.isArray(value.sources) || !value.permissions || !value.capabilities || !Array.isArray(value.limitations)) throw new ApiError('监控能力响应不完整。', 0, 'METRICS_RESPONSE_INVALID');
  return value;
}

export function validateVitalsOverview(value: VitalsOverview, scope: VitalsScope): VitalsOverview {
  if (!value || value.clusterId !== scope.clusterId || value.workspaceId !== scope.workspaceId || value.scope !== (scope.metricsScope ?? 'workspace') || scope.sourceId && value.source && value.source.id !== scope.sourceId) throw new ApiError('监控响应的范围已变化，请刷新当前范围。', 0, 'METRICS_SCOPE_CHANGED');
  if (value.units?.latency !== 'milliseconds' || value.units?.throughput !== 'requests/second' || value.units?.bandwidth !== 'bytes/second') throw new ApiError('监控指标单位不受支持。', 0, 'METRICS_UNITS_INVALID');
  for (const name of VITALS_SERIES) {
    const points = value.series?.[name];
    if (!Array.isArray(points) || points.length > MAX_VITALS_POINTS || points.some(point => !point || !Number.isFinite(point.ts) || point.value !== null && (typeof point.value !== 'number' || !Number.isFinite(point.value)))) throw new ApiError('监控响应超出采样预算或含无效数值。', 0, 'METRICS_RESPONSE_INVALID');
  }
  if (!value.cards || !value.quality || !Array.isArray(value.topN?.services) || !Array.isArray(value.topN?.consumers) || !Array.isArray(value.nodes)) throw new ApiError('监控响应不完整，请重新获取。', 0, 'METRICS_RESPONSE_INVALID');
  return value;
}

/** A successful response from an obsolete account/scope cannot enter the chart cache. */
export async function requestVitals<T>(path: string, captured: VitalsScope, current: () => VitalsScope, signal?: AbortSignal, validate?: (value: T, scope: VitalsScope) => T): Promise<T> {
  const check = () => {
    if (signal?.aborted) throw new DOMException('监控查询已取消', 'AbortError');
    if (!canonicalId(captured.clusterId) || !canonicalId(captured.workspaceId) || getApiActorId() !== captured.actorId || !sameVitalsScope(captured, current())) throw new ApiError('账号、权限或监控范围已变化，已丢弃旧响应。', 0, 'METRICS_SCOPE_CHANGED');
  };
  check();
  const result = await api<T>(path, { signal });
  check();
  return validate ? validate(result, captured) : result;
}
