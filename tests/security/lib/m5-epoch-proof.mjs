import { entity, scope } from './m5-harness.mjs';
import { collectorCounterTotal } from './m5-consumer-oracle.mjs';

/** Dedicated graph, so historical probes never mutate the final chart fixture. */
export async function proveRealEpochIsolation(h, { admin, cluster, source, target, graph, taggedActor, catalog, overview }) {
  const deniedQuery = serviceId => { const end = Math.floor(Date.now() / 1000) * 1000; return { serviceId, start: new Date(end - 300_000).toISOString(), end: new Date(end).toISOString(), step: 15 }; };
  const currentEpoch = (rows, id) => rows.find(row => row.closed_at === null && row.entity_type === 'routes' && row.route_id === id);
  const before = currentEpoch(catalog(), graph.route.id);
  h.check(Boolean(before), 'Epoch/Before', 'dedicated real Route has a verified current membership epoch');
  const path = `/m5/${h.tag}/${graph.label}/ok`;
  await h.waitProxy(cluster, path, 200, { apikey: graph.apiKey });
  const historicalTime = Math.floor(Date.now() / 1000);
  // Query a raw counter after the actual Prometheus scrape, rather than waiting
  // for an entire rate interval merely to establish historical identity.
  await h.poll(() => h.prometheus(`kong_http_status{cluster_id="${cluster.id}",route_id="${graph.route.id}",membership_epoch="${before.epoch_id}"}`, { time: Math.floor(Date.now() / 1000) }).result,
    rows => rows.some(row => Number(row.value[1]) > 0), 'actual Prometheus observes old-epoch traffic');
  const stableTime = Math.floor(Date.now() / 1000);
  h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/entities/services/${graph.service.id}`, source), 'PATCH', { tags: [h.tag, 'team:other'] }), 'Epoch/Tag', 'audited Service business tag mutation');
  await h.reject(taggedActor, scope(`/clusters/${cluster.id}/vitals/overview`, source, deniedQuery(graph.service.id)), 'GET', undefined, 'Epoch/Tag', 'old tag-group cookies cannot read changed Service');
  const afterTag = currentEpoch(catalog(), graph.route.id);
  h.check(afterTag && afterTag.epoch_id !== before.epoch_id && afterTag.workspace_id === source.id, 'Epoch/Tag', 'actual native tag change opens a distinct verified Route epoch');
  const gap = await overview(admin, cluster, source, { serviceId: graph.service.id }, 'Epoch/Tag');
  h.check(gap.series.qps.every(point => point.value === null), 'Epoch/Tag', 'new membership epoch does not expose previous native counter history as a rate');
  const historical = h.prometheus(`kong_http_status{cluster_id="${cluster.id}",route_id="${graph.route.id}",membership_epoch="${before.epoch_id}"}`, { time: stableTime }).result;
  h.check(historical.some(row => Number(row.value[1]) > 0 && row.metric.workspace_id === source.id), 'Epoch/Immutable', 'real historical Prometheus samples retain their original workspace and epoch');

  const plan = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/workspace-migrations/plan`, source), 'POST', {
    source_workspace_id: source.id, target_workspace_id: target.id,
    roots: [{ type: 'services', id: graph.service.id }, { type: 'consumers', id: graph.consumer.id }],
  }), 'Epoch/Migration', 'review audited joint Service and Consumer workspace migration');
  h.check(plan.conflicts.length === 0, 'Epoch/Migration', 'dedicated joint migration has no unresolved cross-workspace reference');
  const applied = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/workspace-migrations/${plan.id}/apply`, source), 'POST', {
    confirmed: true, confirm_name: target.name, plan_hash: plan.plan_hash,
  }), 'Epoch/Migration', 'typed reviewed migration executes via normal BFF workflow');
  h.check(applied.state === 'succeeded', 'Epoch/Migration', 'joint migration reaches a terminal successful receipt');
  const moved = new Set(plan.affected.map(row => `${row.type}:${row.id}`));
  for (const fixture of h.journal) if (fixture.clusterId === cluster.id && moved.has(`${fixture.type}:${fixture.id}`)) fixture.workspaceId = target.id;
  await h.reject(admin, scope(`/clusters/${cluster.id}/vitals/overview`, source, deniedQuery(graph.service.id)), 'GET', undefined, 'Epoch/Migration', 'even platform metrics cannot select migrated Service from the old workspace');
  const destination = currentEpoch(catalog(), graph.route.id);
  h.check(destination && destination.epoch_id !== afterTag.epoch_id && destination.workspace_id === target.id, 'Epoch/Migration', 'actual destination catalog resolves a new workspace membership epoch');
  const migratedGap = await overview(admin, cluster, target, { serviceId: graph.service.id }, 'Epoch/Migration');
  h.check(migratedGap.series.qps.every(point => point.value === null), 'Epoch/Migration', 'destination charts exclude source-workspace history under the same native IDs');
  await h.waitProxy(cluster, path, 200, { apikey: graph.apiKey });
  const key = entity(h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/consumers/${graph.consumer.id}/credentials/key-auth/${graph.credentialId}`, target, { reveal: true })), 'Epoch/Migration', 'authorized migrated credential readback'));
  h.check(key.key === graph.apiKey, 'Epoch/Migration', 'migration retains the original credential and actual proxy authentication remains valid');
  return { sourceWorkspace: source.id, targetWorkspace: target.id, historicalEpoch: before.epoch_id, tagChangedEpoch: afterTag.epoch_id, destinationEpoch: destination.epoch_id, historicalEvaluationAt: new Date(stableTime * 1000).toISOString(), nativeIDsPreserved: true, originalCredentialStillValid: true, historyNotRelabeled: true, historicalProbeStartedAt: new Date(historicalTime * 1000).toISOString() };
}

export function proveRealCollectorSanitization(h, { cluster, graph, token, scrapeToken, foreignConsumerId, canary }) {
  const scrape = () => {
    const response = h.internal('collector', `/metrics/${cluster.id}`, { token: scrapeToken });
    h.check(response.status === 200, 'Collector/Sanitize', 'real collector exposes current authenticated bounded counters');
    return response.text;
  };
  const before = collectorCounterTotal(scrape(), { route_id: graph.route.id, consumer_id: graph.consumer.id, code: '201' });
  const now = Date.now() - 1;
  const raw = {
    service: { id: graph.service.id }, route: { id: graph.route.id }, consumer: { id: graph.consumer.id }, started_at: now,
    latencies: { request: 0, kong: 0, proxy: 0 }, request: { size: 3, headers: { authorization: canary, cookie: canary }, url: `http://example.invalid/?credential=${canary}`, body: canary }, response: { status: 201, size: 4 },
  };
  const encoded = h.remember(Buffer.from(`kongos:${token}`).toString('base64'));
  const response = h.internal('collector', `/ingest/${cluster.id}`, { method: 'POST', headers: { Authorization: `Basic ${encoded}` }, body: [raw, raw, { ...raw, consumer: { id: foreignConsumerId } }, { ...raw, started_at: now - 301_000 }] });
  h.check(response.status === 202 && response.json.accepted === 2 && response.json.rejected === 2, 'Collector/Sanitize', 'actual collector accepts both identical legitimate events and rejects cross-workspace Consumer plus too-old event');
  const after = scrape();
  h.check(collectorCounterTotal(after, { route_id: graph.route.id, consumer_id: graph.consumer.id, code: '201' }) - before === 2, 'Collector/AtLeastOnce', 'two identical events increment the actual counter twice; no unsafe hash deduplication claim');
  h.check(!after.includes(canary), 'Collector/Sanitize', 'scrape exposition does not retain raw headers, URL, query, body or cookie canary');
  return { actualAccepted: 2, actualRejected: 2, rawSensitiveFieldsDiscarded: true, duplicateLegitimateEventsCountedSeparately: true, noExactlyOnceClaim: true };
}
