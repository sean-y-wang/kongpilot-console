import { entity, rows, scope } from './m7-harness.mjs';
import { eventRead, eventWrite } from './m7-event-acceptance.mjs';
import { observationSequence } from './m7-producer-acceptance.mjs';

/** Continue the original healthy baseline and unused health transition only. */
export async function completeM7ExistingUpstreamProducer(h, actors, channel) {
  const area = actors.direct, actor = actors.admin, upstreamId = '138c34c9-bdac-470c-a5fa-64564474aebe', targetId = '4c92e70c-a2be-43bb-8b6b-f87f1d52a9bf', certificateId = '50675a17-ca7f-4113-8003-08fb8f246c84';
  const certificateIntent = h.state.samplingIntents[2];
  h.check(certificateIntent?.state === 'completed' && certificateIntent.id === certificateId && certificateIntent.samples.length === 5 &&
    !h.state.samplingIntents.some(intent => intent.type === 'upstreams') && !h.state.fixtures.some(row => row.type === 'subscriptions' && row.name === `${h.state.testTag}-health`),
    'completed original certificate samples are retained and every Upstream producer intent is still unused');
  const health = h.data(await h.request(actor, scope(area.cid, area.wid, `upstreams/${upstreamId}/health`)));
  h.check(Array.isArray(health.data) && health.data.length === 1 && health.data[0].id === targetId && health.data[0].health === 'HEALTHY',
    'current real Kong health confirms the original single Target baseline without another healthy write');
  const expiry = rows(await eventRead(h, actor, area, 'records', { nativeType: 'certificates', nativeId: certificateId, eventType: 'certificate.expiring', size: 20 })).find(row => row.payload?.expiry?.bucket === 'expired');
  h.check(expiry && expiry.actorType === 'system' && expiry.actorId === null && expiry.phase === 'observation' && expiry.payload.quality === 'verified' &&
    Date.parse(expiry.payload.expiry.expiresAt) <= Date.now() && certificateIntent.samples.some(sample => sample.quality === 'verified' && Date.parse(sample.observedAt) < Date.parse(expiry.payload.expiry.expiresAt)),
    'retained original certificate samples and immutable event prove actual pre-expiry and expired state');
  await eventWrite(h, actor, actors.approver, area, 'subscriptions', 'POST', { name: `${h.state.testTag}-health`, channelId: channel.id, eventTypes: ['upstream.health.changed'], nativeType: 'upstreams', nativeIds: [upstreamId] }, 'event.subscription.save');
  const samples = await observationSequence(h, area, 'upstreams', upstreamId, async (_sample, index) => {
    if (index === 1) await h.request(actor, scope(area.cid, area.wid, `upstreams/${upstreamId}/targets/${targetId}/unhealthy`), 'POST');
  });
  const transition = await h.poll(async () => rows(await eventRead(h, actor, area, 'records', { nativeType: 'upstreams', nativeId: upstreamId, eventType: 'upstream.health.changed', size: 20 })).find(row => row.payload?.health?.before === 'healthy' && row.payload?.health?.after === 'unhealthy'), Boolean,
    'original Upstream changes health after two real spaced confirmed observations');
  h.check(transition.actorType === 'system' && transition.actorId === null && transition.phase === 'observation' && transition.payload.quality === 'verified' && samples.filter(sample => sample.quality === 'verified').length >= 3,
    'actual Upstream transition retains system authority and verified live continuity');
  const certificate = entity(h.data(await h.request(actor, scope(area.cid, area.wid, `entities/certificates/${certificateId}`)))), upstream = entity(h.data(await h.request(actor, scope(area.cid, area.wid, `entities/upstreams/${upstreamId}`))));
  h.check(certificate.id === certificateId && upstream.id === upstreamId, 'completed producers retain the exact original native IDs');
  h.public ??= {}; h.public.producers = { certificateId, upstreamId, eventIds: [expiry.id, transition.id], realExpiry: true, actualHealthChange: true, syntheticObservationInputs: false, sameLiveAuthority: true };
  h.state.producersComplete = true; h.save(); return { certificate, upstream, eventIds: [expiry.id, transition.id] };
}
