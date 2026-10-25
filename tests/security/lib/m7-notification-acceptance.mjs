import { randomUUID } from 'node:crypto';
import { entity, rows, scope } from './m7-harness.mjs';
import { nativeCreate, role, wsGrant } from './m7-fixtures.mjs';
import { confirmation, eventRead, eventWrite, settledDelivery } from './m7-event-acceptance.mjs';

const queryFor = (area, extra = {}) => new URLSearchParams({ clusterId: area.cid, workspaceId: area.wid, ...extra });
export async function notificationAcceptance(h, actors, area, channel) {
  const { owner, other, admin, approver, readonly } = actors;
  const service = await nativeCreate(h, admin, area, 'services', { name: `${h.state.testTag}-fanout`, host: 'echo-upstream', port: 8081, protocol: 'http', tags: ['m7:fanout'] });
  const prefs = [], subscriptions = [];
  for (let index = 0; index < 55; index++) {
    const name = `${h.state.testTag}-owner-${index}`, key = randomUUID();
    const pref = entity(h.data(await h.request(owner, '/notifications/preferences', 'POST', { clusterId: area.cid, workspaceId: area.wid, name, eventTypes: ['entity.updated'], nativeType: 'services', nativeIds: [service.id], inAppEnabled: true }, { key })));
    h.state.fixtures.push({ type: 'preferences', id: pref.id, name: pref.name, actorLabel: 'owner', ...area }); prefs.push(pref); h.save();
    const sub = (await eventWrite(h, admin, approver, area, 'subscriptions', 'POST', { name: `${h.state.testTag}-fanout-${index}`, channelId: channel.id, eventTypes: ['entity.updated'], nativeType: 'services', nativeIds: [service.id] }, 'event.subscription.save')).entity;
    subscriptions.push(sub);
    if (index === 0) {
      await h.request(other, `/notifications/preferences/${pref.id}`, 'GET', undefined, { expected: [404] });
      await h.request(admin, `/notifications/preferences/${pref.id}`, 'GET', undefined, { expected: [404] });
      await h.request(other, `/notifications/operations/by-key/${key}`, 'GET', undefined, { expected: [404] });
      await h.request(admin, `/notifications/operations/by-key/${key}`, 'GET', undefined, { expected: [404] });
      h.check(true, 'even global console administrator cannot read another owner preference or personal operation ledger');
    }
  }
  const before = entity(h.data(await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`))));
  const changed = entity(h.data(await h.request(admin, scope(area.cid, area.wid, `entities/services/${service.id}`), 'PATCH', { retries: before.retries === 3 ? 4 : 3 })));
  h.check(changed.retries !== before.retries, 'one real native service mutation drives fanout without synthetic event input');
  const event = await h.poll(async () => rows(await eventRead(h, admin, area, 'records', { nativeType: 'services', nativeId: service.id, eventType: 'entity.updated', size: 20 })).find(v => v.phase === 'terminal'), Boolean, 'real audited terminal mutation creates one native event');
  const deliveries = await h.poll(async () => rows(await eventRead(h, admin, area, 'deliveries', { eventId: event.id, size: 100 })), values => values.length === 55, 'more than50 real shared subscriptions are reached across bounded fanout pages', 45000);
  h.check(new Set(deliveries.map(v => v.subscriptionId)).size === 55, 'bounded fanout does not duplicate a shared subscription');
  await h.poll(async () => rows(await eventRead(h, admin, area, 'deliveries', { eventId: event.id, size: 100 })), values => values.length === 55 && values.every(v => v.state === 'succeeded'), 'all55 real fanout deliveries reach successful provider acknowledgement', 60000);
  const notifications = await h.poll(async () => rows(h.data(await h.request(owner, `/notifications?${queryFor(area, { size: 100 })}`))).filter(v => v.eventId === event.id), values => values.length === 1, '55 matching personal preferences produce one owner notification using event deduplication');
  let notification = notifications[0]; h.state.notificationFixture = { id: notification.id, eventId: event.id, ownerId: owner.user.id, ...area }; h.save();
  for (const actor of [other, admin]) await h.request(actor, `/notifications/${notification.id}`, 'GET', undefined, { expected: [404] });
  await h.request(readonly, '/notifications/preferences', 'POST', { clusterId: area.cid, workspaceId: area.wid, name: `${h.state.testTag}-readonly-forbidden`, eventTypes: ['entity.updated'], inAppEnabled: true }, { expected: [403] });
  const marked = h.data(await h.request(owner, `/notifications/${notification.id}/read`, 'POST', { revision: notification.revision }));
  h.check(marked.readAt && marked.revision === notification.revision + 1, 'owner read operation changes only current exact notification revision'); notification = marked;
  const dismissed = h.data(await h.request(owner, `/notifications/${notification.id}/dismiss`, 'POST', { revision: notification.revision }));
  h.check(dismissed.dismissedAt, 'owner dismiss persists actual personal state');
  let pref = prefs[0]; const body = { clusterId: area.cid, workspaceId: area.wid, name: pref.name, eventTypes: pref.eventTypes, nativeType: pref.nativeType, nativeIds: pref.nativeIds, inAppEnabled: false, revision: pref.revision };
  pref = entity(h.data(await h.request(owner, `/notifications/preferences/${pref.id}`, 'PATCH', body)));
  h.check(pref.inAppEnabled === false, 'personal subscription configuration can be disabled by its owner');
  pref = entity(h.data(await h.request(owner, `/notifications/preferences/${pref.id}`, 'DELETE', confirmation(pref))));
  h.check(pref.status === 'deleted', 'personal preference removal preserves soft tombstone');
  pref = entity(h.data(await h.request(owner, `/notifications/preferences/${pref.id}/restore`, 'POST', confirmation(pref))));
  h.check(pref.status === 'active' && pref.inAppEnabled === false, 'preference restore retains previous muted setting');
  await h.request(readonly, scope(area.cid, area.wid, `events/channels/${channel.id}/test`), 'POST', confirmation(channel), { expected: [403] });
  const visible = await eventRead(h, readonly, area, `channels/${channel.id}`);
  h.check(Object.values(visible.capabilities).every(v => v === false), 'read-only actor safe channel view has no mutation capabilities');
  h.public ??= {}; h.public.fanout = { sharedSubscriptions: 55, successfulDeliveries: 55, personalPreferences: 55, deduplicatedOwnerNotifications: 1 };
  return { service, event, subscriptions, prefs, notification: dismissed };
}
export async function lateAckFenceAcceptance(h, actors, area, materials) {
  const channel = (await eventWrite(h, actors.owner, actors.approver, area, 'channels', 'POST', { name: `${h.state.testTag}-immutable-intent`, type: 'webhook', endpoint: 'https://event-receiver:9087/hook', auth: { type: 'bearer', token: materials.httpBearer } }, 'event.channel.save')).entity;
  h.receiver('event-receiver', { action: 'fault', fault: { delayMs: 14000, times: 1 } });
  const queued = (await eventWrite(h, actors.owner, actors.approver, area, `channels/${channel.id}/test`, 'POST', confirmation(channel), 'event.channel.test')).queued;
  await h.poll(async () => h.receiver('event-receiver', { action: 'stats' }).records.some(v => v.deliveryId === queued.deliveryId), Boolean, 'real receiver observes original request body before changing current credential generation');
  const rotated = (await eventWrite(h, actors.admin, actors.approver, area, `channels/${channel.id}`, 'PATCH', { revision: channel.revision, auth: { type: 'basic', ...materials.httpBasic } }, 'event.channel.save')).entity;
  h.check(rotated.credentialGeneration > channel.credentialGeneration, 'channel mutation changes current credential generation without changing original external intent');
  const delivery = await settledDelivery(h, actors.admin, area, queued.deliveryId, ['uncertain', 'paused_authority'], 30000);
  const attempts = rows(await eventRead(h, actors.admin, area, `deliveries/${delivery.id}/attempts`, { size: 20 }));
  h.check(attempts.length === 1 && attempts[0].sendStarted === true && attempts[0].outcome === 'uncertain', 'late provider acknowledgement after generation change cannot promote old intent to succeeded or resend it');
  const records = h.receiver('event-receiver', { action: 'stats' }).records.filter(v => v.deliveryId === queued.deliveryId);
  h.check(records.length === 1, 'receiver proves immutable original external intent was sent exactly once');
  const denied = await h.request(actors.admin, scope(area.cid, area.wid, `events/deliveries/${delivery.id}/replay`), 'POST', confirmation(delivery), { expected: [409] });
  h.check(denied.payload?.error?.code === 'DELIVERY_UNRESOLVED', 'immutable uncertain attempt forbids replay even when current delivery authority is paused');
  h.receiver('event-receiver', { action: 'fault', fault: { times: 0, delayMs: 0 } });
  return { channel: rotated, delivery };
}
export async function readonlyNotificationAcceptance(h, actors, area) {
  // Configure a personal preference with a temporary real grant, then revoke
  // that grant before the event. The read-only account's original role stays
  // unchanged; no SQL fixture insertion can mint a notification for it.
  const tempRole = await role(h, actors.admin, 'notification-setup-only', ['write', 'delete'].map(action => wsGrant(area.cid, area.wid, 'notifications', action)), area.cid, area.wid);
  const binding = h.data(await h.request(actors.admin, `/iam/users/${actors.readonly.user.id}/role-bindings`, 'POST', { role_id: tempRole.id, cluster_id: area.cid, workspace_id: area.wid }));
  const service = await nativeCreate(h, actors.admin, area, 'services', { name: `${h.state.testTag}-readonly-notification`, host: 'echo-upstream', port: 8081, tags: ['m7:readonly-notification'] });
  const pref = entity(h.data(await h.request(actors.readonly, '/notifications/preferences', 'POST', { clusterId: area.cid, workspaceId: area.wid, name: `${h.state.testTag}-readonly-notification`, eventTypes: ['entity.updated'], nativeType: 'services', nativeIds: [service.id], inAppEnabled: true })));
  h.state.fixtures.push({ type: 'preferences', id: pref.id, name: pref.name, actorLabel: 'read-only', ...area }); h.save();
  await h.request(actors.admin, `/iam/users/${actors.readonly.user.id}/role-bindings/${binding.id}`, 'DELETE', { revision: binding.revision, confirmed: true, confirm_name: tempRole.name });
  await h.request(actors.admin, scope(area.cid, area.wid, `entities/services/${service.id}`), 'PATCH', { retries: 2 });
  const values = await h.poll(async () => rows(h.data(await h.request(actors.readonly, `/notifications?${queryFor(area, { size: 100 })}`))).filter(v => v.link?.kind === 'event'), v => v.length > 0, 'current read-only actor receives its own source-authorized notification');
  const notification = values[0];
  h.check(notification.capabilities.read === true && notification.capabilities.write === false, 'notification capabilities use current revoked write authority');
  await h.request(actors.readonly, `/notifications/${notification.id}/read`, 'POST', { revision: notification.revision }, { expected: [403] });
  const unchanged = h.data(await h.request(actors.readonly, `/notifications/${notification.id}`));
  h.check(unchanged.revision === notification.revision && unchanged.readAt === notification.readAt, 'denied read-only mark has no personal mutation');
  // The preference now belongs to a genuine read-only owner. Cleanup receives
  // an explicit temporary grant through BFF before its own soft removal.
  h.state.readonlyPreferenceSetup = { roleId: tempRole.id, roleName: tempRole.name, bindingId: binding.id, userId: actors.readonly.user.id, preferenceId: pref.id, ...area }; h.save();
}
