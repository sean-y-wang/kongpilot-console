import { randomUUID } from 'node:crypto';
import { entity, rows, scope } from './m7-harness.mjs';

export const confirmation = value => ({ revision: value.revision, confirmed: true, confirm_name: value.name ?? value.id });
export async function eventRead(h, actor, area, path, query) {
  const data = h.data(await h.request(actor, scope(area.cid, area.wid, `events/${path}`, query)));
  // A workflow receipt deliberately also carries an entity summary. It is
  // never a directory detail and must retain its original receipt namespace.
  return /^(channels|subscriptions|deliveries|records)\/[a-f0-9-]{36}$/.test(path) ? entity(data) : data;
}
export async function eventWrite(h, actor, approver, area, path, method, body, expectedHandler, approval = false) {
  const key = randomUUID(), received = h.data(await h.request(actor, scope(area.cid, area.wid, `events/${path}`), method, body, { key }));
  h.check(received.handler === expectedHandler && received.clusterId === area.cid && received.workspaceId === area.wid && received.idempotencyKey === key, 'event receipt binds original handler actor key cluster and workspace', { handler: expectedHandler, approval });
  if (approval) {
    h.check(received.domain === 'workflow' && received.state === 'pending' && received.configurationCommitted === false && received.submissionCompleted === true, 'approval receipt proves submission without configuration execution', { handler: expectedHandler });
    let detail = h.data(await h.request(approver, scope(area.cid, area.wid, `workflows/${received.workflowId}`))), wf = detail.entity;
    h.check(wf.kind === 'event-metadata' && detail.steps.length === 1 && detail.steps.every(step => step.kind === 'metadata'), 'fixed event metadata approval exposes only one metadata step');
    const decisionKey = randomUUID(), decision = h.data(await h.request(approver, scope(area.cid, area.wid, `workflows/${wf.id}/approve`), 'POST', { revision: wf.revision, planHash: wf.planHash, confirmed: true, confirm_name: wf.kind, reason: 'M7 independent metadata approval', execute: false }, { key: decisionKey })).entity;
    h.check(decision.id === wf.id && decision.clusterId === area.cid && decision.workspaceId === area.wid && decision.state === 'approved' && decision.planHash === wf.planHash, 'approval response binds exact original workflow and plan');
    const decisionReceipt = h.data(await h.request(approver, scope(area.cid, area.wid, `workflows/receipts/by-key/${decisionKey}`)));
    h.check(decisionReceipt.action === 'approve' && decisionReceipt.idempotencyKey === decisionKey && decisionReceipt.decisionCompleted === true && decisionReceipt.workflowId === wf.id && decisionReceipt.clusterId === area.cid && decisionReceipt.workspaceId === area.wid, 'original decision key proves one persisted decision for exact workflow scope');
    wf = h.data(await h.request(actor, scope(area.cid, area.wid, `workflows/${wf.id}`))).entity;
    h.check(wf.state === 'approved', 'independent approver decision is actually persisted');
    const executionKey = randomUUID(), execution = h.data(await h.request(actor, scope(area.cid, area.wid, `workflows/${wf.id}/execute`), 'POST', { revision: wf.revision, planHash: wf.planHash, confirmed: true, confirm_name: wf.kind }, { key: executionKey }));
    h.check(execution.workflowId === wf.id && execution.clusterId === area.cid && execution.workspaceId === area.wid && execution.state === 'succeeded' && execution.steps.length === 1 && execution.steps.every(step => step.state === 'succeeded'), 'execution response proves exact workflow single metadata terminal result');
    const executionReceipt = h.data(await h.request(actor, scope(area.cid, area.wid, `workflows/receipts/by-key/${executionKey}`)));
    h.check(executionReceipt.action === 'execute' && executionReceipt.idempotencyKey === executionKey && executionReceipt.workflowId === wf.id && executionReceipt.executionId === execution.executionId && executionReceipt.clusterId === area.cid && executionReceipt.workspaceId === area.wid && executionReceipt.state === 'succeeded', 'original execution key resolves exact existing terminal execution without re-dispatch');
  } else h.check(received.domain === 'iam' && received.state === 'succeeded', 'direct event metadata uses terminal IAM receipt');
  const receipt = await eventRead(h, actor, area, `operations/by-key/${key}`);
  h.check(receipt.state === 'succeeded' && receipt.configurationCommitted === true && receipt.executionCompleted === true && receipt.handler === expectedHandler && receipt.idempotencyKey === key && receipt.clusterId === area.cid && receipt.workspaceId === area.wid && receipt.domain === received.domain && receipt.id === received.id && (approval ? receipt.workflowId === received.workflowId : !receipt.workflowId), 'original event receipt proves completed exact business operation', { handler: expectedHandler, approval });
  h.state.eventOperations ??= []; h.state.eventOperations.push({ key, handler: expectedHandler, approval, cid: area.cid, wid: area.wid, operationId: receipt.id, workflowId: receipt.workflowId ?? null, queued: receipt.result?.queued ?? null }); h.save();
  if (receipt.result?.entity) {
    const value = receipt.result.entity, type = expectedHandler.includes('channel') ? 'channels' : 'subscriptions';
    if (!h.state.fixtures.some(v => v.id === value.id)) { h.state.fixtures.push({ type, id: value.id, name: value.name, ...area }); h.save(); }
  }
  return receipt.result;
}
export async function settledDelivery(h, actor, area, id, states = ['succeeded'], timeoutMs = 45000) {
  const terminal = ['succeeded', 'exhausted', 'uncertain', 'paused_authority', 'cancelled'];
  const value = await h.poll(() => eventRead(h, actor, area, `deliveries/${id}`), v => terminal.includes(v.state), 'delivery reaches a real terminal or explicitly paused state', timeoutMs);
  h.check(states.includes(value.state), `delivery expected ${states.join('/')} received ${value.state}`, { deliveryId: id, state: value.state });
  const attempts = rows(await eventRead(h, actor, area, `deliveries/${id}/attempts`, { size: 20 }));
  h.check(attempts.length > 0, 'real delivery attempts are visible without payload or credentials', { deliveryId: id, attemptCount: attempts.length });
  return value;
}
export async function testChannel(h, actor, approver, area, id, approval, expected = ['succeeded']) {
  const channel = await eventRead(h, actor, area, `channels/${id}`), result = await eventWrite(h, actor, approver, area, `channels/${id}/test`, 'POST', confirmation(channel), 'event.channel.test', approval);
  h.check(result?.queued?.deliveryId && result.queued.eventId, 'test queue receipt names a durable exact event and delivery');
  const delivery = await settledDelivery(h, actor, area, result.queued.deliveryId, expected);
  return { delivery, queued: result.queued };
}
export async function nineMetadataHandlers(h, actors, area, materials, approval = false) {
  const { admin, approver } = actors, suffix = approval ? 'approval' : 'direct';
  let result = await eventWrite(h, admin, approver, area, 'channels', 'POST', { name: `${h.state.testTag}-${suffix}-nine`, type: 'email', endpoint: { recipients: ['acceptance@example.test'] }, auth: { type: 'none' } }, 'event.channel.save', approval), channel = result.entity;
  h.check(channel.type === 'email' && channel.configured && channel.status === 'active', 'safe channel projection proves configured active metadata without SMTP secret');
  channel = (await eventWrite(h, admin, approver, area, `channels/${channel.id}`, 'PATCH', { revision: channel.revision, status: 'active' }, 'event.channel.save', approval)).entity;
  channel = (await eventWrite(h, admin, approver, area, `channels/${channel.id}/status`, 'POST', { ...confirmation(channel), status: 'disabled' }, 'event.channel.status', approval)).entity;
  h.check(channel.status === 'disabled', 'channel status metadata disables real channel');
  channel = (await eventWrite(h, admin, approver, area, `channels/${channel.id}/status`, 'POST', { ...confirmation(channel), status: 'active' }, 'event.channel.status', approval)).entity;
  let subscription = (await eventWrite(h, admin, approver, area, 'subscriptions', 'POST', { name: `${h.state.testTag}-${suffix}-nine-sub`, channelId: channel.id, eventTypes: ['entity.created'], nativeType: 'services', tags: ['m7:metadata-silent'] }, 'event.subscription.save', approval)).entity;
  subscription = (await eventWrite(h, admin, approver, area, `subscriptions/${subscription.id}`, 'PATCH', { revision: subscription.revision, eventTypes: ['entity.created', 'entity.updated'] }, 'event.subscription.save', approval)).entity;
  subscription = (await eventWrite(h, admin, approver, area, `subscriptions/${subscription.id}`, 'DELETE', confirmation(subscription), 'event.subscription.delete', approval)).entity;
  h.check(subscription.status === 'deleted', 'subscription deletes to soft metadata tombstone');
  subscription = (await eventWrite(h, admin, approver, area, `subscriptions/${subscription.id}/restore`, 'POST', confirmation(subscription), 'event.subscription.restore', approval)).entity;
  h.check(subscription.status === 'disabled', 'subscription restoration does not auto resume delivery');
  // STARTTLS strip is known failure before AUTH or DATA: safe to replay once
  // after repairing the provider. An uncertain body send is never replayable.
  const smtpBefore = h.receiver('event-mail', { action: 'stats' });
  h.receiver('event-mail', { action: 'fault', fault: { starttlsDisabled: true, times: 100 } });
  const { delivery } = await testChannel(h, admin, approver, area, channel.id, approval, ['exhausted']);
  const failedAttempts = rows(await eventRead(h, admin, area, `deliveries/${delivery.id}/attempts`, { size: 20 })), smtpAfter = h.receiver('event-mail', { action: 'stats' });
  h.check(delivery.errorCode === 'EVENT_SMTP_STARTTLS_REQUIRED' && failedAttempts.length === 1 && failedAttempts[0].sendStarted === false && smtpAfter.auth === smtpBefore.auth && smtpAfter.received === smtpBefore.received, 'stripped STARTTLS rejects before SMTP AUTH and DATA with no receiver credential or message exposure');
  h.receiver('event-mail', { action: 'fault', fault: { starttlsDisabled: false, times: 0 } });
  const replay = await eventWrite(h, admin, approver, area, `deliveries/${delivery.id}/replay`, 'POST', confirmation(delivery), 'event.delivery.replay', approval);
  await settledDelivery(h, admin, area, replay.queued.deliveryId);
  channel = await eventRead(h, admin, area, `channels/${channel.id}`);
  channel = (await eventWrite(h, admin, approver, area, `channels/${channel.id}`, 'DELETE', confirmation(channel), 'event.channel.delete', approval)).entity;
  h.check(channel.status === 'deleted', 'channel deletes to soft metadata tombstone');
  channel = (await eventWrite(h, admin, approver, area, `channels/${channel.id}/restore`, 'POST', confirmation(channel), 'event.channel.restore', approval)).entity;
  h.check(channel.status === 'disabled', 'channel restore retains disabled status and requires explicit re-enable');
  const handlers = new Set(h.state.eventOperations.filter(v => v.approval === approval && v.cid === area.cid && v.wid === area.wid).map(v => v.handler));
  h.check(handlers.size === 9, 'all nine fixed metadata handlers complete through real original receipts', { mode: suffix, handlers: handlers.size }); return { channel, subscription };
}
export async function fourProviderDelivery(h, actors, area, materials) {
  const types = [
    { type: 'webhook', endpoint: 'https://event-receiver:9087/hook', auth: { type: 'bearer', token: materials.httpBearer } },
    { type: 'email', endpoint: { recipients: ['acceptance@example.test'] }, auth: { type: 'none' } },
    { type: 'slack', endpoint: 'https://event-receiver:9087/hook', auth: { type: 'none' } },
    { type: 'feishu', endpoint: 'https://event-receiver:9087/hook', auth: { type: 'none' } },
  ]; const channels = [];
  for (const config of types) {
    const result = await eventWrite(h, actors.admin, actors.approver, area, 'channels', 'POST', { ...config, name: `${h.state.testTag}-${config.type}` }, 'event.channel.save');
    const channel = result.entity; channels.push(channel); await testChannel(h, actors.admin, actors.approver, area, channel.id, false);
  }
  const webhook = channels[0];
  h.receiver('event-receiver', { action: 'fault', fault: { status: 429, times: 1 } });
  const retried = await testChannel(h, actors.admin, actors.approver, area, webhook.id, false);
  const retryAttempts = rows(await eventRead(h, actors.admin, area, `deliveries/${retried.delivery.id}/attempts`, { size: 20 }));
  const retryRecords = h.receiver('event-receiver', { action: 'stats' }).records.filter(v => v.deliveryId === retried.delivery.id);
  h.check(retryAttempts.length === 2 && retryAttempts.some(v => v.httpStatus === 429) && retryRecords.length === 2 && new Set(retryRecords.map(v => v.idempotencyDigest)).size === 1 && new Set(retryRecords.map(v => v.bodyDigest)).size === 1, 'known429 bounded worker retry preserves original idempotency and immutable body');
  h.receiver('event-receiver', { action: 'fault', fault: { status: 200, times: 0 } });
  h.receiver('event-receiver', { action: 'fault', fault: { dropAfterBody: true, times: 1 } });
  const { delivery } = await testChannel(h, actors.admin, actors.approver, area, webhook.id, false, ['uncertain']);
  const denied = await h.request(actors.admin, scope(area.cid, area.wid, `events/deliveries/${delivery.id}/replay`), 'POST', confirmation(delivery), { expected: [409] });
  h.check(denied.payload?.error?.code === 'DELIVERY_UNRESOLVED', 'uncertain external body send cannot be replayed to duplicate delivery');
  h.receiver('event-receiver', { action: 'fault', fault: { times: 0, dropAfterBody: false } });
  const basic = (await eventWrite(h, actors.admin, actors.approver, area, 'channels', 'POST', { name: `${h.state.testTag}-basic`, type: 'webhook', endpoint: 'https://event-receiver:9087/hook', auth: { type: 'basic', ...materials.httpBasic } }, 'event.channel.save')).entity;
  await testChannel(h, actors.admin, actors.approver, area, basic.id, false);
  const webStats = h.receiver('event-receiver', { action: 'stats' }), smtpStats = h.receiver('event-mail', { action: 'stats' });
  h.check(webStats.unique >= 4 && smtpStats.unique >= 1 && webStats.auth >= 2 && smtpStats.auth >= 1, 'local receivers independently confirm provider shape TLS SMTP AUTH bearer and Basic delivery');
  h.public ??= {}; h.public.providerStats = { webhookUnique: webStats.unique, smtpUnique: smtpStats.unique, receiverDuplicates: webStats.duplicates + smtpStats.duplicates };
  return channels;
}
