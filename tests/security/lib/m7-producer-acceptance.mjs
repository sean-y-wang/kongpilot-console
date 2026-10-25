import { randomUUID } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { M7_COMPOSE, entity, rows, scope, sha256 } from './m7-harness.mjs';
import { nativeCreate } from './m7-fixtures.mjs';
import { eventRead, eventWrite } from './m7-event-acceptance.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const dispositions = new Set(['baseline_created', 'baseline_reset', 'unchanged', 'candidate', 'event_queued', 'quality_only', 'duplicate']);
export function certificateEndDate(date) { return date.toISOString().replace(/\D/g, '').slice(2, 14) + 'Z'; }
function certificate(h) {
  const directory = mkdtempSync(join(tmpdir(), 'kongos-m7-certificate-')); chmodSync(directory, 0o700); mkdirSync(join(directory, 'newcerts'), { mode: 0o700 });
  h.state.privateMaterialDirectories ??= []; h.state.privateMaterialDirectories.push(directory); h.save();
  writeFileSync(join(directory, 'index'), '', { mode: 0o600 }); writeFileSync(join(directory, 'serial'), '01\n', { mode: 0o600 });
  const config = `[ca]\ndefault_ca=local\n[local]\ndatabase=${directory}/index\nnew_certs_dir=${directory}/newcerts\nserial=${directory}/serial\nprivate_key=${directory}/ca.key\ncertificate=${directory}/ca.crt\ndefault_md=sha256\ndefault_days=1\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n`;
  writeFileSync(join(directory, 'ca.cnf'), config, { mode: 0o600 });
  const run = args => { try { execFileSync('openssl', args, { cwd: directory, stdio: ['ignore', 'pipe', 'pipe'] }); } catch { throw new Error('M7_LOCAL_CERTIFICATE_GENERATION_FAILED'); } };
  run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=M7 Test Only CA', '-keyout', 'ca.key', '-out', 'ca.crt']);
  run(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=m7-expiry.example.test', '-keyout', 'leaf.key', '-out', 'leaf.csr']);
  const expiresAt = new Date(Date.now() + 75000);
  run(['ca', '-batch', '-config', 'ca.cnf', '-in', 'leaf.csr', '-out', 'leaf.crt', '-notext', '-enddate', certificateEndDate(expiresAt)]);
  for (const file of ['ca.key', 'leaf.key']) chmodSync(join(directory, file), 0o600);
  const cert = readFileSync(join(directory, 'leaf.crt'), 'utf8'), key = readFileSync(join(directory, 'leaf.key'), 'utf8');
  h.state.secrets.push(key, readFileSync(join(directory, 'ca.key'), 'utf8')); h.save(); return { cert, key, expiresAt: expiresAt.toISOString() };
}

/** One process owns all real samples. Keys and subject precede its first GET;
 * a stopped/unknown sequence is never restarted with newly allocated keys. */
export async function observationSequence(h, area, type, id, afterSample = async () => undefined, count = 5) {
  h.check(['certificates', 'ca_certificates', 'upstreams'].includes(type) && UUID.test(id) && Number.isInteger(count) && count >= 1 && count <= 5, 'bounded sampler has exact fixed native subject');
  h.check(!h.state.samplingIntents.some(intent => intent.cid === area.cid && intent.type === type && intent.id === id && intent.state !== 'completed'), 'unresolved original sampling subject cannot allocate new keys or restart');
  const keys = Array.from({ length: count }, () => randomUUID()), intent = { cid: area.cid, wid: area.wid, type, id, keys, state: 'prepared', at: new Date().toISOString(), samples: [] };
  h.state.samplingIntents.push(intent); h.save();
  const command = [...M7_COMPOSE, 'exec', '-T', '-e', `EVENT_OBSERVATION_TEST_SCOPE=${area.cid}:${type}:${id}`, 'console-api', 'node', 'dist/infrastructure/event-observe-test.js', '--test-only', area.cid, type, id, keys.join(',')];
  let child, buffered = '', size = 0, pending = Promise.resolve(), exitCode, stopping = false, transportFailed = false;
  let timer, escalation, closeDeadline, resolveStopped;
  const stopped = new Promise(resolve => { resolveStopped = resolve; });
  const stopChild = () => {
    if (stopping) return;
    stopping = true;
    if (!child) { resolveStopped(); return; }
    try { child.kill('SIGTERM'); } catch { /* The original process may already be gone. */ }
    escalation = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
    // A malformed child implementation cannot make shutdown unbounded. Current
    // in-flight callbacks are still awaited below before declaring uncertainty.
    closeDeadline = setTimeout(() => { transportFailed = true; resolveStopped(); }, 3000);
  };
  try {
    child = spawn('docker', command, { stdio: ['ignore', 'pipe', 'pipe'] });
    child.once('error', () => { transportFailed = true; stopChild(); });
    child.once('close', code => { exitCode = code; resolveStopped(); });
    timer = setTimeout(() => { transportFailed = true; stopChild(); }, 150000);
    child.stderr.on('data', () => undefined); // Never publish raw stderr.
    child.stderr.on('error', () => { transportFailed = true; stopChild(); });
    child.stdout.on('error', () => { transportFailed = true; stopChild(); });
    child.stdout.on('data', chunk => {
      if (stopping) return;
      size += chunk.length;
      if (size > 16384) { transportFailed = true; stopChild(); return; }
      buffered += chunk.toString('utf8'); let end;
      while ((end = buffered.indexOf('\n')) !== -1) {
        const line = buffered.slice(0, end); buffered = buffered.slice(end + 1);
        pending = pending.then(async () => {
          if (stopping) throw new Error('M7_SAMPLER_CANCELLED_NO_FURTHER_CALLBACK');
          let sample; try { sample = JSON.parse(line); } catch { throw new Error('M7_SAMPLER_RESPONSE_INVALID'); }
          const index = intent.samples.length;
          // Retain a safe transport projection before rejecting a response;
          // diagnostics never need to guess what the original child returned.
          (intent.receivedResponses ??= []).push({ responseSha256: sha256(line),
            status: ['confirmed', 'uncertain'].includes(sample.status) ? sample.status : null,
            samplingKeyMatches: sample.samplingKey === keys[index], observationId: UUID.test(sample.observationId ?? '') ? sample.observationId : null,
            quality: ['verified', 'partial'].includes(sample.quality) ? sample.quality : null,
            disposition: dispositions.has(sample.disposition) ? sample.disposition : null,
            reconciled: typeof sample.reconciled === 'boolean' ? sample.reconciled : null,
            failureCode: typeof sample.failureCode === 'string' && /^[A-Z0-9_]{2,128}$/.test(sample.failureCode) ? sample.failureCode : null,
            failureKind: ['Error', 'TypeError', 'RangeError', 'ForbiddenException', 'ConflictException', 'ServiceUnavailableException', 'HttpException', 'DatabaseError'].includes(sample.failureKind) ? sample.failureKind : null,
            failureStage: ['source', 'persistence'].includes(sample.failureStage) ? sample.failureStage : null }); h.save();
          h.check(index < keys.length && sample.status === 'confirmed' && sample.samplingKey === keys[index] && UUID.test(sample.observationId) && (sample.eventId == null || UUID.test(sample.eventId)), 'real sampler response binds exact reserved key and observation');
          h.check(['verified', 'partial'].includes(sample.quality) && Number.isFinite(Date.parse(sample.observedAt)) && (!sample.disposition || dispositions.has(sample.disposition)) && sample.reconciled === false, 'new sequence contains fresh real observations without artificial time quality or baseline values');
          intent.samples.push(sample); intent.state = 'observed'; h.save();
          if (stopping) throw new Error('M7_SAMPLER_CANCELLED_NO_FURTHER_CALLBACK');
          await afterSample(sample, index);
        });
        // A failed proof terminates the sampler, while the original pending
        // callback settles before the durable unknown checkpoint is written.
        pending.catch(stopChild);
      }
    });
    await stopped; await pending;
    h.check(!stopping && !transportFailed && exitCode === 0 && !buffered.trim() && intent.samples.length === count, 'one live authority finishes all reserved bounded real samples');
    intent.state = 'completed'; h.save(); return intent.samples;
  } catch (error) {
    stopChild(); await stopped;
    try { await pending; } catch { /* Preserve the first failure; never replay. */ }
    intent.state = 'unknown'; h.save({ phase: 'stopped-producer-unknown' }); throw error;
  } finally { clearTimeout(timer); clearTimeout(escalation); clearTimeout(closeDeadline); }

}

export async function producerAcceptance(h, actors, channel, { expirySubscriptionSuffix = 'expiry' } = {}) {
  const area = actors.direct, actor = actors.admin;
  const certificateMaterial = certificate(h), cert = await nativeCreate(h, actor, area, 'certificates', { cert: certificateMaterial.cert, key: certificateMaterial.key, tags: ['m7:expiry'] });
  await eventWrite(h, actor, actors.approver, area, 'subscriptions', 'POST', { name: `${h.state.testTag}-${expirySubscriptionSuffix}`, channelId: channel.id, eventTypes: ['certificate.expiring'], nativeType: 'certificates', nativeIds: [cert.id] }, 'event.subscription.save');
  const certSamples = await observationSequence(h, area, 'certificates', cert.id);
  const expiry = await h.poll(async () => rows(await eventRead(h, actor, area, 'records', { nativeType: 'certificates', nativeId: cert.id, eventType: 'certificate.expiring', size: 20 })).find(value => value.payload?.expiry?.bucket === 'expired'), Boolean, 'actual signed certificate crosses expiry boundary and produces a current trusted event');
  h.check(expiry.actorType === 'system' && expiry.actorId === null && expiry.phase === 'observation' && expiry.payload.quality === 'verified' && new Date(expiry.payload.expiry.expiresAt).getTime() <= Date.now(), 'certificate expiry uses actual X509 time and system source with no user supplied observation');
  h.check(certSamples.some(sample => sample.quality === 'verified' && new Date(sample.observedAt).getTime() < new Date(expiry.payload.expiry.expiresAt).getTime()), 'bounded same-authority certificate sequence proves a genuine pre-expiry sample');
  const upstream = await nativeCreate(h, actor, area, 'upstreams', { name: `${h.state.testTag}-health`, healthchecks: { passive: { unhealthy: { http_failures: 1 } } }, tags: ['m7:health'] });
  const target = entity(h.data(await h.request(actor, scope(area.cid, area.wid, `upstreams/${upstream.id}/targets`), 'POST', { target: 'echo-upstream:8081', weight: 100 })));
  h.state.fixtures.push({ type: 'targets', id: target.id, name: target.target, parentId: upstream.id, ...area }); h.save();
  await h.request(actor, scope(area.cid, area.wid, `upstreams/${upstream.id}/targets/${target.id}/healthy`), 'POST');
  await eventWrite(h, actor, actors.approver, area, 'subscriptions', 'POST', { name: `${h.state.testTag}-health`, channelId: channel.id, eventTypes: ['upstream.health.changed'], nativeType: 'upstreams', nativeIds: [upstream.id] }, 'event.subscription.save');
  const healthSamples = await observationSequence(h, area, 'upstreams', upstream.id, async (_sample, index) => {
    if (index === 1) await h.request(actor, scope(area.cid, area.wid, `upstreams/${upstream.id}/targets/${target.id}/unhealthy`), 'POST');
  });
  const health = await h.poll(async () => rows(await eventRead(h, actor, area, 'records', { nativeType: 'upstreams', nativeId: upstream.id, eventType: 'upstream.health.changed', size: 20 })).find(value => value.payload?.health?.before === 'healthy' && value.payload?.health?.after === 'unhealthy'), Boolean, 'two real spaced Upstream observations confirm health transition');
  h.check(health.actorType === 'system' && health.actorId === null && health.phase === 'observation' && health.payload.quality === 'verified', 'Upstream health event retains actual system authority');
  h.check(healthSamples.filter(v => v.quality === 'verified').length >= 3, 'one live authority supplies multiple verified actual health observations');
  h.public ??= {}; h.public.producers = { certificateId: cert.id, upstreamId: upstream.id, eventIds: [expiry.id, health.id], realExpiry: true, actualHealthChange: true, syntheticObservationInputs: false, sameLiveAuthority: true };
  h.state.producersComplete = true; h.save(); return { certificate: cert, upstream, eventIds: [expiry.id, health.id] };
}
