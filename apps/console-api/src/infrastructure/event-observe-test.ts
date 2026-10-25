import 'reflect-metadata';
import { constants, closeSync, fstatSync, fsyncSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { DbService } from './db.service';
import { SecretService } from './secret.service';
import { EventRepositoryService, observationDigest } from '../modules/event-core/event-repository.service';
import type { DetectorSubject } from '../modules/event-core/event.types';
import { ObservationAuthorityService } from '../modules/event-observers/observation-authority.service';
import { NativeKongPolicyService } from '../modules/authorization/native-kong-policy.service';

const UUID = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
interface SamplingInput { clusterId: string; subjectType: DetectorSubject; subjectId: string; samplingKey: string; receiptDirectory: string }
interface SamplingDependencies { db: DbService; secrets: SecretService; authority: ObservationAuthorityService; events: EventRepositoryService }

/** Fixed error metadata only; raw messages, stacks, responses and credentials
 * never leave this auxiliary process. A failure remains uncertain. */
export function safeObservationFailure(error: unknown): { failureCode: string | null; failureKind: string | null } {
  try {
    const value = error as any;
    const response = typeof value?.getResponse === 'function' ? value.getResponse() : null;
    const code = response && typeof response === 'object' ? response.code ?? value?.code : value?.code;
    const kinds = ['Error', 'TypeError', 'RangeError', 'ForbiddenException', 'ConflictException', 'ServiceUnavailableException', 'HttpException', 'DatabaseError'];
    return { failureCode: typeof code === 'string' && /^[A-Z0-9_]{2,128}$/.test(code) ? code : null,
      failureKind: kinds.includes(value?.name) ? value.name : null };
  } catch { return { failureCode: null, failureKind: null }; }
}

/** Test-only real-source sampler. The private original receipt precedes SQL;
 * re-invocation only reconciles it, and never repeats a network observation. */
export async function sampleObservationOnce(deps: SamplingDependencies, input: SamplingInput): Promise<Record<string, unknown>> {
  if (![input.clusterId, input.subjectId, input.samplingKey].every(v => UUID.test(v))
    || !['certificates', 'ca_certificates', 'upstreams'].includes(input.subjectType)) throw new Error('OBSERVATION_TEST_INPUT_INVALID');
  mkdirSync(input.receiptDirectory, { recursive: true, mode: 0o700 });
  const directory = lstatSync(input.receiptDirectory);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o777) !== 0o700
    || directory.uid !== process.getuid?.()) throw new Error('OBSERVATION_TEST_DIRECTORY_UNSAFE');
  const path = join(input.receiptDirectory, `${input.samplingKey}.json`);
  const identity = { version: 1, clusterId: input.clusterId, subjectType: input.subjectType, subjectId: input.subjectId, samplingKey: input.samplingKey };
  let fd: number;
  try { fd = openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error: any) {
    if (error.code !== 'EEXIST') throw new Error('OBSERVATION_TEST_RECEIPT_UNAVAILABLE');
    const existing = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    let old: any;
    try {
      const stat = fstatSync(existing);
      if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid?.()) throw new Error();
      old = JSON.parse(readFileSync(existing, 'utf8'));
    } catch { throw new Error('OBSERVATION_TEST_RECEIPT_INVALID'); }
    finally { closeSync(existing); }
    for (const [key, value] of Object.entries(identity)) if (old[key] !== value) throw new Error('OBSERVATION_TEST_RECEIPT_SCOPE_CHANGED');
    if (old.state !== 'ready' || !UUID.test(old.observationId) || !/^[\da-f]{64}$/.test(old.observationHmac)) return { status: 'uncertain', samplingKey: input.samplingKey };
    const row = await deps.db.one<any>('SELECT observation_hmac,cluster_id,workspace_id,quality,observed_at FROM event_detection_observations WHERE id=$1', [old.observationId]);
    if (!row || row.cluster_id !== input.clusterId || row.observation_hmac !== old.observationHmac) return { status: 'uncertain', samplingKey: input.samplingKey, observationId: old.observationId };
    const event = await deps.db.one<{ id: string }>('SELECT id FROM event_records WHERE observation_id=$1', [old.observationId]);
    return { status: 'confirmed', samplingKey: input.samplingKey, observationId: old.observationId, eventId: event?.id ?? null,
      quality: row.quality, observedAt: new Date(row.observed_at).toISOString(), reconciled: true };
  }
  let captured: Awaited<ReturnType<ObservationAuthorityService['observe']>> | undefined, committed = false;
  const persist = (value: unknown) => {
    const buffer = Buffer.from(JSON.stringify(value) + '\n'); ftruncateSync(fd, 0);
    let offset = 0;
    while (offset < buffer.length) { const count = writeSync(fd, buffer, offset, buffer.length - offset, offset); if (count < 1) throw new Error('OBSERVATION_TEST_RECEIPT_UNAVAILABLE'); offset += count; }
    fsyncSync(fd);
  };
  try {
    persist({ ...identity, state: 'reserved' });
    const dirFd = openSync(input.receiptDirectory, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    captured = await deps.authority.observe(input.clusterId, input.subjectType, input.subjectId);
    persist({ ...identity, state: 'ready', observationId: captured.input.observationId, observationHmac: observationDigest(deps.secrets, captured.input) });
    const receipt = await deps.db.transaction(tx => deps.events.enqueueObservation(captured!.input, tx));
    committed = true;
    return { status: 'confirmed', samplingKey: input.samplingKey, observationId: receipt.observationId, eventId: receipt.eventId,
      disposition: receipt.disposition, quality: captured.input.quality, observedAt: captured.input.observedAt, reconciled: false };
  } catch (error) {
    return { status: 'uncertain', samplingKey: input.samplingKey, observationId: captured?.input.observationId ?? null,
      failureStage: captured ? 'persistence' : 'source', ...safeObservationFailure(error) };
  } finally { captured?.release(committed); closeSync(fd); }
}

async function main(): Promise<void> {
  const [flag, clusterId, subjectType, subjectId, rawKeys, extra] = process.argv.slice(2);
  const keys = parseSamplingKeys(rawKeys);
  if (process.env.NODE_ENV !== 'development' || flag !== '--test-only' || extra !== undefined
    || !UUID.test(clusterId ?? '') || !UUID.test(subjectId ?? '') || !['certificates', 'ca_certificates', 'upstreams'].includes(subjectType)
    || process.env.EVENT_OBSERVATION_TEST_SCOPE !== `${clusterId}:${subjectType}:${subjectId}`) throw new Error('OBSERVATION_TEST_FORBIDDEN');
  // This auxiliary process does not start another delivery worker or sampler.
  process.env.EVENT_DELIVERY_WORKER_ENABLED = 'false';
  process.env.EVENT_OUTBOX_WORKER_ENABLED = 'false';
  process.env.SKIP_MIGRATIONS = 'true';
  process.env.DEFAULT_KONG_ADMIN_URL = '';
  process.env.METRICS_BRIDGE_ENABLED = 'false';
  const { NestFactory } = await import('@nestjs/core');
  const { AppModule } = await import('../app.module');
  const { EventObserverService } = await import('../modules/event-observers/event-observer.service');
  const { EntityIndexService } = await import('../modules/entities/entity-index.service');
  const { AuditExportService } = await import('../modules/audit/audit-export.service');
  // These lifecycle hooks belong to this isolated, test-only CLI process.
  // Keep the actual DI/policies and detector implementation; suppress its
  // unrelated index/export timers before Nest initializes the auxiliary app.
  for (const service of [EventObserverService, EntityIndexService, AuditExportService]) service.prototype.onModuleInit = () => undefined;
  const app = await NestFactory.createApplicationContext(AppModule, { logger: false, abortOnError: false });
  try {
    initializeObservationPolicy(app);
    const deps = { db: app.get(DbService), secrets: app.get(SecretService), authority: app.get(ObservationAuthorityService), events: app.get(EventRepositoryService) };
    await sampleObservationSequence(deps, { clusterId, subjectType: subjectType as DetectorSubject, subjectId,
      receiptDirectory: '/tmp/kongos-m7-observation-receipts' }, keys, result => {
      process.stdout.write(JSON.stringify(result) + '\n'); if (result.status !== 'confirmed') process.exitCode = 2;
    });
  } finally { await app.close(); }
}
/** Application contexts do not execute the HTTP bootstrap. Install the same
 * real policy before any auxiliary Kong read; no test policy bypass is used. */
export function initializeObservationPolicy(app: { get(type: typeof NativeKongPolicyService): NativeKongPolicyService }): void {
  app.get(NativeKongPolicyService).install();
}
export function parseSamplingKeys(value: string): string[] {
  const keys = typeof value === 'string' ? value.split(',') : [];
  if (keys.length < 1 || keys.length > 5 || keys.some(key => !UUID.test(key)) || new Set(keys).size !== keys.length) throw new Error('OBSERVATION_TEST_KEYS_INVALID');
  return keys;
}
/** A bounded sequence retains the same live authority. Separate processes
 * cannot claim continuity across a restart, even when their receipts exist. */
export async function sampleObservationSequence(deps: SamplingDependencies, input: Omit<SamplingInput, 'samplingKey'>,
  keys: string[], emit: (result: Record<string, unknown>) => void,
  wait: (milliseconds: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms))): Promise<void> {
  parseSamplingKeys(keys.join(','));
  for (let index = 0; index < keys.length; index++) {
    const result = await sampleObservationOnce(deps, { ...input, samplingKey: keys[index] });
    emit(result);
    if (result.status !== 'confirmed') return;
    if (index + 1 < keys.length) await wait(30_000);
  }
}
if (require.main === module) main().catch(() => { process.stderr.write('OBSERVATION_TEST_FAILED\n'); process.exitCode = 1; });
