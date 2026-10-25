import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { OutboxRepositoryService } from '../../apps/console-api/src/modules/event-core/outbox-repository.service';
import { DeliveryRepositoryService } from '../../apps/console-api/src/modules/event-core/delivery-repository.service';
import { NotificationOperationsService } from '../../apps/console-api/src/modules/event-core/notification-operations.service';
import { HistoricalEventAccessService } from '../../apps/console-api/src/modules/authorization/historical-event-access.service';

const id = (n: number) => `${n.toString(16).padStart(8, '0')}-1111-4111-8111-111111111111`;
const cid = id(1), wid = id(2), uid = id(3), eid = id(4), did = id(5), channel = id(6);
const actor = { id: uid, username: 'synthetic-current-owner', superAdmin: false };
function event(secrets: SecretService) {
  const payload = { version: 1, title: '网关变更', summary: '网关变更', eventType: 'entity.updated', phase: 'terminal', result: 'success' };
  return { id: eid, cluster_id: cid, workspace_id: wid, event_type: payload.eventType, phase: 'terminal',
    source_kind: 'audit', source_id: id(7), actor_type: 'user', actor_id: uid, occurred_at: new Date().toISOString(),
    source_scope: { version: 1, quality: 'verified', module: 'services', before: null, after: { workspaceId: wid, physicalTags: ['business:allowed'] } },
    source_scope_hmac: 'a'.repeat(64), payload_safe: payload, payload_digest: secrets.fingerprint(payload), audit_event_id: id(7), audit_event_hash: 'b'.repeat(64) };
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'a8'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M7 independent resumable fanout source adversaries', () => {
  it('keeps a stable >50 candidate bound, resumes once, and checks current authority on the later page', async () => {
    const secrets = new SecretService(), source = event(secrets), inserted: any[] = [], revoked = new Set<string>();
    const row: any = { id: id(8), event_id: eid, state: 'dispatching', revision: 1, lease_generation: 1,
      lease_owner_hash: secrets.fingerprint('synthetic-owner'), lease_until: new Date(Date.now() + 30000),
      subscription_upper_bound: 55, personal_upper_bound: 0, subscription_cursor: null, personal_cursor: null,
      subscription_complete: false, personal_complete: true };
    const candidates = Array.from({ length: 55 }, (_, index) => ({ sequence: index + 1, subscription_id: id(100 + index),
      cluster_id: cid, workspace_id: wid, created_by: id(200 + index), revision: 1, current_revision: 1,
      channel_id: channel, channel_revision: 2, credential_generation: 3, current_channel: channel,
      status: 'active', current_status: 'active', channel_status: 'active', event_types: ['entity.updated'],
      native_type: null, native_ids: [], physical_tags: [] }));
    const db: any = { transaction: async (fn: any) => fn(db),
      query: vi.fn(async (sql: string, params: any[]) => {
        if (sql.includes('WITH due AS')) return [structuredClone(row)];
        if (sql.includes('event_subscription_versions')) {
          expect(params[0]).toBe(55); expect(params[4]).toBe(50);
          return candidates.filter(v => v.sequence <= params[0] && (!params[3] || v.subscription_id > params[3])).slice(0, 50);
        }
        throw new Error('Unexpected source-only query');
      }), one: vi.fn(async (sql: string, params: any[]) => {
        if (sql.includes('FROM event_outbox')) return structuredClone(row);
        if (sql.includes('FROM event_records')) return structuredClone(source);
        if (sql.includes('FROM users')) return { id: params[0], username: 'synthetic', super_admin: false };
        if (sql.startsWith('UPDATE event_outbox')) {
          row.subscription_cursor = JSON.parse(params[1]); row.subscription_complete = params[3];
          row.personal_complete = params[4]; row.state = params[5]; row.revision++;
          return { revision: row.revision };
        }
        throw new Error('Unexpected source-only lookup');
      }), exec: vi.fn(async (sql: string, params: any[]) => {
        if (sql.startsWith('INSERT INTO event_deliveries')) { inserted.push(params); return 1; }
        throw new Error('Unexpected source-only write');
      }) };
    const access: any = { assertWholeWorkspace: vi.fn(async (a: any) => {
      if (revoked.has(a.id)) throw new Error('Unexpected whole-authority call after deny');
    }), canSourceRead: vi.fn(async (a: any) => !revoked.has(a.id)) };
    const repository = new OutboxRepositoryService(db, secrets, access), [claim] = await repository.claimDue({ owner: 'synthetic-owner', limit: 1, leaseMs: 30000 });
    expect(await repository.fanoutPage(claim)).toEqual({ complete: false, created: 50 });
    // Revoke after the first page. The next candidate must not use a cached
    // first-page decision; a later config revision also makes a row ineligible.
    revoked.add(candidates[51].created_by);
    access.assertWholeWorkspace.mockImplementation(async () => undefined);
    candidates[52].current_revision = 2;
    candidates.push({ ...candidates[54], sequence: 56, subscription_id: id(999), created_by: id(998) });
    expect(await repository.fanoutPage(claim)).toEqual({ complete: true, created: 3 });
    expect(inserted).toHaveLength(53);
    expect(inserted.some(params => params[9] === candidates[51].created_by)).toBe(false);
    expect(inserted.some(params => params[4] === candidates[52].subscription_id || params[4] === id(999))).toBe(false);
    expect(access.canSourceRead.mock.calls.some(args => args[0].id === candidates[51].created_by)).toBe(true);
    await expect(repository.fanoutPage({ ...claim })).rejects.toMatchObject({ response: { code: 'OUTBOX_CLAIM_INVALID' } });
  });
});

function deliveryFixture() {
  const secrets = new SecretService(), source = event(secrets), attempts: any[] = [];
  const row: any = { id: did, event_id: eid, occurred_at: source.occurred_at, source_id: source.source_id,
    cluster_id: cid, workspace_id: wid, delivery_kind: 'test', subscription_id: null, subscription_revision: null,
    channel_id: channel, channel_revision: 2, credential_generation: 3, creator_id: uid, state: 'claimed',
    lease_owner_hash: secrets.fingerprint('synthetic-worker'), lease_generation: 1, lease_until: new Date(Date.now() + 30000),
    attempt_count: 0, idempotency_key: 'synthetic-original-intent', payload_safe: source.payload_safe,
    payload_digest: source.payload_digest, expires_at: new Date(Date.now() + 3600000) };
  const db: any = { transaction: async (fn: any) => fn(db), query: vi.fn(async () => [structuredClone(row)]),
    one: vi.fn(async () => structuredClone(row)), exec: vi.fn(async (sql: string, params: any[]) => {
      if (sql.startsWith('INSERT INTO event_delivery_attempts')) attempts.push(params);
      if (sql.includes("SET state='sending'")) { row.state = 'sending'; row.intent_attempt_no = params[1]; row.intent_lease_generation = params[2]; row.intent_started_at = new Date(); }
      else if (sql.startsWith('UPDATE event_deliveries SET state=$2')) {
        row.state = params[1]; row.attempt_count = params[2]; row.lease_owner_hash = null; row.lease_until = null;
        row.intent_attempt_no = null; row.intent_lease_generation = null; row.intent_started_at = null;
      }
      return 1;
    }) };
  const access: any = { assertDeliveryCurrent: vi.fn(async () => undefined) };
  return { row, attempts, db, access, repository: new DeliveryRepositoryService(db, secrets, access) };
}
describe('M7 independent immutable delivery intent and owner-ledger adversaries', () => {
  it('records a real same-lease ACK once and invalidates its completed claim', async () => {
    const f = deliveryFixture(), [claim] = await f.repository.claimDue({ owner: 'synthetic-worker', limit: 1, leaseMs: 30000 });
    await f.repository.commitSendIntent(claim);
    expect(await f.repository.finalize(claim, { outcome: 'succeeded', sendStarted: true, durationMs: 1, retryable: false })).toBe(true);
    expect(f.row.state).toBe('succeeded'); expect(f.attempts).toHaveLength(1); expect(f.attempts[0][3]).toBe(1);
    await expect(f.repository.finalize(claim, { outcome: 'succeeded', sendStarted: true, durationMs: 2, retryable: false })).rejects.toMatchObject({ response: { code: 'DELIVERY_CLAIM_INVALID' } });
    expect(f.attempts).toHaveLength(1);
  });
  it('does not let a late ACK overwrite a replacement lease or create an attempt', async () => {
    const f = deliveryFixture(), [claim] = await f.repository.claimDue({ owner: 'synthetic-worker', limit: 1, leaseMs: 30000 });
    await f.repository.commitSendIntent(claim); f.row.lease_generation++;
    expect(await f.repository.finalize(claim, { outcome: 'succeeded', sendStarted: true, durationMs: 9, retryable: false })).toBe(false);
    expect(f.attempts).toEqual([]); expect(f.row.state).toBe('sending'); expect(f.row.lease_generation).toBe(2);
  });
  it('recovers an expired committed intent as immutable uncertain and rejects its later ACK', async () => {
    const f = deliveryFixture(), [claim] = await f.repository.claimDue({ owner: 'synthetic-worker', limit: 1, leaseMs: 30000 });
    await f.repository.commitSendIntent(claim); f.row.lease_until = new Date(0);
    expect(await f.repository.recoverExpiredIntents({ limit: 1 })).toBe(1);
    expect(f.row.state).toBe('uncertain'); expect(f.row.attempt_count).toBe(1);
    expect(f.attempts[0][4]).toBe(1); // Recovery uses the committed original lease generation.
    const count = f.attempts.length;
    expect(await f.repository.finalize(claim, { outcome: 'succeeded', sendStarted: true, durationMs: 9, retryable: false })).toBe(false);
    expect(f.attempts).toHaveLength(count); expect(f.row.state).toBe('uncertain');
  });
  it('denies another owner even for a super-admin before using a personal ledger', async () => {
    const db: any = { one: vi.fn(), query: vi.fn() }, auth: any = { snapshot: vi.fn() };
    const access = new HistoricalEventAccessService(db, auth, new SecretService(), {} as any);
    await expect(access.assertNotificationOwner({ ...actor, id: id(99), superAdmin: true }, uid, cid, wid, 'read')).rejects.toMatchObject({ response: { code: 'PERMISSION_DENIED' } });
    expect(db.one).not.toHaveBeenCalled(); expect(auth.snapshot).not.toHaveBeenCalled();
  });
  it('queries personal receipts with the current actor and never decrypts a foreign key result', async () => {
    const secrets = new SecretService(), decrypt = vi.spyOn(secrets, 'decrypt'), db: any = { one: vi.fn(async () => null) };
    const access: any = { permissionVersion: vi.fn(async () => 'current') }, writer = new NotificationOperationsService(db, secrets, access, {} as any);
    await expect(writer.receipt({ user: actor, idempotencyKey: 'unused-personal-key' } as any, 'synthetic-foreign-key')).rejects.toMatchObject({ response: { code: 'NOTIFICATION_OPERATION_NOT_FOUND' } });
    expect(db.one).toHaveBeenCalledWith(expect.stringContaining('actor_id=$1 AND idempotency_key=$2'), [uid, 'synthetic-foreign-key']);
    expect(decrypt).not.toHaveBeenCalled();
  });
});
