import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { AuditService } from '../../apps/console-api/src/modules/audit/audit.service';
import { SecretService, canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';

describe('AuditService redacted, transactional hash chain', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());

  function database() {
    const tx: any = { exec: vi.fn().mockResolvedValue(1), one: vi.fn().mockResolvedValue({ last_sequence: '41', last_hash: 'prior-hash' }) };
    const db: any = { transaction: vi.fn(async (callback: any) => callback(tx)) };
    return { tx, db };
  }

  it('uses serialized head updates and hashes exactly the persisted redacted record', async () => {
    const { tx, db } = database();
    const outbox={fromAudit:vi.fn().mockResolvedValue(null)};
    const audit = new AuditService(db, new SecretService(),outbox as any);
    const receipt = await audit.append({ clusterId: 'a-cluster', actorId: 'an-actor', entityType: 'plugins', entityId: 'plugin-one',
      action: 'update', before: { password: 'old-value', enabled: false }, after: { password: 'new-value', enabled: true } });
    expect(tx.exec.mock.calls[0][0]).toBe('SELECT pg_advisory_xact_lock(hashtext($1))');
    expect(tx.one.mock.calls[0][0]).toContain('FOR UPDATE');
    const insert = tx.exec.mock.calls.find((call: any[]) => String(call[0]).startsWith('INSERT INTO audit_events'));
    const p = insert[1];
    const record = { id: p[0], chain_scope: p[1], sequence: p[2], actor_id: p[3], actor_type: p[4], source_ip: p[5],
      cluster_id: p[6], workspace_id: p[7], entity_type: p[8], entity_id: p[9], action: p[10], before: JSON.parse(p[11]),
      after: JSON.parse(p[12]), json_patch: JSON.parse(p[13]), workflow_id: p[14], result: p[15], request_id: p[16],
      prev_hash: p[17], occurred_at: p[19] };
    expect(p[18]).toBe(createHash('sha256').update(canonicalJson(record)).digest('hex'));
    expect(p[2]).toBe('42');
    expect(JSON.stringify(p)).not.toContain('old-value');
    expect(JSON.stringify(p)).not.toContain('new-value');
    expect(tx.exec.mock.calls.at(-1)[1]).toEqual(['cluster:a-cluster', '42', p[18]]);
    expect(receipt).toEqual({ id: p[0], chainScope: p[1], sequence: p[2], eventHash: p[18], occurredAt: p[19] });
    expect(outbox.fromAudit).toHaveBeenCalledExactlyOnceWith(receipt,{quality:'legacy_unknown',module:'plugins'},tx);
  });

  it('uses a supplied mutation transaction for atomic audit persistence', async () => {
    const base = database();
    const supplied = database();
    await new AuditService(base.db, new SecretService(),{fromAudit:vi.fn().mockResolvedValue(null)} as any).append({ entityType: 'cluster', action: 'create' }, supplied.db);
    expect(base.db.transaction).not.toHaveBeenCalled();
    expect(supplied.db.transaction).toHaveBeenCalledOnce();
  });

  it('does not advance the chain if event insertion fails', async () => {
    const { tx, db } = database();
    tx.exec.mockImplementation(async (sql: string) => { if (sql.startsWith('INSERT INTO audit_events')) throw new Error('write rejected'); return 1; });
    const outbox={fromAudit:vi.fn().mockResolvedValue(null)};
    await expect(new AuditService(db, new SecretService(),outbox as any).append({ entityType: 'cluster', action: 'create' })).rejects.toThrow('write rejected');
    expect(tx.exec.mock.calls.some((call: any[]) => String(call[0]).startsWith('UPDATE audit_chain_heads'))).toBe(false);
    expect(outbox.fromAudit).not.toHaveBeenCalled();
  });
  it('keeps the exact hints outside the hash and propagates outbox failure into the supplied transaction',async()=>{
    const {db,tx}=database();const hints={quality:'verified' as const,module:'services',nativeType:'services',nativeId:'native-id',beforeExists:false,afterExists:true,afterTags:['tag'],afterWorkspaceId:'workspace-id'};
    const outbox={fromAudit:vi.fn().mockRejectedValue(new Error('outbox failed'))};
    await expect(new AuditService(db,new SecretService(),outbox as any).append({entityType:'services',action:'create',scopeHints:hints})).rejects.toThrow('outbox failed');
    const inserted=tx.exec.mock.calls.find((call:any[])=>String(call[0]).startsWith('INSERT INTO audit_events'));
    expect(inserted[1]).toHaveLength(20);expect(JSON.stringify(inserted[1])).not.toContain('native-id');
    expect(outbox.fromAudit).toHaveBeenCalledWith(expect.objectContaining({sequence:'42'}),hints,tx);
  });
});
