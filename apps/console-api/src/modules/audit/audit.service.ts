import { Injectable } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { AuditOutboxWriter } from '../event-core/audit-outbox-writer.service';
import type { TrustedAuditScopeHints } from '../event-core/event.types';
export type { TrustedAuditScopeHints } from '../event-core/event.types';

export interface AuditEvent {
  actorId?: string | null;
  actorType?: string;
  clusterId?: string | null;
  workspaceId?: string | null;
  entityType: string;
  entityId?: string | null;
  action: string;
  before?: unknown;
  after?: unknown;
  result?: string;
  requestId?: string;
  ip?: string;
  workflowId?: string | null;
  /** Server-only sampling proof; never added to the legacy nineteen-field hash. */
  scopeHints?: TrustedAuditScopeHints;
}

export type JsonPatchOperation = { op: 'add' | 'remove' | 'replace'; path: string; value?: unknown };

/** Server receipt for the exact committed chain row; it grants no read or write authority. */
export interface AuditOutboxReceipt {
  id: string;
  chainScope: string;
  sequence: string;
  eventHash: string;
  occurredAt: string;
}

/** RFC 6902 patch including correct root operations, JSON pointer escaping, and arrays. */
export function jsonDiff(before: unknown, after: unknown, path = ''): JsonPatchOperation[] {
  if (canonicalJson(before) === canonicalJson(after)) return [];
  if (before === null || after === null || typeof before !== 'object' || typeof after !== 'object'
    || Array.isArray(before) !== Array.isArray(after)) return [{ op: 'replace', path, value: after }];
  if (Array.isArray(before) && Array.isArray(after)) {
    // Replacing an array is valid RFC 6902 and avoids index-shift errors on removals.
    return [{ op: 'replace', path, value: after }];
  }
  const left = before as Record<string, unknown>;
  const right = after as Record<string, unknown>;
  const childPath = (name: string) => `${path}/${name.replace(/~/g, '~0').replace(/\//g, '~1')}`;
  const patch: JsonPatchOperation[] = [];
  for (const name of Object.keys(left).sort()) if (!Object.hasOwn(right, name)) patch.push({ op: 'remove', path: childPath(name) });
  for (const name of Object.keys(right).sort()) {
    if (!Object.hasOwn(left, name)) patch.push({ op: 'add', path: childPath(name), value: right[name] });
    else patch.push(...jsonDiff(left[name], right[name], childPath(name)));
  }
  return patch;
}

@Injectable()
export class AuditService {
  constructor(private readonly db: DbService, private readonly secrets: SecretService,
    private readonly outbox: AuditOutboxWriter) {}

  async append(event: AuditEvent, transaction?: DbService): Promise<AuditOutboxReceipt> {
    const before = this.secrets.redact(event.before ?? null);
    const after = this.secrets.redact(event.after ?? null);
    const patch = jsonDiff(before, after);
    const scope = event.clusterId ? `cluster:${event.clusterId}` : 'global';
    return (transaction ?? this.db).transaction(async tx => {
      // The scope lock also serializes first-time chain-head creation across API replicas.
      await tx.exec('SELECT pg_advisory_xact_lock(hashtext($1))', [`kongos:audit:${scope}`]);
      await tx.exec('INSERT INTO audit_chain_heads(chain_scope) VALUES ($1) ON CONFLICT DO NOTHING', [scope]);
      const head = await tx.one<{last_sequence: string; last_hash: string}>(
        'SELECT last_sequence::text, last_hash FROM audit_chain_heads WHERE chain_scope = $1 FOR UPDATE', [scope]);
      if (!head) throw new Error('Audit chain head was not created');
      const sequence = (BigInt(head.last_sequence) + 1n).toString();
      const id = randomUUID();
      const occurredAt = new Date().toISOString();
      const record = {
        id, chain_scope: scope, sequence,
        actor_id: event.actorId ?? null, actor_type: event.actorType ?? (event.actorId ? 'user' : 'system'),
        source_ip: event.ip ?? null, cluster_id: event.clusterId ?? null, workspace_id: event.workspaceId ?? null,
        entity_type: event.entityType, entity_id: event.entityId ?? null, action: event.action,
        before, after, json_patch: patch, workflow_id: event.workflowId ?? null,
        result: event.result ?? 'success', request_id: event.requestId ?? null,
        prev_hash: head.last_hash, occurred_at: occurredAt,
      };
      const eventHash = createHash('sha256').update(canonicalJson(record)).digest('hex');
      await tx.exec(`INSERT INTO audit_events(id, chain_scope, sequence, actor_id, actor_type, source_ip,
        cluster_id, workspace_id, entity_type, entity_id, action, before, after, json_patch,
        workflow_id, result, request_id, prev_hash, event_hash, occurred_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14::jsonb,$15,$16,$17,$18,$19,$20)`,
      [id, scope, sequence, record.actor_id, record.actor_type, record.source_ip, record.cluster_id,
        record.workspace_id, record.entity_type, record.entity_id, record.action,
        JSON.stringify(before), JSON.stringify(after), JSON.stringify(patch), record.workflow_id,
        record.result, record.request_id, record.prev_hash, eventHash, occurredAt]);
      await tx.exec('UPDATE audit_chain_heads SET last_sequence = $2, last_hash = $3 WHERE chain_scope = $1',
        [scope, sequence, eventHash]);
      const receipt={ id, chainScope: scope, sequence, eventHash, occurredAt };
      await this.outbox.fromAudit(receipt,event.scopeHints??{quality:'legacy_unknown',module:event.entityType},tx);
      return receipt;
    });
  }
}
