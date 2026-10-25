import { Body, Controller, ForbiddenException, Get, Headers, HttpException, NotFoundException, Param, Post, Query, Req,
  BadRequestException, ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { AuditService } from '../audit/audit.service';
import { pageSize, type EntityActor } from '../entities/entities.types';
import { portalObject, portalConfirm, portalRevision, PortalCursor } from '../portal/portal-input';
import { workflowId, workflowKey } from './workflow-validation';
import { EntityChangeScheduleRepository } from './entity-change-schedule.repository';
import { EntityScheduledAuthorityService } from './entity-scheduled-authority.service';

const schemaHash = '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f';
/** Global APP_GUARD AuthGuard authenticates the HTTP principal. As with the
 * existing intent controller, current cluster/module and complete object
 * permissions are enforced by Authz and the fixed repository/Authority policy.
 * No actor, source, approval or claim body can enter these routes. */
@ApiTags('定时实体变更')
@Controller('clusters/:clusterId/entity-schedules')
export class EntityChangeSchedulesController {
  private readonly cursors = new PortalCursor();
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
    private readonly audit: AuditService, private readonly authz: AuthorizationService, private readonly context: KongExecutionContextService,
    private readonly repository: EntityChangeScheduleRepository, private readonly authority: EntityScheduledAuthorityService) {}
  private actor(req: EntityActor, query: Record<string, unknown>, key?: string): EntityActor {
    return { user: req.user, requestId: req.requestId, ip: req.ip, workspaceId: workflowId(query.workspaceId), idempotencyKey: key };
  }
  private async schema(tx = this.db): Promise<void> {
    const row = await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='024_m11_entity_schedules.sql'");
    if (row?.checksum !== schemaHash) throw new ServiceUnavailableException({ code: 'ENTITY_SCHEDULE_STORAGE_UNAVAILABLE' });
  }
  private scoped<T>(cid: string, actor: EntityActor, action: 'read' | 'write' | 'approve', fn: () => Promise<T>): Promise<T> {
    return this.context.runActor({ actor: actor.user, clusterId: cid, workspaceId: actor.workspaceId, module: 'workflows', action, requestId: actor.requestId }, fn);
  }
  private async scopeRow(cid: string, wid: string, id: string, tx = this.db): Promise<any> {
    const row = await tx.one<any>(`SELECT s.id,s.owner_id,s.intent_id,s.intent_revision,p.revision,p.state,p.claim_id,a.workflow_id
      FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
      LEFT JOIN entity_change_schedule_activations a ON a.schedule_id=s.id WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.id=$3`, [cid, wid, id]);
    if (!row) throw new NotFoundException({ code: 'ENTITY_SCHEDULE_NOT_FOUND' });
    return row;
  }
  @Get()
  async list(@Param('clusterId') clusterId: string, @Query() query: Record<string, unknown>, @Req() req: EntityActor): Promise<unknown> {
    const value = portalObject(query, ['workspaceId', 'size', 'cursor']), cid = workflowId(clusterId), actor = this.actor(req, value), size = pageSize(value.size);
    return this.scoped(cid, actor, 'read', async () => {
      await this.authz.assertCluster(actor.user, cid, 'workflows', 'read', actor.workspaceId); await this.schema();
      const version = await this.authz.permissionVersion(actor.user), binding = this.secrets.fingerprint({ kind: 'entity-schedules', cid, wid: actor.workspaceId, actor: actor.user.id, version, size });
      const after = this.cursors.decode(value.cursor, binding), offset = after?.offset ?? 0;
      if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000000 || after && (Object.keys(after).length !== 1 || !Object.hasOwn(after, 'offset'))) throw new BadRequestException({ code: 'INVALID_CURSOR' });
      const rows = await this.db.query<any>(`SELECT id FROM entity_change_schedules WHERE cluster_id=$1 AND workspace_id=$2
        ORDER BY created_at DESC,id DESC LIMIT $3 OFFSET $4`, [cid, actor.workspaceId, size + 1, offset]);
      const candidates = rows.slice(0, size), items = [];
      for (const row of candidates) {
        try { const id = workflowId(row.id), receipt = await this.repository.get(id, actor); items.push({ ...receipt, capabilities: await this.authority.projection(id, actor) }); }
        catch (error) { if (!(error instanceof HttpException && error.getStatus() === 403)) throw error; }
      }
      if (await this.authz.permissionVersion(actor.user) !== version) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED' });
      // Advance every scanned candidate, including hidden rows, with a bounded
      // lookahead. The cursor exposes no unauthorized schedule UUID or count.
      return { items, size, total: null, nextCursor: rows.length > size ? this.cursors.encode(binding, { offset: offset + candidates.length }) : null };
    });
  }
  @Get(':id')
  async get(@Param('clusterId') clusterId: string, @Param('id') scheduleId: string, @Query() query: Record<string, unknown>, @Req() req: EntityActor): Promise<unknown> {
    const value = portalObject(query, ['workspaceId']), cid = workflowId(clusterId), id = workflowId(scheduleId), actor = this.actor(req, value);
    return this.scoped(cid, actor, 'read', async () => {
      await this.authz.assertCluster(actor.user, cid, 'workflows', 'read', actor.workspaceId); await this.schema();
      await this.scopeRow(cid, actor.workspaceId!, id); const receipt = await this.repository.get(id, actor);
      return { entity: { ...receipt, capabilities: await this.authority.projection(id, actor) } };
    });
  }
  private async command(cid: string, id: string, action: 'activate' | 'cancel', body: unknown, actor: EntityActor): Promise<unknown> {
    const value = portalObject(body, ['revision', 'confirmed', 'confirm_name'], 4096); portalRevision(value.revision); portalConfirm(value, `${action}-schedule`);
    const key = workflowKey(actor.idempotencyKey), wid = actor.workspaceId!, keyHmac = this.secrets.fingerprint({ domain: 'entity-schedule-command', cid, wid, actor: actor.user.id, key });
    const requestHmac = this.secrets.fingerprint({ cid, wid, id, action, actor: actor.user.id, body: value }), auditAction = `workflow.schedule.${action}.command`;
    // Replays require current read access before the original command record
    // is inspected. Returning that safe DTO does not restart an occurrence.
    await this.authz.assertCluster(actor.user, cid, 'workflows', 'read', wid); await this.schema();
    await this.scopeRow(cid, wid, id); await this.repository.get(id, actor);
    return this.redis.withLock(`entity-schedule-command:${keyHmac}`, () => this.db.transaction(async tx => {
      await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-command:'||$1,0))", [keyHmac]);
      const old = await tx.one<any>(`SELECT action,after FROM audit_events WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3
        AND action IN('workflow.schedule.activate.command','workflow.schedule.cancel.command') AND after->>'keyHmac'=$4 ORDER BY occurred_at,id LIMIT 1`, [cid, wid, actor.user.id, keyHmac]);
      if (old) {
        if (old.action !== auditAction || old.after?.scheduleId !== id || old.after?.requestHmac !== requestHmac || !old.after?.receipt) throw new ConflictException({ code: 'IDEMPOTENCY_CONFLICT' });
        await this.repository.get(id, actor, tx); await this.redis.assertLeaseOwnership(); return structuredClone(old.after.receipt);
      }
      const scoped = await this.scopeRow(cid, wid, id, tx), mode = action === 'activate' && scoped.owner_id !== actor.user.id ? 'approve' : 'write';
      return this.scoped(cid, actor, mode, async () => {
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        await this.authz.assertCluster(actor.user, cid, 'workflows', mode, wid, tx);
        const version = await this.authz.permissionVersion(actor.user, tx);
        // Same impact domain/order as repository.lock(): serialize the physical
        // reservation before taking the mutable progress row lock.
        const physical = await tx.one<any>('SELECT transport_scope FROM entity_change_schedules WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [cid, wid, id]);
        if (!physical) throw new NotFoundException({ code: 'ENTITY_SCHEDULE_NOT_FOUND' });
        await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))", [physical.transport_scope]);
        await tx.one('SELECT schedule_id FROM entity_change_schedule_progress WHERE schedule_id=$1 FOR UPDATE', [id]);
        const current = await this.scopeRow(cid, wid, id, tx);
        if (current.revision !== value.revision) throw new ConflictException({ code: 'REVISION_CONFLICT' });
        const entity = action === 'activate' ? await this.authority.activateApproved(id, actor, tx) : await this.repository.cancel(id, actor, tx);
        const receipt = { entity: { ...(entity as any), capabilities: await this.authority.projection(id, actor, tx) }, commandCompleted: true };
        await this.audit.append({ actorId: actor.user.id, clusterId: cid, workspaceId: wid, entityType: 'workflows', entityId: current.workflow_id ?? null,
          workflowId: current.workflow_id ?? null, action: auditAction, result: 'success', requestId: actor.requestId, ip: actor.ip,
          before: { scheduleId: id, revision: current.revision, state: current.state }, after: { scheduleId: id, keyHmac, requestHmac, receipt } }, tx);
        if (await this.authz.permissionVersion(actor.user, tx) !== version) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED' });
        await this.redis.assertLeaseOwnership(); return receipt;
      });
    }));
  }
  @Post(':id/activate')
  activate(@Param('clusterId') clusterId: string, @Param('id') scheduleId: string, @Query() query: Record<string, unknown>, @Body() body: unknown,
    @Headers('x-idempotency-key') key: string, @Req() req: EntityActor): Promise<unknown> {
    const value = portalObject(query, ['workspaceId']), cid = workflowId(clusterId), id = workflowId(scheduleId), actor = this.actor(req, value, key);
    return this.scoped(cid, actor, 'read', () => this.command(cid, id, 'activate', body, actor));
  }
  @Post(':id/cancel')
  cancel(@Param('clusterId') clusterId: string, @Param('id') scheduleId: string, @Query() query: Record<string, unknown>, @Body() body: unknown,
    @Headers('x-idempotency-key') key: string, @Req() req: EntityActor): Promise<unknown> {
    const value = portalObject(query, ['workspaceId']), cid = workflowId(clusterId), id = workflowId(scheduleId), actor = this.actor(req, value, key);
    return this.scoped(cid, actor, 'read', () => this.command(cid, id, 'cancel', body, actor));
  }
}
