import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { AuditService } from '../audit/audit.service';

export interface SelfApprovalSetting { enabled: boolean; revision: number; updatedBy: string | null; updatedAt: string }

/** Platform override (default OFF) that lets an active super-admin approve
 * their own console workflow. The DB (SQL052) independently enforces the same
 * rule at vote insert; this service is the app-side gate and the audited switch. */
@Injectable()
export class WorkflowSelfApprovalService {
  constructor(private readonly db: DbService, private readonly audit: AuditService) {}
  async read(tx: DbService = this.db): Promise<SelfApprovalSetting> {
    const row = await tx.one<any>('SELECT super_admin_self_approval,revision,updated_by,updated_at FROM workflow_self_approval_settings WHERE singleton');
    return { enabled: row?.super_admin_self_approval === true, revision: Number(row?.revision ?? 1), updatedBy: row?.updated_by ?? null, updatedAt: row ? new Date(row.updated_at).toISOString() : new Date(0).toISOString() };
  }
  /** True only when the setting is on and the user is currently an active super-admin. */
  async permitted(userId: string, tx: DbService = this.db): Promise<boolean> {
    const row = await tx.one<{ ok: boolean }>('SELECT m11_self_approval_permitted($1) AS ok', [userId]);
    return row?.ok === true;
  }
  async update(body: unknown, actor: { user: { id: string; superAdmin?: boolean }; requestId?: string; ip?: string }): Promise<SelfApprovalSetting> {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new BadRequestException({ code: 'INVALID_SELF_APPROVAL_SETTING' });
    const value = body as Record<string, unknown>;
    if (Object.keys(value).some(key => !['enabled', 'revision', 'confirmed'].includes(key)) || typeof value.enabled !== 'boolean' || !Number.isInteger(value.revision) || value.confirmed !== true)
      throw new BadRequestException({ code: 'INVALID_SELF_APPROVAL_SETTING', message: '需要 enabled、revision 并确认' });
    return this.db.transaction(async tx => {
      const before = await this.read(tx);
      const changed = await tx.exec('UPDATE workflow_self_approval_settings SET super_admin_self_approval=$1,revision=revision+1,updated_by=$2,updated_at=now() WHERE singleton AND revision=$3', [value.enabled, actor.user.id, value.revision]);
      if (changed !== 1) throw new ConflictException({ code: 'SELF_APPROVAL_SETTING_CHANGED', message: '设置已被其他管理员修改，请刷新后重试' });
      const after = await this.read(tx);
      await this.audit.append({ actorId: actor.user.id, entityType: 'workflow_settings', entityId: null, action: 'workflow.self_approval_setting.update', requestId: actor.requestId, ip: actor.ip,
        before: { enabled: before.enabled, revision: before.revision }, after: { enabled: after.enabled, revision: after.revision } } as any, tx);
      return after;
    });
  }
}
