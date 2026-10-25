import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';

/** Portal credential change verbs exposed to developers. UI "停用/禁用" maps to revoke. */
export type PortalCredentialChangeAction = 'rotate' | 'revoke';
export type PortalCredentialChangeInput = PortalCredentialChangeAction | 'disable';

export type PortalGrantLifecycleState =
  | 'pending' | 'active' | 'partial' | 'rotating' | 'revoking' | 'revoked' | 'uncertain' | 'disabled';
export type PortalCredentialLifecycleState =
  | 'pending' | 'active' | 'rotating' | 'revoking' | 'revoked' | 'uncertain' | 'deleted';

/** Portal credential kinds admitted to SQL026/SQL045 business schedules. */
export const PORTAL_CREDENTIAL_SCHEDULE_KINDS = Object.freeze([
  'portal-credential-issue',
  'portal-credential-rotate',
  'portal-credential-revoke',
] as const);
export type PortalCredentialScheduleKind = (typeof PORTAL_CREDENTIAL_SCHEDULE_KINDS)[number];

export function isPortalCredentialScheduleKind(kind: string): kind is PortalCredentialScheduleKind {
  return (PORTAL_CREDENTIAL_SCHEDULE_KINDS as readonly string[]).includes(kind);
}

export function normalizePortalCredentialChangeAction(action: PortalCredentialChangeInput): PortalCredentialChangeAction {
  if (action === 'disable') return 'revoke';
  if (action === 'rotate' || action === 'revoke') return action;
  throw new BadRequestException({
    code: 'INVALID_PORTAL_CREDENTIAL_ACTION',
    message: '门户凭证变更仅支持 rotate / revoke（disable 映射为 revoke）',
  });
}

/** Capabilities for portal-web: both grant and credential must be active. */
export function portalCredentialCapabilities(
  grantState: string,
  credentialState: string,
): Readonly<{ reveal: boolean; rotate: boolean; revoke: boolean }> {
  const usable = grantState === 'active' && credentialState === 'active';
  return Object.freeze({ reveal: usable, rotate: usable, revoke: usable });
}

/**
 * Admission for rotate/revoke compile: grant must be active and point at the
 * named active credential. Concurrent change leaves grant rotating/revoking and
 * fails closed here.
 */
export function assertPortalCredentialChangeAdmission(input: Readonly<{
  action: PortalCredentialChangeInput;
  grantState: string;
  grantCurrentCredentialId: string | null;
  credentialId: string;
  credentialState: string;
}>): PortalCredentialChangeAction {
  const action = normalizePortalCredentialChangeAction(input.action);
  if (input.grantState !== 'active') {
    throw new ConflictException({
      code: 'PORTAL_GRANT_NOT_ACTIVE',
      message: '授权非有效状态，不能发起轮换或吊销；若处于轮换中/吊销中请先撤销或等待审批结论',
    });
  }
  if (input.credentialState !== 'active') {
    throw new ConflictException({
      code: 'PORTAL_CREDENTIAL_UNAVAILABLE',
      message: '仅有效凭证可轮换或吊销',
    });
  }
  if (!input.grantCurrentCredentialId || input.grantCurrentCredentialId !== input.credentialId) {
    throw new ConflictException({
      code: 'PORTAL_GRANT_NOT_ACTIVE',
      message: '只能对当前代次有效凭证发起变更',
    });
  }
  return action;
}

/**
 * Allocate the next credential generation under unique(grant_id, generation).
 * Soft-deleted unused rotate rows still occupy a generation slot, so callers
 * must pass MAX(generation) rather than current_generation alone.
 */
export function nextPortalCredentialGeneration(currentGeneration: number, maxExistingGeneration: number): number {
  if (!Number.isInteger(currentGeneration) || currentGeneration < 0
    || !Number.isInteger(maxExistingGeneration) || maxExistingGeneration < 0) {
    throw new ConflictException({
      code: 'PORTAL_CREDENTIAL_GENERATION_INVALID',
      message: '凭证代次无效',
    });
  }
  const next = Math.max(currentGeneration, maxExistingGeneration) + 1;
  if (next <= currentGeneration) {
    throw new ConflictException({
      code: 'PORTAL_CREDENTIAL_GENERATION_INVALID',
      message: '下一凭证代次必须大于当前代次',
    });
  }
  return next;
}

/** Cancel / reject / expire of unused rotate|revoke must restore grant → active. */
export function assertUnusedPortalCredentialChangeCancellation(input: Readonly<{
  kind: string;
  grantState: string;
  workflowTerminal: 'cancelled' | 'rejected' | 'expired';
}>): 'rotating' | 'revoking' {
  if (input.kind === 'portal-credential-rotate') {
    if (input.grantState !== 'rotating') {
      throw new ConflictException({
        code: 'PORTAL_GRANT_STATE_CHANGED',
        message: '轮换工单终止时期望授权处于 rotating',
      });
    }
    return 'rotating';
  }
  if (input.kind === 'portal-credential-revoke') {
    if (input.grantState !== 'revoking') {
      throw new ConflictException({
        code: 'PORTAL_GRANT_STATE_CHANGED',
        message: '吊销工单终止时期望授权处于 revoking',
      });
    }
    return 'revoking';
  }
  throw new ForbiddenException({
    code: 'PORTAL_CHANGE_CANCELLATION_KIND_UNSUPPORTED',
    message: '仅 portal-credential-rotate / portal-credential-revoke 走未执行变更恢复',
  });
}

/** Fail-closed: unknown portal-credential-* kinds stay off the schedule allowlist. */
export function assertPortalCredentialScheduleKindSupported(kind: string): asserts kind is PortalCredentialScheduleKind {
  if (isPortalCredentialScheduleKind(kind)) return;
  throw new ForbiddenException({
    code: 'WORKFLOW_SCHEDULE_PORTAL_KIND_UNSUPPORTED',
    message: '门户定时仅允许 portal-credential-issue / rotate / revoke',
  });
}

/** Rotate metadata receipt: new credential active, old revoked with recycle, grant active. */
export function assertPortalCredentialRotateReceipt(input: Readonly<{
  grantState: string;
  currentCredentialId: string | null;
  newCredentialId: string;
  newCredentialState: string;
  oldCredentialId: string;
  oldCredentialState: string;
  oldRecycleEntryId: string | null;
}>): void {
  if (input.grantState !== 'active' || input.currentCredentialId !== input.newCredentialId) {
    throw new ConflictException({
      code: 'PORTAL_ROTATE_RECEIPT_INVALID',
      message: '轮换回执要求授权回到 active 且指向新凭证',
    });
  }
  if (input.newCredentialState !== 'active') {
    throw new ConflictException({
      code: 'PORTAL_ROTATE_RECEIPT_INVALID',
      message: '轮换回执要求新凭证为 active',
    });
  }
  if (input.oldCredentialState !== 'revoked' || !input.oldRecycleEntryId) {
    throw new ConflictException({
      code: 'PORTAL_ROTATE_RECEIPT_INVALID',
      message: '轮换回执要求旧凭证已吊销并带回收条目',
    });
  }
  if (input.oldCredentialId === input.newCredentialId) {
    throw new ConflictException({
      code: 'PORTAL_ROTATE_RECEIPT_INVALID',
      message: '轮换回执要求新旧凭证标识不同',
    });
  }
}

/** Revoke metadata receipt: grant revoked; no non-terminal credentials remain. */
export function assertPortalCredentialRevokeReceipt(input: Readonly<{
  grantState: string;
  remainingNonTerminalCredentialIds: readonly string[];
  revokedCredentialId: string;
  revokedCredentialState: string;
  recycleEntryId: string | null;
}>): void {
  if (input.grantState !== 'revoked') {
    throw new ConflictException({
      code: 'PORTAL_REVOKE_RECEIPT_INVALID',
      message: '吊销回执要求授权为 revoked',
    });
  }
  if (input.remainingNonTerminalCredentialIds.length > 0) {
    throw new ConflictException({
      code: 'PORTAL_REVOCATION_INCOMPLETE',
      message: '吊销回执要求授权下无 pending/active 等非终态凭证',
    });
  }
  if (input.revokedCredentialState !== 'revoked' || !input.recycleEntryId) {
    throw new ConflictException({
      code: 'PORTAL_REVOKE_RECEIPT_INVALID',
      message: '吊销回执要求目标凭证已吊销并带回收条目',
    });
  }
}
