import { describe, expect, it } from 'vitest';
import {
  assertPortalCredentialChangeAdmission,
  assertPortalCredentialRevokeReceipt,
  assertPortalCredentialRotateReceipt,
  assertPortalCredentialScheduleKindSupported,
  assertUnusedPortalCredentialChangeCancellation,
  nextPortalCredentialGeneration,
  normalizePortalCredentialChangeAction,
  portalCredentialCapabilities,
} from '../../apps/console-api/src/modules/portal/portal-credential-lifecycle-contract';

const grantId = '11111111-1111-4111-8111-111111111111';
const credA = '22222222-2222-4222-8222-222222222222';
const credB = '33333333-3333-4333-8333-333333333333';

describe('KP-006 portal credential change admission + disable→revoke', () => {
  it('maps disable to revoke and admits only active grant+current credential', () => {
    expect(normalizePortalCredentialChangeAction('disable')).toBe('revoke');
    expect(assertPortalCredentialChangeAdmission({
      action: 'disable',
      grantState: 'active',
      grantCurrentCredentialId: credA,
      credentialId: credA,
      credentialState: 'active',
    })).toBe('revoke');
    expect(assertPortalCredentialChangeAdmission({
      action: 'rotate',
      grantState: 'active',
      grantCurrentCredentialId: credA,
      credentialId: credA,
      credentialState: 'active',
    })).toBe('rotate');
  });

  it('rejects concurrent rotating/revoking and non-current credentials (fail-closed)', () => {
    expect(() => assertPortalCredentialChangeAdmission({
      action: 'rotate',
      grantState: 'rotating',
      grantCurrentCredentialId: credA,
      credentialId: credA,
      credentialState: 'active',
    })).toThrow(/PORTAL_GRANT_NOT_ACTIVE|授权非有效/);
    expect(() => assertPortalCredentialChangeAdmission({
      action: 'revoke',
      grantState: 'revoking',
      grantCurrentCredentialId: credA,
      credentialId: credA,
      credentialState: 'active',
    })).toThrow(/PORTAL_GRANT_NOT_ACTIVE|授权非有效/);
    expect(() => assertPortalCredentialChangeAdmission({
      action: 'rotate',
      grantState: 'active',
      grantCurrentCredentialId: credA,
      credentialId: credB,
      credentialState: 'active',
    })).toThrow(/PORTAL_GRANT_NOT_ACTIVE|当前代次/);
    expect(() => assertPortalCredentialChangeAdmission({
      action: 'revoke',
      grantState: 'active',
      grantCurrentCredentialId: credA,
      credentialId: credA,
      credentialState: 'pending',
    })).toThrow(/PORTAL_CREDENTIAL_UNAVAILABLE|仅有效凭证/);
  });
});

describe('KP-006 portal credential capabilities gate on grant+credential', () => {
  it('exposes reveal/rotate/revoke only when both are active', () => {
    expect(portalCredentialCapabilities('active', 'active')).toEqual({ reveal: true, rotate: true, revoke: true });
    expect(portalCredentialCapabilities('rotating', 'active')).toEqual({ reveal: false, rotate: false, revoke: false });
    expect(portalCredentialCapabilities('revoking', 'active')).toEqual({ reveal: false, rotate: false, revoke: false });
    expect(portalCredentialCapabilities('active', 'pending')).toEqual({ reveal: false, rotate: false, revoke: false });
    expect(portalCredentialCapabilities('active', 'revoked')).toEqual({ reveal: false, rotate: false, revoke: false });
  });
});

describe('KP-006 unused rotate/revoke cancellation restore contract', () => {
  it('requires rotating grant for rotate cancel/reject/expire', () => {
    expect(assertUnusedPortalCredentialChangeCancellation({
      kind: 'portal-credential-rotate',
      grantState: 'rotating',
      workflowTerminal: 'cancelled',
    })).toBe('rotating');
    expect(assertUnusedPortalCredentialChangeCancellation({
      kind: 'portal-credential-revoke',
      grantState: 'revoking',
      workflowTerminal: 'rejected',
    })).toBe('revoking');
  });

  it('rejects mismatched grant state and non-change kinds', () => {
    expect(() => assertUnusedPortalCredentialChangeCancellation({
      kind: 'portal-credential-rotate',
      grantState: 'active',
      workflowTerminal: 'cancelled',
    })).toThrow(/PORTAL_GRANT_STATE_CHANGED|rotating/);
    expect(() => assertUnusedPortalCredentialChangeCancellation({
      kind: 'portal-credential-revoke',
      grantState: 'rotating',
      workflowTerminal: 'expired',
    })).toThrow(/PORTAL_GRANT_STATE_CHANGED|revoking/);
    expect(() => assertUnusedPortalCredentialChangeCancellation({
      kind: 'portal-credential-issue',
      grantState: 'pending',
      workflowTerminal: 'cancelled',
    })).toThrow(/PORTAL_CHANGE_CANCELLATION_KIND_UNSUPPORTED|未执行变更恢复/);
  });
});

describe('KP-006 generation allocation after soft-deleted unused rotate', () => {
  it('skips occupied generations from cancelled pending rows', () => {
    expect(nextPortalCredentialGeneration(1, 2)).toBe(3);
    expect(nextPortalCredentialGeneration(0, 0)).toBe(1);
    expect(nextPortalCredentialGeneration(1, 1)).toBe(2);
    expect(() => nextPortalCredentialGeneration(-1, 0)).toThrow(/PORTAL_CREDENTIAL_GENERATION_INVALID|代次无效/);
  });
});

describe('KP-006 scheduled portal credential kinds (SQL045)', () => {
  it('admits issue / rotate / revoke and rejects unknown portal kinds', () => {
    expect(() => assertPortalCredentialScheduleKindSupported('portal-credential-issue')).not.toThrow();
    expect(() => assertPortalCredentialScheduleKindSupported('portal-credential-rotate')).not.toThrow();
    expect(() => assertPortalCredentialScheduleKindSupported('portal-credential-revoke')).not.toThrow();
    expect(() => assertPortalCredentialScheduleKindSupported('portal-credential-disable')).toThrow(
      /WORKFLOW_SCHEDULE_PORTAL_KIND_UNSUPPORTED|门户定时仅允许/,
    );
    expect(() => assertPortalCredentialScheduleKindSupported('portal-publication')).toThrow(
      /WORKFLOW_SCHEDULE_PORTAL_KIND_UNSUPPORTED|门户定时仅允许/,
    );
  });
});

describe('KP-006 rotate/revoke receipt contracts', () => {
  it('accepts rotate receipt with new active + old revoked recycle', () => {
    expect(() => assertPortalCredentialRotateReceipt({
      grantState: 'active',
      currentCredentialId: credB,
      newCredentialId: credB,
      newCredentialState: 'active',
      oldCredentialId: credA,
      oldCredentialState: 'revoked',
      oldRecycleEntryId: grantId,
    })).not.toThrow();
  });

  it('rejects incomplete rotate receipts', () => {
    expect(() => assertPortalCredentialRotateReceipt({
      grantState: 'rotating',
      currentCredentialId: credA,
      newCredentialId: credB,
      newCredentialState: 'active',
      oldCredentialId: credA,
      oldCredentialState: 'revoked',
      oldRecycleEntryId: grantId,
    })).toThrow(/PORTAL_ROTATE_RECEIPT_INVALID|回到 active/);
    expect(() => assertPortalCredentialRotateReceipt({
      grantState: 'active',
      currentCredentialId: credB,
      newCredentialId: credB,
      newCredentialState: 'active',
      oldCredentialId: credA,
      oldCredentialState: 'active',
      oldRecycleEntryId: null,
    })).toThrow(/PORTAL_ROTATE_RECEIPT_INVALID|旧凭证已吊销/);
  });

  it('accepts revoke receipt and rejects remaining non-terminal credentials', () => {
    expect(() => assertPortalCredentialRevokeReceipt({
      grantState: 'revoked',
      remainingNonTerminalCredentialIds: [],
      revokedCredentialId: credA,
      revokedCredentialState: 'revoked',
      recycleEntryId: grantId,
    })).not.toThrow();
    expect(() => assertPortalCredentialRevokeReceipt({
      grantState: 'revoked',
      remainingNonTerminalCredentialIds: [credB],
      revokedCredentialId: credA,
      revokedCredentialState: 'revoked',
      recycleEntryId: grantId,
    })).toThrow(/PORTAL_REVOCATION_INCOMPLETE|非终态/);
  });
});
