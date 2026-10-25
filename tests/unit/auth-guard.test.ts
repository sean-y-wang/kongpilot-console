import 'reflect-metadata';
import { createHash } from 'node:crypto';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Public, RequireSuperAdmin } from '../../apps/console-api/src/common/auth';
import { AuthGuard } from '../../apps/console-api/src/modules/auth/auth.guard';
import { AuthService } from '../../apps/console-api/src/modules/auth/auth.service';

class ProtectedController {
  read() {}
  @RequireSuperAdmin() write() {}
  @Public() login() {}
}

const csrf = 'test-csrf-token';
const session = {
  user: { id: 'user-id', username: 'reader', superAdmin: false },
  sessionId: 'session-id',
  csrfHash: createHash('sha256').update(csrf).digest('hex'),
};

function context(request: any, action: 'read' | 'write' | 'login' = 'read'): ExecutionContext {
  return {
    getHandler: () => ProtectedController.prototype[action],
    getClass: () => ProtectedController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

describe('M0 authentication and mutation guard', () => {
  let authenticate: ReturnType<typeof vi.fn>;
  let checkCsrf: ReturnType<typeof vi.fn>;
  let guard: AuthGuard;

  beforeEach(() => {
    authenticate = vi.fn().mockResolvedValue(session);
    checkCsrf = vi.fn((token: string | undefined, expected: string) => AuthService.prototype.checkCsrf(token, expected));
    // Header/CSRF isolation; actual binding and lifetime fences are exercised
    // by the real execution-context M4 security suite.
    guard = new AuthGuard(new Reflector(), { authenticate, checkCsrf } as unknown as AuthService, { bindHttpActor: vi.fn() } as any);
  });

  it('rejects anonymous access before controller invocation', async () => {
    await expect(guard.canActivate(context({ method: 'GET', headers: {} }))).rejects.toMatchObject({ status: 401 });
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('leaves only explicitly public handlers unauthenticated', async () => {
    expect(await guard.canActivate(context({ method: 'POST', headers: {} }, 'login'))).toBe(true);
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('attaches the authenticated actor and session to the request', async () => {
    const request: any = { method: 'GET', headers: {}, cookies: { kongos_access: 'signed-cookie' } };
    expect(await guard.canActivate(context(request))).toBe(true);
    expect(authenticate).toHaveBeenCalledWith('signed-cookie');
    expect(request.user).toEqual(session.user);
    expect(request.sessionId).toBe('session-id');
    expect(checkCsrf).not.toHaveBeenCalled();
  });

  it('propagates revoked or expired session denial', async () => {
    authenticate.mockRejectedValue(new UnauthorizedException({ code: 'SESSION_EXPIRED', message: '会话已失效' }));
    await expect(guard.canActivate(context({ method: 'GET', headers: { authorization: 'Bearer revoked-token' } }))).rejects.toMatchObject({ status: 401 });
  });

  it('denies a read-only user on a platform-administrator handler', async () => {
    await expect(guard.canActivate(context({ method: 'POST', headers: { authorization: 'Bearer reader-token' } }, 'write'))).rejects.toMatchObject({ status: 403 });
  });

  it('allows the platform administrator after authentication', async () => {
    authenticate.mockResolvedValue({ ...session, user: { ...session.user, superAdmin: true } });
    expect(await guard.canActivate(context({ method: 'POST', headers: { authorization: 'Bearer administrator-token' } }, 'write'))).toBe(true);
  });

  it.each(['POST', 'PATCH', 'PUT', 'DELETE'])('requires CSRF for cookie-authenticated %s', async (method) => {
    await expect(guard.canActivate(context({ method, headers: {}, cookies: { kongos_access: 'cookie-token' } }))).rejects.toMatchObject({ status: 403 });
    expect(checkCsrf).toHaveBeenCalledWith(undefined, session.csrfHash);
  });

  it('denies an invalid CSRF token on a cookie-authenticated write', async () => {
    await expect(guard.canActivate(context({ method: 'PATCH', headers: { 'x-csrf-token': 'wrong' }, cookies: { kongos_access: 'cookie-token' } }))).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('accepts a valid CSRF token on a cookie-authenticated write', async () => {
    expect(await guard.canActivate(context({ method: 'PATCH', headers: { 'x-csrf-token': csrf }, cookies: { kongos_access: 'cookie-token' } }))).toBe(true);
  });

  it('accepts an authenticated bearer write without browser cookies', async () => {
    expect(await guard.canActivate(context({ method: 'PATCH', headers: { authorization: 'Bearer cli-token' } }))).toBe(true);
    expect(authenticate).toHaveBeenCalledWith('cli-token');
    expect(checkCsrf).not.toHaveBeenCalled();
  });

  it('does not fall back to a valid cookie when an invalid bearer token is supplied', async () => {
    authenticate.mockRejectedValue(new UnauthorizedException());
    await expect(guard.canActivate(context({ method: 'GET', headers: { authorization: 'Bearer invalid' }, cookies: { kongos_access: 'valid-cookie' } }))).rejects.toMatchObject({ status: 401 });
    expect(authenticate).toHaveBeenCalledWith('invalid');
  });
});
