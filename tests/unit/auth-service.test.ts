import 'reflect-metadata';
import { executionFixture } from './execution-test-fixture';
import { createHash } from 'node:crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthService } from '../../apps/console-api/src/modules/auth/auth.service';

const secret = 'test-only-app-secret-that-is-long-enough-for-hs256';
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const sid = 'a9285662-956a-488c-8092-dd6b4ca351af';
const userId = '466cf398-ed18-44a9-986d-a67c2d49ed78';
const row = { id: userId, username: 'admin', super_admin: true, session_id: sid, csrf_token_hash: hash('csrf'), credential_epoch: '1', session_credential_epoch: '1', auth_source: 'local', revision: 1, family_id: sid, refresh_generation: 0, session_expires_at: new Date(Date.now()+86400000) };

describe('M0 signed sessions and refresh rotation', () => {
  let db: any;
  let redis: any;
  let audit: any;
  let auth: AuthService;

  beforeEach(() => {
    vi.stubEnv('APP_SECRET', secret);
    db = { one: vi.fn().mockResolvedValue(row), exec: vi.fn().mockResolvedValue(1), transaction: vi.fn() };
    db.transaction.mockImplementation((fn: (tx: any) => unknown) => fn(db));
    redis = { rateLimit: vi.fn().mockResolvedValue({ allowed: true }), client: { del: vi.fn().mockResolvedValue(1), set: vi.fn().mockResolvedValue('OK') } };
    audit = { append: vi.fn().mockResolvedValue(undefined) };
    auth = new AuthService(db, redis, audit, {snapshot:vi.fn(async (user:any)=>({user,version:'test:1'})),capabilities:vi.fn(async ()=>({modules:{},grants:[],clusters:[],platformAdmin:true}))} as any,executionFixture(),{} as any);
  });

  afterEach(() => vi.unstubAllEnvs());

  function token(options: jwt.SignOptions = {}) {
    return jwt.sign({ sid }, secret, { algorithm: 'HS256', issuer: 'kongos-console', audience: 'kongos-api', subject: userId, expiresIn: '15m', ...options });
  }

  it('verifies issuer, audience and subject then checks the current database session', async () => {
    expect(await auth.authenticate(token())).toMatchObject({ user: { id: userId, username: 'admin', superAdmin: true }, sessionId: sid, csrfHash: hash('csrf') });
    expect(db.one).toHaveBeenCalledWith(expect.stringContaining('s.revoked_at IS NULL'), [sid, userId]);
    expect(db.one.mock.calls[0][0]).toContain("u.status='active'");
  });

  it.each([
    ['issuer', { issuer: 'untrusted-issuer' }],
    ['audience', { audience: 'different-service' }],
    ['expiry', { expiresIn: -1 }],
    ['algorithm', { algorithm: 'HS384' }],
  ] as const)('rejects a token with invalid %s before reading a session', async (_case, options) => {
    await expect(auth.authenticate(token(options))).rejects.toMatchObject({ status: 401 });
    expect(db.one).not.toHaveBeenCalled();
  });

  it('rejects a revoked, disabled or missing session even with a valid JWT', async () => {
    db.one.mockResolvedValue(null);
    await expect(auth.authenticate(token())).rejects.toMatchObject({ status: 401 });
  });

  it('rejects a token signed by a different key', async () => {
    const forged = jwt.sign({ sid }, 'wrong-key', { algorithm: 'HS256', issuer: 'kongos-console', audience: 'kongos-api', subject: userId });
    await expect(auth.authenticate(forged)).rejects.toMatchObject({ status: 401 });
    expect(db.one).not.toHaveBeenCalled();
  });

  it('rotates refresh material under a row lock without persisting cleartext', async () => {
    db.one.mockResolvedValue({ ...row, refresh_token_hash: hash('old-secret') });
    const result = await auth.refresh(`${sid}.old-secret`, 'csrf');
    expect(db.one).toHaveBeenCalledWith(expect.stringContaining('FOR UPDATE OF s'), [sid]);
    expect(result.refreshToken).not.toBe(`${sid}.old-secret`);
    const newSecret = result.refreshToken.split('.')[1];
    expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('refresh_token_hash=$2'), [sid, hash(newSecret)]);
    expect(JSON.stringify(db.exec.mock.calls)).not.toContain(newSecret);
  });

  it('blocks refresh without the session CSRF token', async () => {
    db.one.mockResolvedValue({ ...row, refresh_token_hash: hash('old-secret') });
    await expect(auth.refresh(`${sid}.old-secret`, undefined)).rejects.toMatchObject({ status: 403 });
    expect(db.exec).not.toHaveBeenCalled();
  });

  it('blocks stale refresh material and does not mint new tokens', async () => {
    db.one.mockImplementation(async (sql:string)=>sql.includes('auth_refresh_history')?null:{ ...row, refresh_token_hash: hash('already-rotated') });
    await expect(auth.refresh(`${sid}.old-secret`, 'csrf')).rejects.toMatchObject({ status: 401 });
    expect(db.exec).not.toHaveBeenCalled();
  });

  it('rejects malformed refresh handles before database access', async () => {
    await expect(auth.refresh('not-a-session.secret', 'csrf')).rejects.toMatchObject({ status: 401 });
    expect(db.one).not.toHaveBeenCalled();
  });

  it('revokes only the requesting user session and clears its Redis entry', async () => {
    await auth.revoke(sid, userId);
    expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('WHERE id=$1 AND user_id=$2'), [sid, userId]);
    expect(redis.client.del).toHaveBeenCalledWith(`auth:session:${sid}`);
  });

  it('hashes both refresh and CSRF material when creating a session', async () => {
    const password = 'test-only-password';
    const passwordHash = await bcrypt.hash(password, 4);
    db.one.mockImplementation(async (sql: string) => sql.startsWith('SELECT')
      ? { ...row, password_hash: passwordHash, status: 'active' }
      : { id: sid });
    const result = await auth.login('admin', password, '127.0.0.1', 'test-runner');
    const insertion = db.one.mock.calls.find(([sql]: [string]) => sql.startsWith('INSERT INTO auth_sessions'));
    expect(insertion).toBeDefined();
    expect(insertion[0]).toContain('refresh_token_hash,csrf_token_hash');
    expect(insertion[1]).toContain(hash(result.refreshToken.split('.')[1]));
    expect(insertion[1]).toContain(hash(result.csrfToken));
    expect(JSON.stringify(insertion[1])).not.toContain(result.refreshToken.split('.')[1]);
    expect(JSON.stringify(insertion[1])).not.toContain(result.csrfToken);
    expect(JSON.stringify(insertion[1])).not.toContain(password);
    expect(jwt.verify(result.accessToken, secret)).toMatchObject({ sub: userId, sid:result.refreshToken.split('.')[0] });
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'login', result: 'success', actorId: userId }),db);
  });

  it('counts and audits a wrong password without creating a session', async () => {
    db.one.mockResolvedValue({ ...row, password_hash: await bcrypt.hash('correct-password', 4), status: 'active' });
    await expect(auth.login('admin', 'wrong-password', '127.0.0.1', 'test-runner')).rejects.toMatchObject({ status: 401 });
    expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('locked_until<=now()'), [userId]);
    expect(db.one).toHaveBeenCalledTimes(1);
    expect(redis.client.set).not.toHaveBeenCalled();
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'login', result: 'denied' }),db);
  });

  it('rejects a locked account without creating a session', async () => {
    db.one.mockResolvedValue({ ...row, locked_until: new Date(Date.now() + 60_000).toISOString() });
    await expect(auth.login('admin', 'any-password', '127.0.0.1', 'test-runner')).rejects.toMatchObject({ status: 403 });
    expect(redis.client.set).not.toHaveBeenCalled();
    expect(db.exec).not.toHaveBeenCalled();
  });

  it('rejects excessive login attempts before reading an account', async () => {
    redis.rateLimit.mockResolvedValue({ allowed: false });
    await expect(auth.login('admin', 'any-password', '127.0.0.1', 'test-runner')).rejects.toMatchObject({ status: 429 });
    expect(db.one).not.toHaveBeenCalled();
  });

  it.each(['a'.repeat(73), '中'.repeat(25)])('rejects a password above the bcrypt UTF-8 byte limit', async (password) => {
    await expect(auth.login('admin', password, '127.0.0.1', 'test-runner')).rejects.toMatchObject({ status: 401 });
    expect(db.one).not.toHaveBeenCalled();
    expect(redis.rateLimit).not.toHaveBeenCalled();
  });

  it('recovers a CSRF token only from a current refresh session and its existing cookie token', async () => {
    db.one.mockResolvedValue({ ...row, refresh_token_hash: hash('old-secret') });
    expect(await auth.csrfForRefresh(`${sid}.old-secret`, 'csrf')).toBe('csrf');
    expect(db.one).toHaveBeenCalledWith(expect.stringContaining('s.revoked_at IS NULL'), [sid]);
    expect(db.one.mock.calls[0][0]).toContain("u.status='active'");
    expect(db.exec).not.toHaveBeenCalled();
  });

  it('does not reveal CSRF token for a revoked refresh session', async () => {
    db.one.mockResolvedValue(null);
    await expect(auth.csrfForRefresh(`${sid}.old-secret`, 'csrf')).rejects.toMatchObject({ status: 401 });
  });

  it('does not reveal CSRF token for stale refresh material', async () => {
    db.one.mockResolvedValue({ ...row, refresh_token_hash: hash('rotated-secret') });
    await expect(auth.csrfForRefresh(`${sid}.old-secret`, 'csrf')).rejects.toMatchObject({ status: 401 });
  });

  it.each([undefined, 'incorrect-csrf'])('denies CSRF recovery with an invalid cookie token', async (value) => {
    db.one.mockResolvedValue({ ...row, refresh_token_hash: hash('old-secret') });
    await expect(auth.csrfForRefresh(`${sid}.old-secret`, value)).rejects.toMatchObject({ status: 403 });
    expect(db.exec).not.toHaveBeenCalled();
  });

  it('can recover the same actor after access expiry without using the expired JWT', async () => {
    await expect(auth.authenticate(token({ expiresIn: -1 }))).rejects.toMatchObject({ status: 401 });
    expect(db.one).not.toHaveBeenCalled();
    db.one.mockResolvedValue({ ...row, refresh_token_hash: hash('old-secret') });
    const recoveredCsrf = await auth.csrfForRefresh(`${sid}.old-secret`, 'csrf');
    const refreshed = await auth.refresh(`${sid}.old-secret`, recoveredCsrf);
    expect(refreshed.user.id).toBe(userId);
    expect(jwt.verify(refreshed.accessToken, secret)).toMatchObject({ sub: userId, sid });
  });
});
