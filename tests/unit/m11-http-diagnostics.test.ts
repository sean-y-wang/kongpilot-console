import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErrorFilter } from '../../apps/console-api/src/common/http';

/** Exercise the real HTTP filter with deliberately hostile PostgreSQL error
 * data. This is a logging boundary test, not evidence of runtime execution. */
function diagnose(error: unknown) {
  const logged = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  const response = { status: vi.fn(), json: vi.fn() };
  response.status.mockReturnValue(response);
  const request = { requestId: 'diagnostics-boundary-request' };
  const host = { switchToHttp: () => ({ getResponse: () => response, getRequest: () => request }) };
  new ErrorFilter().catch(error, host as any);
  expect(logged).toHaveBeenCalledTimes(1);
  expect(response.status).toHaveBeenCalledWith(500);
  return {
    log: JSON.parse(logged.mock.calls[0][0] as string),
    encodedLog: logged.mock.calls[0][0] as string,
    body: response.json.mock.calls[0][0],
  };
}

afterEach(() => vi.restoreAllMocks());

describe('M11 bounded PostgreSQL diagnostics do not disclose credentials', () => {
  it('logs only SQLSTATE and safe server identifiers, never message, detail, SQL or parameters', () => {
    const secret = 'api-key-and-private-password-never-in-logs';
    const error = Object.assign(new Error(`database rejected ${secret}`), {
      code: '23514', constraint: 'entity_change_baselines_check',
      table: 'entity_change_baselines', schema: 'public', routine: 'ExecConstraints',
      detail: `Failing row contains (${secret})`,
      query: `INSERT INTO credentials VALUES ('${secret}')`,
      parameters: [secret], hint: `secret: ${secret}`, where: `secret: ${secret}`,
    });
    const result = diagnose(error);
    expect(result.log).toEqual({
      level: 'error', requestId: 'diagnostics-boundary-request', errorType: 'Error',
      code: 'INTERNAL_ERROR', status: 500, sqlState: '23514',
      constraint: 'entity_change_baselines_check', table: 'entity_change_baselines',
      schema: 'public', routine: 'ExecConstraints',
    });
    expect(result.encodedLog).not.toContain(secret);
    expect(JSON.stringify(result.body)).not.toContain(secret);
    expect(result.body).toEqual({ error: { code: 'INTERNAL_ERROR', message: '服务暂时不可用' }, meta: { requestId: 'diagnostics-boundary-request' } });
  });

  it('drops malicious, overlong and non-string diagnostic identifiers', () => {
    const secret = 'PRIVATE KEY\ncredential=must-not-be-logged';
    const error = Object.assign(new Error(secret), {
      code: '23514', table: `credentials\n${secret}`, constraint: `constraint"${secret}`,
      schema: 's'.repeat(129), routine: { credential: secret }, detail: secret,
    });
    const result = diagnose(error);
    expect(result.log).toEqual({ level: 'error', requestId: 'diagnostics-boundary-request', errorType: 'Error', code: 'INTERNAL_ERROR', status: 500, sqlState: '23514' });
    expect(result.encodedLog).not.toContain('credential');
    expect(result.encodedLog).not.toContain('PRIVATE KEY');
    expect(JSON.stringify(result.body)).not.toContain('PRIVATE KEY');
  });

  it('omits all database diagnostics when SQLSTATE is invalid, even if identifiers look safe', () => {
    const result = diagnose(Object.assign(new Error('do-not-log-secret'), {
      code: '23514\nsecret', table: 'credentials', constraint: 'safe_identifier',
      schema: 'public', routine: 'ExecConstraints', detail: 'do-not-log-secret',
    }));
    expect(result.log).toEqual({ level: 'error', requestId: 'diagnostics-boundary-request', errorType: 'Error', code: 'INTERNAL_ERROR', status: 500 });
    expect(result.encodedLog).not.toContain('secret');
    expect(result.encodedLog).not.toContain('credentials');
  });
});
