import { ForbiddenException, HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { writeFailureDiagnostic } from '../../apps/console-api/src/infrastructure/kong/write-failure-diagnostics';

const clusterId = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const operationId = 'a3ea3b8c-aa2b-48ae-9d7a-d8e8123b978b';
describe('unknown-write diagnostics', () => {
  it('records only a bounded internal code and original UUID attribution', () => {
    const error = new ForbiddenException({ code: 'APPROVED_STEP_REQUIRED', message: 'private credential',
      fields: { key: 'private credential' }, body: { token: 'private credential' } });
    expect(writeFailureDiagnostic('sdk-response', clusterId, error, operationId)).toEqual({
      event: 'kong_write_response_authorization_failed', stage: 'sdk-response', clusterId, operationId,
      code: 'APPROVED_STEP_REQUIRED', writeResult: 'unknown_requires_verification', retryAllowed: false
    });
  });
  it.each(['secret@example.test', 'APPROVED_KEY\nprivate', 'A'.repeat(97), undefined, { secret: 'private' }])(
    'does not copy an unstructured or oversized error code (%j)', code => {
      const value = writeFailureDiagnostic('native-policy-response', 'private cluster URL',
        new HttpException({ code, message: 'private' }, 403), 'private operation token');
      expect(value).toMatchObject({ clusterId: null, operationId: null, code: 'UNCLASSIFIED_AUTHORIZATION_FAILURE', retryAllowed: false });
      expect(JSON.stringify(value)).not.toContain('private');
    });
  it('does not serialize arbitrary thrown objects or Error messages', () => {
    for (const error of [new Error('private'), { code: 'APPROVED_STEP_REQUIRED', key: 'private' }, 'private']) {
      expect(writeFailureDiagnostic('sdk-response', clusterId, error).code).toBe('UNCLASSIFIED_AUTHORIZATION_FAILURE');
    }
  });
});
