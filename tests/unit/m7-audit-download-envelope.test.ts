import { describe, expect, it } from 'vitest';
import { StreamableFile } from '@nestjs/common';
import { firstValueFrom, of } from 'rxjs';
import { EnvelopeInterceptor } from '../../apps/console-api/src/common/http';
describe('M7 bounded audit download HTTP representation', () => {
  const context: any = { switchToHttp: () => ({ getRequest: () => ({ requestId: 'audit-download-request' }) }) };
  it('passes the protected stream to Nest without serializing its private internals', async () => {
    const output = new StreamableFile(Buffer.from('{"result":"success"}\n'));
    const result = await firstValueFrom(new EnvelopeInterceptor().intercept(context, { handle: () => of(output) }));
    expect(result).toBe(output); expect(result).not.toHaveProperty('data');
  });
  it('retains the ordinary JSON envelope for receipts and list responses', async () => {
    const data = { jobId: 'original-job', durable: true };
    expect(await firstValueFrom(new EnvelopeInterceptor().intercept(context, { handle: () => of(data) }))).toEqual({ data, meta: { requestId: 'audit-download-request' } });
  });
});
