import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const mocks = vi.hoisted(() => ({ lookup: vi.fn(), httpRequest: vi.fn(), httpsRequest: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: mocks.lookup }));
vi.mock('node:http', () => ({ request: mocks.httpRequest }));
vi.mock('node:https', () => ({ request: mocks.httpsRequest }));
import { outboundJson, outboundText } from '../../apps/console-api/src/infrastructure/kong/outbound';

/** Synthetic Node HTTP/DNS adapters and fake time exercise the real outbound
 * deadline/guard code deterministically. No network server, real Gateway,
 * SQL, native authority or receipt is represented by these fixtures. */
const start = new Date('2026-10-13T20:00:00.000Z').getTime();
const requests: Array<{ request: any; target: URL; options: any; startedAt: number }> = [];
let responseDelay: number | null, responseBody: string, responseStatus: number;
const wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
function requestAdapter(target: URL, options: any, responseCallback: (response: any) => void) {
  const request: any = new EventEmitter(); let destroyed = false;
  request.write = vi.fn();
  request.destroy = vi.fn((error: Error) => { if (!destroyed) { destroyed = true; request.emit('error', error); request.emit('close'); } });
  request.end = vi.fn(() => {
    if (responseDelay === null) return;
    setTimeout(() => {
      if (destroyed) return;
      const response: any = new EventEmitter(); response.statusCode = responseStatus;
      responseCallback(response); response.emit('data', Buffer.from(responseBody));
      if (!destroyed) response.emit('end'); request.emit('close');
    }, responseDelay);
  });
  requests.push({ request, target, options, startedAt: Date.now() }); return request;
}
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(start); vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'kong');
  mocks.lookup.mockReset(); mocks.httpRequest.mockReset(); mocks.httpsRequest.mockReset(); requests.length = 0;
  mocks.lookup.mockResolvedValue([{ address: '192.0.2.20', family: 4 }]);
  mocks.httpRequest.mockImplementation(requestAdapter); mocks.httpsRequest.mockImplementation(requestAdapter);
  responseDelay = 1; responseBody = '{"ok":true}'; responseStatus = 200;
});
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('M11 independent DNS/preparation/network budgets (synthetic HTTP)', () => {
  it('allows durable preparation beyond 5 seconds then grants the unchanged 5-second native network budget', async () => {
    mocks.lookup.mockImplementation(async () => { await wait(100); return [{ address: '192.0.2.20', family: 4 }]; });
    responseDelay = 4900; const fence = vi.fn(), prepare = vi.fn(async () => wait(6000));
    const assertion = expect(outboundJson('http://kong:8001', '/services', 'POST', { name: 'synthetic' }, {}, null, 5000, fence, prepare))
      .resolves.toEqual({ status: 200, body: { ok: true }, bytes: 11 });
    await vi.advanceTimersByTimeAsync(11000); await assertion;
    expect(prepare).toHaveBeenCalledTimes(1); expect(fence).toHaveBeenCalledTimes(1); expect(mocks.httpRequest).toHaveBeenCalledTimes(1);
    expect(requests[0].startedAt - start).toBe(6100); expect(requests[0].request.destroy).not.toHaveBeenCalled();
    expect(requests[0].request.end).toHaveBeenCalledTimes(1); expect(vi.getTimerCount()).toBe(0);
  });
  it('keeps a separate 5-second stalled network limit after slow DNS and permission preparation', async () => {
    mocks.lookup.mockImplementation(async () => { await wait(4500); return [{ address: '192.0.2.20', family: 4 }]; });
    responseDelay = null; const prepare = vi.fn(async () => wait(6000)), fence = vi.fn();
    const result = outboundJson('http://kong:8001', '/services', 'POST', { name: 'synthetic' }, {}, null, 5000, fence, prepare);
    const assertion = expect(result).rejects.toMatchObject({ message: 'Upstream timeout', code: 'ETIMEDOUT' });
    await vi.advanceTimersByTimeAsync(15499);
    expect(requests[0].startedAt - start).toBe(10500); expect(requests[0].request.destroy).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1); await assertion;
    expect(Date.now() - start).toBe(15500); expect(requests[0].request.destroy).toHaveBeenCalledTimes(1);
    expect(mocks.httpRequest).toHaveBeenCalledTimes(1); expect(fence).toHaveBeenCalledTimes(1); expect(vi.getTimerCount()).toBe(0);
  });
  it('stops stalled DNS without preparing a write, allocating a socket or spending its guard', async () => {
    mocks.lookup.mockImplementation(() => new Promise(() => {})); const prepare = vi.fn(), fence = vi.fn();
    const assertion = expect(outboundJson('http://kong:8001', '/', 'POST', {}, {}, null, 5000, fence, prepare))
      .rejects.toMatchObject({ message: 'DNS timeout', code: 'ETIMEDOUT' });
    await vi.advanceTimersByTimeAsync(5000); await assertion;
    expect(prepare).not.toHaveBeenCalled(); expect(fence).not.toHaveBeenCalled(); expect(mocks.httpRequest).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
  it('pins the sole resolved address after preparation and never re-resolves for the socket', async () => {
    const original = { address: '192.0.2.20', family: 4 }; mocks.lookup.mockResolvedValue([original]);
    const prepare = vi.fn(async () => { mocks.lookup.mockResolvedValue([{ address: '169.254.169.254', family: 4 }]); await wait(6000); });
    const assertion = expect(outboundJson('http://kong:8001', '/', 'POST', {}, {}, null, 5000, undefined, prepare)).resolves.toMatchObject({ status: 200 });
    await vi.advanceTimersByTimeAsync(6001); await assertion;
    const single = vi.fn(), all = vi.fn(); requests[0].options.lookup('kong', {}, single); requests[0].options.lookup('kong', { all: true }, all);
    expect(single).toHaveBeenCalledWith(null, original.address, original.family); expect(all).toHaveBeenCalledWith(null, [original]);
    expect(mocks.lookup).toHaveBeenCalledTimes(1);
  });
  it('rejects a forbidden mixed DNS answer before entering preparation', async () => {
    mocks.lookup.mockResolvedValue([{ address: '192.0.2.20', family: 4 }, { address: '169.254.169.254', family: 4 }]);
    const prepare = vi.fn(); await expect(outboundJson('http://kong:8001', '/', 'POST', {}, {}, null, 5000, undefined, prepare)).rejects.toMatchObject({ status: 403 });
    expect(prepare).not.toHaveBeenCalled(); expect(mocks.httpRequest).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0);
  });
  it('does not create an HTTP request when durable revalidation rejects after its await', async () => {
    const rejection = new ForbiddenException({ code: 'CURRENT_AUTHORITY_REVOKED' }), fence = vi.fn();
    const assertion = expect(outboundJson('http://kong:8001', '/', 'POST', {}, {}, null, 5000, fence, async () => { await wait(6000); throw rejection; })).rejects.toBe(rejection);
    await vi.advanceTimersByTimeAsync(6000); await assertion;
    expect(fence).not.toHaveBeenCalled(); expect(mocks.httpRequest).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0);
  });
  it('retains the final synchronous revocation fence after successful slow revalidation', async () => {
    let allowed = true;
    const fence = vi.fn(() => { if (!allowed) throw new ForbiddenException({ code: 'CURRENT_AUTHORITY_REVOKED' }); });
    const assertion = expect(outboundJson('http://kong:8001', '/', 'POST', {}, {}, null, 5000, fence,
      async () => { await wait(6000); allowed = false; })).rejects.toMatchObject({ response: { code: 'CURRENT_AUTHORITY_REVOKED' } });
    await vi.advanceTimersByTimeAsync(6000); await assertion;
    expect(fence).toHaveBeenCalledTimes(1); expect(mocks.httpRequest).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0);
  });
  it.each(['deadline', 'closed'])('cannot extend the real Context ticket when its outer lifetime is %s', async kind => {
    const context = new KongExecutionContextService(), actor = { id: 'controlled-user', username: 'controlled', superAdmin: false };
    context.installPolicy({ authorizeRequest: async () => ({}), authorizeResponse: async (_decision, response) => response });
    const work = context.runHttp({}, async () => {
      context.bindHttpActor(actor, 'controlled-http-session'); const close = context.captureHttpCloser();
      return context.runActor({ actor, clusterId: 'controlled-cluster', workspaceId: 'controlled-workspace' },
        () => context.runOperation({ actor, clusterId: 'controlled-cluster', workspaceId: 'controlled-workspace', operationId: 'controlled-operation', entityType: 'services', action: 'update' }, async () => {
          const ticket = await context.authorizeRequest({ id: 'controlled-cluster', admin_url: 'http://kong:8001', execution_mode: 'direct' }, 'PATCH', '/services/controlled', {}, {});
          return outboundJson('http://kong:8001', '/services/controlled', 'PATCH', {}, {}, null, 5000, () => context.assertTicketActive(ticket),
            async () => { await wait(kind === 'deadline' ? 120001 : 6000); if (kind === 'closed') close(); });
        }));
    });
    const assertion = expect(work).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    await vi.advanceTimersByTimeAsync(kind === 'deadline' ? 120001 : 6000); await assertion;
    expect(mocks.httpRequest).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0);
  });
  it('keeps HTTPS certificate validation defaults and the original server hostname', async () => {
    const assertion = expect(outboundJson('https://kong:8444', '/', 'POST', {}, {}, null, 5000, undefined, async () => wait(6000))).resolves.toMatchObject({ status: 200 });
    await vi.advanceTimersByTimeAsync(6001); await assertion;
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1); expect(mocks.httpRequest).not.toHaveBeenCalled();
    expect(requests[0].target.hostname).toBe('kong'); expect(requests[0].target.protocol).toBe('https:');
    expect(requests[0].options).not.toHaveProperty('rejectUnauthorized'); expect(requests[0].options).not.toHaveProperty('servername');
  });
  it('still bounds response size and never retries a write following that transport error', async () => {
    responseBody = 'x'.repeat(17);
    const assertion = expect(outboundJson('http://kong:8001', '/', 'POST', {}, {}, null, 5000, undefined, async () => wait(6000), 16)).rejects.toMatchObject({ code: 'RESPONSE_TOO_LARGE' });
    await vi.advanceTimersByTimeAsync(6001); await assertion;
    expect(requests[0].request.destroy).toHaveBeenCalledTimes(1); expect(mocks.httpRequest).toHaveBeenCalledTimes(1); expect(vi.getTimerCount()).toBe(0);
  });
  it('preserves standalone text transport timeout and final guard behavior', async () => {
    responseBody = '# synthetic metrics\n'; const fence = vi.fn();
    const assertion = expect(outboundText('http://kong:8001', '/metrics', null, 5000, fence)).resolves.toMatchObject({ status: 200, body: responseBody });
    await vi.advanceTimersByTimeAsync(1); await assertion;
    expect(fence).toHaveBeenCalledTimes(1); expect(requests[0].options.headers.Accept).toBe('text/plain; version=0.0.4');
    expect(mocks.httpRequest).toHaveBeenCalledTimes(1); expect(vi.getTimerCount()).toBe(0);
  });
});
