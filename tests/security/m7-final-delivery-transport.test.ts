import 'reflect-metadata';
import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SmtpDeliveryTransport } from '../../apps/console-api/src/modules/event-delivery/smtp-delivery.transport';
import { HttpDeliveryTransport } from '../../apps/console-api/src/modules/event-delivery/http-delivery.transport';

// These are source-only protocol peers. No socket, environment file or running
// service is opened; the production send/fence state machines still execute.
const io = vi.hoisted(() => ({ connect: undefined as any, plain: undefined as any, request: undefined as any }));
vi.mock('node:tls', async importOriginal => ({ ...await importOriginal<any>(), connect: (...args: any[]) => io.connect(...args) }));
vi.mock('node:net', async importOriginal => ({ ...await importOriginal<any>(), createConnection: (...args: any[]) => io.plain(...args) }));
vi.mock('node:https', async importOriginal => ({ ...await importOriginal<any>(), request: (...args: any[]) => io.request(...args),
  Agent: class { createConnection: any; destroy() {} } }));

const envelope: any = { version: 1, eventId: '11111111-1111-4111-8111-111111111111',
  deliveryId: '22222222-2222-4222-8222-222222222222', clusterId: '33333333-3333-4333-8333-333333333333',
  workspaceId: '44444444-4444-4444-8444-444444444444', occurredAt: '2026-10-11T00:00:00.000Z',
  eventType: 'entity.updated', phase: 'terminal', result: 'success', summary: 'safe' };

function fixture(options: { mode?: 'starttls' | 'implicit-tls'; noStarttls?: boolean; tlsFailure?: boolean;
  revokeAfterTls?: boolean; revokeAt354?: boolean; changeGenerationAtTls?: boolean; httpStatus?: number } = {}) {
  const writes: string[] = [], connections: any[] = [], requests: any[] = [];
  let closed = false, authority = true, generation = 1, started = 0;
  const controller = new AbortController();
  class Peer extends EventEmitter {
    authorized = !options.tlsFailure;
    destroyed = false;
    destroy() { this.destroyed = true; this.emit('close'); return this; }
    write(value: string | Buffer) {
      const text = value.toString(); writes.push(text);
      let reply = text.startsWith('EHLO') ? `250-kongos.test\r\n${options.noStarttls ? '' : '250-STARTTLS\r\n'}250 AUTH PLAIN\r\n`
        : text.startsWith('STARTTLS') ? '220 Go TLS\r\n' : text.startsWith('AUTH ') ? '235 Authenticated\r\n'
        : text.startsWith('DATA') ? '354 Continue\r\n' : '250 Accepted\r\n';
      queueMicrotask(() => { if (text.startsWith('DATA') && options.revokeAt354) authority = false; this.emit('data', Buffer.from(reply)); });
      return true;
    }
  }
  io.plain = vi.fn((config: any) => {
    connections.push(config); const peer = new Peer();
    setImmediate(() => { peer.emit('connect'); peer.emit('data', Buffer.from('220 Ready\r\n')); });
    return peer;
  });
  io.connect = vi.fn((config: any) => {
    connections.push(config); const peer = new Peer();
    setImmediate(() => {
      if (options.revokeAfterTls) authority = false;
      if (options.changeGenerationAtTls) generation++;
      if (options.tlsFailure) { peer.emit('error', new Error('Synthetic TLS refusal')); return; }
      peer.emit('secureConnect');
      if (!config.socket) setImmediate(() => peer.emit('data', Buffer.from('220 Ready\r\n')));
    });
    return peer;
  });
  io.request = vi.fn((url: URL, config: any, receive: any) => {
    requests.push({ url, config }); const req = new EventEmitter() as any;
    req.destroy = vi.fn(); req.end = vi.fn((body: Buffer) => {
      writes.push(body.toString()); const response = new EventEmitter() as any;
      response.statusCode = options.httpStatus ?? 200; response.headers = {}; response.destroy = vi.fn();
      receive(response); queueMicrotask(() => { response.emit('data', Buffer.from('ok')); response.emit('end'); });
    });
    setImmediate(() => req.emit('socket')); return req;
  });
  const fence: any = { signal: controller.signal,
    prepareSend: vi.fn(async () => { if (!authority || generation !== 1 || closed) throw new Error('EVENT_DELIVERY_AUTHORITY_REVOKED'); }),
    beforeSend: vi.fn(() => { if (!authority || generation !== 1 || closed) throw new Error('EVENT_DELIVERY_FENCE_CLOSED'); }),
    onSendStarted: vi.fn(() => { started++; }) };
  const policy: any = { smtpConfig: () => ({ host: 'smtp.example.test', port: 465,
    mode: options.mode ?? 'implicit-tls', servername: 'smtp.example.test', from: 'console@example.test',
    username: 'Synthetic-user', password: 'Synthetic-password' }),
    resolveDestination: vi.fn(async (hostname: string, port: number) => ({ hostname, port, pinned: { address: '10.50.0.5', family: 4 } })),
    httpUrl: (value: string) => new URL(value), httpsCa: () => undefined };
  return { writes, connections, requests, policy, fence, started: () => started,
    smtp: new SmtpDeliveryTransport(policy), http: new HttpDeliveryTransport(policy), close: () => { closed = true; controller.abort(); } };
}
const smtpChannel: any = { type: 'email', endpoint: { recipients: ['recipient@example.test'] }, auth: { type: 'none' } };
const httpChannel: any = { type: 'webhook', endpoint: { url: 'https://hooks.example.test/private-path' },
  auth: { type: 'bearer', token: 'Synthetic-private-bearer' } };

describe('M7 independent protocol-boundary source adversaries', () => {
  afterEach(() => vi.clearAllMocks());
  it.each(['implicit-tls', 'starttls'] as const)('only sends SMTP credentials and body after authenticated %s', async mode => {
    const f = fixture({ mode }), result = await f.smtp.send(smtpChannel, envelope, f.fence);
    expect(result.outcome).toBe('succeeded'); expect(f.writes.some(v => v.startsWith('AUTH PLAIN '))).toBe(true);
    expect(f.writes.some(v => v.startsWith('Message-ID:') || v.includes('Message-ID:'))).toBe(true);
    const tlsConfig = f.connections.find(v => v.rejectUnauthorized === true);
    expect(tlsConfig.minVersion).toBe('TLSv1.2'); expect(tlsConfig.servername).toBe('smtp.example.test');
    if (mode === 'implicit-tls') expect(tlsConfig.host).toBe('10.50.0.5'); else expect(tlsConfig.socket).toBeDefined();
  });
  it('fails STARTTLS stripping before AUTH, MAIL or the message body', async () => {
    const f = fixture({ mode: 'starttls', noStarttls: true }), result = await f.smtp.send(smtpChannel, envelope, f.fence);
    expect(result.errorCode).toBe('EVENT_SMTP_STARTTLS_REQUIRED'); expect(result.sendStarted).toBe(false);
    expect(f.writes).toHaveLength(1); expect(f.writes[0]).toMatch(/^EHLO /); expect(io.connect).not.toHaveBeenCalled();
  });
  it('fails an invalid TLS peer without exposing credentials or DATA', async () => {
    const f = fixture({ tlsFailure: true }), result = await f.smtp.send(smtpChannel, envelope, f.fence);
    expect(result.errorCode).toBe('EVENT_SMTP_TLS_FAILED'); expect(result.sendStarted).toBe(false); expect(f.writes).toEqual([]);
  });
  it.each(['implicit-tls', 'starttls'] as const)('blocks a post-%s authority revocation before AUTH', async mode => {
    const f = fixture({ mode, revokeAfterTls: true }), result = await f.smtp.send(smtpChannel, envelope, f.fence);
    expect(result.outcome).toBe('failed'); expect(result.sendStarted).toBe(false);
    expect(f.writes.some(v => /^AUTH |^MAIL |^DATA/.test(v))).toBe(false);
  });
  it('stops the actual message body if authority changes while waiting for SMTP 354', async () => {
    const f = fixture({ revokeAt354: true }), result = await f.smtp.send(smtpChannel, envelope, f.fence);
    expect(result.outcome).toBe('uncertain'); expect(result.sendStarted).toBe(true);
    expect(f.writes.some(v => v.startsWith('AUTH '))).toBe(true); expect(f.writes).toContain('DATA\r\n');
    expect(f.writes.some(v => v.includes('Message-ID:'))).toBe(false);
  });
  it('rechecks HTTP authority after TLS before constructing credential headers or POST', async () => {
    const f = fixture({ revokeAfterTls: true }), result = await f.http.send(httpChannel, envelope, 'delivery-original-intent', f.fence);
    expect(result.sendStarted).toBe(false); expect(result.outcome).toBe('failed'); expect(f.requests).toEqual([]); expect(f.writes).toEqual([]);
  });
  it('closes a changed endpoint credential generation after TLS before any HTTP body', async () => {
    const f = fixture({ changeGenerationAtTls: true }), result = await f.http.send(httpChannel, envelope, 'delivery-original-intent', f.fence);
    expect(result.outcome).toBe('failed'); expect(f.requests).toEqual([]); expect(f.writes).toEqual([]);
  });
  it('pins TLS to the exact validated address and refuses a redirect without another request', async () => {
    const f = fixture({ httpStatus: 302 }), result = await f.http.send(httpChannel, envelope, 'delivery-original-intent', f.fence);
    expect(result.errorCode).toBe('EVENT_DELIVERY_REDIRECT_DENIED'); expect(result.retryable).toBe(false);
    expect(f.requests).toHaveLength(1); expect(f.connections[0]).toMatchObject({ host: '10.50.0.5', servername: 'hooks.example.test', rejectUnauthorized: true });
    expect(f.requests[0].config.headers['idempotency-key']).toBe('delivery-original-intent');
    expect(f.writes[0]).not.toContain('Synthetic-private-bearer');
  });
});
