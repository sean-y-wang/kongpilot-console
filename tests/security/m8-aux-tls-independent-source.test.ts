// @ts-nocheck -- actual helper, synthetic RAM DTOs and HTTPS EventEmitter only.
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { sha256 } from './lib/m8-harness.mjs';

const transport = vi.hoisted(() => ({ request: vi.fn(), authorized: true, observe: null }));
vi.mock('node:https', () => ({ request: (...args) => transport.request(...args) }));
import { proxyRequest } from './lib/m8-native-acceptance.mjs';

function fixture() {
  const area = { cid: randomUUID(), wid: randomUUID() }, certificateId = randomUUID(), operationKey = randomUUID();
  const cert = '-----BEGIN CERTIFICATE-----\nSynthetic-public-certificate-bytes\n-----END CERTIFICATE-----', key = 'Synthetic-private-key-bytes', tag = 'synthetic-m8-tls';
  const body = { cert, key, tags: [tag] };
  const packet = { index: 0, key: operationKey, method: 'POST', path: `/api/v1/clusters/${area.cid}/entities/certificates`,
    query: `?workspaceId=${area.wid}`, clusterId: area.cid, workspaceId: area.wid, body, bodySha256: sha256(JSON.stringify(body)),
    actorId: randomUUID(), sessionId: randomUUID(), requestId: randomUUID(), headers: { Cookie: 'kongos_access=SyntheticAccessCookie', 'Content-Type': 'application/json', 'X-Idempotency-Key': operationKey },
    state: 'response_observed', status: 201, responseData: { entity: { id: certificateId, cert } } };
  const sniId = randomUUID(), sniBody = { name: `${tag}.invalid`, certificate: { id: certificateId } }, sniKey = randomUUID();
  const sniPacket = { ...structuredClone(packet), index: 1, key: sniKey, path: `/api/v1/clusters/${area.cid}/entities/snis`, requestId: randomUUID(),
    body: sniBody, bodySha256: sha256(JSON.stringify(sniBody)), headers: { ...packet.headers, 'X-Idempotency-Key': sniKey }, responseData: { entity: { id: sniId, ...sniBody } } };
  const h = { state: { testTag: tag, phase: 'ready', requests: [packet, sniPacket], secrets: [], proxyChecks: [],
      sessions: { admin: { user: { id: packet.actorId }, sid: packet.sessionId } }, scopes: { direct: area, approval: { cid: randomUUID(), wid: randomUUID() } },
      nativeFixture: { area, certificate: { id: certificateId, cert }, sni: { id: sniId, ...sniBody } } },
    remember: vi.fn(), assertWritable: vi.fn(), check: (condition, name) => { if (!condition) throw Error(name); },
    save: vi.fn(extra => { Object.assign(h.state, extra); }) };
  return { area, h, packet, sniPacket, cert, tag };
}

beforeEach(() => {
  transport.authorized = true; transport.observe = null;
  transport.request.mockReset().mockImplementation((options, callback) => {
    transport.observe?.(options);
    const req = new EventEmitter();
    req.end = vi.fn(() => queueMicrotask(() => {
      const response = new EventEmitter(); response.statusCode = 200; response.socket = { authorized: transport.authorized };
      response.destroy = vi.fn(); callback(response);
      response.emit('data', Buffer.from(JSON.stringify({ upstream: 'synthetic' }))); response.emit('end');
    }));
    return req;
  });
});

describe('independent original-packet TLS trust proof', () => {
  it('uses only published proxy TLS with exact SNI, explicit CA and certificate authorization', async () => {
    const f = fixture();
    await expect(proxyRequest(f.h, f.area, `/m8/${f.tag}/oauth2/oauth2/token`, { method: 'POST', tls: true, body: { grant_type: 'synthetic' }, expected: 200 })).resolves.toMatchObject({ status: 200 });
    expect(transport.request).toHaveBeenCalledTimes(1);
    expect(transport.request.mock.calls[0][0]).toMatchObject({ hostname: '127.0.0.1', port: 8443, servername: `${f.tag}.invalid`, ca: f.cert, rejectUnauthorized: true });
    expect(f.h.state.proxyChecks[0]).toMatchObject({ state: 'response_observed', tlsAuthorized: true, publicCaSha256: sha256(f.cert) });
  });
  it('durably captures exact SNI and public CA fingerprint in the original prepared packet before transport', async () => {
    const f = fixture(); let original;
    transport.observe = () => { original = structuredClone(f.h.state.proxyChecks[0]); };
    await proxyRequest(f.h, f.area, `/m8/${f.tag}/oauth2/echo`, { tls: true });
    expect(original).toMatchObject({ state: 'prepared', tls: true, servername: `${f.tag}.invalid`, publicCaSha256: sha256(f.cert),
      originalCertificateRequestId: f.packet.requestId, originalCertificateBodySha256: f.packet.bodySha256, originalSniRequestId: f.sniPacket.requestId });
    expect(f.h.save).toHaveBeenCalled();
  });
  it.each(['method', 'clusterScope', 'workspaceScope', 'queryScope', 'state', 'bodySha256', 'missingActor', 'missingRequestId', 'nonUuidKey'])('rejects an unbound certificate creation packet with incorrect %s before TLS transport', async changed => {
    const f = fixture();
    if (changed === 'method') f.packet.method = 'DELETE';
    else if (changed === 'clusterScope') { const cid = randomUUID(); f.packet.clusterId = cid; f.packet.path = `/api/v1/clusters/${cid}/entities/certificates`; }
    else if (changed === 'workspaceScope') { f.packet.workspaceId = randomUUID(); f.packet.query = `?workspaceId=${f.packet.workspaceId}`; }
    else if (changed === 'queryScope') f.packet.query = `?workspaceId=${randomUUID()}`;
    else if (changed === 'state') { f.packet.state = 'response_unknown'; delete f.packet.status; }
    else if (changed === 'missingActor') { delete f.h.state.sessions.admin; delete f.packet.actorId; delete f.packet.sessionId; delete f.sniPacket.actorId; delete f.sniPacket.sessionId; }
    else if (changed === 'missingRequestId') delete f.packet.requestId;
    else if (changed === 'nonUuidKey') { f.packet.key = 'synthetic-non-uuid'; f.packet.headers['X-Idempotency-Key'] = f.packet.key; }
    else f.packet.bodySha256 = '0'.repeat(64);
    await expect(proxyRequest(f.h, f.area, `/m8/${f.tag}/oauth2/oauth2/token`, { method: 'POST', tls: true, body: { grant_type: 'synthetic' } })).rejects.toThrow();
    expect(transport.request).not.toHaveBeenCalled();
    expect(f.h.state.proxyChecks).toHaveLength(0);
  });
  it('retains unknown original TLS intent and stops when the TLS socket is not authorized', async () => {
    const f = fixture(); transport.authorized = false;
    await expect(proxyRequest(f.h, f.area, `/m8/${f.tag}/oauth2/oauth2/token`, { method: 'POST', tls: true, body: { grant_type: 'synthetic' } })).rejects.toThrow('M8_PROXY_RESPONSE_UNKNOWN_ORIGINAL_RETAINED');
    expect(f.h.state.phase).toBe('stopped-proxy-unknown');
    expect(f.h.state.proxyChecks[0].state).toBe('response_unknown');
    expect(transport.request).toHaveBeenCalledTimes(1);
  });
});
