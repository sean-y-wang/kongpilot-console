import { describe, it, expect } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const cid = 'dff45535-ed8d-4851-b7a6-6376feac7f59', id = '12491546-24cc-4f35-be68-bbe6f25da3b1';
function execution() {
  const service = new KongExecutionContextService();
  service.installPolicy({ authorizeRequest: async frame => { service.assertEventObservationRead(frame); return { source: 'trusted' }; }, authorizeResponse: async (_ticket, result) => result });
  return service;
}
describe('M7 private observation native read boundary', () => {
  it.each(['/plugins', '/services', '/cache', '/clustering', '/vaults', `/upstreams/name/health`, `/certificates/${id}/snis`])('cannot mint observer capability for %s', async path => {
    const service = execution();
    await expect(service.runEventObservationRead(cid, [path], async () => undefined)).rejects.toMatchObject({ status: 403 });
  });
  it('rejects HTTP and nested actor contexts even for a legal path', async () => {
    const service = execution();
    await expect(service.runHttp({}, () => service.runEventObservationRead(cid, ['/'], async () => undefined))).rejects.toMatchObject({ status: 403 });
  });
  it('cannot write, add filters or exceed bounded size inside a real observer capability', async () => {
    const service = execution(), cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
    await service.runEventObservationRead(cid, ['/upstreams', '/'], async () => {
      await expect(service.authorizeRequest(cluster, 'POST', '/upstreams', { name: 'write' }, {})).rejects.toMatchObject({ status: 403 });
      await expect(service.authorizeRequest(cluster, 'GET', '/upstreams', undefined, { tags: 'owner' })).rejects.toMatchObject({ status: 403 });
      await expect(service.authorizeRequest(cluster, 'GET', '/upstreams', undefined, { size: 101 })).rejects.toMatchObject({ status: 403 });
      await expect(service.authorizeRequest(cluster, 'GET', '/upstreams', undefined, { size: 100 })).resolves.toBeDefined();
      await expect(service.authorizeRequest(cluster, 'GET', '/', undefined, { size: 1 })).rejects.toMatchObject({ status: 403 });
    });
  });
  it('copied frame and closed frame cannot be used as a capability', async () => {
    const service = execution(); let captured: any;
    await service.runEventObservationRead(cid, ['/'], async () => {
      captured = service.current(); service.assertEventObservationRead(captured);
      expect(() => service.assertEventObservationRead({ ...captured })).toThrow();
    });
    expect(() => service.assertEventObservationRead(captured)).toThrow();
  });
});
