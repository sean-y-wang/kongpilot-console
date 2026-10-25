import { createServer, type RequestListener, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const lookup = vi.hoisted(() => vi.fn());
vi.mock('node:dns/promises', () => ({ lookup }));
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';

describe('M0 outbound DNS pinning and real HTTP transport', () => {
  let server: Server | undefined;

  beforeEach(() => {
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'localhost,127.0.0.1,169.254.169.254,::ffff:a9fe:a9fe');
    lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
  });

  afterEach(async () => {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = undefined;
    }
    vi.unstubAllEnvs();
  });

  async function listen(handler: RequestListener): Promise<number> {
    server = createServer(handler);
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
    return (server.address() as AddressInfo).port;
  }

  it('resolves once and supports Node HTTP lookup options.all', async () => {
    const port = await listen((_req, res) => { res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}'); });
    expect(await outboundJson(`http://localhost:${port}`, '/')).toEqual({ status: 200, body: { ok: true }, bytes: 11 });
    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it('does not follow a redirect to a metadata service', async () => {
    let hits = 0;
    const port = await listen((_req, res) => { hits++; res.statusCode = 302; res.setHeader('Location', 'http://169.254.169.254/latest/meta-data/'); res.end(); });
    const response = await outboundJson(`http://localhost:${port}`, '/');
    expect(response.status).toBe(302);
    expect(hits).toBe(1);
  });

  it('bounds a stalled HTTP response', async () => {
    const port = await listen(() => {});
    await expect(outboundJson(`http://localhost:${port}`, '/', 'GET', undefined, {}, undefined, 30)).rejects.toMatchObject({ code: 'ETIMEDOUT' });
  });

  it('includes stalled DNS resolution in the request deadline', async () => {
    lookup.mockImplementation(() => new Promise(() => {}));
    await expect(outboundJson('http://localhost', '/', 'GET', undefined, {}, undefined, 30)).rejects.toMatchObject({ code: 'ETIMEDOUT' });
  });

  it.each([
    'http://169.254.169.254/',
    'http://[::ffff:169.254.169.254]/',
  ])('blocks metadata addresses even when explicitly host-allowed: %s', async (base) => {
    await expect(outboundJson(base, '/')).rejects.toMatchObject({ status: 403 });
  });

  it('rejects DNS answers containing IPv4-mapped metadata addresses', async () => {
    lookup.mockResolvedValue([{ address: '::ffff:a9fe:a9fe', family: 6 }]);
    await expect(outboundJson('http://localhost', '/')).rejects.toMatchObject({ status: 403 });
  });

  it('rejects a mixed DNS answer set containing a forbidden address', async () => {
    lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }, { address: '169.254.169.254', family: 4 }]);
    await expect(outboundJson('http://localhost', '/')).rejects.toMatchObject({ status: 403 });
  });
});
