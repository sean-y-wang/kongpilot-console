import { describe, expect, it, afterEach } from 'vitest';
import { PortalAuthService } from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';

const svc = () => Object.create(PortalAuthService.prototype) as any;
const env = { ...process.env };
afterEach(() => { process.env = { ...env }; });

describe('PORTAL_PUBLIC_ORIGINS in production', () => {
  it('allows plain http only for loopback demo origins', () => {
    process.env.NODE_ENV = 'production';
    process.env.PORTAL_PUBLIC_ORIGINS = 'http://127.0.0.1:8082,http://localhost:8082';
    expect(svc().allowedOrigins()).toEqual(['http://127.0.0.1:8082', 'http://localhost:8082']);
  });
  it('still rejects http for non-loopback hosts', () => {
    process.env.NODE_ENV = 'production';
    process.env.PORTAL_PUBLIC_ORIGINS = 'http://portal.example.com';
    expect(() => svc().allowedOrigins()).toThrow('explicit portal origins');
  });
});
