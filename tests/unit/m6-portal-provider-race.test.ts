import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const hooks = vi.hoisted(() => ({ setters: [] as Array<ReturnType<typeof vi.fn>>, clear: vi.fn(), login: vi.fn() }));
vi.mock('react', async original => { const actual = await original<typeof import('react')>(); return { ...actual, useState: (initial: unknown) => { const setter = vi.fn(); hooks.setters.push(setter); return [initial, setter]; }, useRef: (initial?: unknown) => ({ current: initial }), useEffect: vi.fn() }; });
vi.mock('@tanstack/react-query', () => ({ useQueryClient: () => ({ clear: hooks.clear }) }));
const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actorA = '2ecb4666-d31b-4c16-a591-b9b0c40fd58a', actorB = 'b62bce3c-41a1-4a98-80c1-06d98fd85d3c';
const tenant = { clusterId: cid, workspaceId: wid, slug: 'test-space', name: 'Test', branding: {}, registrationEnabled: true };
const developer = (id: string) => ({ ...tenant, id, username: 'developer', email: 'test@example.com', displayName: 'Developer', revision: 1, status: 'active' as const, mustChangePassword: false, createdAt: new Date().toISOString() });
const json = (data: unknown, status = 200) => new Response(JSON.stringify({ data }), { status });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve }; }
beforeEach(() => { vi.resetModules(); hooks.setters.length = 0; hooks.clear.mockReset(); hooks.login.mockReset(); vi.stubGlobal('window', { dispatchEvent: vi.fn() }); vi.stubGlobal('sessionStorage', { removeItem: vi.fn(), getItem: vi.fn(() => null) }); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('actual PortalProvider current-actor recovery boundary', () => {
  it.each(['existing-actor', 'anonymous-bootstrap'])('ignores a delayed %s me result after verified API B publication, before React B is applied', async variant => {
    const client = await import('../../apps/portal-web/src/api/portal-client'); client.setPortalScope(tenant); vi.spyOn(client, 'portalLogin').mockImplementation((...args) => hooks.login(...args));
    vi.stubGlobal('React', await import('react')); const { PortalProvider } = await import('../../apps/portal-web/src/app/PortalContext'); const delayed = deferred<Response>(), allowReact = deferred<ReturnType<typeof developer>>(); let reads = 0;
    vi.stubGlobal('fetch', vi.fn(() => ++reads === 1 && variant === 'existing-actor' ? Promise.resolve(json(developer(actorA))) : delayed.promise));
    const value = (PortalProvider({ tenant, children: null }) as any).props.value;
    if (variant === 'existing-actor') await value.refreshMe();
    const pending = value.refreshMe(); hooks.login.mockImplementation(async () => { client.setPortalIdentity(developer(actorB)); client.setPortalCsrf('synthetic-csrf'); return allowReact.promise; }); const login = value.login('developer', 'synthetic-password-only');
    delayed.resolve(json(developer(actorA))); await pending;
    expect(client.getPortalIdentity()?.id).toBe(actorB); expect(hooks.setters[0].mock.calls.map(call => call[0]?.id)).toEqual(variant === 'existing-actor' ? [actorA] : []); expect(hooks.clear).not.toHaveBeenCalled(); expect(sessionStorage.removeItem).not.toHaveBeenCalled();
    allowReact.resolve(developer(actorB)); await login; expect(hooks.setters[0].mock.calls.at(-1)?.[0]?.id).toBe(actorB);
  });
  it('ends a password-revoked session immediately while preserving only existing safe recovery references for same-account reauthentication', async () => {
    const client = await import('../../apps/portal-web/src/api/portal-client'); client.setPortalScope(tenant); vi.spyOn(client, 'portalLogin').mockImplementation((...args) => hooks.login(...args)); vi.stubGlobal('React', await import('react')); const { PortalProvider } = await import('../../apps/portal-web/src/app/PortalContext'); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(developer(actorA)))); const value = (PortalProvider({ tenant, children: null }) as any).props.value; await value.refreshMe(); value.endSession(); expect(client.getPortalIdentity()).toBeUndefined(); expect(hooks.setters[0].mock.calls.at(-1)?.[0]).toBeUndefined(); expect(sessionStorage.removeItem).not.toHaveBeenCalled(); expect(hooks.clear).toHaveBeenCalledOnce();
  });
  it('does not let an unmounted old tenant me response clear or publish into the new tenant', async () => {
    const client = await import('../../apps/portal-web/src/api/portal-client'); client.setPortalScope(tenant); vi.spyOn(client, 'portalLogin').mockImplementation((...args) => hooks.login(...args)); vi.stubGlobal('React', await import('react')); const { PortalProvider } = await import('../../apps/portal-web/src/app/PortalContext'); const pendingResponse = deferred<Response>(); vi.stubGlobal('fetch', vi.fn(() => pendingResponse.promise)); const value = (PortalProvider({ tenant, children: null }) as any).props.value; const pending = value.refreshMe(); client.setPortalScope({ ...tenant, workspaceId: actorB }); client.setPortalIdentity({ id: actorB, clusterId: cid, workspaceId: actorB }); pendingResponse.resolve(json(developer(actorA))); await pending; expect(client.getPortalIdentity()?.id).toBe(actorB); expect(hooks.setters[0]).not.toHaveBeenCalled(); expect(sessionStorage.removeItem).not.toHaveBeenCalled();
  });
});
