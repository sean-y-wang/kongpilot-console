import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const hooks = vi.hoisted(() => ({ setters: [] as Array<ReturnType<typeof vi.fn>>, close: vi.fn(), clear: vi.fn(), login: vi.fn() }));
vi.mock('react', async original => {
  const actual = await original<typeof import('react')>();
  return { ...actual, useState: (initial: unknown) => { const setter = vi.fn(); hooks.setters.push(setter); return [initial, setter]; },
    useRef: (initial?: unknown) => ({ current: initial }), useEffect: vi.fn() };
});
vi.mock('@tanstack/react-query', () => ({ useQueryClient: () => ({ clear: hooks.clear }) }));
vi.mock('../../apps/console-web/src/components/MutationConfirm', () => ({ closeMutationConfirmDialogs: hooks.close }));
vi.mock('../../apps/console-web/src/api/login-session', () => ({ loadLoginSession: (...args: unknown[]) => hooks.login(...args) }));

const actorA = '2ecb4666-d31b-4c16-a591-b9b0c40fd58a', actorB = 'b62bce3c-41a1-4a98-80c1-06d98fd85d3c';
const session = (id: string) => ({ user: { id, username: id === actorA ? 'old-account' : 'new-account', superAdmin: false, permissionsVersion: `${id}:1` }, csrfToken: `${id}-csrf` });
const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }

beforeEach(() => { vi.resetModules(); hooks.setters.length = 0; hooks.close.mockReset(); hooks.clear.mockReset(); hooks.login.mockReset();
  vi.stubGlobal('window', { dispatchEvent: vi.fn() }); vi.stubGlobal('sessionStorage', { removeItem: vi.fn() }); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('actual AuthProvider ignores old reloads after verified API actor publication', () => {
  // React scheduling is deliberately controlled, not a browser renderer.
  // AuthProvider and client are actual modules. The login bridge reproduces
  // the already independently verified helper boundary: publish B before
  // allowing React's awaiting login() continuation to apply session B.
  it.each(['old-account-200', 'new-account-200', 'old-account-401'])
    ('does not restore A or end B for %s in the API-B/ref-A gap, then applies B', async variant => {
      const client = await import('../../apps/console-web/src/api/client');
      vi.stubGlobal('React', await import('react'));
      const { AuthProvider } = await import('../../apps/console-web/src/app/AuthContext');
      const oldReload = deferred<Response>(), allowReactApply = deferred<ReturnType<typeof session>>();
      let meReads = 0;
      const observed: string[] = [];
      vi.stubGlobal('fetch', vi.fn(async (url: string) => {
        observed.push(url);
        if (url === '/api/v1/auth/me') return ++meReads === 1 ? json({ data: session(actorA) }) : oldReload.promise;
        throw new Error('unexpected fixture request');
      }));
      const value = (AuthProvider({ children: null }) as any).props.value;
      await value.refresh(); expect(client.getApiActorId()).toBe(actorA);
      expect(hooks.setters[0].mock.calls.map(call => call[0]?.id)).toEqual([actorA]);
      const pendingReload = value.reloadCapabilities().catch((error: unknown) => error);
      await vi.waitFor(() => expect(meReads).toBe(2));
      hooks.login.mockImplementation(async () => {
        client.setApiActorId(actorB); client.setCsrfToken(session(actorB).csrfToken);
        return allowReactApply.promise;
      });
      const pendingLogin = value.login('new-account', 'fixture-password-only');
      expect(client.getApiActorId()).toBe(actorB);
      if (variant === 'old-account-401') oldReload.resolve(json({ error: { code: 'SESSION_EXPIRED' } }, 401));
      else oldReload.resolve(json({ data: session(variant === 'old-account-200' ? actorA : actorB) }));
      const result = await pendingReload;
      if (variant === 'old-account-401') expect(result).toMatchObject({ code: 'SESSION_CHANGED' });
      expect(client.getApiActorId()).toBe(actorB);
      expect(hooks.setters[0].mock.calls.map(call => call[0]?.id)).toEqual([actorA]);
      expect(hooks.close).not.toHaveBeenCalled(); expect(hooks.clear).not.toHaveBeenCalled();
      expect(sessionStorage.removeItem).not.toHaveBeenCalled(); expect(window.dispatchEvent).not.toHaveBeenCalled();
      expect(observed).not.toContain('/api/v1/auth/refresh');
      allowReactApply.resolve(session(actorB)); await pendingLogin;
      expect(client.getApiActorId()).toBe(actorB);
      expect(hooks.setters[0].mock.calls.map(call => call[0]?.id)).toEqual([actorA, actorB]);
      expect(hooks.clear).toHaveBeenCalledTimes(1);
    });
});
