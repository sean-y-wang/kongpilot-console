import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearPortalSelectionStorage, initialPortalTenantSlug, matchedPortalTenant, portalTenantStorageKey, rememberResolvedPortalTenant, validPortalTenantSlug, type PortalSelectionStorage } from '../../apps/portal-web/src/app/tenant-selection';

const hooks = vi.hoisted(() => ({
  initialized: false, slug: undefined as string | undefined,
  selection: { current: undefined as string | undefined },
  effects: [] as Array<() => void>, query: {} as any,
  clear: vi.fn(), render: vi.fn(), setSlug: vi.fn(),
}));
vi.mock('react', async original => {
  const actual = await original<typeof import('react')>();
  return { ...actual,
    useState: (initial: unknown) => {
      if (!hooks.initialized) { hooks.slug = typeof initial === 'function' ? initial() : initial; hooks.selection.current = hooks.slug; hooks.initialized = true; }
      return [hooks.slug, (value: string | undefined) => { hooks.setSlug(value); hooks.slug = value; }];
    },
    useRef: () => hooks.selection,
    useEffect: (effect: () => void) => { hooks.effects.push(effect); },
  };
});
vi.mock('react-dom/client', () => ({ default: { createRoot: () => ({ render: hooks.render }) } }));
vi.mock('@tanstack/react-query', () => ({
  QueryClient: class { clear = hooks.clear; }, QueryClientProvider: 'QueryClientProvider', useQuery: () => hooks.query,
}));
vi.mock('antd', () => ({ Alert: 'Alert', App: 'App', Button: 'Button', Card: 'Card', ConfigProvider: 'ConfigProvider', Input: { Search: 'Search' }, Select: 'Select', Space: 'Space', Spin: 'Spin', Typography: { Title: 'Title', Paragraph: 'Paragraph', Text: 'Text' } }));
vi.mock('react-router-dom', () => ({ BrowserRouter: 'BrowserRouter', Link: 'Link', Navigate: 'Navigate', Route: 'Route', Routes: 'Routes', useLocation: vi.fn(), useNavigate: vi.fn() }));
vi.mock('../../apps/portal-web/src/app/PortalContext', () => ({ PortalProvider: function PortalProvider() {}, usePortal: vi.fn() }));
vi.mock('../../apps/portal-web/src/features/PublicPages', () => ({ ApiDocumentPage: 'ApiDocumentPage', AuthPage: 'AuthPage', CatalogPage: 'CatalogPage', MarkdownPage: 'MarkdownPage' }));
vi.mock('../../apps/portal-web/src/features/Applications', () => ({ ApplicationDetailPage: 'ApplicationDetailPage', ApplicationsPage: 'ApplicationsPage' }));
vi.mock('../../apps/portal-web/src/features/Requests', () => ({ RequestDetailPage: 'RequestDetailPage', RequestsPage: 'RequestsPage' }));
vi.mock('../../apps/portal-web/src/components/Shared', () => ({ PortalErrorView: 'PortalErrorView', ProfileForm: 'ProfileForm', Protected: 'Protected', RecoveryBanner: 'RecoveryBanner' }));
vi.mock('../../apps/portal-web/src/app/i18n', () => ({}));

const A = { slug: 'tenant-a', clusterId: '5b316db5-b0b7-4b91-8197-f893ecb76540', workspaceId: 'ac18ace3-6ecd-473e-a09b-46be792203d7', name: 'A', branding: {}, registrationEnabled: true };
const B = { ...A, slug: 'tenant-b', workspaceId: '2ecb4666-d31b-4c16-a591-b9b0c40fd58a', name: 'B' };
const recoveryKey = 'kongos.portal.recovery';
function storage(): PortalSelectionStorage & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return { values, getItem: vi.fn(key => values.get(key) ?? null), setItem: vi.fn((key, value) => { values.set(key, value); }), removeItem: vi.fn(key => { values.delete(key); }) };
}
function findRoot(element: any): () => any {
  if (typeof element?.type === 'function' && element.type.name === 'PortalRoot') return element.type;
  for (const child of [element?.props?.children].flat()) { if (!child) continue; try { return findRoot(child); } catch {} }
  throw new Error('actual PortalRoot entry not found');
}
async function actualRoot(search: string, selectedStorage: PortalSelectionStorage) {
  vi.stubGlobal('location', { search }); vi.stubGlobal('sessionStorage', selectedStorage); vi.stubGlobal('document', { getElementById: () => ({}) });
  await import('../../apps/portal-web/src/main');
  return findRoot(hooks.render.mock.calls[0][0]);
}
function resetSelection() { hooks.initialized = false; hooks.slug = undefined; hooks.selection.current = undefined; }
function effects() { for (const effect of hooks.effects.splice(0)) effect(); }
beforeEach(() => { vi.resetModules(); resetSelection(); hooks.effects.length = 0; hooks.query = { data: undefined, isFetching: false }; hooks.clear.mockReset(); hooks.render.mockReset(); hooks.setSlug.mockReset(); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('resolved public portal tenant selection', () => {
  it('retains a URL tenant only after resolution and restores it on a query-free reload', () => {
    const selectedStorage = storage();
    expect(initialPortalTenantSlug('?tenant=tenant-a', selectedStorage)).toBe(A.slug);
    expect(selectedStorage.setItem).not.toHaveBeenCalled();
    expect(rememberResolvedPortalTenant(A.slug, A, selectedStorage)).toBe(true);
    expect(initialPortalTenantSlug('', selectedStorage)).toBe(A.slug);
    expect([...selectedStorage.values]).toEqual([[portalTenantStorageKey, A.slug]]);
  });
  it('gives an explicit valid URL selection priority over a validated stored hint', () => {
    const selectedStorage = storage(); selectedStorage.values.set(portalTenantStorageKey, B.slug);
    expect(initialPortalTenantSlug('?tenant=tenant-a', selectedStorage)).toBe(A.slug);
    expect(selectedStorage.getItem).not.toHaveBeenCalled();
  });
  it.each(['', '-tenant', 'Tenant', 'tenant_name', 'a'.repeat(81), 'tenant/a', ' tenant'])('rejects invalid URL and stored slugs %j consistently', invalid => {
    const selectedStorage = storage(); selectedStorage.values.set(portalTenantStorageKey, invalid);
    expect(validPortalTenantSlug(invalid)).toBe(false);
    expect(initialPortalTenantSlug(`?tenant=${encodeURIComponent(invalid)}`, selectedStorage)).toBeUndefined();
    expect(initialPortalTenantSlug('', selectedStorage)).toBeUndefined();
    expect(rememberResolvedPortalTenant(invalid, { ...A, slug: invalid }, selectedStorage)).toBe(false);
    expect(selectedStorage.setItem).not.toHaveBeenCalled();
  });
  it('accepts a leading lowercase letter or digit and at most 80 characters', () => {
    for (const slug of ['a', '0', 'a-b', '9' + '-'.repeat(79)]) expect(validPortalTenantSlug(slug)).toBe(true);
  });
  it.each([undefined, null, {}, { ...A, slug: B.slug }, { ...A, clusterId: 'not-a-uuid' }, { ...A, workspaceId: '00000000-0000-0000-0000-000000000000' }])('never persists or derives a scope from an unresolved/mismatched result', resolved => {
    const selectedStorage = storage();
    expect(matchedPortalTenant(A.slug, resolved)).toBeUndefined();
    expect(rememberResolvedPortalTenant(A.slug, resolved, selectedStorage)).toBe(false);
    expect(selectedStorage.setItem).not.toHaveBeenCalled();
  });
  it('rejects a late A result after the current selection becomes B', () => {
    const selectedStorage = storage();
    expect(matchedPortalTenant(B.slug, A)).toBeUndefined();
    expect(rememberResolvedPortalTenant(B.slug, A, selectedStorage)).toBe(false);
    expect(rememberResolvedPortalTenant(B.slug, B, selectedStorage)).toBe(true);
    expect([...selectedStorage.values]).toEqual([[portalTenantStorageKey, B.slug]]);
  });
  it('clears tenant and recovery hints while retaining unrelated storage', () => {
    const selectedStorage = storage(); selectedStorage.values.set(portalTenantStorageKey, A.slug); selectedStorage.values.set(recoveryKey, 'synthetic-recovery'); selectedStorage.values.set('unrelated', 'keep');
    clearPortalSelectionStorage(selectedStorage);
    expect([...selectedStorage.values]).toEqual([['unrelated', 'keep']]);
  });
  it('tolerates storage operation failures and still attempts both switch removals', () => {
    const unavailable = { getItem: vi.fn(() => { throw new Error('unavailable'); }), setItem: vi.fn(() => { throw new Error('unavailable'); }), removeItem: vi.fn(() => { throw new Error('unavailable'); }) };
    expect(initialPortalTenantSlug('', unavailable)).toBeUndefined();
    expect(initialPortalTenantSlug('?tenant=tenant-a', unavailable)).toBe(A.slug);
    expect(rememberResolvedPortalTenant(A.slug, A, unavailable)).toBe(false);
    expect(() => clearPortalSelectionStorage(unavailable)).not.toThrow();
    expect(unavailable.removeItem.mock.calls).toEqual([[portalTenantStorageKey], [recoveryKey]]);
  });
  it('tolerates a SecurityError from the browser sessionStorage getter', () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'sessionStorage');
    Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, get: () => { throw new DOMException('unavailable', 'SecurityError'); } });
    try {
      expect(initialPortalTenantSlug('?tenant=tenant-a')).toBe(A.slug);
      expect(initialPortalTenantSlug('')).toBeUndefined();
      expect(rememberResolvedPortalTenant(A.slug, A)).toBe(false);
      expect(() => clearPortalSelectionStorage()).not.toThrow();
    } finally { if (previous) Object.defineProperty(globalThis, 'sessionStorage', previous); else delete (globalThis as any).sessionStorage; }
  });
});

describe('actual PortalRoot wiring with controlled React hooks', () => {
  it('uses the same matched resolved tenant for provider scope and success-only persistence across reload', async () => {
    const selectedStorage = storage(); hooks.query = { data: A, isFetching: false };
    const root = await actualRoot('?tenant=tenant-a', selectedStorage), first = root();
    expect(first.type.name).toBe('PortalProvider'); expect(first.props.tenant).toBe(A); expect(first.key).toBe(`${A.clusterId}:${A.workspaceId}`);
    expect(selectedStorage.setItem).not.toHaveBeenCalled(); effects();
    expect(selectedStorage.values.get(portalTenantStorageKey)).toBe(A.slug);
    resetSelection(); vi.stubGlobal('location', { search: '' });
    const reloaded = root(); expect(reloaded.props.tenant).toBe(A); expect(hooks.slug).toBe(A.slug);
  });
  it.each([undefined, { ...A, slug: B.slug }, { ...A, clusterId: 'invalid' }])('does not render a provider or remember a failed/mismatched public resolution', async resolved => {
    const selectedStorage = storage(); hooks.query = { data: resolved, isFetching: false };
    const root = await actualRoot('?tenant=tenant-a', selectedStorage), result = root(); effects();
    expect(result.type).toBe('div'); expect(selectedStorage.setItem).not.toHaveBeenCalled();
  });
  it('clears prior scope/cache/recovery before selecting B and fences previously scheduled A persistence and rendering', async () => {
    const selectedStorage = storage(); selectedStorage.values.set(portalTenantStorageKey, A.slug); selectedStorage.values.set(recoveryKey, 'synthetic-recovery');
    hooks.query = { data: A, isFetching: false };
    const root = await actualRoot('?tenant=tenant-a', selectedStorage), initial = root();
    const api = await import('../../apps/portal-web/src/api/portal-client'); api.setPortalScope(A); api.setPortalIdentity({ ...A, id: 'b62bce3c-41a1-4a98-80c1-06d98fd85d3c' });
    initial.props.children.props.changeTenant();
    expect(api.getPortalScope()).toBeUndefined(); expect(api.getPortalIdentity()).toBeUndefined(); expect(hooks.clear).toHaveBeenCalledOnce(); expect(selectedStorage.values.size).toBe(0);
    const picker = root(); expect(picker.type.name).toBe('TenantPicker'); picker.props.onSelect(B.slug);
    expect(hooks.slug).toBe(B.slug); expect(selectedStorage.setItem).not.toHaveBeenCalled();
    const lateA = root(); effects(); expect(lateA.type).toBe('div'); expect(selectedStorage.values.size).toBe(0);
    hooks.query = { data: B, isFetching: false }; const currentB = root(); effects();
    expect(currentB.props.tenant).toBe(B); expect(currentB.key).toBe(`${B.clusterId}:${B.workspaceId}`); expect([...selectedStorage.values]).toEqual([[portalTenantStorageKey, B.slug]]);
  });
  it('updates the in-memory selection even when storage read/write/removal all fail', async () => {
    const unavailable = { getItem: vi.fn(() => { throw new Error('unavailable'); }), setItem: vi.fn(() => { throw new Error('unavailable'); }), removeItem: vi.fn(() => { throw new Error('unavailable'); }) };
    hooks.query = { data: A, isFetching: false }; const root = await actualRoot('?tenant=tenant-a', unavailable), provider = root();
    expect(() => effects()).not.toThrow(); expect(provider.props.tenant).toBe(A);
    expect(() => provider.props.children.props.changeTenant()).not.toThrow(); expect(hooks.slug).toBeUndefined();
    const picker = root(); expect(() => picker.props.onSelect(B.slug)).not.toThrow(); expect(hooks.slug).toBe(B.slug);
  });
  it('keeps the existing browser test navigating to query-free application URLs', () => {
    const browserSource = readFileSync('tests/e2e/m6.spec.ts', 'utf8');
    expect(browserSource).toContain('page.goto(`/applications/${fixture.applicationId}`)');
    expect(browserSource).not.toContain('page.goto(`/applications/${fixture.applicationId}?tenant=');
  });
});
