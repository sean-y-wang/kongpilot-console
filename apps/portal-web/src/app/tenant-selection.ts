import { portalRecoveryStorageKey, validId } from '../api/portal-client';
import type { Tenant } from '../api/types';

export const portalTenantStorageKey = 'kongos.portal.tenant';
export type PortalSelectionStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function availableStorage(): PortalSelectionStorage | undefined {
  try { return typeof sessionStorage === 'undefined' ? undefined : sessionStorage; }
  catch { return undefined; }
}

export function validPortalTenantSlug(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,79}$/.test(value);
}

export function initialPortalTenantSlug(search: string, storage = availableStorage()): string | undefined {
  const supplied = new URLSearchParams(search).get('tenant');
  if (supplied !== null) return validPortalTenantSlug(supplied) ? supplied : undefined;
  try {
    const stored = storage?.getItem(portalTenantStorageKey);
    return validPortalTenantSlug(stored) ? stored : undefined;
  } catch { return undefined; }
}

export function matchedPortalTenant(slug: string | undefined, resolved: unknown): Tenant | undefined {
  if (!validPortalTenantSlug(slug) || !resolved || typeof resolved !== 'object' || Array.isArray(resolved)) return undefined;
  const tenant = resolved as Partial<Tenant>;
  return tenant.slug === slug && validId(tenant.clusterId) && validId(tenant.workspaceId) ? tenant as Tenant : undefined;
}

export function rememberResolvedPortalTenant(slug: string | undefined, resolved: unknown, storage = availableStorage()): boolean {
  const tenant = matchedPortalTenant(slug, resolved);
  if (!tenant || !storage) return false;
  try { storage.setItem(portalTenantStorageKey, tenant.slug); return true; }
  catch { return false; }
}

export function clearPortalSelectionStorage(storage = availableStorage()): void {
  for (const key of [portalTenantStorageKey, portalRecoveryStorageKey]) {
    try { storage?.removeItem(key); } catch {}
  }
}
