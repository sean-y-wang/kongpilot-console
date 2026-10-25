import { vi } from 'vitest';
import { WorkspaceResolverService, WorkspaceRow } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';

export const DEFAULT_WORKSPACE_ID = 'f9054597-284d-4ed5-b13e-619bf4f7dc93';
export const PAY_WORKSPACE_ID = 'a11904df-c0d3-450d-bcea-4b6f21e6a0c6';
export const OPS_WORKSPACE_ID = 'c5ee2c60-48c4-4222-b53b-617e030f1854';

/** Real resolver policy with a small metadata repository: tests exercise its
 * native membership/tag rules rather than reimplementing those assertions. */
export function workspaceTestResolver(clusterId: string) {
  const rows: WorkspaceRow[] = [
    [DEFAULT_WORKSPACE_ID, 'default'], [PAY_WORKSPACE_ID, 'pay'], [OPS_WORKSPACE_ID, 'ops'],
  ].map(([id, code]) => ({ id, code, cluster_id: clusterId, name: code, description: '', owner_user_id: null,
    status: 'active', is_default: code === 'default', revision: 1, deleted_at: null, retention_until: null, created_at: '', updated_at: '' }));
  const db = {
    exec: vi.fn().mockResolvedValue(1),
    one: vi.fn().mockImplementation(async (sql: string, params: any[]) => {
      if (params[0] !== clusterId) return null;
      if (sql.includes("code='default'")) return rows[0];
      return rows.find(row => sql.includes('code=$2') ? row.code === params[1] : row.id === params[1]) || null;
    }),
  };
  return { resolver: new WorkspaceResolverService(db as any), db, rows };
}
