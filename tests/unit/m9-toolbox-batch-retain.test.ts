import { describe, expect, it } from 'vitest';
import { diffTransferGraphs } from '../../apps/console-api/src/modules/config-transfer';
import { toolboxBatchTarget, validateBatchSelection } from '../../apps/console-api/src/modules/toolbox/batch-plan';
import { graph } from './m8-config-transfer.fixture';

describe('toolbox batch delete retains unselected inherited children unchanged', () => {
  it('does not stamp workspace tags onto an untagged retained credential/target', () => {
    const g: any = graph();
    for (const o of g.objects) if (o.entityType === 'credentials' || o.entityType === 'targets') o.payload.tags = null;
    const root = g.objects.find((o: any) => o.entityType === 'services');
    const codes = Object.fromEntries([g.scope.workspaceId].map((w: string) => [w, 'test']));
    const target = toolboxBatchTarget(g, validateBatchSelection({ action: 'delete', roots: [{ type: 'services', id: root.nativeId }] }), codes);
    const diff = diffTransferGraphs(g, target, { mode: 'sync', syncConfirmed: true });
    expect(diff.changes.filter(c => c.action !== 'delete').map(c => c.objectKey)).toEqual([]);
    expect(diff.changes.some(c => c.action === 'delete' && c.nativeId === root.nativeId)).toBe(true);
  });
});
