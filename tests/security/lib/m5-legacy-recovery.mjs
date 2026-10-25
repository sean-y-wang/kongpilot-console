import { readFileSync } from 'node:fs';
import { entity, rows, scope } from './m5-harness.mjs';

/** Explicit Root-authorized recovery of two historical test receipts. Reads
 * and writes use only BFF; native reconciliation itself performs GET only. */
export async function recoverKnownLegacyReceipts(h, admin, cluster) {
  const preflight = JSON.parse(readFileSync('artifacts/M5/legacy-mutation-entry-preflight.json', 'utf8'));
  const operations = preflight.operations.filter(row => row.operation.cluster_id === cluster.id);
  h.check(operations.length === 2 && operations.every(row => row.entries.length === 1), 'Legacy/Preflight', 'exact two preflight unknown operations have a unique preserved archive');
  const workspaces = rows(h.ok(await h.request(admin, `/clusters/${cluster.id}/workspaces?size=100`), 'Legacy/Scope', 'BFF current canonical workspace discovery'));
  const defaultWorkspace = workspaces.find(row => row.is_default === true && row.code === 'default');
  h.check(Boolean(defaultWorkspace), 'Legacy/Scope', 'historical untagged receipts bind to the actual canonical default UUID');
  const results = [];
  const rememberKnown = value => {
    if (!value || typeof value !== 'object') return;
    for (const [name, item] of Object.entries(value)) {
      if (/^(key|password|secret|client_secret|access_token|refresh_token)$/i.test(name) && typeof item === 'string' && item.length >= 8 && !item.includes('[REDACTED]')) h.remember(item);
      else if (item && typeof item === 'object') rememberKnown(item);
    }
  };
  for (const row of operations) {
    const archived = row.entries[0], workspace = { id: archived.workspace_id ?? row.operation.workspace_id ?? defaultWorkspace.id };
    const preview = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/recycle-bin/${archived.id}`, workspace)), 'Legacy/Archive', 'authorized redacted archived graph preview');
    h.check(preview.entry.id === archived.id && preview.entry.original_id === row.operation.entity_id, 'Legacy/Archive', 'preview matches the selected original archive and identity');
    let receipt = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/mutations/${row.operation.id}`, workspace)), 'Legacy/Receipt', 'current original durable receipt lookup');
    if (receipt.state === 'uncertain') {
      receipt = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/mutations/${row.operation.id}/reconcile`, workspace), 'POST', { confirmed: true, confirm_name: preview.entry.root_name }), 'Legacy/Reconcile', 'typed platform-authorized read-only native graph reconciliation');
      h.check(['succeeded', 'failed'].includes(receipt.state) && receipt.verifiedObjects > 0 && receipt.appliedObjects >= 0 && receipt.appliedObjects <= receipt.verifiedObjects, 'Legacy/Reconcile', 'fresh complete graph proof reaches a known terminal outcome without retrying an unknown native write');
    }
    h.check(['succeeded', 'failed'].includes(receipt.state), 'Legacy/Reconcile', 'historical uncertainty must close honestly before monitoring writes');
    const currentPreview = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/recycle-bin/${archived.id}`, workspace)), 'Legacy/Archive', 'reconciled archive retains its honest current node state');
    if (row.operation.action === 'delete' && currentPreview.entry.state === 'partially_deleted') {
      const before = entity(h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/entities/certificates/${row.operation.entity_id}`, workspace, { reveal: true })), 'Legacy/Secrets', 'authorized existing certificate secret captured only in private scan reference'));
      rememberKnown(before); h.persistReference();
      const restored = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/recycle-bin/${archived.id}/restore`, workspace), 'POST', { confirmed: true, confirm_name: preview.entry.root_name }), 'Legacy/Restore', 'explicitly confirmed original archive recovery after known partial deletion');
      h.check(restored.state === 'restored', 'Legacy/Restore', 'known partial certificate archive is completely restored by its original-ID recovery workflow');
    }
    if (row.operation.entity_type === 'consumers') {
      for (const kind of ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']) {
        const credentials = h.ok(await h.request(admin, scope(`/clusters/${cluster.id}/consumers/${row.operation.entity_id}/credentials/${kind}`, workspace, { reveal: true, size: 100 })), 'Legacy/Secrets', 'authorized historical credential captured only for final secret coverage');
        rememberKnown(credentials);
      }
      h.persistReference();
    }
    results.push({ operationId: row.operation.id, entryId: archived.id, state: receipt.state, observedOutcome: receipt.observedOutcome ?? 'previously_reconciled', verifiedObjects: receipt.verifiedObjects ?? null, configurationRestoredAfterKnownPartial: row.operation.action === 'delete' && currentPreview.entry.state === 'partially_deleted', noUnknownNativeRetry: true });
  }
  return results;
}
