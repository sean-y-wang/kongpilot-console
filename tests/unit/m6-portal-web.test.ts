import { RevealLease } from '../../apps/portal-web/src/components/reveal-lease';
import { describe, expect, it } from 'vitest';
import { expandSchema, localPointer, safeMarkdownUrl, sanitizeOpenApi } from '../../apps/portal-web/src/components/document-safety';
import { safePortalRecoveries, portalReceiptComplete, portalPath } from '../../apps/portal-web/src/api/portal-client';
import { canInScope, permissionEntityTypes } from '../../apps/console-web/src/api/permissions';
import type { Capabilities } from '../../apps/console-web/src/api/types';
import { portalWorkflowReceiptPath, workflowReceiptProvesCompletion, consolePortalReceiptProvesCompletion } from '../../apps/console-web/src/api/workflow-recovery';
const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22', id = 'bc7bd065-9372-405d-9782-015d31a30aa1';
const scope = { clusterId: cid, workspaceId: wid }, reference = { ...scope, actorId: actor, idempotencyKey: key, createdAt: new Date().toISOString(), state: 'uncertain' };
const workflowEntityTypes = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'targets', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
describe('M6 safe document reading', () => {
  it.each(['javascript:alert(1)', 'data:text/html,test', 'http://example.com', '//example.com', '/api/v1/portal/auth/logout', '/pages/../api', 'https://user:pass@example.com', 'https://example.com/\nkey'])('rejects unsafe Markdown link %s', value => expect(safeMarkdownUrl(value)).toBeUndefined());
  it('permits controlled navigation and HTTPS text links, while images cannot beacon to remote services', () => { expect(safeMarkdownUrl('/pages/getting-started')).toBe('/pages/getting-started'); expect(safeMarkdownUrl('https://example.com/docs')).toBe('https://example.com/docs'); expect(safeMarkdownUrl('/assets/logo.png', true)).toBe('/assets/logo.png'); expect(safeMarkdownUrl('https://example.com/track.png', true)).toBeUndefined(); expect(safeMarkdownUrl('/assets/../image.png', true)).toBeUndefined(); });
  it('refuses external references and prototype keys instead of fetching or resolving them', () => { expect(() => sanitizeOpenApi({ openapi: '3.0.3', components: { schemas: { External: { $ref: 'https://example.com/secret' } } } })).toThrow(); expect(() => sanitizeOpenApi(JSON.parse('{"openapi":"3.0.3","__proto__":{"admin":true}}'))).toThrow(); expect(() => localPointer({}, '#/constructor')).toThrow(); });
  it('redacts both named secret schemas and sensitive parameter examples without masking ordinary boolean configuration', () => { const doc = sanitizeOpenApi({ openapi: '3.0.3', paths: { '/pay': { get: { parameters: [{ name: 'api_key', example: 'private-example' }] } } }, components: { schemas: { Input: { properties: { client_secret: { type: 'string', default: 'private-default' }, credentials: { type: 'boolean', default: false } } } } } }); expect(JSON.stringify(doc)).not.toContain('private-example'); expect(JSON.stringify(doc)).not.toContain('private-default'); expect(doc.components.schemas.Input.properties.credentials.default).toBe(false); });
  it('bounds cyclic local schema expansion and resolves escaped JSON Pointers only within the current document', () => { const doc = { openapi: '3.0.3', components: { schemas: { Node: { properties: { next: { $ref: '#/components/schemas/Node' } } }, 'a/b': { type: 'string' } } } }; const safe = sanitizeOpenApi(doc); expect(JSON.stringify(expandSchema(safe, { $ref: '#/components/schemas/Node' }))).toContain('循环引用'); expect(localPointer(safe, '#/components/schemas/a~1b')).toEqual({ type: 'string' }); expect(() => localPointer(safe, '#/components/schemas/a~3b')).toThrow(); });
  it('refuses excessive depth and oversized documents before rendering', () => { let node: any = {}; for (let i = 0; i < 35; i++) node = { nested: node }; expect(() => sanitizeOpenApi({ openapi: '3.0.3', node })).toThrow(); expect(() => sanitizeOpenApi({ openapi: '3.0.3', text: 'x'.repeat(3 * 1024 * 1024) })).toThrow(); });
});
describe('M6 private tenant and parent receipt boundaries', () => {
  it('forces explicit tenant query values inside the Portal namespace', () => { expect(portalPath('/applications?clusterId=other&workspaceId=other', scope)).toBe(`/api/v1/portal/applications?clusterId=${cid}&workspaceId=${wid}`); expect(() => portalPath('http://kong:8001/plugins', scope)).toThrow(); expect(() => portalPath('//kong/plugins', scope)).toThrow(); });
  it('stores safe original identifiers only and rejects other tenants, accounts, expired records and secret payloads', () => { const now = Date.now(); const value = [{ ...reference, body: { password: 'never-store' }, key: 'never-store' }, { ...reference, actorId: id }, { ...reference, workspaceId: id }, { ...reference, createdAt: new Date(now - 86400001).toISOString() }]; const rows = safePortalRecoveries(value, { ...scope, id: actor }, now); expect(rows).toEqual([reference]); expect(JSON.stringify(rows)).not.toContain('never-store'); });
  it('requires exact tenant and durable terminal SQL proof without treating pending approval as issued credentials', () => { const receipt = { ...scope, id, state: 'succeeded', remoteStarted: false, remoteCompleted: true }; expect(portalReceiptComplete(receipt, reference)).toBe(true); for (const patch of [{ workspaceId: id }, { remoteCompleted: false }, { state: 'uncertain' }, { idempotencyKey: id }]) expect(portalReceiptComplete({ ...receipt, ...patch }, reference)).toBe(false); });
  it('routes console publication and workflow original keys to dedicated parent endpoints', () => { const recovery = { ...scope, idempotencyKey: key, operationId: id, kind: 'portal' as const }; expect(portalWorkflowReceiptPath(recovery)).toBe(`/clusters/${cid}/portal/operations/by-key/${key}?workspaceId=${wid}`); expect(portalWorkflowReceiptPath({ ...recovery, kind: 'workflow' })).toBe(`/clusters/${cid}/workflows/receipts/by-key/${key}?workspaceId=${wid}`); expect(() => portalWorkflowReceiptPath({ ...recovery, domain: 'iam' })).toThrow(); });
  it('accepts an approved decision as complete only with a server-bound decision receipt and never infers execute completion', () => { const recovery = { ...scope, idempotencyKey: key, kind: 'workflow' as const }, receipt = { ...scope, id, workflowId: id, idempotencyKey: key, state: 'approved', action: 'approve', decisionCompleted: true, steps: [], propagation: 'not_started' }; expect(workflowReceiptProvesCompletion(receipt, recovery)).toBe(true); expect(workflowReceiptProvesCompletion({ ...receipt, action: 'execute' }, recovery)).toBe(false); expect(workflowReceiptProvesCompletion({ ...receipt, decisionCompleted: false }, recovery)).toBe(false); expect(workflowReceiptProvesCompletion({ ...receipt, workspaceId: id }, recovery)).toBe(false); });
  it('requires every native parent step acknowledged and never treats not_sent/partial/uncertain as safe to resubmit', () => { const recovery = { ...scope, idempotencyKey: key, kind: 'portal' as const }, receipt = { ...scope, id, workflowId: id, idempotencyKey: key, state: 'succeeded', action: 'execute', steps: [{ id, name: 'issue-key', state: 'succeeded', remoteStarted: true, remoteCompleted: true }], propagation: 'pending' }; expect(consolePortalReceiptProvesCompletion({ kind: 'workflow', state: 'succeeded', receipt }, recovery)).toBe(true); for (const state of ['partial', 'uncertain', 'failed']) expect(consolePortalReceiptProvesCompletion({ kind: 'workflow', state, receipt: { ...receipt, state } }, recovery)).toBe(false); expect(consolePortalReceiptProvesCompletion({ kind: 'not_sent', state: 'not_sent' }, recovery)).toBe(false); expect(consolePortalReceiptProvesCompletion({ kind: 'workflow', state: 'succeeded', receipt: { ...receipt, steps: [{ ...receipt.steps[0], remoteCompleted: false }] } }, recovery)).toBe(false); });
  it('keeps Portal limited to Services/Routes while M11 workflows accept only the supported native entity types', () => {
    expect(permissionEntityTypes('portal')).toEqual(['services', 'routes']);
    expect(permissionEntityTypes('workflows')).toEqual(workflowEntityTypes);
    expect(permissionEntityTypes('monitoring')).toEqual(['services', 'routes', 'consumers']);
    expect(permissionEntityTypes('annotations')).toEqual(workflowEntityTypes.slice(0, 8));
    expect(permissionEntityTypes('secrets')).toContain('key-auth');
    for (const type of ['vaults', 'keys', 'key-sets', 'event-hooks', 'clustering']) {
      expect(permissionEntityTypes('portal')).not.toContain(type);
      expect(permissionEntityTypes('workflows')).not.toContain(type);
    }
  });
  it.each(workflowEntityTypes)('keeps typed %s workflow authority separate from native CRUD and secret viewing', type => {
    const entityScope = { ...scope, entityType: type, entity: { id, tags: ['workspace:pay'] } };
    for (const action of ['read', 'write', 'delete', 'approve'] as const) {
      const capabilities: Capabilities = { platformAdmin: false, clusters: [cid], modules: {}, grants: [{
        cluster_id: cid, workspace_id: wid, module: 'workflows', action, scope_type: 'entity',
        scope_values: [{ entity_type: type, entity_id: id }],
      }] };
      expect(canInScope(capabilities, 'workflows', action, entityScope)).toBe(true);
      for (const nativeAction of ['read', 'write', 'delete'] as const)
        expect(canInScope(capabilities, type, nativeAction, entityScope)).toBe(false);
      expect(canInScope(capabilities, 'secrets', 'read', entityScope)).toBe(false);
      expect(canInScope(capabilities, 'portal', action, entityScope)).toBe(false);
      expect(canInScope(capabilities, 'workflows', action, { ...entityScope, clusterId: key })).toBe(false);
      expect(canInScope(capabilities, 'workflows', action, { ...entityScope, workspaceId: key })).toBe(false);
      expect(canInScope(capabilities, 'workflows', action, { ...entityScope, entity: { id: key } })).toBe(false);
      expect(canInScope(capabilities, 'workflows', action, { ...entityScope, entityType: type === 'services' ? 'routes' : 'services' })).toBe(false);
      for (const otherAction of ['read', 'write', 'delete', 'approve'] as const)
        if (otherAction !== action) expect(canInScope(capabilities, 'workflows', otherAction, entityScope)).toBe(false);
    }
  });
});


describe('M6 actual ephemeral key-view lease', () => {
  const context = { credentialId: id, credentialGeneration: 2, originalActorId: actor, currentActorId: actor, active: true, visible: true };
  const response = { credentialId: id, generation: 2, key: 'synthetic-key-for-unit-only' };
  it('uses a local bounded display lifetime, which does not claim the gateway credential expires', () => { const lease = new RevealLease(), ticket = lease.begin(), now = 100000; expect(lease.accept(ticket, response, context, now)?.expiresAt).toBe(new Date(now + 60000).toISOString()); expect(lease.accept(ticket, { ...response, expiresAt: new Date(now + 10000).toISOString() }, context, now)?.expiresAt).toBe(new Date(now + 10000).toISOString()); });
  it('rejects delayed reveal after close/visibility/unmount or superseding request without retaining key in the lease', () => { const lease = new RevealLease(), ticket = lease.begin(); lease.invalidate(); expect(lease.accept(ticket, response, context)).toBeUndefined(); const current = lease.begin(); expect(lease.accept(current, response, { ...context, visible: false })).toBeUndefined(); expect(lease.accept(current, response, { ...context, active: false })).toBeUndefined(); lease.begin(); expect(lease.accept(current, response, context)).toBeUndefined(); expect(JSON.stringify(lease)).not.toContain(response.key); });
  it('requires original actor, exact credential and generation and refuses already-expired server viewing hints', () => { const lease = new RevealLease(), ticket = lease.begin(); expect(lease.accept(ticket, response, { ...context, currentActorId: key })).toBeUndefined(); expect(lease.accept(ticket, { ...response, credentialId: key }, context)).toBeUndefined(); expect(lease.accept(ticket, { ...response, generation: 3 }, context)).toBeUndefined(); expect(lease.accept(ticket, { ...response, expiresAt: 'invalid' }, context)).toBeUndefined(); expect(lease.accept(ticket, { ...response, expiresAt: new Date(0).toISOString() }, context)).toBeUndefined(); });
});


it('only releases a known approval-required submission with explicit server SQL proof, never direct-mode submission', () => { const reference = { clusterId: cid, workspaceId: wid, idempotencyKey: key, kind: 'workflow' as const }; const receipt = { clusterId: cid, workspaceId: wid, id, workflowId: id, idempotencyKey: key, state: 'pending', action: 'submit', approvalRequired: true, submissionCompleted: true, steps: [], propagation: 'not_started' }; expect(workflowReceiptProvesCompletion(receipt, reference)).toBe(true); for (const patch of [{ approvalRequired: false }, { submissionCompleted: false }, { action: 'execute' }, { workspaceId: id }]) expect(workflowReceiptProvesCompletion({ ...receipt, ...patch }, reference)).toBe(false); });


it('does not unlock an approve-and-execute or prior submission when later native execution is uncertain, partial or running', () => { const reference = { clusterId: cid, workspaceId: wid, idempotencyKey: key, kind: 'workflow' as const }; const base = { clusterId: cid, workspaceId: wid, id, workflowId: id, idempotencyKey: key, decisionCompleted: true, submissionCompleted: true, approvalRequired: true, steps: [], propagation: 'pending' }; for (const state of ['uncertain', 'partial', 'executing', 'running', 'failed']) for (const action of ['approve', 'submit']) expect(workflowReceiptProvesCompletion({ ...base, action, state }, reference)).toBe(false); });

it('only accepts an original-key cancellation with durable decision proof and a terminal cancelled state', () => { const reference = { clusterId: cid, workspaceId: wid, idempotencyKey: key, kind: 'workflow' as const }; const receipt = { clusterId: cid, workspaceId: wid, id, workflowId: id, idempotencyKey: key, state: 'cancelled', action: 'cancel', decisionCompleted: true, steps: [], propagation: 'not_started' }; expect(workflowReceiptProvesCompletion(receipt, reference)).toBe(true); for (const patch of [{ decisionCompleted: false }, { state: 'pending' }, { state: 'uncertain' }, { state: 'partial' }, { action: 'execute' }, { workspaceId: id }, { idempotencyKey: id }]) expect(workflowReceiptProvesCompletion({ ...receipt, ...patch }, reference)).toBe(false); });
