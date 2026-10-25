import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { compileGovernanceFix } from '../../apps/console-api/src/modules/governance/governance-fix-compiler';
import { inspectGovernanceInventory } from '../../apps/console-api/src/modules/governance/inspection-engine';
import { parseDeckDocument } from '../../apps/console-api/src/modules/config-transfer/deck-parser';
import { normalizeDeckDocument } from '../../apps/console-api/src/modules/config-transfer/deck-normalizer';
import type { CaptureGraph, CapturedSchemaBundle, ConfigurationScope } from '../../apps/console-api/src/modules/configuration/configuration.types';
import type { GovernanceLintContext, LintFinding } from '../../apps/console-api/src/modules/governance/lint-types';
import { lintFixture, lintObject } from './m10-lint-fixture';

async function finding(context: GovernanceLintContext, match: string, options: any = {}): Promise<LintFinding> {
  const result = await inspectGovernanceInventory(context, options); const selected = result.findings.find(item => item.code === match || item.ruleCode === match);
  if (!selected) throw new Error('Synthetic test finding missing'); return selected;
}
function normalizeFixWithRealM8(context: GovernanceLintContext, yaml: string) {
  const scope: ConfigurationScope = { ...context.scope!, kind: 'workspace', rootIds: [], transportScope: 'synthetic-pure-normalizer-scope' };
  const schemas: CapturedSchemaBundle = { entities: context.schemas!, plugins: context.pluginSchemas!, enabledPlugins: context.enabledPlugins!, kongVersion: '1.5.1', adapterVersion: 'kong-1.5', schemaHmac: 'synthetic-schema' };
  // Public pure graph fixture only. No runtime capability, Native ticket or authorization proof.
  const references = { objects: context.objects.map(object => ({ objectKey: `${object.entityType}:${object.nativeId}`, nativeId: object.nativeId,
    entityType: object.entityType, objectWorkspaceId: scope.workspaceId, payload: object.payload })) } as CaptureGraph;
  return normalizeDeckDocument(parseDeckDocument(yaml), schemas, { scope, workspaceCode: 'default', references });
}
describe('M10 fixed one-issue compiler (no native calls or authorizing proofs)', () => {
  it('adds only explicit owner tag, preserves workspace/business tags and omits every private/timestamp field', async () => {
    const object = { ...lintObject('certificates', { tags: ['workspace:payments', 'team:pay'], cert: 'safe-cert-marker', key: '[REDACTED:private-key]', created_at: 123 }), annotations: { state: 'absent' as const } };
    const context = lintFixture([object]), issue = await finding(context, 'OWNER_MISSING');
    const fix = compileGovernanceFix(context, issue, { action: 'owner_tag_add', values: { ownerTag: 'owner:payments' } });
    expect(parse(fix.yaml!)).toEqual({ _format_version: '1.1', certificates: [{ id: object.nativeId, tags: ['owner:payments', 'team:pay', 'workspace:payments'] }] });
    expect(fix.selectedObjects).toEqual([{ entityType: 'certificates', nativeId: object.nativeId }]); expect(fix.yaml).not.toMatch(/REDACTED|created_at|safe-cert-marker/);
  });
  it('handles native null tags as an empty tag set', async () => {
    const object = { ...lintObject('consumers', { tags: null }), annotations: { state: 'absent' as const } }, context = lintFixture([object]);
    const fix = compileGovernanceFix(context, await finding(context, 'OWNER_MISSING'), { action: 'owner_tag_add', values: { ownerTag: 'owner:ops' } });
    expect((fix.document!.consumers as any)[0].tags).toEqual(['owner:ops']);
  });
  it('compiles a positive field fix from an authorized incomplete projection without inventing negative coverage', async () => {
    const object = { ...lintObject('services', { tags: ['team:pay'] }), annotations: { state: 'absent' as const } }, context = { ...lintFixture([object]), completeness: 'incomplete' as const, projection: true };
    const fix = compileGovernanceFix(context, await finding(context, 'OWNER_MISSING'), { action: 'owner_tag_add', values: { ownerTag: 'owner:pay' } });
    expect(fix.kind).toBe('configuration'); expect(fix.blockerCodes).toEqual([]);
  });
  it.each(['pay', 'owner:', 'owner:with space', 'owner:../../secret', 'workspace:ops'])('requires a valid explicit owner selection %s', async ownerTag => {
    const object = { ...lintObject('services'), annotations: { state: 'absent' as const } }, context = lintFixture([object]);
    const issue = await finding(context, 'OWNER_MISSING'); expect(() => compileGovernanceFix(context, issue, { action: 'owner_tag_add', values: { ownerTag } })).toThrow('GOVERNANCE_FIX_OWNER_REQUIRED');
  });
  it('adds plugin identity without copying redacted secret config', async () => {
    const object = { ...lintObject('plugins', { name: 'rate-limiting', config: { redis_password: '[REDACTED]' } }), annotations: { state: 'absent' as const } }, context = lintFixture([object]);
    const fix = compileGovernanceFix(context, await finding(context, 'OWNER_MISSING'), { action: 'owner_tag_add', values: { ownerTag: 'owner:ops' } });
    expect((fix.document!.plugins as any)[0]).toEqual({ id: object.nativeId, name: 'rate-limiting', tags: ['owner:ops'] });
  });
  it('compiles an explicit secure protocol choice into a minimal merge document', async () => {
    const object = lintObject('routes', { protocols: ['http', 'https'], paths: ['/pay'], created_at: 123 }), context = lintFixture([object]);
    const fix = compileGovernanceFix(context, await finding(context, 'builtin.route_https'), { action: 'route_https_only', values: { protocols: ['https'] } });
    expect(fix.document).toEqual({ _format_version: '1.1', routes: [{ id: object.nativeId, protocols: ['https'] }] }); expect(fix.yaml).not.toContain('paths');
  });
  it.each([[], ['http'], ['https', 'https'], ['https', 'tls']])('rejects invalid or Kong-incompatible protocol choices %j', async protocols => {
    const object = lintObject('routes', { protocols: ['http'] }), context = lintFixture([object]), issue = await finding(context, 'builtin.route_https');
    expect(() => compileGovernanceFix(context, issue, { action: 'route_https_only', values: { protocols } })).toThrow();
  });
  it('requires all explicit timeout values and normalizes only native 1.5 field names', async () => {
    const object = lintObject('services', { connect_timeout: 0, host: 'api.test' }), context = lintFixture([object]), issue = await finding(context, 'builtin.service_timeouts');
    const fix = compileGovernanceFix(context, issue, { action: 'service_timeouts_set', values: { connectTimeout: 3000, readTimeout: 5000, writeTimeout: 5000 } });
    expect(fix.document).toEqual({ _format_version: '1.1', services: [{ id: object.nativeId, connect_timeout: 3000, write_timeout: 5000, read_timeout: 5000 }] });
    expect(() => compileGovernanceFix(context, issue, { action: 'service_timeouts_set', values: { connectTimeout: -1, readTimeout: 5000, writeTimeout: 5000 } })).toThrow('GOVERNANCE_FIX_TIMEOUTS_REQUIRED');
  });
  it('requires a deliberate new name and checks visible uniqueness', async () => {
    const a = lintObject('services', { name: 'dup' }), b = lintObject('services', { name: 'dup' }), c = lintObject('services', { name: 'existing' }), context = lintFixture([a, b, c]);
    const issue = await finding(context, 'UNIQUE_FIELD_CONFLICT'), fix = compileGovernanceFix(context, issue, { action: 'entity_rename', values: { name: 'payments-api' } });
    expect((fix.document!.services as any)[0].name).toBe('payments-api');
    expect(() => compileGovernanceFix(context, issue, { action: 'entity_rename', values: { name: 'existing' } })).toThrow('GOVERNANCE_FIX_NAME_CONFLICT');
  });
  it('renames consumer username/custom_id according to the actual unique field, never inventing name', async () => {
    const a = lintObject('consumers', { username: 'dup' }), b = lintObject('consumers', { username: 'dup' }), context = lintFixture([a, b]);
    const fix = compileGovernanceFix(context, await finding(context, 'UNIQUE_FIELD_CONFLICT'), { action: 'entity_rename', values: { name: 'payments-client' } });
    expect((fix.document!.consumers as any)[0]).toEqual({ id: b.nativeId, username: 'payments-client' });
  });
  it('replaces only the selected broken reference with a currently known authorized object', async () => {
    const missing = randomUUID(), certificate = lintObject('certificates'), service = lintObject('services', { client_certificate: { id: missing } }), context = lintFixture([service, certificate]);
    const issue = await finding(context, 'SERVICE_INVALID_CLIENT_CERTIFICATE');
    const fix = compileGovernanceFix(context, issue, { action: 'reference_replace_or_clear', values: { operation: 'replace', replacementId: certificate.nativeId } });
    expect(fix.document).toEqual({ _format_version: '1.1', services: [{ id: service.nativeId, client_certificate: { id: certificate.nativeId } }] });
    expect(() => compileGovernanceFix(context, issue, { action: 'reference_replace_or_clear', values: { operation: 'replace', replacementId: randomUUID() } })).toThrow('GOVERNANCE_FIX_REFERENCE_REQUIRED');
  });
  it('can explicitly clear an optional reference while refusing required SNI certificate null', async () => {
    const service = lintObject('services', { client_certificate: { id: randomUUID() } }), sni = lintObject('snis', { name: 'api.test', certificate: { id: randomUUID() } }), context = lintFixture([service, sni]);
    const clear = compileGovernanceFix(context, await finding(context, 'SERVICE_INVALID_CLIENT_CERTIFICATE'), { action: 'reference_replace_or_clear', values: { operation: 'clear' } });
    expect((clear.document!.services as any)[0].client_certificate).toBeNull();
    const sniIssue = await finding(context, 'SNI_INVALID_CERTIFICATE'); expect(() => compileGovernanceFix(context, sniIssue, { action: 'reference_replace_or_clear', values: { operation: 'clear' } })).toThrow('GOVERNANCE_FIX_SCHEMA_INVALID');
  });
  it('nests SNI owner and rename fixes under an existing certificate and passes the real M8 normalizer', async () => {
    const certificate = lintObject('certificates', { key: '[REDACTED:private-key]' });
    const a = { ...lintObject('snis', { name: 'api.test', certificate: { id: certificate.nativeId } }), annotations: { state: 'absent' as const } };
    const b = lintObject('snis', { name: 'api.test', certificate: { id: certificate.nativeId } }), context = lintFixture([certificate, a, b]);
    const owner = compileGovernanceFix(context, await finding(context, 'OWNER_MISSING'), { action: 'owner_tag_add', values: { ownerTag: 'owner:ops' } });
    expect(owner.document).toEqual({ _format_version: '1.1', certificates: [{ id: certificate.nativeId, snis: [{ id: a.nativeId, tags: ['owner:ops'] }] }] });
    expect(normalizeFixWithRealM8(context, owner.yaml!).objects.map(object => object.entityType)).toEqual(['certificates', 'snis']);
    const rename = compileGovernanceFix(context, await finding(context, 'UNIQUE_FIELD_CONFLICT'), { action: 'entity_rename', values: { name: 'new.api.test' } });
    const normalized = normalizeFixWithRealM8(context, rename.yaml!); expect(normalized.objects.find(object => object.entityType === 'snis')?.payload.name).toBe('new.api.test');
    expect(rename.yaml).not.toContain('REDACTED');
  });
  it('nests an explicit SNI certificate replacement under that actual new certificate and passes M8 parsing', async () => {
    const certificate = lintObject('certificates'), sni = lintObject('snis', { name: 'api.test', certificate: { id: randomUUID() } }), context = lintFixture([certificate, sni]);
    const replacement = compileGovernanceFix(context, await finding(context, 'SNI_INVALID_CERTIFICATE'), { action: 'reference_replace_or_clear', values: { operation: 'replace', replacementId: certificate.nativeId } });
    const normalized = normalizeFixWithRealM8(context, replacement.yaml!); expect(normalized.objects.find(object => object.entityType === 'snis')?.payload.certificate).toEqual({ id: certificate.nativeId });
  });
  it('does not expose clear/replace repair for uncertain workspace references', async () => {
    const service = lintObject('services', { client_certificate: { id: randomUUID() } }), base = lintFixture([service]);
    const context = { ...base, collections: base.collections.map(collection => ({ ...collection, extent: 'workspace' as const })) };
    const issue = await finding(context, 'SERVICE_INVALID_CLIENT_CERTIFICATE'); expect(issue.status).toBe('not_evaluated');
    expect(() => compileGovernanceFix(context, issue, { action: 'reference_replace_or_clear', values: { operation: 'clear' } })).toThrow('GOVERNANCE_FIX_CURRENT_ISSUE_REQUIRED');
  });
  it('never writes description to Kong; it emits a fixed annotation intent', async () => {
    const object = { ...lintObject('services'), annotations: { state: 'absent' as const } }, context = lintFixture([object]);
    const fix = compileGovernanceFix(context, await finding(context, 'DESCRIPTION_MISSING'), { action: 'annotation_description_set', values: { description: '支付生产服务' } });
    expect(fix).toMatchObject({ kind: 'annotation', annotation: { entityType: 'services', nativeId: object.nativeId, description: '支付生产服务' } }); expect(fix.yaml).toBeUndefined(); expect(fix.document).toBeUndefined();
  });
  it('emits explicit certificate archive intent rather than a destructive sync of omitted objects', async () => {
    const certificate = lintObject('certificates'), context = lintFixture([certificate]);
    const fix = compileGovernanceFix(context, await finding(context, 'CERTIFICATE_UNUSED'), { action: 'unused_certificate_archive', values: {} });
    expect(fix).toMatchObject({ kind: 'archive', archive: { entityType: 'certificates', nativeId: certificate.nativeId } }); expect(fix.yaml).toBeUndefined();
  });
  it('requires real global plugin capability/current schema for explicitly chosen baseline config', async () => {
    const context = lintFixture(), issue = await finding(context, 'SECURITY_BASELINE_MISSING', { securityBaselinePlugins: ['rate-limiting'] });
    const fix = compileGovernanceFix(context, issue, { action: 'baseline_plugin_configure', values: { pluginName: 'rate-limiting', config: { minute: 100 }, ownerTag: 'owner:ops' } });
    const payload = (fix.document!.plugins as any)[0]; expect(payload.name).toBe('rate-limiting'); expect(payload.config.minute).toBe(100); expect(payload.enabled).toBe(true);
    expect(payload.service).toBeUndefined(); expect(payload.id).toBeUndefined(); expect(fix.selectedObjects).toEqual([]);
    expect(() => compileGovernanceFix(context, issue, { action: 'baseline_plugin_configure', values: { pluginName: 'enterprise-security', config: {} } })).toThrow('GOVERNANCE_FIX_BASELINE_SCOPE_REQUIRED');
  });
  it('enables the existing disabled global baseline instance instead of creating a duplicate', async () => {
    const plugin = lintObject('plugins', { name: 'rate-limiting', enabled: false, config: { minute: 50, policy: 'redis', redis_host: 'private-existing-cache', redis_password: '[REDACTED]' } }), context = lintFixture([plugin]);
    const issue = await finding(context, 'SECURITY_BASELINE_MISSING', { securityBaselinePlugins: ['rate-limiting'] });
    const fix = compileGovernanceFix(context, issue, { action: 'baseline_plugin_configure', values: { pluginName: 'rate-limiting', config: { minute: 100 } } });
    expect((fix.document!.plugins as any)[0]).toMatchObject({ id: plugin.nativeId, enabled: true }); expect(fix.selectedObjects).toEqual([{ entityType: 'plugins', nativeId: plugin.nativeId }]);
    expect((fix.document!.plugins as any)[0].config).toEqual({ minute: 100 }); expect(fix.yaml).not.toContain('policy'); expect(fix.yaml).not.toContain('private-existing-cache');
  });
  it('does not generate secret placeholders, accept unknown fields or instantiate native operations', async () => {
    const object = lintObject('routes', { protocols: ['http'] }), context = lintFixture([object]), issue = await finding(context, 'builtin.route_https');
    expect(() => compileGovernanceFix(context, issue, { action: 'route_https_only', values: { protocols: ['https'], approved: true } })).toThrow('GOVERNANCE_FIX_INVALID_INPUT');
    expect(() => compileGovernanceFix(context, issue, { action: 'owner_tag_add', values: { ownerTag: '[REDACTED]' } })).toThrow('GOVERNANCE_FIX_SECRET_MARKER');
    expect(() => compileGovernanceFix(context, issue, { action: 'native_request', values: { path: '/routes', method: 'DELETE' } })).toThrow('GOVERNANCE_FIX_UNSUPPORTED_ACTION');
  });
  it('rejects stale issues after protocol/owner/reference/description changed', async () => {
    const route = lintObject('routes', { protocols: ['http'] }), context = lintFixture([route]), issue = await finding(context, 'builtin.route_https');
    const current = { ...context, objects: [{ ...route, payload: { ...route.payload, protocols: ['https'] } }] };
    expect(() => compileGovernanceFix(current, issue, { action: 'route_https_only', values: { protocols: ['https'] } })).toThrow('GOVERNANCE_FIX_ISSUE_RESOLVED');
    expect(() => compileGovernanceFix({ ...context, objects: [] }, issue, { action: 'route_https_only', values: { protocols: ['https'] } })).toThrow('GOVERNANCE_FIX_OBJECT_UNAVAILABLE');
  });
});
