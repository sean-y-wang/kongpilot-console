import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { inspectGovernanceInventory } from '../../apps/console-api/src/modules/governance/inspection-engine';
import { lintContextFromInventory, type GovernanceLintContext, type LintFinding } from '../../apps/console-api/src/modules/governance/lint-types';
import { lintFixture, lintObject } from './m10-lint-fixture';

const codes = (result: { findings: readonly LintFinding[] }) => result.findings.filter(finding => finding.status === 'confirmed').map(finding => finding.code);
describe('M10 schema-aware structural inspection (synthetic damaged graphs)', () => {
  it('uses recorded 1.5 schemas to detect nonsecure Route and valid timeout defaults', async () => {
    const service = lintObject('services', { host: 'api.example.com', connect_timeout: 60_000, write_timeout: 60_000, read_timeout: 60_000 });
    const route = lintObject('routes', { protocols: ['http', 'https'], service: { id: service.nativeId }, paths: ['/pay'] });
    const result = await inspectGovernanceInventory(lintFixture([service, route]));
    expect(result.findings.some(finding => finding.ruleCode === 'builtin.route_https' && finding.fixCodes.includes('route_https_only'))).toBe(true);
    expect(result.findings.some(finding => finding.ruleCode === 'builtin.service_timeouts')).toBe(false);
    expect(result.findings.some(finding => /upstream/i.test(finding.code))).toBe(false);
  });
  it.each(['https', 'grpcs', 'tls'])('accepts secure route protocol %s', async protocol => {
    const result = await inspectGovernanceInventory(lintFixture([lintObject('routes', { protocols: [protocol] })]));
    expect(result.findings.some(finding => finding.ruleCode === 'builtin.route_https')).toBe(false);
  });
  it('does not claim it knows whether returned default timeouts were explicitly set at creation', async () => {
    const result = await inspectGovernanceInventory(lintFixture([lintObject('services', { connect_timeout: 60000, read_timeout: 60000, write_timeout: 60000 })]));
    expect(result.ruleResults.find(rule => rule.ruleCode === 'builtin.service_timeouts')).toMatchObject({ evaluatedObjects: 1, failedObjects: 0 });
  });
  it('reports malformed/missing timeout values and owner/description with fixed safe fixes', async () => {
    const object = { ...lintObject('services', { connect_timeout: 0, read_timeout: 1000 }), annotations: { state: 'absent' as const } };
    const result = await inspectGovernanceInventory(lintFixture([object]));
    expect(result.findings.find(finding => finding.ruleCode === 'builtin.service_timeouts')?.fixCodes).toEqual(['service_timeouts_set']);
    expect(codes(result)).toContain('OWNER_MISSING'); expect(codes(result)).toContain('DESCRIPTION_MISSING');
  });
  it('uses owner tags or readable annotations and never interprets inaccessible metadata as absent', async () => {
    const tagged = { ...lintObject('consumers', { tags: ['owner:pay'] }), annotations: { state: 'not_authorized' as const } };
    const inaccessible = { ...lintObject('upstreams'), annotations: { state: 'not_authorized' as const } };
    const result = await inspectGovernanceInventory(lintFixture([tagged, inaccessible]));
    expect(result.findings.filter(finding => finding.nativeId === tagged.nativeId && finding.code === 'OWNER_MISSING')).toHaveLength(0);
    const owner = result.findings.find(finding => finding.nativeId === inaccessible.nativeId && finding.code === 'OWNER_MISSING');
    expect(owner).toMatchObject({ status: 'not_evaluated', fixCodes: [] }); expect(result.complete).toBe(false);
  });
  it('does not invent missing owner after silently truncating a valid tag array', async () => {
    const object = { ...lintObject('services', { tags: [...Array.from({ length: 300 }, (_, i) => `tag-${i}`), 'owner:payments'] }), annotations: { state: 'absent' as const } };
    const result = await inspectGovernanceInventory(lintFixture([object])); expect(codes(result)).not.toContain('OWNER_MISSING');
  });
  it.each([
    ['plugins', 'service', 'PLUGIN_ORPHAN_REFERENCE'], ['plugins', 'route', 'PLUGIN_ORPHAN_REFERENCE'], ['plugins', 'consumer', 'PLUGIN_ORPHAN_REFERENCE'],
    ['routes', 'service', 'ROUTE_INVALID_SERVICE'], ['snis', 'certificate', 'SNI_INVALID_CERTIFICATE'], ['services', 'client_certificate', 'SERVICE_INVALID_CLIENT_CERTIFICATE'],
  ] as const)('confirms impossible damaged %s.%s FK only with cluster coverage', async (type, field, code) => {
    const object = lintObject(type, { [field]: { id: randomUUID() }, protocols: ['https'] }); const context = lintFixture([object]);
    expect(codes(await inspectGovernanceInventory(context))).toContain(code);
    const workspace = { ...context, scope: { ...context.scope!, kind: 'workspace' as const }, collections: context.collections.map(collection => ({ ...collection, extent: 'workspace' as const })) };
    const projected = await inspectGovernanceInventory(workspace);
    expect(projected.findings.find(finding => finding.code === code)).toMatchObject({ status: 'not_evaluated', fixCodes: [] });
  });
  it('does not treat unsupported 1.5 Service.ca_certificates as a real native field', async () => {
    const service = lintObject('services', { ca_certificates: [randomUUID()], connect_timeout: 1000, read_timeout: 1000, write_timeout: 1000 });
    const result = await inspectGovernanceInventory(lintFixture([service])); expect(codes(result)).not.toContain('SERVICE_INVALID_CA_CERTIFICATE');
  });
  it('checks optional CA references only when the probed schema actually advertises them', async () => {
    const service = lintObject('services', { ca_certificates: [randomUUID()] }), context = lintFixture([service]);
    const schemas: any = structuredClone(context.schemas); schemas.services.fields.push({ ca_certificates: { type: 'array', elements: { type: 'string', uuid: true } } });
    const result = await inspectGovernanceInventory({ ...context, schemas }); expect(codes(result)).toContain('SERVICE_INVALID_CA_CERTIFICATE');
  });
  it('excludes valid mTLS/client-cert use from orphan certificate reports', async () => {
    const certificate = lintObject('certificates'), service = lintObject('services', { client_certificate: { id: certificate.nativeId } });
    const result = await inspectGovernanceInventory(lintFixture([certificate, service])); expect(codes(result)).not.toContain('CERTIFICATE_UNUSED');
  });
  it('excludes certificate SNI use even if the authorized referencing object is closure-only', async () => {
    const certificate = lintObject('certificates'), sni = { ...lintObject('snis', { name: 'api.example.com', certificate: { id: certificate.nativeId } }), referenceOnly: true, selected: false };
    const result = await inspectGovernanceInventory(lintFixture([certificate, sni])); expect(codes(result)).not.toContain('CERTIFICATE_UNUSED');
    expect(result.findings.some(finding => finding.nativeId === sni.nativeId)).toBe(false);
  });
  it('suggests archive only for genuinely unused cert with complete global SNI and Service reference coverage', async () => {
    const certificate = lintObject('certificates'), context = lintFixture([certificate]);
    const unused = (await inspectGovernanceInventory(context)).findings.find(finding => finding.code === 'CERTIFICATE_UNUSED');
    expect(unused).toMatchObject({ status: 'confirmed', fixCodes: ['unused_certificate_archive'] });
    const incomplete = { ...context, collections: context.collections.map(collection => collection.entityType === 'services' ? { ...collection, complete: false } : collection) };
    const skipped = (await inspectGovernanceInventory(incomplete)).findings.find(finding => finding.code === 'CERTIFICATE_UNUSED');
    expect(skipped).toMatchObject({ status: 'not_evaluated', fixCodes: [] });
  });
  it('reports genuine schema-unique duplicate names without copying field values', async () => {
    const secretName = 'example-unique-business-name', a = lintObject('services', { name: secretName }), b = lintObject('services', { name: secretName });
    const result = await inspectGovernanceInventory(lintFixture([a, b])); const duplicate = result.findings.find(finding => finding.code === 'UNIQUE_FIELD_CONFLICT');
    expect(duplicate).toMatchObject({ field: 'name', severity: 'error', status: 'confirmed', relatedObjects: [{ entityType: 'services', nativeId: a.nativeId }] });
    expect(JSON.stringify(duplicate)).not.toContain(secretName);
  });
  it('distinguishes exact unique conflicts from accepted route overlaps and regex uncertainty', async () => {
    const a = lintObject('routes', { name: 'one', protocols: ['https'], hosts: ['api.example.com'], methods: ['GET'], paths: ['/api'] });
    const b = lintObject('routes', { name: 'two', protocols: ['https'], hosts: ['*.example.com'], methods: ['GET'], paths: ['/api/orders'] });
    const c = lintObject('routes', { name: 'three', protocols: ['https'], hosts: ['api.example.com'], methods: ['POST'], paths: ['/api'] });
    const result = await inspectGovernanceInventory(lintFixture([a, b, c]));
    const overlaps = result.findings.filter(finding => finding.code === 'ROUTE_POTENTIAL_OVERLAP'); expect(overlaps).toHaveLength(1);
    expect(overlaps[0]).toMatchObject({ status: 'potential', fixCodes: [] }); expect(codes(result)).not.toContain('UNIQUE_FIELD_CONFLICT');
  });
  it('does not invent uniqueness on repeated plugin names with different scopes', async () => {
    const service = lintObject('services'), a = lintObject('plugins', { name: 'rate-limiting' }), b = lintObject('plugins', { name: 'rate-limiting', service: { id: service.nativeId } });
    const result = await inspectGovernanceInventory(lintFixture([service, a, b])); expect(result.findings.some(finding => finding.code === 'PLUGIN_BINDING_DUPLICATE')).toBe(false);
    expect(result.findings.some(finding => finding.code === 'UNIQUE_FIELD_CONFLICT' && finding.entityType === 'plugins')).toBe(false);
  });
  it('labels repeated exact plugin tuples as a review hint, not a claimed schema409', async () => {
    const result = await inspectGovernanceInventory(lintFixture([lintObject('plugins', { name: 'rate-limiting' }), lintObject('plugins', { name: 'rate-limiting' })]));
    expect(result.findings.find(finding => finding.code === 'PLUGIN_BINDING_DUPLICATE')).toMatchObject({ status: 'potential', reasonCodes: ['BINDING_TUPLE_OVERLAP'] });
  });
  it('checks explicit baseline policy only against enabled plugins and globally bound enabled instances', async () => {
    const service = lintObject('services'), scoped = lintObject('plugins', { name: 'rate-limiting', service: { id: service.nativeId }, enabled: true });
    const result = await inspectGovernanceInventory(lintFixture([service, scoped]), { securityBaselinePlugins: ['rate-limiting', 'enterprise-security-plugin'] });
    expect(result.findings.find(finding => finding.ruleCode === 'builtin.security_baseline.rate-limiting')).toMatchObject({ status: 'confirmed', fixCodes: ['baseline_plugin_configure'] });
    expect(result.findings.find(finding => finding.ruleCode === 'builtin.security_baseline.enterprise-security-plugin')).toMatchObject({ status: 'not_evaluated', reasonCodes: ['PLUGIN_NOT_ENABLED_ON_GATEWAY'] });
    const global = lintObject('plugins', { name: 'rate-limiting', enabled: true });
    expect((await inspectGovernanceInventory(lintFixture([global]), { securityBaselinePlugins: ['rate-limiting'] })).findings).toHaveLength(0);
  });
  it('does not check global baseline from a full workspace or tag-filtered projection', async () => {
    const context = lintFixture(); const workspace = { ...context, collections: context.collections.map(collection => ({ ...collection, extent: 'workspace' as const })) };
    const result = await inspectGovernanceInventory(workspace, { securityBaselinePlugins: ['rate-limiting'] });
    expect(result.findings[0]).toMatchObject({ status: 'not_evaluated', reasonCodes: ['PLUGIN_COLLECTION_NOT_CLUSTER_COMPLETE'] });
  });
  it('applies an explicit naming policy via isolated regex and skips absent optional names', async () => {
    const result = await inspectGovernanceInventory(lintFixture([lintObject('services', { name: 'Bad Name' }), lintObject('routes', { protocols: ['https'] })]), { namingPattern: '^[a-z][a-z0-9-]*$' });
    expect(result.findings.find(finding => finding.ruleCode === 'builtin.naming')).toMatchObject({ status: 'confirmed', fixCodes: ['entity_rename'] });
    expect(result.ruleResults.find(rule => rule.ruleCode === 'builtin.naming')).toMatchObject({ skippedObjects: 1 });
  });
  it('allows disabled/overridden builtin DSL without disabling structural governance checks', async () => {
    const route = { ...lintObject('routes', { protocols: ['http'] }), annotations: { state: 'absent' as const } };
    const disabled: any = { code: 'builtin.route_https', given: { entityTypes: ['routes'] }, then: { path: 'protocols', op: 'https_only' }, severity: 'error', description: 'Disabled policy', enabled: false };
    const result = await inspectGovernanceInventory(lintFixture([route]), { rules: [disabled] });
    expect(result.findings.some(finding => finding.ruleCode === 'builtin.route_https')).toBe(false); expect(codes(result)).toContain('OWNER_MISSING');
    const customThen = { ...disabled, enabled: true, then: { path: 'name', op: 'required' } };
    const overridden = await inspectGovernanceInventory(lintFixture([route]), { rules: [customThen] });
    expect(overridden.findings.find(finding => finding.ruleCode === 'builtin.route_https')?.fixCodes).toEqual([]);
  });
  it('keeps authorized closure references available to custom Lint without linting their metadata', async () => {
    const certificate = { ...lintObject('certificates'), referenceOnly: true, selected: false };
    const service = lintObject('services', { client_certificate: { id: certificate.nativeId } });
    const result = await inspectGovernanceInventory(lintFixture([service, certificate]), { includeBuiltins: false, rules: [{ code: 'test.reference', given: { entityTypes: ['services'] }, then: { path: 'client_certificate', op: 'reference_exists', entityType: 'certificates' }, severity: 'error', description: 'Reference must exist', enabled: true }] });
    expect(result.ruleResults[0]).toMatchObject({ evaluatedObjects: 1, failedObjects: 0 }); expect(result.findings.some(finding => finding.nativeId === certificate.nativeId)).toBe(false);
  });
  it('limits pairwise route overlap work and does not publish complete coverage after exhaustion', async () => {
    const objects = Array.from({ length: 1000 }, () => lintObject('routes', { protocols: ['https'], methods: ['GET'], hosts: ['api.test'], paths: ['/'] }));
    const result = await inspectGovernanceInventory(lintFixture(objects), { operationLimit: 20_000, findingLimit: 10 });
    expect(result.complete).toBe(false); expect(result.budget.exhausted).toBe(true); expect(result.findings.length).toBeLessThanOrEqual(10);
  });
  it('marks oversized route conditions as unevaluated rather than silently declaring truncated routes disjoint', async () => {
    const route = lintObject('routes', { protocols: ['https'], paths: Array.from({ length: 300 }, (_, i) => `/path-${i}`) });
    const result = await inspectGovernanceInventory(lintFixture([route]));
    expect(result.findings.find(finding => finding.code === 'ROUTE_POTENTIAL_OVERLAP')).toMatchObject({ status: 'not_evaluated', reasonCodes: ['ROUTE_CONDITION_BUDGET_EXHAUSTED'] }); expect(result.complete).toBe(false);
  });
  it('adapts canonical inventory coverage without treating projected EOF as cluster coverage', () => {
    const fixture = lintFixture(); const inventory: any = { scope: { ...fixture.scope, transportScope: 'private-physical-proof', rootIds: [] }, objects: fixture.objects, schemas: fixture.schemas, pluginSchemas: {}, enabledPlugins: [], completeness: 'complete', projection: true,
      coverage: { services: { state: 'projected', eof: true, extent: 'projection' }, 'targets:upstream-id': { state: 'complete', eof: true, extent: 'workspace' } } };
    const context = lintContextFromInventory(inventory); expect(context.collections).toEqual([{ entityType: 'services', complete: false, extent: 'projection', parentId: undefined }, { entityType: 'targets', complete: true, extent: 'workspace', parentId: 'upstream-id' }]);
    expect('transportScope' in context.scope!).toBe(false);
  });
});
