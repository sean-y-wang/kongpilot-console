import { describe, expect, it } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { parseDeckDocument, normalizeDeckDocument, normalizeCaptureGraph, serializeDeck11, serializeDeck11WithReport, diffTransferGraphs, compileTransferDag, normalizeSchema, ConfigTransferError, formatSafeDiff } from '../../apps/console-api/src/modules/config-transfer';
import type { NormalizedTransferGraph } from '../../apps/console-api/src/modules/config-transfer';
import { graph, schemas, id } from './m8-config-transfer.fixture';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';

const doc = (value: object) => parseDeckDocument(JSON.stringify({ _format_version: '1.1', ...value }));
function normalized(g = graph()): NormalizedTransferGraph {
  return normalizeDeckDocument(parseDeckDocument(serializeDeck11(g)), g.schemas, { scope: g.scope, workspaceCode: 'test', references: g, basicPasswordIntents: { [g.objects.find(o => o.credentialKind === 'basic-auth')!.objectKey]: 'replace' } });
}
const compiler = (keys: string[]) => ({ stepIds: Object.fromEntries(keys.map((key, i) => [key, id(500 + i)])), sourceManifestHmac: 'private-source', baselineManifestHmac: 'private-before', expiresAt: '2026-10-11T14:00:00Z', fingerprint: (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex'), redact: (_: unknown) => [{ op: 'replace', path: '/private', value: '[REDACTED]' }] });
describe('M8 compiler sealed SDK envelopes',()=>{
 it('seals the effective Service separately from the exact native delta',()=>{
  const g=graph(),target=normalizeDeckDocument(doc({services:[{id:id(1),retries:3}]}),g.schemas,{scope:g.scope,workspaceCode:'test',references:g});
  const diff=diffTransferGraphs(g,target),plan=compileTransferDag(diff,compiler(diff.changes.map(c=>c.objectKey))),step=plan.steps[0];
  expect(step.body).toEqual({retries:3});expect(step.nativeRequests[0].body).toEqual({retries:3});
  expect(step.deckWirePayload).toMatchObject({id:id(1),host:'fixture.invalid',protocol:'http',port:80,retries:3,path:null});
  expect(step.deckWirePayload).not.toHaveProperty('created_at');const mutated=structuredClone(plan);mutated.steps[0].deckWirePayload!.host='substituted.invalid';
  expect(compiler([]).fingerprint(mutated)).not.toBe(compiler([]).fingerprint(plan));
  expect(step.deckWireSetFields).toEqual(['tags']);const changedSet=structuredClone(plan);changedSet.steps[0].deckWireSetFields=['host'];
  expect(compiler([]).fingerprint(changedSet)).not.toBe(compiler([]).fingerprint(plan));
  expect(step.deckWirePayload!.tags).toEqual(['kos-tag-dGVhbTpwYXk','kos-ws-test']);
 });
 it('uses trusted Basic recovery only for the keep-password SDK envelope',()=>{
  const g=graph(),target=normalizeDeckDocument(doc({consumers:[{id:id(3),basicauth_credentials:[{id:id(11),username:'renamed-basic'}]}]}),g.schemas,{scope:g.scope,workspaceCode:'test',references:g,basicPasswordIntents:{[g.objects.find(o=>o.credentialKind==='basic-auth')!.objectKey]:'keep'}});
  const diff=diffTransferGraphs(g,target),plan=compileTransferDag(diff,compiler(diff.changes.map(c=>c.objectKey))),step=plan.steps.find(s=>s.credentialKind==='basic-auth')!;
  expect(step.deckWirePayload!.password).toBe('fixture-not-a-live-password');expect(step.before).toMatchObject({password:'fixture-native-basic-hash'});
  expect(step.body).not.toHaveProperty('password');expect(step.nativeRequests[0].body).not.toHaveProperty('password');
 });
});
function code(fn: () => unknown, expected: string): void { try { fn(); throw Error('Expected rejection'); } catch (error) { expect(error).toBeInstanceOf(ConfigTransferError); expect((error as ConfigTransferError).code).toBe(expected); } }

describe('M8 bounded YAML/JSON parser', () => {
  it('accepts JSON and quoted 1.1 YAML without silently applying YAML1.1 scalars', () => {
    expect(doc({ services: [] }).formatVersion).toBe('1.1');
    expect(parseDeckDocument('_format_version: "1.1"\nservices: []\n').document.services).toEqual([]);
  });
  it.each([
    ['_format_version: "1.1"\nservices: &a []', 'CONFIGURATION_YAML_ALIAS_OR_ANCHOR'],
    ['_format_version: "1.1"\nservices: [*a]', 'CONFIGURATION_YAML_ALIAS_OR_ANCHOR'],
    ['_format_version: "1.1"\nservices: !local []', 'CONFIGURATION_INVALID_YAML'],
    ['_format_version: "1.1"\nservices: []\nservices: []', 'CONFIGURATION_INVALID_YAML'],
    ['_format_version: "1.1"\n---\n_format_version: "1.1"', 'CONFIGURATION_MULTIPLE_DOCUMENTS'],
    ['_format_version: 1.1', 'CONFIGURATION_FORMAT_VERSION'],
    ['_format_version: "1.1"\ntargets: []', 'CONFIGURATION_UNKNOWN_ROOT_FIELD'],
    ['_format_version: "1.1"\nsnis: []', 'CONFIGURATION_UNKNOWN_ROOT_FIELD'],
    ['_format_version: "1.1"\n_workspace: test', 'CONFIGURATION_UNKNOWN_ROOT_FIELD'],
    ['_format_version: "1.1"\nservices: [{"__proto__": {polluted: true}}]', 'CONFIGURATION_RESERVED_KEY'],
    ['_format_version: "1.1"\nservices: [{constructor: bad}]', 'CONFIGURATION_RESERVED_KEY'],
    ['_format_version: "1.1"\nplugins: [{config: {$ref: "https://fixture.invalid/secret"}}]', 'CONFIGURATION_RESERVED_KEY'],
    ['_format_version: "1.1"\nplugins: [{config: {secret: "[REDACTED:123]"}}]', 'CONFIGURATION_SECRET_MARKER'],
    ['_format_version: "1.1"\nservices: [{host: .inf}]', 'CONFIGURATION_INVALID_SCALAR'],
    ['_format_version: "1.1"\nservices: [{1: value}]', 'CONFIGURATION_INVALID_MAP_KEY'],
  ])('rejects unsafe document case %s without echoing secret content', (content, errorCode) => code(() => parseDeckDocument(content), errorCode));
  it('enforces byte/node/depth budgets including mapping keys', () => {
    code(() => parseDeckDocument('_format_version: "1.1"', { bytes: 10 }), 'CONFIGURATION_DOCUMENT_TOO_LARGE');
    code(() => parseDeckDocument('_format_version: "1.1"\nservices: []', { nodes: 2 }), 'CONFIGURATION_DOCUMENT_NODE_LIMIT');
    code(() => parseDeckDocument('_format_version: "1.1"\nservices: [{host: x}]', { depth: 2 }), 'CONFIGURATION_DOCUMENT_DEPTH_LIMIT');
    code(() => parseDeckDocument('_format_version: "1.1"', { depth: 33 }), 'CONFIGURATION_INVALID_PARSE_LIMIT');
  });
});

describe('Kong 1.5 lazy schema validation state across captures',()=>{
 it('compiles a fresh rollback across only an implicit string minimum change, preserving both immutable digests',()=>{
  const current=graph(),historic=graph();current.objects.find(o=>o.entityType==='services')!.payload.retries=1;
  (current.schemas.entities.services as any).fields.find((v:any)=>v.host).host.len_min=1;
  current.schemas.schemaHmac=current.schemaHmac='current-worker-validated-schema';current.objects.forEach(o=>o.schemaHmac=current.schemaHmac);
  const original=canonicalJson({current,historic}),target=normalizeCaptureGraph(historic,{[historic.scope.workspaceId]:'test'}),diff=diffTransferGraphs(current,target,{mode:'rollback',rollbackBaselineVerified:true});
  expect(diff.changes).toHaveLength(1);expect(diff.changes[0]).toMatchObject({entityType:'services',action:'update',writePayload:{retries:0}});
  const plan=compileTransferDag(diff,compiler(diff.changes.map(c=>c.objectKey)));expect(plan.schemaHmac).toBe('current-worker-validated-schema');expect(plan.steps[0].beforeHmac).toBe(current.objects[0].beforeHmac);expect(canonicalJson({current,historic})).toBe(original);
 });
 it.each([0,2,null,false,'1'])('rejects a changed explicit minimum %j despite a current rollback capture',value=>{const current=graph(),historic=graph();(historic.schemas.entities.services as any).fields.find((v:any)=>v.host).host.len_min=value;const target=normalizeCaptureGraph(historic,{[historic.scope.workspaceId]:'test'});code(()=>diffTransferGraphs(current,target,{mode:'rollback',rollbackBaselineVerified:true}),'CONFIGURATION_DIFF_SCOPE_MISMATCH');});
 it('rejects real schema constraints even if a caller supplies an unchanged opaque schema digest',()=>{const current=graph(),target=normalized(current);const changed=structuredClone(target.schemas);(changed.entities.services as any).fields.find((v:any)=>v.retries).retries.default=99;(target as any).schemas=changed;code(()=>diffTransferGraphs(current,target),'CONFIGURATION_DIFF_SCOPE_MISMATCH');});
 it('rejects scope, adapter, enabled plugin and Kong version changes despite equivalent strings',()=>{for(const kind of ['scope','adapter','plugins','kong']){const current=graph(),historic=graph(),target=normalizeCaptureGraph(historic,{[historic.scope.workspaceId]:'test'});if(kind==='scope')target.scope.transportScope='other';if(kind==='adapter')target.schemas.adapterVersion='other';if(kind==='plugins')(target.schemas as any).enabledPlugins=[];if(kind==='kong')target.schemas.kongVersion='1.5.2';code(()=>diffTransferGraphs(current,target),'CONFIGURATION_DIFF_SCOPE_MISMATCH');}});
 it('validates strings with the Kong default minimum and counts UTF-8 bytes',()=>{const schema=(field:any)=>({fields:[{value:field}]});code(()=>normalizeSchema({value:''},schema({type:'string'})),'CONFIGURATION_SCHEMA_LENGTH');expect(normalizeSchema({value:''},schema({type:'string',len_min:0}))).toEqual({value:''});expect(normalizeSchema({value:'界'},schema({type:'string',len_eq:3}))).toEqual({value:'界'});code(()=>normalizeSchema({value:'界'},schema({type:'string',len_max:2})),'CONFIGURATION_SCHEMA_LENGTH');});
});

describe('M8 recorded Kong 1.5 schema normalization and decK shape', () => {
  it('exports and restores captured SNI objects rather than Certificate Admin name observations', () => {
    const g = graph(), certificate = g.objects.find(o => o.entityType === 'certificates')!;
    certificate.payload.snis = ['fixture.invalid', 'foreign-workspace.invalid'];
    certificate.recovery.restorePayload = structuredClone(certificate.payload);
    const output = parse(serializeDeck11(g));
    expect(output.certificates[0].snis).toHaveLength(1);
    expect(output.certificates[0].snis[0]).toMatchObject({ id: id(8), name: 'fixture.invalid' });
    expect(JSON.stringify(output)).not.toContain('foreign-workspace.invalid');
    const restore = normalizeCaptureGraph(g, { [g.scope.workspaceId]: 'test' });
    expect(restore.objects.find(o => o.entityType === 'certificates')?.payload).not.toHaveProperty('snis');
    expect(restore.objects.find(o => o.entityType === 'snis')?.nativeId).toBe(id(8));
    expect(certificate.payload.snis).toEqual(['fixture.invalid', 'foreign-workspace.invalid']);
    expect(diffTransferGraphs(g, restore).changes).toHaveLength(0);
  });
  it('round trips every core type, targets, SNI and six credentials with IDs, false/zero/null and combined bindings', () => {
    const g = graph(), text = serializeDeck11(g), output = parse(text), target = normalized(g);
    expect(output._format_version).toBe('1.1'); expect(output.targets).toBeUndefined(); expect(output.snis).toBeUndefined();
    expect(output.services[0].routes[0]).toMatchObject({ strip_path: false, regex_priority: 0, preserve_host: false });
    expect(output.services[0].path).toBeUndefined(); expect(output.services[0].created_at).toBeUndefined();
    const report = serializeDeck11WithReport(g); expect(report.formatOmissions).toContainEqual({ objectKey: `services:${id(1)}`, jsonPointer: '/path', reason: 'deck11_optional_null' });
    expect(g.objects[0].payload.path).toBeNull(); expect(normalizeCaptureGraph(g, { [g.scope.workspaceId]: 'test' }).objects[0].payload.path).toBeNull();
    expect(output.upstreams[0].targets[0].weight).toBe(0); expect(output.certificates[0].snis[0].id).toBe(id(8));
    expect(output.plugins[0]).toMatchObject({ consumer: id(3), service: id(1), route: id(2), enabled: false });
    expect(output.consumers[0].basicauth_credentials[0].password).toBe('fixture-not-a-live-password');
    expect(text).not.toContain('fixture-native-basic-hash'); expect(g.objects.find(o => o.credentialKind === 'basic-auth')!.payload.password).toBe('fixture-native-basic-hash');
    expect(target.objects).toHaveLength(15); expect(target.objects.find(o => o.entityType === 'plugins')!.dependencies).toContain(`consumers:${id(3)}`);
    expect(target.objects[0].payload.tags).toContain('kos-tag-dGVhbTpwYXk');
  });
  it.each(['tls_verify', 'tls_verify_depth', 'ca_certificates', 'expression'])('rejects unavailable Service field %s instead of dropping it', field => {
    const g = graph(); code(() => normalizeDeckDocument(doc({ services: [{ id: id(1), host: 'fixture.invalid', [field]: true }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_UNKNOWN_FIELD');
  });
  it('rejects nonexistent OAuth hash_secret, unknown plugin config and invalid record/set element fields', () => {
    const g = graph();
    code(() => normalizeDeckDocument(doc({ consumers: [{ id: id(3), oauth2_credentials: [{ id: id(13), hash_secret: true }] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_UNKNOWN_FIELD');
    code(() => normalizeDeckDocument(doc({ plugins: [{ id: id(4), name: 'correlation-id', config: { made_up: true } }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_UNKNOWN_FIELD');
    code(() => normalizeDeckDocument(doc({ routes: [{ id: id(2), sources: [{ ip: '192.0.2.1', bogus: true }] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_UNKNOWN_FIELD');
  });
  it('canonicalizes sets of records and maps while preserving array order and rejecting wrong types', () => {
    const s = { fields: [{ records: { type: 'set', elements: { type: 'record', fields: [{ enabled: { type: 'boolean' } }, { n: { type: 'number' } }] } } }, { map: { type: 'map', values: { type: 'array', elements: { type: 'string' } } } }] };
    expect(normalizeSchema({ records: [{ enabled: false, n: 0 }], map: { test: ['b', 'a'] } }, s)).toEqual({ records: [{ enabled: false, n: 0 }], map: { test: ['b', 'a'] } });
    code(() => normalizeSchema({ records: [{ enabled: 'false' }] }, s), 'CONFIGURATION_SCHEMA_VALUE');
  });
  it('validates actual statsd array-of-record fields, conditional constraints and response-limiting map records', () => {
    const g = graph(), bundle = schemas();
    for (const name of ['statsd', 'response-ratelimiting']) { (bundle.plugins as any)[name] = JSON.parse(readFileSync(`tests/fixtures/kong-1.5.1/plugin-schema-${name}.json`, 'utf8')); (bundle.enabledPlugins as string[]).push(name); }
    const input = doc({ plugins: [{ id: id(201), name: 'statsd', config: { metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 0.5 }] } }, { id: id(202), name: 'response-ratelimiting', config: { limits: { widget: { minute: 10, hour: 20 } }, fault_tolerant: false, redis_database: 0 } }] });
    const parsed = normalizeDeckDocument(input, bundle, { scope: g.scope, workspaceCode: 'test' });
    expect(parsed.objects[0].payload.config).toEqual({ metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 0.5 }] });
    expect(parsed.objects[1].payload.config).toMatchObject({ fault_tolerant: false, redis_database: 0, limits: { widget: { minute: 10 } } });
    code(() => normalizeDeckDocument(doc({ plugins: [{ id: id(201), name: 'statsd', config: { metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 0 }] } }] }), bundle, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_SCHEMA_RANGE');
    code(() => normalizeDeckDocument(doc({ plugins: [{ id: id(201), name: 'statsd', config: { metrics: [{ name: 'unique_users', stat_type: 'counter', sample_rate: 1 }] } }] }), bundle, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_PLUGIN_CONSTRAINT');
  });
  it('requires frozen missing IDs and explicit Basic password intent', () => {
    const g = graph(); code(() => normalizeDeckDocument(doc({ services: [{ host: 'fixture.invalid' }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_NATIVE_ID_REQUIRED');
    expect(normalizeDeckDocument(doc({ services: [{ host: 'fixture.invalid' }] }), g.schemas, { scope: g.scope, workspaceCode: 'test', allocatedNativeIds: { 'services[0]': id(200) } }).objects[0].nativeId).toBe(id(200));
    code(() => normalizeDeckDocument(doc({ consumers: [{ id: id(3), basicauth_credentials: [{ id: id(11), username: 'fixture-basic', password: 'looks-like-any-string' }] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_BASIC_PASSWORD_INTENT_REQUIRED');
  });
  it('rejects duplicate IDs, inconsistent nested parent and physical workspace migration', () => {
    const g = graph();
    code(() => normalizeDeckDocument(doc({ services: [{ id: id(1), host: 'a' }, { id: id(1), host: 'b' }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_DUPLICATE_NATIVE_ID');
    code(() => normalizeDeckDocument(doc({ services: [{ id: id(1), routes: [{ id: id(2), service: id(90) }] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_PARENT_REFERENCE_MISMATCH');
    code(() => normalizeDeckDocument(doc({ services: [{ id: id(1), tags: ['kos-ws-other'] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_UNKNOWN_WORKSPACE_TAG');
  });
  it('rejects actual protocol subset conflicts and empty source records before any mutation', () => {
    const g = graph();
    code(() => normalizeDeckDocument(doc({ routes: [{ id: id(2), protocols: ['http', 'tcp'] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_SCHEMA_SUBSET');
    code(() => normalizeDeckDocument(doc({ routes: [{ id: id(2), sources: [{}] }] }), g.schemas, { scope: g.scope, workspaceCode: 'test' }), 'CONFIGURATION_SCHEMA_ENTITY_CHECK');
  });
  it('never deploys missing Basic plaintext, incomplete EOF, TTL or a child outside its exported parent', () => {
    const g = graph(); g.objects.find(o => o.credentialKind === 'basic-auth')!.recovery = { state: 'requires_secret_input', blockerCodes: ['missing'] };
    code(() => serializeDeck11(g), 'CONFIGURATION_RECOVERY_NOT_COMPLETE');
    const eof = graph(); eof.collections[0].terminalObserved = false; code(() => serializeDeck11(eof), 'CONFIGURATION_COLLECTION_NOT_COMPLETE');
    const ttl = graph(); ttl.objects[0].payload.ttl = 60; code(() => serializeDeck11(ttl), 'CONFIGURATION_TTL_EXPORT_UNSUPPORTED');
    const ref = graph(); ref.objects.find(o => o.entityType === 'upstreams')!.affected = false; ref.objects.find(o => o.entityType === 'upstreams')!.referenceOnly = true; code(() => serializeDeck11(ref), 'CONFIGURATION_EXPORT_PARENT_OUTSIDE_SCOPE');
  });
  it('review requires a caller-owned redactor and cannot be reimported as a deployment', () => {
    code(() => serializeDeck11(graph(), { mode: 'review' }), 'CONFIGURATION_REDACTOR_REQUIRED');
    const review = serializeDeck11(graph(), { mode: 'review', redact: () => ({ _format_version: '1.1', certificates: [{ id: id(7), key: '[REDACTED]' }] }) });
    code(() => parseDeckDocument(review), 'CONFIGURATION_SECRET_MARKER');
  });
});

describe('M8 diff and frozen dependency compiler', () => {
  function healthcheckGraph() {
    const g = graph(), upstream = g.objects.find(o => o.entityType === 'upstreams')!;
    const payload = normalizeSchema({ ...upstream.payload, healthchecks: {} }, g.schemas.entities.upstreams, { defaults: true });
    (payload.healthchecks as any).active.https_sni = null;
    upstream.payload = payload;
    return g;
  }
  it('round-trips recorded 1.5.1 nested optional null without inventing an Upstream update', () => {
    const g = healthcheckGraph(), original = structuredClone(g), exported = serializeDeck11WithReport(g);
    expect(exported.formatOmissions).toContainEqual({ objectKey: `upstreams:${id(5)}`, jsonPointer: '/healthchecks/active/https_sni', reason: 'deck11_optional_null' });
    expect((parse(exported.yaml).upstreams[0].healthchecks.active)).not.toHaveProperty('https_sni');
    expect(diffTransferGraphs(g, normalized(g)).changes).toHaveLength(0);
    const target = normalized(g); target.objects.find(o => o.entityType === 'services')!.payload.retries = 2;
    const diff = diffTransferGraphs(g, target);
    expect(diff.changes).toHaveLength(1);
    expect(diff.changes[0]).toMatchObject({ entityType: 'services', writePayload: { retries: 2 }, patch: [{ op: 'replace', path: '/retries', value: 2 }] });
    expect(g).toEqual(original);
  });
  it('merges nested record fields while preserving omitted siblings and replacing explicitly supplied arrays', () => {
    const g = healthcheckGraph(), target = normalized(g), upstream = target.objects.find(o => o.entityType === 'upstreams')!;
    upstream.payload.healthchecks = { active: { timeout: 3, healthy: { http_statuses: [201] } } };
    const diff = diffTransferGraphs(g, target), change = diff.changes[0];
    expect(diff.changes).toHaveLength(1);
    expect(change.effectivePayload!.healthchecks).toMatchObject({ active: { timeout: 3, https_sni: null, concurrency: 10, healthy: { http_statuses: [201], interval: 0 } }, passive: { type: 'http' } });
    expect((change.effectivePayload!.healthchecks as any).active.healthy.http_statuses).toEqual([201]);
    expect(change.patch.some(p => p.op === 'remove' && p.path.includes('https_sni'))).toBe(false);
  });
  it('keeps explicit optional null clears and complete snapshot record replacement exact', () => {
    const g = healthcheckGraph(), upstream = g.objects.find(o => o.entityType === 'upstreams')!;
    (upstream.payload.healthchecks as any).active.https_sni = 'upstream.fixture.invalid';
    const target = normalized(g); (target.objects.find(o => o.entityType === 'upstreams')!.payload.healthchecks as any).active.https_sni = null;
    const clear = diffTransferGraphs(g, target).changes[0];
    expect((clear.writePayload!.healthchecks as any).active.https_sni).toBeNull();
    expect(clear.patch).toContainEqual({ op: 'replace', path: '/healthchecks/active/https_sni', value: null });
    const snapshot = healthcheckGraph(); delete (snapshot.objects.find(o => o.entityType === 'upstreams')!.payload.healthchecks as any).active.https_sni;
    const exact = diffTransferGraphs(g, normalizeCaptureGraph(snapshot, { [g.scope.workspaceId]: 'test' }), { mode: 'rollback', rollbackBaselineVerified: true });
    expect(exact.changes[0].patch).toContainEqual({ op: 'remove', path: '/healthchecks/active/https_sni' });
  });
  it('still replaces entity maps and foreign references rather than inheriting omitted keys', () => {
    const g = graph(), target = normalized(g), route = target.objects.find(o => o.entityType === 'routes')!;
    route.payload.headers = { 'x-another': ['new'] };
    route.payload.service = { id: id(123) };
    const diff = diffTransferGraphs(g, target), change = diff.changes.find(o => o.entityType === 'routes')!;
    expect(change.effectivePayload!.headers).toEqual({ 'x-another': ['new'] });
    expect(change.effectivePayload!.service).toEqual({ id: id(123) });
  });
  it('an exact full export has no changes, including independently compared trusted Basic password', () => {
    const g = graph(), diff = diffTransferGraphs(g, normalized(g)); expect(diff.changes).toHaveLength(0); expect(diff.unchangedCount).toBe(15);
  });
  it('merge omission never deletes, sync requires confirmation and rollback requires a new before capture', () => {
    const g = graph(), empty = normalizeDeckDocument(doc({}), g.schemas, { scope: g.scope, workspaceCode: 'test' });
    expect(diffTransferGraphs(g, empty).changes).toHaveLength(0);
    code(() => diffTransferGraphs(g, empty, { mode: 'sync' }), 'CONFIGURATION_SYNC_CONFIRMATION_REQUIRED');
    code(() => diffTransferGraphs(g, empty, { mode: 'rollback' }), 'CONFIGURATION_FRESH_ROLLBACK_BASELINE_REQUIRED');
  });
  it('orders Consumer before its bound Plugin/credentials and deletes in reverse dependency order', () => {
    const g = graph(), empty = normalizeDeckDocument(doc({}), g.schemas, { scope: g.scope, workspaceCode: 'test' });
    const diff = diffTransferGraphs(g, empty, { mode: 'sync', syncConfirmed: true }), plan = compileTransferDag(diff, compiler(diff.changes.map(c => c.objectKey)));
    expect(plan.steps.map(step => step.stepOrder)).toEqual(Array.from({ length: 15 }, (_, i) => i + 1));
    expect(plan.steps.filter(step => step.stepOrder > 0)).toHaveLength(15);
    const at = (type: string) => plan.steps.findIndex(s => s.entityType === type);
    expect(at('plugins')).toBeLessThan(at('consumers')); expect(at('credentials')).toBeLessThan(at('consumers')); expect(at('routes')).toBeLessThan(at('services')); expect(at('snis')).toBeLessThan(at('certificates')); expect(at('targets')).toBeLessThan(at('upstreams'));
    const blank = graph(); blank.objects = []; const creates = diffTransferGraphs(blank, normalized(g));
    const createPlan = compileTransferDag(creates, compiler(creates.changes.map(c => c.objectKey)));
    expect(createPlan.steps.map(step => step.stepOrder)).toEqual(Array.from({ length: 15 }, (_, i) => i + 1));
    const pos = (type: string) => createPlan.steps.findIndex(s => s.entityType === type);
    expect(pos('consumers')).toBeLessThan(pos('plugins')); expect(pos('consumers')).toBeLessThan(pos('credentials')); expect(pos('certificates')).toBeLessThan(pos('services'));
  });
  it('detects Basic password-only intent independently of decK and blocks destructive nonrestorable before', () => {
    const g = graph(), target = normalized(g), basic = target.objects.find(o => o.credentialKind === 'basic-auth')!; basic.payload.password = 'fixture-rotated-password';
    const diff = diffTransferGraphs(g, target); expect(diff.changes).toHaveLength(1); expect(diff.changes[0].writePayload!.password).toBe('fixture-rotated-password');
    g.objects.find(o => o.credentialKind === 'basic-auth')!.recovery = { state: 'requires_secret_input', blockerCodes: ['missing'] };
    const blocked = diffTransferGraphs(g, target); expect(blocked.blockerCodes).toContain('CONFIGURATION_BEFORE_NOT_RECOVERABLE'); code(() => compileTransferDag(blocked, compiler(blocked.changes.map(c => c.objectKey))), 'CONFIGURATION_PLAN_BLOCKED');
  });
  it('snapshot rollback preserves explicit null and freezes plugin map removals for the dedicated exact PATCH handler', () => {
    const snapshot = graph(), desired = normalizeCaptureGraph(snapshot, { [snapshot.scope.workspaceId]: 'test' }), current = graph();
    current.objects[0].payload.path = '/drifted';
    const diff = diffTransferGraphs(current, desired, { mode: 'rollback', rollbackBaselineVerified: true });
    expect(diff.changes[0].writePayload!.path).toBeNull();
    const plugin = current.objects.find(o => o.entityType === 'plugins')!;
    (plugin.payload.config as any).generator = 'uuid';
    const omitted = snapshot.objects.find(o => o.entityType === 'plugins')!;
    delete (omitted.payload.config as any).generator;
    const exact = diffTransferGraphs(current, normalizeCaptureGraph(snapshot, { [snapshot.scope.workspaceId]: 'test' }), { mode: 'rollback', rollbackBaselineVerified: true });
    const pluginChange = exact.changes.find(c => c.entityType === 'plugins')!;
    expect(exact.blockerCodes).toEqual([]); expect(pluginChange.clearMap).toContain('/config/generator');
    const plan = compileTransferDag(exact, compiler(exact.changes.map(c => c.objectKey))), pluginStep = plan.steps.find(s => s.entityType === 'plugins')!;
    expect(pluginStep.clearMap).toContain('/config/generator'); expect((pluginStep.nativeRequests[0].body as any).config.generator).toBeUndefined();
    expect(pluginStep.objectWorkspaceId).toBe(current.scope.workspaceId);
  });
  it('freezes Target POST append, zero weight and identical physical Mutation/native tags with no duplicate parent field', () => {
    const g = graph(), target = normalized(g); target.objects.find(o => o.entityType === 'targets')!.payload.weight = 10;
    const diff = diffTransferGraphs(g, target), key = diff.changes[0].objectKey;
    code(() => compileTransferDag(diff, compiler([key])), 'CONFIGURATION_NATIVE_ID_REQUIRED');
    const plan = compileTransferDag(diff, { ...compiler([key]), allocatedTargetIds: { [key]: id(400) } });
    expect(plan.steps[0]).toMatchObject({ nativeId: id(6), allocatedNativeId: id(400), nativeRequests: [{ method: 'POST', canonicalPath: `/upstreams/${id(5)}/targets`, body: { id: id(400), target: 'fixture.invalid:8081', weight: 10 } }] });
    expect(plan.steps[0].body!.upstream).toBeUndefined();
    expect((plan.steps[0].nativeRequests[0].body as any).tags).toEqual(['kos-tag-dGVhbTpwYXk', 'kos-ws-test']);
    const blank = graph(); blank.objects = []; const create = diffTransferGraphs(blank, normalized(g)), p = compileTransferDag(create, compiler(create.changes.map(c => c.objectKey))), service = p.steps.find(s => s.entityType === 'services')!;
    expect(service.body!.tags).toContain('kos-ws-test'); expect(service.body!.tags).toEqual((service.nativeRequests[0].body as any).tags); expect(service.body!.tags).not.toContain('workspace:test'); expect(service.maskedDiff).toEqual([{ op: 'replace', path: '/private', value: '[REDACTED]' }]);
  });
  it('seals each allocated create ID into both exact Mutation and native POST bodies even when a write payload omitted it', () => {
    const full = graph(), blank = graph(); blank.objects = [];
    const diff = diffTransferGraphs(blank, normalized(full));
    diff.changes.forEach(change => { delete change.writePayload!.id; });
    const plan = compileTransferDag(diff, compiler(diff.changes.map(change => change.objectKey)));
    for (const step of plan.steps) {
      expect(step.body!.id).toBe(step.allocatedNativeId);
      expect(step.nativeRequests[0].method).toBe('POST');
      expect(step.body).toEqual(step.nativeRequests[0].body);
      expect(step.bodyHmac).toBe(step.nativeRequests[0].bodyHmac);
    }
    diff.changes[0].writePayload!.id = id(999);
    code(() => compileTransferDag(diff, compiler(diff.changes.map(change => change.objectKey))), 'CONFIGURATION_CREATE_ID_MISMATCH');
  });
  it('binds DELETE confirmation to the actual Recycle Mutation parent/kind payload while native DELETE stays null', () => {
    const full = graph(), empty = normalizeDeckDocument(doc({}), full.schemas, { scope: full.scope, workspaceCode: 'test' });
    const diff = diffTransferGraphs(full, empty, { mode: 'sync', syncConfirmed: true });
    const fingerprint = (value: unknown): string => createHmac('sha256', 'synthetic-source-only-key').update(canonicalJson(value)).digest('hex');
    const plan = compileTransferDag(diff, { ...compiler(diff.changes.map(change => change.objectKey)), fingerprint });
    for (const step of plan.steps) {
      const recyclePayload = { confirmed: true, confirm_name: step.body!.confirm_name, parentId: step.parentId ?? undefined, credentialKind: step.credentialKind ?? undefined };
      expect(step.body).toEqual(recyclePayload); expect(step.bodyHmac).toBe(fingerprint(recyclePayload));
      expect(step.nativeRequests[0]).toMatchObject({ method: 'DELETE', body: null, bodyHmac: fingerprint(null) });
      if (step.entityType === 'targets' || step.entityType === 'credentials') {
        expect(step.body!.parentId).toBe(step.parentId);
        const missingParent = { confirmed: true, confirm_name: step.body!.confirm_name, credentialKind: step.credentialKind ?? undefined };
        expect(fingerprint(missingParent)).not.toBe(step.bodyHmac);
      }
      if (step.entityType === 'credentials') {
        expect(step.body!.credentialKind).toBe(step.credentialKind);
        expect(fingerprint({ confirmed: true, confirm_name: step.body!.confirm_name, parentId: step.parentId })).not.toBe(step.bodyHmac);
      }
    }
  });
  it('reference-only objects are never deleted or changed and managed boundaries block changing protected objects', () => {
    const g = graph(); g.objects.find(o => o.entityType === 'ca_certificates')!.affected = false; g.objects.find(o => o.entityType === 'ca_certificates')!.referenceOnly = true;
    const empty = normalizeDeckDocument(doc({}), g.schemas, { scope: g.scope, workspaceCode: 'test' });
    expect(diffTransferGraphs(g, empty, { mode: 'sync', syncConfirmed: true }).changes.some(c => c.entityType === 'ca_certificates')).toBe(false);
    const target = normalized(graph()); target.objects.find(o => o.entityType === 'ca_certificates')!.payload.cert = 'fixture-another-ca';
    expect(diffTransferGraphs(g, target).blockerCodes).toContain('CONFIGURATION_REFERENCE_ONLY_MUTATION');
    const protectedGraph = graph(); protectedGraph.objects[0].managedBoundary = 'portal'; const desired = normalized(protectedGraph); desired.objects.find(o => o.entityType === 'services')!.payload.host = 'other.invalid';
    expect(diffTransferGraphs(protectedGraph, desired).blockerCodes).toContain('CONFIGURATION_MANAGED_BOUNDARY');
  });
  it('rejects cycles, missing step IDs, scope/hash swaps and duplicate plugin binding conflicts', () => {
    const g = graph(), target = normalized(g); target.objects.find(o => o.entityType === 'services')!.payload.host = 'new.invalid';
    const diff = diffTransferGraphs(g, target); code(() => compileTransferDag(diff, compiler([])), 'CONFIGURATION_NATIVE_ID_REQUIRED');
    const swapped = normalized(g); swapped.scope.clusterId = id(900); code(() => diffTransferGraphs(g, swapped), 'CONFIGURATION_DIFF_SCOPE_MISMATCH');
    const blank = graph(); blank.objects = []; const all = normalized(g); all.objects.find(o => o.entityType === 'certificates')!.dependencies = [`services:${id(1)}`];
    const cyclic = diffTransferGraphs(blank, all); code(() => compileTransferDag(cyclic, compiler(cyclic.changes.map(c => c.objectKey))), 'CONFIGURATION_DEPENDENCY_CYCLE');
  });
  it('does not execute native requests or expose unredacted patches through ConfigPlan', () => {
    const g = graph(), target = normalized(g); target.objects.find(o => o.entityType === 'services')!.payload.retries = 1;
    const diff = diffTransferGraphs(g, target), plan = compileTransferDag(diff, compiler(diff.changes.map(c => c.objectKey)));
    expect(plan.steps).toHaveLength(1); expect(plan.steps[0].nativeRequests[0].method).toBe('PATCH'); expect(plan.steps[0].beforeHmac).toBe(g.objects[0].beforeHmac); expect(plan.steps[0].maskedDiff).toEqual([{ op: 'replace', path: '/private', value: '[REDACTED]' }]);
    const safe = formatSafeDiff(diff, compiler([]).redact);
    expect(JSON.stringify(safe)).not.toContain('fixture-not-a-live'); expect((safe.changes as any)[0].before).toBeUndefined();
  });
});
