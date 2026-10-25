import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { CaptureGraph, CaptureObject, CapturedSchemaBundle } from '../../apps/console-api/src/modules/configuration/configuration.types';
import { configurationObjectKey } from '../../apps/console-api/src/modules/config-transfer';

export const id = (n: number): string => `${n.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`;
const fixture = (name: string): unknown => JSON.parse(readFileSync(resolve('tests/fixtures/kong-1.5.1', name), 'utf8'));
const record = (fields: Record<string, unknown>) => ({ fields: Object.entries(fields).map(([name, definition]) => ({ [name]: definition })) });
const common = { id: { type: 'string', uuid: true, auto: true }, created_at: { type: 'integer', auto: true }, tags: { type: 'set', elements: { type: 'string' } } };
const consumer = { type: 'foreign', reference: 'consumers', required: true };
/** Eight core and plugin schemas are actual recorded 1.5.1 responses. Child schemas
 * here are explicitly synthetic; actual child response recording belongs to capture. */
export function schemas(): CapturedSchemaBundle {
  const entities: Record<string, unknown> = {};
  for (const type of ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis']) entities[type] = fixture(`schema-${type}.json`);
  entities.targets = record({ ...common, upstream: { type: 'foreign', reference: 'upstreams', required: true }, target: { type: 'string', required: true }, weight: { type: 'integer', default: 100, between: [0, 1000] } });
  entities.keyauth_credentials = record({ ...common, consumer, key: { type: 'string', required: true, unique: true } });
  entities.basicauth_credentials = record({ ...common, consumer, username: { type: 'string', required: true, unique: true }, password: { type: 'string', required: true } });
  entities.jwt_secrets = record({ ...common, consumer, key: { type: 'string', required: true, unique: true }, secret: { type: 'string', required: true }, rsa_public_key: { type: 'string' }, algorithm: { type: 'string', default: 'HS256', one_of: ['HS256', 'RS256'] } });
  entities.oauth2_credentials = record({ ...common, consumer, name: { type: 'string', required: true }, client_id: { type: 'string', required: true, unique: true }, client_secret: { type: 'string', required: true }, redirect_uris: { type: 'array', elements: { type: 'string' }, required: true } });
  entities.hmacauth_credentials = record({ ...common, consumer, username: { type: 'string', required: true, unique: true }, secret: { type: 'string', required: true } });
  entities.acls = record({ ...common, consumer, group: { type: 'string', required: true } });
  return { entities, plugins: { 'correlation-id': fixture('plugin-schema-correlation-id.json') }, enabledPlugins: ['correlation-id'], kongVersion: '1.5.1', adapterVersion: 'kong-1.5', schemaHmac: 'synthetic-schema-hmac' };
}
export function graph(): CaptureGraph {
  const bundle = schemas();
  const object = (type: CaptureObject['entityType'], n: number, payload: Record<string, unknown>, parentId?: string, kind?: CaptureObject['credentialKind']): CaptureObject => ({ objectKey: configurationObjectKey(type, id(n), parentId, kind), entityType: type, nativeId: id(n), ...(parentId ? { parentType: type === 'targets' ? 'upstreams' : 'consumers', parentId } : {}), ...(kind ? { credentialKind: kind } : {}), objectWorkspaceId: id(100), ownershipTags: ['kos-ws-test'], affected: true, referenceOnly: false, dependencies: [], payload: { id: id(n), tags: ['kos-ws-test', 'kos-tag-dGVhbTpwYXk'], ...payload }, beforeHmac: `private-hmac-${n}`, schemaHmac: bundle.schemaHmac, observedAt: '2026-10-11T12:00:00Z', recovery: { state: 'complete', blockerCodes: [] }, managedBoundary: 'none' });
  const objects: CaptureObject[] = [
    object('services', 1, { name: 'svc', host: 'fixture.invalid', protocol: 'http', port: 80, retries: 0, path: null, client_certificate: { id: id(7) }, created_at: 1, updated_at: 2 }),
    object('routes', 2, { name: 'route', service: { id: id(1) }, paths: ['/fixture'], protocols: ['http'], preserve_host: false, strip_path: false, regex_priority: 0, sources: [{ ip: '192.0.2.0/24', port: 0 }], headers: { 'x-fixture': ['a', 'b'] } }),
    object('consumers', 3, { username: 'consumer', custom_id: null }),
    object('plugins', 4, { name: 'correlation-id', service: { id: id(1) }, route: { id: id(2) }, consumer: { id: id(3) }, enabled: false, config: { header_name: 'X-Fixture-ID', echo_downstream: false } }),
    object('upstreams', 5, { name: 'upstream', algorithm: 'round-robin', slots: 100, hash_on: 'none', hash_fallback: 'none' }),
    object('targets', 6, { upstream: { id: id(5) }, target: 'fixture.invalid:8081', weight: 0 }, id(5)),
    object('certificates', 7, { cert: 'fixture-not-a-real-certificate', key: 'fixture-not-a-real-private-key' }),
    object('snis', 8, { name: 'fixture.invalid', certificate: { id: id(7) } }),
    object('ca_certificates', 9, { cert: 'fixture-not-a-real-ca-certificate' }),
    object('credentials', 10, { consumer: { id: id(3) }, key: 'fixture-not-a-live-key' }, id(3), 'key-auth'),
    object('credentials', 11, { consumer: { id: id(3) }, username: 'fixture-basic', password: 'fixture-native-basic-hash' }, id(3), 'basic-auth'),
    object('credentials', 12, { consumer: { id: id(3) }, key: 'fixture-jwt', secret: 'fixture-not-a-live-jwt-secret', algorithm: 'HS256', rsa_public_key: null }, id(3), 'jwt'),
    object('credentials', 13, { consumer: { id: id(3) }, name: 'fixture-oauth', client_id: 'fixture-client', client_secret: 'fixture-not-a-live-client-secret', redirect_uris: ['https://fixture.invalid/callback'] }, id(3), 'oauth2'),
    object('credentials', 14, { consumer: { id: id(3) }, username: 'fixture-hmac', secret: 'fixture-not-a-live-hmac-secret' }, id(3), 'hmac-auth'),
    object('credentials', 15, { consumer: { id: id(3) }, group: 'fixture-group' }, id(3), 'acls'),
  ];
  const deps: Record<number, string[]> = { 1: [`certificates:${id(7)}`], 2: [`services:${id(1)}`], 4: [`services:${id(1)}`, `routes:${id(2)}`, `consumers:${id(3)}`], 6: [`upstreams:${id(5)}`], 8: [`certificates:${id(7)}`] };
  objects.forEach((obj, i) => { obj.dependencies = deps[i + 1] ?? (obj.entityType === 'credentials' ? [`consumers:${id(3)}`] : []); });
  const basic = objects.find(obj => obj.credentialKind === 'basic-auth')!;
  basic.recovery.restorePayload = { ...basic.payload, password: 'fixture-not-a-live-password' };
  const collections = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'].map(entityType => ({ collectionKey: entityType, entityType: entityType as any, queryHmac: 'private-query', pageSize: 100, pageCount: 1, recordCount: 1, terminalObserved: true, cursorChainHmac: 'private-cursor', coverageHmac: 'private-coverage' }));
  return { scope: { clusterId: id(101), workspaceId: id(100), transportScope: 'synthetic-physical', kind: 'workspace', rootIds: [] }, objects, collections, completeness: 'complete', consistency: 'console_fenced_best_effort', kongVersion: bundle.kongVersion, adapterVersion: bundle.adapterVersion, schemaHmac: bundle.schemaHmac, schemas: bundle, permissionVersion: 'private-permission', captureEpoch: 'private-capture', observedFrom: '2026-10-11T12:00:00Z', observedUntil: '2026-10-11T12:00:01Z', pageCount: 8, recordCount: 15, byteCount: 5000, nativeCallCount: 8, warningCodes: [], requiredCollections: collections.map(c => c.collectionKey), credentialEpoch: 1, clusterRevision: 1, workspaceRevision: 1, jobId: id(102), snapshotId: id(103), versionId: id(104), materialId: id(105) };
}
