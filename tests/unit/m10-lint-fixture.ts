import { randomUUID } from 'node:crypto';
import services from '../fixtures/kong-1.5.1/schema-services.json';
import routes from '../fixtures/kong-1.5.1/schema-routes.json';
import consumers from '../fixtures/kong-1.5.1/schema-consumers.json';
import plugins from '../fixtures/kong-1.5.1/schema-plugins.json';
import upstreams from '../fixtures/kong-1.5.1/schema-upstreams.json';
import certificates from '../fixtures/kong-1.5.1/schema-certificates.json';
import cas from '../fixtures/kong-1.5.1/schema-ca_certificates.json';
import snis from '../fixtures/kong-1.5.1/schema-snis.json';
import rateLimiting from '../fixtures/kong-1.5.1/plugin-schema-rate-limiting.json';
import { GOVERNANCE_NATIVE_TYPES, type GovernanceLintContext, type GovernanceNativeType, type LintObject } from '../../apps/console-api/src/modules/governance/lint-types';

/** Recorded 1.5 schemas, explicitly synthetic object graph. Impossible broken
 * FK/unique rows here are rule fixtures, never claimed as native Kong evidence. */
export function lintFixture(objects: readonly LintObject[] = []): GovernanceLintContext {
  return { objects, schemas: { services, routes, consumers, plugins, upstreams, certificates, ca_certificates: cas, snis,
    targets: { fields: [{ id: { type: 'string', uuid: true } }, { target: { type: 'string' } }, { weight: { type: 'integer' } }, { tags: { type: 'set', elements: { type: 'string' } } }] } },
    pluginSchemas: { 'rate-limiting': rateLimiting }, enabledPlugins: ['rate-limiting', 'ip-restriction'],
    collections: GOVERNANCE_NATIVE_TYPES.filter(type => type !== 'targets').map(entityType => ({ entityType, complete: true, extent: 'cluster' })),
    completeness: 'complete', projection: false, scope: { kind: 'cluster', clusterId: randomUUID(), workspaceId: randomUUID() } };
}
export function lintObject(entityType: GovernanceNativeType, payload: Record<string, unknown> = {}): LintObject {
  const nativeId = randomUUID(); return { entityType, nativeId, payload: { id: nativeId, tags: [], ...payload },
    selected: true, annotations: { state: 'readable', description: 'Test description', ownerUserId: randomUUID() } };
}
