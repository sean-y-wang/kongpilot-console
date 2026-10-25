import 'reflect-metadata';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {BadRequestException, NotFoundException} from '@nestjs/common';
import {EntityChangeCompilerService} from '../../apps/console-api/src/modules/entities/entity-change-compiler.service';
import {EntityService} from '../../apps/console-api/src/modules/entities/entities.service';
import {CREDENTIAL_KINDS, CREDENTIAL_SCHEMAS, type CredentialKind} from '../../apps/console-api/src/modules/entities/entities.types';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {validateKnownFields} from '../../apps/console-api/src/infrastructure/kong/schema';
import {workspaceTag} from '../../apps/console-api/src/infrastructure/kong/tags';
import {normalizeSchema, schemaFields} from '../../apps/console-api/src/modules/config-transfer/schema-normalization';
import {ConfigTransferError} from '../../apps/console-api/src/modules/config-transfer/transfer.types';
import {PAY_WORKSPACE_ID, workspaceTestResolver} from './workspace-test-helper';

const load = (kind: CredentialKind) => JSON.parse(readFileSync(new URL(`../fixtures/kong15-recorded-admin/schema-${CREDENTIAL_SCHEMAS[kind]}.json`, import.meta.url), 'utf8'));
const minimum: Record<CredentialKind, Record<string, unknown>> = {
  'key-auth': {}, 'basic-auth': {username: 'basic-client', password: 'source-unit-basic-password'}, jwt: {},
  oauth2: {name: 'source-unit-app'}, 'hmac-auth': {username: 'hmac-client'}, acls: {group: 'source-unit-team'},
};
/** Public Compiler.prepare + EntityService + actual workspace/authorization
 * policies, using read-only transport/metadata adapters and recorded real
 * Kong 1.5.1 DAO schemas. This fixture neither creates approval/native
 * capability nor asserts runtime credential usability. */
function fixture() {
  const cid = randomUUID(), consumerId = randomUUID(), uid = randomUUID(), sessionId = randomUUID(), secrets = new SecretService();
  const execution = new KongExecutionContextService(), workspace = workspaceTestResolver(cid), actor = {user: {id: uid, username: 'source-admin', superAdmin: true}, workspaceId: PAY_WORKSPACE_ID};
  const consumer = {id: consumerId, username: 'original-parent', tags: [workspaceTag('pay')]};
  const kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => {
      if (method !== 'GET') throw new Error('Compiler preparation attempted a native mutation');
      if (path === `/consumers/${consumerId}`) return structuredClone(consumer);
      throw new NotFoundException({code: 'RECORDED_POINT_ABSENT'});
    }), transportScope: vi.fn(async () => 'af'.repeat(32)),
    prepareSchema: vi.fn(async (_cid: string, path: string, body: unknown) => {
      const parts = path.split('/').filter(Boolean), kind = parts[2] as CredentialKind;
      if (parts[0] !== 'consumers' || parts[1] !== consumerId || !CREDENTIAL_KINDS.includes(kind)) throw new Error('Unknown recorded credential path');
      const recorded = load(kind), schema = recorded.response; validateKnownFields(body, schema);
      return {version: 1, clusterId: cid, canonicalPath: path, nativeType: CREDENTIAL_SCHEMAS[kind], kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1', clusterRevision: 1,
        payloadHmac: secrets.fingerprint(body ?? null), schemaMaterial: {entity: {name: CREDENTIAL_SCHEMAS[kind], canonicalPath: recorded.nativePath, schema}}};
    }),
  };
  const db: any = {one: vi.fn(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM users')) return {id: uid, username: actor.user.username, super_admin: true, status: 'active', permissions_epoch: 1, credential_epoch: 1, force_password_change: false};
    if (sql.includes('FROM auth_sessions')) return {id: sessionId};
    if (sql.includes('FROM iam_epoch')) return {version: 1};
    if (sql.includes('FROM clusters')) return {id: args[0], revision: 1};
    throw new Error(`Unexpected identity read ${sql}`);
  }), query: vi.fn(async () => []), exec: vi.fn(async () => {throw new Error('Preparation must not write SQL');})};
  const authz = new AuthorizationService(db, workspace.resolver, kong, execution), parentAuthorization = vi.spyOn(authz, 'assertNestedParentScope');
  const mutations: any = {execute: vi.fn()}, credentials: any = {save: vi.fn(), getRestorePayload: vi.fn()}, audit: any = {append: vi.fn()}, index: any = {upsert: vi.fn()};
  const entities = new EntityService(kong, authz, mutations, {} as any, credentials, secrets, audit, index, workspace.resolver, execution);
  const compiler = new EntityChangeCompilerService(entities, kong, authz, workspace.resolver, secrets, execution), policy = {assertPacket: vi.fn(), assertStoredSubject: vi.fn()};
  compiler.installPreparationBoundary(policy);
  const run = <T>(fn: () => Promise<T>): Promise<T> => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor.user, sessionId); const close = execution.captureHttpCloser();
    try {return await fn();} finally {close();}
  });
  const prepare = (kind: string, body: Record<string, unknown>) => run(() => compiler.prepare(cid, {kind: 'credential', action: 'create', consumerId, credentialKind: kind, body}, actor));
  const assertZeroWrite = () => {
    for (const write of [mutations.execute, credentials.save, audit.append, index.upsert, db.exec, workspace.db.exec]) expect(write).not.toHaveBeenCalled();
    expect(kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  };
  return {cid, consumerId, actor, secrets, consumer, compiler, kong, credentials, db, policy, parentAuthorization, prepare, assertZeroWrite};
}
beforeEach(() => {vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '7b'.repeat(32)); vi.stubEnv('APP_SECRET', 'nested-credential-source-unit-'.repeat(3));});
afterEach(() => vi.unstubAllEnvs());
describe('M11 nested credential create recorded schema validation', () => {
  it.each(CREDENTIAL_KINDS)('compiles %s with the real required foreign parent while preserving approved wire bytes', async kind => {
    const f = fixture(), input = structuredClone(minimum[kind]), original = structuredClone(input), material = await f.prepare(kind, input), packet = material.packets[0];
    const recorded = load(kind), fields = schemaFields(recorded.response);
    expect(recorded).toMatchObject({credentialValuesRecorded: false, nativePath: `/schemas/${CREDENTIAL_SCHEMAS[kind]}`});
    expect(fields.consumer).toMatchObject({required: true, type: 'foreign', reference: 'consumers'});
    // The underlying real DAO constraint still rejects a standalone payload;
    // the public compiler succeeds only with its server-resolved parent view.
    expect(() => normalizeSchema(packet.body, recorded.response, {defaults: true, required: true})).toThrow(ConfigTransferError);
    expect(packet).toMatchObject({method: 'POST', canonicalPath: `/consumers/${f.consumerId}/${kind}`, nativeType: kind, credentialKind: kind, parentId: f.consumerId,
      before: null, body: {id: packet.nativeId}});
    expect(packet.body).not.toHaveProperty('consumer'); expect(packet.bodyHmac).toBe(f.secrets.fingerprint(packet.body)); expect(input).toEqual(original);
    for (const call of f.kong.prepareSchema.mock.calls) expect(call[2]).not.toHaveProperty('consumer');
    expect(material.schemas[0]).toMatchObject({nativeType: CREDENTIAL_SCHEMAS[kind], payloadHmac: packet.bodyHmac});
    expect(material.prerequisites).toContainEqual(expect.objectContaining({type: 'consumers', path: `/consumers/${f.consumerId}`, nativeId: f.consumerId,
      before: f.consumer, purpose: 'private-parent', fingerprint: f.secrets.fingerprint(f.consumer)}));
    expect(f.parentAuthorization).toHaveBeenCalledWith(f.actor.user, f.cid, 'consumers', f.consumer, kind, 'write', PAY_WORKSPACE_ID, undefined);
    expect(material.metadataObligations).toContainEqual({kind: 'credential-remember', packetKey: packet.key, consumerId: f.consumerId, credentialKind: kind, rawInput: packet.body});
    if (kind === 'key-auth') expect(packet.body?.key).toMatch(/^[a-f\d]{64}$/);
    if (kind === 'jwt') {expect(packet.body?.key).toMatch(/^[a-f\d-]{36}$/); expect(packet.body?.secret).toMatch(/^[a-f\d]{64}$/); expect(packet.body).not.toHaveProperty('algorithm');}
    if (kind === 'oauth2') {expect(packet.body?.client_id).toMatch(/^[a-f\d-]{36}$/); expect(packet.body?.client_secret).toMatch(/^[a-f\d]{64}$/);}
    if (kind === 'hmac-auth') expect(packet.body?.secret).toMatch(/^[a-f\d]{64}$/);
    f.assertZeroWrite();
  });
  it('checks explicit parent ownership before schema processing and strips only an identical resolved relation', async () => {
    const f = fixture(); await expect(f.prepare('key-auth', {consumer: {id: randomUUID()}})).rejects.toMatchObject({status: 400, response: {code: 'PARENT_REFERENCE_IMMUTABLE'}});
    expect(f.kong.prepareSchema).not.toHaveBeenCalled(); f.assertZeroWrite();
    const g = fixture(), input = {consumer: {id: g.consumerId}}, material = await g.prepare('key-auth', input);
    expect(material.packets[0].body).not.toHaveProperty('consumer'); expect(input).toEqual({consumer: {id: g.consumerId}}); g.assertZeroWrite();
  });
  it('rejects unsupported credential kinds before any native read or schema lookup', async () => {
    const f = fixture(); await expect(f.prepare('key-sets', {})).rejects.toMatchObject({status: 400, response: {code: 'UNKNOWN_CREDENTIAL_TYPE'}});
    expect(f.kong.prepareSchema).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled(); f.assertZeroWrite();
  });
  it.each([
    ['basic-auth', {password: 'required-field-secret-sentinel'}, 'username'], ['basic-auth', {username: 'missing-password'}, 'password'],
    ['oauth2', {}, 'name'], ['hmac-auth', {}, 'username'], ['acls', {}, 'group'],
  ] as const)('retains required %s.%s DAO constraints and returns safe 400 fields', async (kind, body, field) => {
    const f = fixture(); let error: any;
    try {await f.prepare(kind, body);} catch (caught) {error = caught;}
    expect(error).toBeInstanceOf(BadRequestException); expect(error.getStatus()).toBe(400);
    expect(error.getResponse()).toMatchObject({code: 'ENTITY_CHANGE_SCHEMA_INVALID', fields: {[field]: 'CONFIGURATION_REQUIRED_FIELD'}});
    expect(JSON.stringify(error.getResponse())).not.toContain('required-field-secret-sentinel'); f.assertZeroWrite();
  });
  it.each([
    ['key-auth', {key: {private: 'schema-secret-sentinel'}}, 'key', 'CONFIGURATION_SCHEMA_VALUE'],
    ['basic-auth', {username: 42, password: 'schema-secret-sentinel'}, 'username', 'CONFIGURATION_SCHEMA_VALUE'],
    ['jwt', {algorithm: 'schema-secret-sentinel'}, 'algorithm', 'CONFIGURATION_SCHEMA_ENUM'],
    ['oauth2', {name: 42, client_secret: 'schema-secret-sentinel'}, 'name', 'CONFIGURATION_SCHEMA_VALUE'],
    ['hmac-auth', {username: false, secret: 'schema-secret-sentinel'}, 'username', 'CONFIGURATION_SCHEMA_VALUE'],
    ['acls', {group: ['schema-secret-sentinel']}, 'group', 'CONFIGURATION_SCHEMA_VALUE'],
  ] as const)('normalizes invalid %s scalar/schema values without echoing secret input', async (kind, body, field, code) => {
    const f = fixture(); let error: any;
    try {await f.prepare(kind, body);} catch (caught) {error = caught;}
    expect(error).toBeInstanceOf(BadRequestException); expect(error.getStatus()).toBe(400);
    const response = error.getResponse(); expect(response).toEqual({code: 'ENTITY_CHANGE_SCHEMA_INVALID', message: '配置不符合当前 Kong schema', fields: {[field]: code}});
    expect(JSON.stringify(response)).not.toContain('schema-secret-sentinel'); f.assertZeroWrite();
  });
  it('rejects an unknown DAO field without echoing its secret value', async () => {
    const f = fixture(); let error: any;
    try {await f.prepare('key-auth', {unsupported_field: 'unknown-secret-sentinel'});} catch (caught) {error = caught;}
    expect(error.getStatus()).toBe(400); expect(error.getResponse()).toMatchObject({code: 'KONG_UNKNOWN_FIELD', fields: {unsupported_field: expect.any(String)}});
    expect(JSON.stringify(error.getResponse())).not.toContain('unknown-secret-sentinel'); f.assertZeroWrite();
  });
});
