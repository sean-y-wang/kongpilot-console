import {describe, expect, it} from 'vitest';
import {currentPromoteRequirements, currentPromoteWindow, validateCurrentPromoteTopology} from '../security/m11-current-promote-natural-http.mjs';

// Pure consistency checks of synthetic public observations. No harness is
// instantiated; no Docker, PostgreSQL, HTTP, credentials or private ledger is
// accessed. Passing these fixtures cannot certify real topology or role ACLs.
const now = Date.parse('2026-10-15T14:00:00.000Z');
const targetUrl = 'http://second-kong-admin:8001';
const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const hash = 'a'.repeat(64);
const flags = () => ({rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, rolcanlogin: true});
function v1(): any {
  const row = (side: string) => ({adminUrl: side === 'source' ? 'http://source-kong-admin:8001' : targetUrl,
    gatewayContainerId: `${side}-gateway-container`, databaseContainerId: `${side}-database-container`, databaseStorageId: `${side}-database-storage`,
    databaseNetworkId: `${side}-database-network`, adminNetworkId: `${side}-admin-network`, kongVersion: '1.5.1'});
  return {version: 1, milestone: 'M11', passed: true, observedAt: new Date(now - 1000).toISOString(), independentDatabases: true,
    migrationsSucceeded: true, adminPortsPublished: false, bffConnectedToKongDatabase: false, exclusiveAdminNetworks: true, source: row('source'), target: row('target')};
}
function v2(privilegedSource = true): any {
  const proof = v1(); proof.version = 2; delete proof.independentDatabases;
  Object.assign(proof, {topologyKind: 'two-kong-shared-postgres-distinct-databases-v1', databaseSeparationVerified: true,
    sharedDatabaseServer: true, sharedStorage: true, independentPostgresProcesses: false, independentFailureDomains: false,
    adminBoundOnlyToDedicatedInterfaces: true, roleIsolationVerified: false, sourceRolePrivileged: privilegedSource, targetRolePrivileged: false});
  for (const [index, side] of ['source', 'target'].entries()) {
    const row = proof[side], databaseOid = 20_001 + index, roleOid = 30_001 + index;
    Object.assign(row, {databaseContainerId: 'shared-postgres-container', databaseStorageId: 'shared-postgres-storage', databaseNetworkId: 'shared-postgres-store-network',
      gatewayNodeId: id(index + 1), gatewayStoreAddress: `172.28.52.${index + 2}`});
    row.databaseEvidence = {postgresMajor: 11, serverSystemIdentifierSha256: hash, databaseName: `kong_${side}`, databaseOid,
      databaseOwnerRoleOid: roleOid, sessionUser: `kong_${side}_role`, sessionUserOid: roleOid, currentUser: `kong_${side}_role`, currentUserOid: roleOid,
      ownConnectionVerified: true, roleFlags: {...flags(), rolsuper: side === 'source' && privilegedSource},
      runtimeConnections: [{gatewayContainerId: row.gatewayContainerId, clientAddress: row.gatewayStoreAddress, datid: databaseOid,
        usesysid: roleOid, backendType: 'client backend', serverSystemIdentifierSha256: hash}]};
  }
  return proof;
}
function acl(): any {
  const proof = v2(false); proof.roleIsolationVerified = true;
  const evidence = (from: 'source' | 'target', to: 'source' | 'target') => ({serverSystemIdentifierSha256: hash,
    fromRoleOid: proof[from].databaseEvidence.sessionUserOid, toDatabaseOid: proof[to].databaseEvidence.databaseOid,
    roleMembershipPathsAbsent: true, foreignDatabaseSessionsAbsent: true,
    effectivePrivileges: {connect: false, create: false, temp: true},
    crossConnect: {phase: 'database-connect', succeeded: false, ownCredentialsVerified: true, sqlState: '42501'}});
  proof.roleIsolationEvidence = {sourceToTarget: evidence('source', 'target'), targetToSource: evidence('target', 'source')}; return proof;
}

describe('current Promote original V1 distinct PostgreSQL resource contract', () => {
  it('retains the original acceptance while making no host-fault-domain or ACL claims', () => {
    expect(validateCurrentPromoteTopology(v1(), targetUrl, now)).toMatchObject({topologyProofVersion: 1,
      topologyKind: 'two-kong-distinct-postgres-resources-v1', databaseSeparationVerified: true, sharedDatabaseServer: false,
      sharedStorage: false, independentPostgresProcesses: true, independentFailureDomains: null, roleIsolationVerified: null});
  });
  it.each(['gatewayContainerId', 'databaseContainerId', 'databaseStorageId', 'databaseNetworkId', 'adminNetworkId'])('still rejects shared %s in the original branch', key => {
    const proof = v1(); proof.target[key] = proof.source[key]; expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
  it.each(['independentDatabases', 'migrationsSucceeded', 'exclusiveAdminNetworks', 'passed'])('still requires original %s', field => {
    const proof = v1(); proof[field] = false; expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
  it('does not route a shared-database V2 proof into the old V1 acceptance', () => {
    const proof = v2(); proof.version = 1; proof.independentDatabases = true; expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
});

describe('current Promote V2 shared PostgreSQL server, actual distinct databases', () => {
  it('accepts actual distinct database/role observations without imposing source Kong role hardening', () => {
    const proof = v2(), before = JSON.stringify(proof), result = validateCurrentPromoteTopology(proof, targetUrl, now);
    expect(result).toMatchObject({topologyProofVersion: 2, topologyKind: proof.topologyKind, databaseSeparationVerified: true,
      sharedDatabaseServer: true, sharedStorage: true, independentPostgresProcesses: false, independentFailureDomains: false,
      sharedFaultDomain: true, sourceRolePrivileged: true, targetRolePrivileged: false, roleIsolationVerified: false});
    expect(Object.isFrozen(result)).toBe(true); expect(JSON.stringify(proof)).toBe(before);
  });
  it('accepts honest false ACL isolation even when both roles are nonprivileged', () => {
    expect(validateCurrentPromoteTopology(v2(false), targetUrl, now)).toMatchObject({sourceRolePrivileged: false, roleIsolationVerified: false});
  });
  it('reports a privileged target honestly without pretending it is a platform ACL pass or forbidding the functional test', () => {
    const proof = v2(); proof.target.databaseEvidence.roleFlags.rolsuper = true; proof.targetRolePrivileged = true;
    expect(validateCurrentPromoteTopology(proof, targetUrl, now)).toMatchObject({sourceRolePrivileged: true, targetRolePrivileged: true, roleIsolationVerified: false});
  });
  it('normalizes canonical decimal OIDs before checking runtime binding', () => {
    const proof = v2();
    for (const side of ['source', 'target']) {
      const db = proof[side].databaseEvidence;
      for (const key of ['databaseOid', 'databaseOwnerRoleOid', 'sessionUserOid', 'currentUserOid']) db[key] = String(db[key]);
      db.runtimeConnections[0].datid = String(db.runtimeConnections[0].datid); db.runtimeConnections[0].usesysid = String(db.runtimeConnections[0].usesysid);
    }
    expect(validateCurrentPromoteTopology(proof, targetUrl, now).databaseSeparationVerified).toBe(true);
  });
  it.each([
    ['unknown version', (p: any) => p.version = 3], ['wrong kind', (p: any) => p.topologyKind = 'url-alias-only'],
    ['legacy ambiguity', (p: any) => p.independentDatabases = true], ['omitted shared server', (p: any) => delete p.sharedDatabaseServer],
    ['false shared storage', (p: any) => p.sharedStorage = false], ['independent PG processes', (p: any) => p.independentPostgresProcesses = true],
    ['independent failure domain', (p: any) => p.independentFailureDomains = true], ['unverified separation', (p: any) => p.databaseSeparationVerified = false],
    ['missing role isolation fact', (p: any) => delete p.roleIsolationVerified], ['concealed source privilege', (p: any) => p.sourceRolePrivileged = false],
    ['concealed target privilege', (p: any) => p.target.databaseEvidence.roleFlags.rolsuper = true],
    ['unbound Admin listener', (p: any) => p.adminBoundOnlyToDedicatedInterfaces = false], ['published Admin', (p: any) => p.adminPortsPublished = true],
    ['BFF on store network', (p: any) => p.bffConnectedToKongDatabase = true], ['nonexclusive Admin', (p: any) => p.exclusiveAdminNetworks = false],
    ['same gateway process', (p: any) => p.target.gatewayContainerId = p.source.gatewayContainerId],
    ['same actual node', (p: any) => p.target.gatewayNodeId = p.source.gatewayNodeId], ['missing node', (p: any) => delete p.target.gatewayNodeId],
    ['same Admin network', (p: any) => p.target.adminNetworkId = p.source.adminNetworkId],
    ['Admin on database network', (p: any) => p.target.adminNetworkId = p.source.databaseNetworkId],
    ['different purported PG container', (p: any) => p.target.databaseContainerId = 'different-container'],
    ['different purported PG storage', (p: any) => p.target.databaseStorageId = 'different-storage'],
    ['different purported PG network', (p: any) => p.target.databaseNetworkId = 'different-network'],
    ['same store IP', (p: any) => p.target.gatewayStoreAddress = p.source.gatewayStoreAddress],
    ['invalid store IP', (p: any) => p.target.gatewayStoreAddress = 'not-an-address'], ['null store IP', (p: any) => p.target.gatewayStoreAddress = null],
    ['loopback store IP', (p: any) => p.target.gatewayStoreAddress = '127.0.0.1'], ['mapped store IP', (p: any) => p.target.gatewayStoreAddress = '::ffff:127.0.0.1'],
    ['expanded mapped store IP', (p: any) => p.target.gatewayStoreAddress = '0:0:0:0:0:ffff:7f00:1'],
    ['missing actual DB evidence', (p: any) => delete p.target.databaseEvidence], ['wrong PG major', (p: any) => p.target.databaseEvidence.postgresMajor = 16],
    ['unverified own connection', (p: any) => p.target.databaseEvidence.ownConnectionVerified = false],
    ['missing actual server identity', (p: any) => delete p.target.databaseEvidence.serverSystemIdentifierSha256],
    ['different actual server', (p: any) => {p.target.databaseEvidence.serverSystemIdentifierSha256 = 'b'.repeat(64); p.target.databaseEvidence.runtimeConnections[0].serverSystemIdentifierSha256 = 'b'.repeat(64);}],
    ['same actual database name', (p: any) => p.target.databaseEvidence.databaseName = p.source.databaseEvidence.databaseName],
    ['same actual database OID', (p: any) => {p.target.databaseEvidence.databaseOid = p.source.databaseEvidence.databaseOid; p.target.databaseEvidence.runtimeConnections[0].datid = p.source.databaseEvidence.databaseOid;}],
    ['same actual login role', (p: any) => {p.target.databaseEvidence.sessionUser = p.source.databaseEvidence.sessionUser; p.target.databaseEvidence.currentUser = p.source.databaseEvidence.currentUser;}],
    ['same actual login OID', (p: any) => {p.target.databaseEvidence.sessionUserOid = p.source.databaseEvidence.sessionUserOid; p.target.databaseEvidence.currentUserOid = p.source.databaseEvidence.currentUserOid; p.target.databaseEvidence.runtimeConnections[0].usesysid = p.source.databaseEvidence.sessionUserOid;}],
    ['SET ROLE substitution', (p: any) => p.target.databaseEvidence.currentUser = 'another_role'],
    ['current-user OID substitution', (p: any) => p.target.databaseEvidence.currentUserOid++],
    ['missing database owner', (p: any) => delete p.target.databaseEvidence.databaseOwnerRoleOid],
    ['missing role flags', (p: any) => delete p.target.databaseEvidence.roleFlags],
    ['string role privilege', (p: any) => p.target.databaseEvidence.roleFlags.rolsuper = 'false'],
    ['nonlogin role', (p: any) => p.target.databaseEvidence.roleFlags.rolcanlogin = false],
    ['empty real connections', (p: any) => p.target.databaseEvidence.runtimeConnections = []],
    ['missing real connections', (p: any) => delete p.target.databaseEvidence.runtimeConnections],
    ['wrong runtime gateway', (p: any) => p.target.databaseEvidence.runtimeConnections[0].gatewayContainerId = p.source.gatewayContainerId],
    ['wrong runtime IP', (p: any) => p.target.databaseEvidence.runtimeConnections[0].clientAddress = p.source.gatewayStoreAddress],
    ['loopback runtime IP', (p: any) => p.target.databaseEvidence.runtimeConnections[0].clientAddress = '127.0.0.1'],
    ['wrong runtime DB', (p: any) => p.target.databaseEvidence.runtimeConnections[0].datid = p.source.databaseEvidence.databaseOid],
    ['wrong runtime role', (p: any) => p.target.databaseEvidence.runtimeConnections[0].usesysid = p.source.databaseEvidence.sessionUserOid],
    ['not a client backend', (p: any) => p.target.databaseEvidence.runtimeConnections[0].backendType = 'autovacuum worker'],
    ['runtime server substitution', (p: any) => p.target.databaseEvidence.runtimeConnections[0].serverSystemIdentifierSha256 = 'b'.repeat(64)],
    ['old observations', (p: any) => p.observedAt = new Date(now - 3_600_001).toISOString()],
    ['future observations', (p: any) => p.observedAt = new Date(now + 5001).toISOString()],
    ['Kong version mismatch', (p: any) => p.target.kongVersion = '3.9.0'],
    ['only source URL alias', (p: any) => p.target.adminUrl = p.source.adminUrl],
  ] as Array<[string, (p: any) => unknown]>)('rejects %s observations rather than treating them as actual DB separation', (_label, mutate) => {
    const proof = v2(); mutate(proof); expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
  it.each([0, -1, 4_294_967_296, 1.5, NaN, '0', '01', ' 123', '123 ', '1e3', '4294967296', '', null, true])('rejects a noncanonical/out-of-range OID %s', value => {
    const proof = v2(); proof.target.databaseEvidence.databaseOid = value; expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
  it('does not accept two textual IPv6 aliases as different store addresses', () => {
    const proof = v2(); proof.source.gatewayStoreAddress = '2001:db8::1'; proof.target.gatewayStoreAddress = '2001:db8:0:0:0:0:0:1';
    expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
  it('does not accept different UUID letter case as two actual Kong nodes', () => {
    const proof = v2(); proof.source.gatewayNodeId = 'abcdef12-abcd-4abc-8abc-abcdef123456'; proof.target.gatewayNodeId = proof.source.gatewayNodeId.toUpperCase();
    expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow('TWO_ACTUAL_KONG_NODE_IDS_REQUIRED');
  });
  it.each(['gatewayContainerId', 'adminNetworkId'])('does not accept hexadecimal case aliases as different %s resources', field => {
    const proof = v2(); proof.source[field] = 'abcde123'.repeat(8); proof.target[field] = proof.source[field].toUpperCase();
    expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow('TWO_ACTUAL_GATEWAY_PROCESSES_AND_ADMIN_NETWORKS_REQUIRED');
  });
  it('accepts consistent IPv6 client-address normalization', () => {
    const proof = v2();
    for (const [index, side] of ['source', 'target'].entries()) {
      proof[side].gatewayStoreAddress = `2001:db8::${index + 1}`;
      proof[side].databaseEvidence.runtimeConnections[0].clientAddress = `2001:db8:0:0:0:0:0:${index + 1}`;
    }
    expect(validateCurrentPromoteTopology(proof, targetUrl, now).databaseSeparationVerified).toBe(true);
  });
});

describe('shared PostgreSQL functional acceptance never fabricates an ACL pass', () => {
  it('reports strong ACL isolation only with nonprivileged roles and both original database-connect refusals', () => {
    expect(validateCurrentPromoteTopology(acl(), targetUrl, now)).toMatchObject({roleIsolationVerified: true, sourceRolePrivileged: false,
      targetRolePrivileged: false, independentFailureDomains: false});
  });
  it.each(['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolreplication', 'rolbypassrls'])('rejects a true ACL claim with original privileged %s', flag => {
    const proof = acl(); proof.source.databaseEvidence.roleFlags[flag] = true; proof.sourceRolePrivileged = true;
    expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow('FALSE_DATABASE_ROLE_ISOLATION_CLAIM');
  });
  it.each([
    ['missing observations', (p: any) => delete p.roleIsolationEvidence], ['one direction only', (p: any) => delete p.roleIsolationEvidence.sourceToTarget],
    ['inherited foreign role', (p: any) => p.roleIsolationEvidence.sourceToTarget.roleMembershipPathsAbsent = false],
    ['existing foreign session', (p: any) => p.roleIsolationEvidence.targetToSource.foreignDatabaseSessionsAbsent = false],
    ['PUBLIC still allows CONNECT', (p: any) => p.roleIsolationEvidence.sourceToTarget.effectivePrivileges.connect = true],
    ['effective cross CREATE', (p: any) => p.roleIsolationEvidence.targetToSource.effectivePrivileges.create = true],
    ['omitted TEMP fact', (p: any) => delete p.roleIsolationEvidence.sourceToTarget.effectivePrivileges.temp],
    ['wrong password', (p: any) => p.roleIsolationEvidence.sourceToTarget.crossConnect.sqlState = '28P01'],
    ['network failure', (p: any) => p.roleIsolationEvidence.targetToSource.crossConnect.sqlState = '08006'],
    ['missing database', (p: any) => p.roleIsolationEvidence.sourceToTarget.crossConnect.sqlState = '3D000'],
    ['unverified original credentials', (p: any) => p.roleIsolationEvidence.sourceToTarget.crossConnect.ownCredentialsVerified = false],
    ['schema denial after connection', (p: any) => p.roleIsolationEvidence.sourceToTarget.crossConnect.phase = 'schema-query'],
    ['successful cross connection', (p: any) => p.roleIsolationEvidence.targetToSource.crossConnect.succeeded = true],
    ['foreign server refusal', (p: any) => p.roleIsolationEvidence.sourceToTarget.serverSystemIdentifierSha256 = 'b'.repeat(64)],
    ['unrelated role refusal', (p: any) => p.roleIsolationEvidence.sourceToTarget.fromRoleOid++],
    ['unrelated database refusal', (p: any) => p.roleIsolationEvidence.targetToSource.toDatabaseOid++],
    ['swapped refusal directions', (p: any) => {const original = p.roleIsolationEvidence.sourceToTarget; p.roleIsolationEvidence.sourceToTarget = p.roleIsolationEvidence.targetToSource; p.roleIsolationEvidence.targetToSource = original;}],
  ] as Array<[string, (p: any) => unknown]>)('rejects an unsupported ACL-isolation claim: %s', (_label, mutate) => {
    const proof = acl(); mutate(proof); expect(() => validateCurrentPromoteTopology(proof, targetUrl, now)).toThrow();
  });
});

describe('Promote evidence documentation and immutable original window', () => {
  it('distinguishes shared failure domains and states that administrative observations are not BFF database access', () => {
    const value = JSON.stringify(currentPromoteRequirements()); expect(value).toContain('two-kong-shared-postgres-distinct-databases-v1');
    expect(value).toContain('roleIsolationVerified'); expect(value).toContain('never BFF database access'); expect(value).toContain('shared');
  });
  it('caps the first window by the actual old expiry rather than extending it by another fourteen minutes', () => {
    const oldExpiry = new Date(now + 800_000).toISOString(), window = currentPromoteWindow(now, [oldExpiry]);
    expect(window.windowEnd).toBe(new Date(Date.parse(oldExpiry) - 5000).toISOString()); expect(window.notBefore).toBe(new Date(now + 240_000).toISOString());
    expect(Object.isFrozen(window)).toBe(true);
  });
  it('rejects an old deadline too short for a legitimate new window instead of renewing it', () => {
    expect(() => currentPromoteWindow(now, [new Date(now + 300_000).toISOString()])).toThrow('ORIGINAL_PROMOTE_DEADLINE_TOO_CLOSE_NO_RENEWAL');
  });
});
