import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {closeSync, existsSync, mkdirSync, openSync, readFileSync, writeSync} from 'node:fs';
import {dirname, resolve, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {isIP} from 'node:net';
import {ReleaseHarness, releaseScope} from './lib/release-harness.mjs';

// SOURCE ONLY until Root explicitly invokes one stage. Importing this module
// performs no ledger read, HTTP, Docker, SQL, authentication or timer call.
// This runner never imports historical Portal/Promote fixture IDs. Only the
// current M11 cid/wid/admin and metadataAcceptance.reviewerSession are adopted.
// Root owns Docker topology inspection, runtime/source equality, SQL evidence,
// and Native transport observation. Different URLs do not prove different DBs.
// V1 certifies distinct PG resources. V2 certifies distinct actual databases
// on one PG11 server and explicitly retains the shared storage/failure domain.
export const CURRENT_PROMOTE_STAGES = Object.freeze(['requirements', 'preflight', 'register', 'policy-requests',
  'policy-approval', 'source-fixture', 'target-fixture', 'compare', 'promote', 'apply', 'author', 'approve', 'activate', 'observe']);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const sha = value => createHash('sha256').update(value).digest('hex');
const entity = value => value?.entity ?? value;
const pause = ms => new Promise(done => setTimeout(done, ms));
const safeCode = error => /^[A-Z][A-Z0-9_]{2,120}$/.test(error?.message ?? '') ? error.message : 'CURRENT_PROMOTE_STAGE_ASSERTION_OR_HTTP_FAILURE';

export function currentPromoteRequirements() {
  return {milestone: 'M11',sourceOnly: true, productionAcceptance: false,
    nativeResources: ['A second real Kong OSS 1.5.x process/container and a separate actual Kong PostgreSQL database/login role; never a second node on the current Kong database.',
      'Use either V1 distinct PostgreSQL resources or V2 one shared PG11 server with different real databases/roles. V2 shares server/storage/failure domain and does not certify independent disaster recovery.',
      'Successful Kong migrations bootstrap; healthy second gateway and database. Existing truly independent resources may be used only when their actual Admin endpoint is not already registered; this runner creates a new registry entry and never aliases an existing registered gateway.',
      'A private second Admin network with only that gateway and console-api; no published Admin ports. V2 binds each Admin listener only to its dedicated interface. console-api joins no Kong database network, including a shared store network.',
      'A fixed second Admin hostname allowed by console-api OUTBOUND_ALLOWED_HOSTS. No DNS alias, second node on the first DB, or invented transport_scope.',
      'No extra Redis or Prometheus is required for this isolated Service-only Promote test. Existing console PostgreSQL/Redis remain in use.'],
    rootEvidence: ['A fresh artifacts/M11 public topology proof and its independently calculated SHA256. Do not include passwords or full Docker inspect output.',
      'Proof version=1, passed=true, milestone=M11, observedAt; source/target {adminUrl,gatewayContainerId,databaseContainerId,databaseStorageId,databaseNetworkId,adminNetworkId,kongVersion}.',
      'Proof booleans independentDatabases=true, migrationsSucceeded=true, adminPortsPublished=false, bffConnectedToKongDatabase=false, exclusiveAdminNetworks=true.',
      'Alternatively proof version=2, topologyKind=two-kong-shared-postgres-distinct-databases-v1, databaseSeparationVerified=true, sharedDatabaseServer=true, sharedStorage=true, independentPostgresProcesses=false, independentFailureDomains=false, adminBoundOnlyToDedicatedInterfaces=true; do not reuse the ambiguous V1 independentDatabases field.',
      'V2 source/target retain the V1 resource fields, share the exact databaseContainerId/storage/network, and add different actual gatewayNodeId UUIDs and gatewayStoreAddress IPs.',
      'Each V2 databaseEvidence has postgresMajor=11, serverSystemIdentifierSha256, databaseName/databaseOid/databaseOwnerRoleOid, sessionUser/sessionUserOid/currentUser/currentUserOid, ownConnectionVerified=true, roleFlags {rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolcanlogin}, runtimeConnections [{gatewayContainerId,clientAddress,datid,usesysid,backendType:client backend,serverSystemIdentifierSha256}]. Runtime connections must be actual pg_stat_activity rows, with host(client_addr) matching the actual Docker store IP.',
      'V2 explicitly supplies roleIsolationVerified, sourceRolePrivileged and targetRolePrivileged booleans. False role isolation and actual source superuser are reported, not blocked as platform defects. True role isolation additionally requires both nonprivileged roles plus roleIsolationEvidence.sourceToTarget/targetToSource {serverSystemIdentifierSha256,fromRoleOid,toDatabaseOid,effectivePrivileges:{connect:false,create:false,temp:boolean},roleMembershipPathsAbsent:true,foreignDatabaseSessionsAbsent:true,crossConnect:{phase:database-connect,succeeded:false,ownCredentialsVerified:true,sqlState:42501}}. Each direction must bind the actual server/from-role/foreign-database OIDs. A wrong password or network error never proves CONNECT denial.',
      'Root obtains actual PG identity/OIDs/roles/connection bindings through its own administrative metadata probes, never BFF database access or environment strings alone. The pure validator only checks consistency of supplied observations; it does not independently establish those facts.',
      'The runner checks these assertions and cross-gateway Service ID invisibility; Root must independently inspect actual Docker/database topology. V1 does not establish separate host failure domains or role ACL isolation either.',
      'Root separately verifies BUSINESS_SCHEDULES_ENABLED=true in the deployed API and the natural worker, immutable NULL-SID claim, source-origin bindings, Native ACKs, and audits.'],
    inputs: ['RELEASE_LAB_READY=true and the existing ReleaseHarness M11 private storage/report selectors.',
      'RELEASE_LAB_M11_CURRENT_PROMOTE_READY=true', 'RELEASE_LAB_M11_CURRENT_PROMOTE_TARGET_ADMIN_URL=http://<independent-kong-admin>:8001',
      'RELEASE_LAB_M11_CURRENT_PROMOTE_TOPOLOGY_REPORT=artifacts/M11/<fresh-public-proof>.json',
      'RELEASE_LAB_M11_CURRENT_PROMOTE_TOPOLOGY_SHA256=<actual SHA256>',
      'RELEASE_LAB_M11_CURRENT_PROMOTE_REPORT_DIR=artifacts/M11/runs/<fresh-current-promote-run>'],
    privateCurrentInputs: ['M11 state.cid and state.wid must be the actual active source approval scope.',
      'state.sessions.admin and state.metadataAcceptance.reviewerSession must be genuine distinct currently authorized HTTP identities.',
      'Owner needs current source/target Service write, drift read, Promote read/write, target snapshots/workflows read/write; reviewer needs actual workflow approval and full stored subject/source/target reads.',
      'The existing source native-change policy must already be fmt2 with one any/threshold1 stage selecting the actual reviewer. This runner reuses it and never upgrades source definitions. New target kinds are upgraded only when necessary.',
      'Use fresh original-SID tokens before the fresh comparison/Promote chain. This runner locally rejects every /auth/ call before transport, including any recursive ReleaseHarness refresh; it never logs in or rotates a SID.'],
    stages: CURRENT_PROMOTE_STAGES,
    sequence: 'register independent approval cluster -> reuse the current satisfiable source Native-change policy; upgrade only necessary new target native-change/configuration_v2 definitions through actual policy approval -> create two fresh same-name Services through Native-change approval -> compare -> Promote plan -> target apply pending wrapper -> author scheduled new revision before any vote -> independent fmt2 approval -> activate -> natural business worker',
    scheduling: {totalDeadlineMinutes: 14, notBeforeDelayMinutes: 4, renewal: false, manualTick: false, manualBusinessExecute: false,
      rule: 'The immutable end is capped once by the fresh plan original 14-minute expiry minus 5 seconds; it is never now+14 minutes beyond that original expiry. All visible old deadlines and server-side private authority checks remain required. Expiry is a retained failure, never a reason to extend or replace the original intent.'},
    promoteSelection: {includeEnvironmentFields: false, includeSecrets: false, includeCredentials: false, selectedType: 'services',
      fixture: 'Two fresh equal logical Service names with different native UUIDs; retries/timeouts differ. Existing target host is retained. No Routes, plugins or credentials are promoted.'},
    recovery: 'A failed or unknown stage is never replayed or advanced. The recover stage only reads the original command keys/IDs; an absent receipt never proves no write. Root decides any separately evidenced recovery.'};
}

export function currentPromoteWindow(now, deadlines) {
  assert(Number.isSafeInteger(now) && Array.isArray(deadlines) && deadlines.length > 0, 'ORIGINAL_PROMOTE_DEADLINES_REQUIRED');
  const parsed = deadlines.map(value => {assert(typeof value === 'string' && Number.isFinite(Date.parse(value)), 'ORIGINAL_PROMOTE_DEADLINE_INVALID'); return Date.parse(value);});
  // The real configuration plan was already assigned its fourteen-minute
  // expiry before HTTP plan/job reads finish. Respect that original anchor.
  const notBefore = now + 240_000, windowEnd = Math.min(now + 840_000, Math.min(...parsed) - 5_000);
  assert(windowEnd >= notBefore + 120_000, 'ORIGINAL_PROMOTE_DEADLINE_TOO_CLOSE_NO_RENEWAL');
  return Object.freeze({notBefore: new Date(notBefore).toISOString(), windowStart: new Date(notBefore).toISOString(), windowEnd: new Date(windowEnd).toISOString()});
}

function currentPromoteImportBinding(g, view) {
  const id = g.importPlanId ?? g.planId, p = view?.entity, item = view?.items?.[0];
  assert(uuid(id) && id === g.planId && g.plan?.id === id && uuid(g.importJobId)
    && Number.isInteger(g.plan.planRevision) && g.plan.planRevision === 1 && hex(g.plan.planHash)
    && p?.id === id && p.planId === id && p.jobId === g.importJobId && p.planRevision === g.plan.planRevision
    && p.planHash === g.plan.planHash && p.state === 'ready' && p.clusterId === g.targetCid && p.workspaceId === g.targetWid
    && p.scope === 'services' && p.executionMode === 'approval' && p.approvalRequired === true && p.capabilities?.apply === true
    && p.recoveryComplete === true && p.stepCount === 1 && p.nativePacketCount === 1 && p.deleteCount === 0
    && Array.isArray(p.blockers) && p.blockers.length === 0
    && typeof p.expiresAt === 'string' && Number.isFinite(Date.parse(p.expiresAt))
    && view.nextCursor === null && view.items.length === 1 && item.entityType === 'services' && item.action === 'update'
    && item.nativeId === g.fixtures?.target?.nativeId && item.referenceOnly === false
    && Array.isArray(item.blockerCodes) && item.blockerCodes.length === 0,
  'ORIGINAL_TARGET_IMPORT_PLAN_BINDING_REQUIRED');
  return p;
}

function currentPromoteApplyReceipt(g, result) {
  const id = g.importPlanId ?? g.planId;
  assert(result?.domain === 'configuration' && result.durable === true && result.kind === 'apply'
    && uuid(result.planId) && result.planId.toLowerCase() !== id.toLowerCase() && uuid(result.jobId) && result.id === result.jobId
    && result.jobId.toLowerCase() !== g.importJobId.toLowerCase()
    && uuid(result.workflowId) && result.planRevision === g.plan.planRevision && result.planHash === g.plan.planHash
    && result.state === 'waiting_approval' && result.executionMode === 'approval' && result.approvalRequired === true
    && result.executionCompleted === false && result.executionId === null && result.registrationCompleted === true && result.submissionCompleted === true
    && result.clusterId === g.targetCid && result.workspaceId === g.targetWid && result.actorId === g.subjects?.admin?.id
    && uuid(g.commands?.['apply:register-workflow']?.key) && result.idempotencyKey === g.commands['apply:register-workflow'].key
    && result.originalScope?.clusterId === g.targetCid && result.originalScope.workspaceId === g.targetWid,
  'REAL_APPROVAL_ONLY_TARGET_APPLY_WRAPPER_REQUIRED');
}

/** freezePlan copies the original manifest into a new apply-job-owned plan.
 * Public plan/job/wrapper reads bind that fork; private SQL origin evidence
 * still belongs to the backend and Root's independent runtime verification. */
export function currentPromoteApplyBinding(g, result, {importPlan, applyPlan, workflow}) {
  const source = currentPromoteImportBinding(g, importPlan); currentPromoteApplyReceipt(g, result);
  const p = applyPlan?.entity, item = applyPlan?.items?.[0];
  assert(p?.id === result.planId && p.planId === result.planId && p.jobId === result.jobId
    && p.planRevision === source.planRevision && p.planHash === source.planHash && p.expiresAt === source.expiresAt
    && p.clusterId === g.targetCid && p.workspaceId === g.targetWid && p.scope === 'services' && p.state === 'pending_approval'
    && p.executionMode === 'approval' && p.approvalRequired === true && p.recoveryComplete === true
    && p.stepCount === 1 && p.nativePacketCount === 1 && p.deleteCount === 0 && Array.isArray(p.blockers) && p.blockers.length === 0
    && applyPlan.nextCursor === null && applyPlan.items.length === 1
    && item.entityType === 'services' && item.action === 'update' && item.nativeId === g.fixtures.target.nativeId
    && item.referenceOnly === false && Array.isArray(item.blockerCodes) && item.blockerCodes.length === 0,
  'NEW_APPLY_PLAN_ORIGINAL_MANIFEST_BINDING_REQUIRED');
  const row = workflow?.entity, step = workflow?.steps?.[0], diff = workflow?.diff?.[0];
  assert(row?.id === result.workflowId && row.clusterId === g.targetCid && row.workspaceId === g.targetWid
    && row.kind === 'configuration_v2' && row.state === 'pending' && row.executionMode === 'approval' && row.approvalRequired === true
    && Number.isInteger(row.planRevision) && row.planRevision === 1 && hex(row.planHash) && row.approval?.format === 2
    && workflow.decisions?.length === 0 && workflow.steps?.length === 1 && uuid(step.id) && step.kind === 'metadata'
    && step.name === 'configuration_v2' && step.state === 'pending' && step.operationId === null
    && workflow.impact?.subject?.type === 'configuration_jobs' && workflow.impact.subject.id === result.jobId && workflow.impact.nativeRequests === 0
    && workflow.diff?.length === 1 && diff.id === step.id && diff.kind === 'metadata' && diff.operation === 'configuration_v2'
    && diff.entityType === 'configuration_jobs' && diff.entityId === result.jobId && diff.before?.id === result.jobId
    && diff.before.kind === 'apply' && diff.after?.jobId === result.jobId,
  'UNVOTED_REAL_CONFIGURATION_FMT2_WRAPPER_REQUIRED');
  return Object.freeze({importPlanId: source.id, applyPlanId: p.id, applyJobId: result.jobId, workflowId: result.workflowId,
    planRevision: source.planRevision, planHash: source.planHash});
}

const resourceId = value => typeof value === 'string' && value.length >= 8 && value.length <= 256;
const resourceIdentity = value => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : value;
const pgName = value => typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 1
  && Buffer.byteLength(value, 'utf8') <= 63 && !/[\u0000-\u001f\u007f]/.test(value);
function oid(value) {
  assert(typeof value === 'number' && Number.isSafeInteger(value) || typeof value === 'string' && /^[1-9][0-9]{0,9}$/.test(value), 'ACTUAL_POSTGRES_OID_REQUIRED');
  const number = Number(value); assert(number >= 1 && number <= 4_294_967_295, 'ACTUAL_POSTGRES_OID_REQUIRED'); return number;
}
const roleFlagNames = Object.freeze(['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolreplication', 'rolbypassrls', 'rolcanlogin']);
const privilegedRole = flags => roleFlagNames.filter(key => key !== 'rolcanlogin').some(key => flags[key]);
function storeIp(value) {
  if (typeof value !== 'string' || !isIP(value) || value.toLowerCase().startsWith('::ffff:')) return null;
  const normalized = isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value;
  return /^127\./.test(normalized) || normalized.toLowerCase().startsWith('::ffff:') || ['0.0.0.0', '::', '::1'].includes(normalized) ? null : normalized;
}

/** Pure Source contract for Root's separately collected observations. This
 * does not query Docker/PG, authenticate evidence, mint backend authority or
 * replace the proof-file SHA, actual transport supervision and SQL checks. */
export function validateCurrentPromoteTopology(proof, targetAdminUrl, now = Date.now()) {
  assert(Number.isSafeInteger(now), 'CURRENT_TOPOLOGY_OBSERVATION_REQUIRED');
  assert(proof && [1, 2].includes(proof.version) && proof.milestone === 'M11' && proof.passed === true
    && proof.migrationsSucceeded === true && proof.adminPortsPublished === false && proof.bffConnectedToKongDatabase === false
    && proof.exclusiveAdminNetworks === true, 'ROOT_INDEPENDENT_NATIVE_TOPOLOGY_REQUIRED');
  assert(Number.isFinite(Date.parse(proof.observedAt)) && Date.parse(proof.observedAt) <= now + 5_000
    && now - Date.parse(proof.observedAt) < 3_600_000, 'CURRENT_TOPOLOGY_OBSERVATION_REQUIRED');
  let facts;
  if (proof.version === 1) {
    // Preserve every original V1 resource-separation gate. A shared-server
    // proof cannot turn this branch into a looser OR of the original checks.
    assert(proof.independentDatabases === true, 'ROOT_INDEPENDENT_NATIVE_TOPOLOGY_REQUIRED');
    for (const side of ['source', 'target']) {
      const row = proof[side]; assert(row && /^1\.5\.\d+$/.test(row.kongVersion) && typeof row.adminUrl === 'string', 'ACTUAL_BOTH_KONG15_TOPOLOGY_REQUIRED');
      for (const key of ['gatewayContainerId', 'databaseContainerId', 'databaseStorageId', 'databaseNetworkId', 'adminNetworkId']) {
        assert(resourceId(row[key]), 'ACTUAL_NATIVE_TOPOLOGY_RESOURCE_ID_REQUIRED');
        assert.notEqual(row[key], proof[side === 'source' ? 'target' : 'source']?.[key], 'SECOND_NATIVE_ENVIRONMENT_MUST_BE_PHYSICALLY_DISTINCT');
      }
    }
    facts = {topologyProofVersion: 1, topologyKind: 'two-kong-distinct-postgres-resources-v1', databaseSeparationVerified: true,
      sharedDatabaseServer: false, sharedStorage: false, independentPostgresProcesses: true,
      independentFailureDomains: null, sharedFaultDomain: null, roleIsolationVerified: null, sourceRolePrivileged: null, targetRolePrivileged: null};
  } else {
    assert(proof.topologyKind === 'two-kong-shared-postgres-distinct-databases-v1'
      && proof.databaseSeparationVerified === true && proof.sharedDatabaseServer === true && proof.sharedStorage === true
      && proof.independentPostgresProcesses === false && proof.independentFailureDomains === false
      && proof.adminBoundOnlyToDedicatedInterfaces === true && !Object.hasOwn(proof, 'independentDatabases')
      && typeof proof.roleIsolationVerified === 'boolean' && typeof proof.sourceRolePrivileged === 'boolean'
      && typeof proof.targetRolePrivileged === 'boolean', 'EXPLICIT_SHARED_POSTGRES_DATABASE_TOPOLOGY_REQUIRED');
    const databases = {};
    for (const side of ['source', 'target']) {
      const row = proof[side], other = proof[side === 'source' ? 'target' : 'source'];
      assert(row && other && /^1\.5\.\d+$/.test(row.kongVersion) && typeof row.adminUrl === 'string', 'ACTUAL_BOTH_KONG15_TOPOLOGY_REQUIRED');
      for (const key of ['gatewayContainerId', 'databaseContainerId', 'databaseStorageId', 'databaseNetworkId', 'adminNetworkId']) {
        assert(resourceId(row[key]), 'ACTUAL_NATIVE_TOPOLOGY_RESOURCE_ID_REQUIRED');
        if (key === 'gatewayContainerId' || key === 'adminNetworkId') assert.notEqual(resourceIdentity(row[key]), resourceIdentity(other[key]), 'TWO_ACTUAL_GATEWAY_PROCESSES_AND_ADMIN_NETWORKS_REQUIRED');
        else assert.equal(resourceIdentity(row[key]), resourceIdentity(other[key]), 'EXACT_SHARED_POSTGRES_RESOURCES_REQUIRED');
      }
      assert(resourceIdentity(row.adminNetworkId) !== resourceIdentity(row.databaseNetworkId) && resourceIdentity(row.adminNetworkId) !== resourceIdentity(other.databaseNetworkId),
        'ADMIN_AND_POSTGRES_NETWORKS_MUST_REMAIN_SEPARATE');
      assert(uuid(row.gatewayNodeId) && uuid(other.gatewayNodeId) && row.gatewayNodeId.toLowerCase() !== other.gatewayNodeId.toLowerCase(), 'TWO_ACTUAL_KONG_NODE_IDS_REQUIRED');
      assert(storeIp(row.gatewayStoreAddress) && storeIp(row.gatewayStoreAddress) !== storeIp(other.gatewayStoreAddress), 'TWO_ACTUAL_GATEWAY_STORE_IPS_REQUIRED');
      const db = row.databaseEvidence, flags = db?.roleFlags;
      assert(db && db.postgresMajor === 11 && hex(db.serverSystemIdentifierSha256)
        && db.ownConnectionVerified === true && pgName(db.databaseName) && pgName(db.sessionUser) && pgName(db.currentUser), 'ACTUAL_POSTGRES_DATABASE_AND_LOGIN_EVIDENCE_REQUIRED');
      const databaseOid = oid(db.databaseOid), roleOid = oid(db.sessionUserOid); oid(db.databaseOwnerRoleOid);
      assert(db.sessionUser === db.currentUser && roleOid === oid(db.currentUserOid), 'ORIGINAL_POSTGRES_LOGIN_ROLE_REQUIRED');
      assert(flags && roleFlagNames.every(key => typeof flags[key] === 'boolean') && flags.rolcanlogin === true,
        'ACTUAL_POSTGRES_ROLE_FLAGS_REQUIRED');
      assert(proof[`${side}RolePrivileged`] === privilegedRole(flags), 'POSTGRES_ROLE_PRIVILEGE_REPORT_MISMATCH');
      assert(Array.isArray(db.runtimeConnections) && db.runtimeConnections.length >= 1 && db.runtimeConnections.length <= 100,
        'ACTUAL_GATEWAY_POSTGRES_CONNECTION_BINDING_REQUIRED');
      for (const connection of db.runtimeConnections) {
        assert(connection && connection.gatewayContainerId === row.gatewayContainerId
          && connection.backendType === 'client backend' && storeIp(connection.clientAddress) === storeIp(row.gatewayStoreAddress)
          && connection.serverSystemIdentifierSha256 === db.serverSystemIdentifierSha256
          && oid(connection.datid) === databaseOid && oid(connection.usesysid) === roleOid,
          'ACTUAL_GATEWAY_POSTGRES_CONNECTION_BINDING_REQUIRED');
      }
      databases[side] = {databaseName: db.databaseName, databaseOid, roleName: db.sessionUser, roleOid, serverHash: db.serverSystemIdentifierSha256};
    }
    assert(databases.source.serverHash === databases.target.serverHash, 'ONE_ACTUAL_SHARED_POSTGRES_SERVER_REQUIRED');
    assert(databases.source.databaseName !== databases.target.databaseName && databases.source.databaseOid !== databases.target.databaseOid,
      'DIFFERENT_ACTUAL_KONG_DATABASES_REQUIRED');
    assert(databases.source.roleName !== databases.target.roleName && databases.source.roleOid !== databases.target.roleOid,
      'DIFFERENT_ACTUAL_KONG_LOGIN_ROLES_REQUIRED');
    if (proof.roleIsolationVerified) {
      // False is a valid, honest functional acceptance profile. Reject only a
      // claim of ACL isolation that contradicts privilege or refusal evidence.
      assert(!proof.sourceRolePrivileged && !proof.targetRolePrivileged, 'FALSE_DATABASE_ROLE_ISOLATION_CLAIM');
      for (const direction of ['sourceToTarget', 'targetToSource']) {
        const evidence = proof.roleIsolationEvidence?.[direction], privileges = evidence?.effectivePrivileges, refused = evidence?.crossConnect;
        const from = databases[direction === 'sourceToTarget' ? 'source' : 'target'], to = databases[direction === 'sourceToTarget' ? 'target' : 'source'];
        assert(evidence?.roleMembershipPathsAbsent === true && evidence.foreignDatabaseSessionsAbsent === true
          && evidence.serverSystemIdentifierSha256 === from.serverHash && oid(evidence.fromRoleOid) === from.roleOid && oid(evidence.toDatabaseOid) === to.databaseOid
          && privileges?.connect === false && privileges.create === false && typeof privileges.temp === 'boolean'
          && refused?.phase === 'database-connect' && refused.succeeded === false && refused.ownCredentialsVerified === true
          && refused.sqlState === '42501', 'FALSE_DATABASE_ROLE_ISOLATION_CLAIM');
      }
    }
    facts = {topologyProofVersion: 2, topologyKind: proof.topologyKind, databaseSeparationVerified: true,
      sharedDatabaseServer: true, sharedStorage: true, independentPostgresProcesses: false, independentFailureDomains: false,
      sharedFaultDomain: true, roleIsolationVerified: proof.roleIsolationVerified,
      sourceRolePrivileged: proof.sourceRolePrivileged, targetRolePrivileged: proof.targetRolePrivileged};
  }
  const normalized = new URL(targetAdminUrl).toString().replace(/\/$/, '');
  assert.equal(new URL(proof.target.adminUrl).toString().replace(/\/$/, ''), normalized, 'ACTUAL_SECOND_ADMIN_TOPOLOGY_ENDPOINT_REQUIRED');
  const sourceAdminUrl = new URL(proof.source.adminUrl).toString().replace(/\/$/, '');
  assert.notEqual(sourceAdminUrl, normalized, 'SOURCE_ADMIN_ALIAS_IS_NOT_SECOND_NATIVE_ENVIRONMENT');
  return Object.freeze({...facts, sourceAdminUrl, targetAdminUrl: normalized});
}

function configuration(env) {
  assert.equal(env.RELEASE_LAB_M11_CURRENT_PROMOTE_READY, 'true', 'ROOT_EXPLICIT_CURRENT_PROMOTE_GATE_REQUIRED');
  const raw = env.RELEASE_LAB_M11_CURRENT_PROMOTE_TARGET_ADMIN_URL, target = new URL(raw);
  assert(['http:', 'https:'].includes(target.protocol) && !target.username && !target.password && !target.search && !target.hash
    && !/%2f|%5c|%00/i.test(target.pathname) && !target.hostname.endsWith('.'), 'SECOND_REAL_KONG_ADMIN_ENDPOINT_REQUIRED');
  const publicRoot = resolve('artifacts/M11'), reportDirectory = resolve(env.RELEASE_LAB_M11_CURRENT_PROMOTE_REPORT_DIR ?? '');
  const proofPath = resolve(env.RELEASE_LAB_M11_CURRENT_PROMOTE_TOPOLOGY_REPORT ?? '');
  assert(reportDirectory.startsWith(publicRoot + sep) && proofPath.startsWith(publicRoot + sep), 'CURRENT_M11_PUBLIC_REPORT_PATH_REQUIRED');
  assert(hex(env.RELEASE_LAB_M11_CURRENT_PROMOTE_TOPOLOGY_SHA256), 'ROOT_ACTUAL_TOPOLOGY_SHA256_REQUIRED');
  const bytes = readFileSync(proofPath); assert(bytes.length <= 128 * 1024 && sha(bytes) === env.RELEASE_LAB_M11_CURRENT_PROMOTE_TOPOLOGY_SHA256, 'ORIGINAL_PUBLIC_TOPOLOGY_PROOF_HASH_REQUIRED');
  const proof = JSON.parse(bytes.toString('utf8'));
  const topology = validateCurrentPromoteTopology(proof, target.toString());
  return {...topology,
    topologySha256: sha(bytes), reportDirectory, proofObservedAt: proof.observedAt};
}

function session(h, g, label, minRemainingMs = 120_000) {
  const value = label === 'admin' ? h.state.sessions.admin : h.state.metadataAcceptance?.reviewerSession;
  assert(uuid(value?.user?.id) && uuid(value.sid) && typeof value.cookie === 'string' && typeof value.csrf === 'string', 'CURRENT_REAL_CONSOLE_SESSION_REQUIRED');
  const access = value.cookie.split('; ').find(part => part.startsWith('kongos_access=')); assert(access, 'CURRENT_REAL_ACCESS_COOKIE_REQUIRED');
  let claims; try {claims = JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1], 'base64url').toString('utf8'));} catch {throw Error('CURRENT_REAL_ACCESS_COOKIE_INVALID');}
  assert(claims.sub === value.user.id && claims.sid === value.sid && Number.isFinite(claims.exp)
    && claims.exp * 1000 > Date.now() + minRemainingMs, 'FRESH_ORIGINAL_SID_TOKEN_REQUIRED_NO_IMPLICIT_REFRESH');
  if (g?.subjects) assert.deepEqual({id: value.user.id, sid: value.sid}, g.subjects[label], 'ORIGINAL_CURRENT_PROMOTE_ACTOR_OR_SID_CHANGED');
  return value;
}

async function read(h, g, path, {reviewer = false, expected = [200]} = {}) {
  return (await h.request(session(h, g, reviewer ? 'reviewer' : 'admin'), path, 'GET', undefined, {expected}));
}

async function once(h, g, stage, label, path, body, {reviewer = false, method = 'POST', receiptPath} = {}) {
  const identity = `${stage}:${label}`, actualLabel = `m11-current-promote-${identity}`;
  assert(!Object.hasOwn(g.commands, identity) && !h.state.requests.some(packet => packet.label === actualLabel), 'ORIGINAL_PROMOTE_PACKET_PRESENT_NO_REPLAY');
  const actual = session(h, g, reviewer ? 'reviewer' : 'admin'), key = randomUUID();
  g.commands[identity] = {key, label: actualLabel, path, method, actor: reviewer ? 'reviewer' : 'admin',
    bodyHash: sha(JSON.stringify(body) ?? 'null'), receiptPath: typeof receiptPath === 'function' ? receiptPath(key) : receiptPath ?? null}; h.save();
  const result = await h.once(actualLabel, actual, path, method, body, {key, expected: [200, 201]});
  const packets = h.state.requests.filter(packet => packet.key === key && packet.path === path && packet.method === method);
  assert(packets.length === 1 && packets[0].label === actualLabel && packets[0].state === 'response_observed'
    && packets[0].actorId === actual.user.id && packets[0].sessionId === actual.sid && packets[0].status === result.status,
    'ORIGINAL_PROMOTE_OPERATION_PACKET_REQUIRED');
  g.commands[identity].requestId = result.requestId; h.save(); return result.data;
}

function scope(g, side, suffix, extra = {}) {return releaseScope(side === 'source' ? g.sourceCid : g.targetCid,
  side === 'source' ? g.sourceWid : g.targetWid, suffix, extra);}
function finished(g, stage) {assert(g.runs[stage]?.state === 'succeeded', 'PREVIOUS_ORIGINAL_PROMOTE_STAGE_REQUIRED');}
function retainDeadlines(g, ...values) {
  for (const value of values) for (const candidate of [value?.expiresAt, value?.authorityExpiresAt, value?.job?.expiresAt, value?.job?.authorityExpiresAt]) {
    if (typeof candidate === 'string' && Number.isFinite(Date.parse(candidate)) && !g.deadlines.includes(candidate)) g.deadlines.push(candidate);
  }
}
function assertWindow(g) {
  assert(g.window && Date.now() < Date.parse(g.window.windowEnd), 'ORIGINAL_PROMOTE_WINDOW_EXPIRED_NO_REARM');
  assert(g.deadlines.length && g.deadlines.every(value => Date.parse(g.window.windowEnd) <= Date.parse(value)), 'ORIGINAL_PROMOTE_DEADLINE_CHANGED_NO_RENEWAL');
}

async function definitions(h, g, side) {
  const value = (await read(h, g, scope(g, side, 'workflow-definitions', {size: '100'}))).data;
  assert(Array.isArray(value.items) && !value.nextCursor, 'COMPLETE_CURRENT_WORKFLOW_DEFINITION_PAGE_REQUIRED'); return value.items;
}

function singleCurrentReviewerPolicy(definition, reviewerId) {
  const policy = definition?.policy, stage = policy?.stages?.[0];
  return definition?.format === 2 && definition.status === 'active' && hex(definition.policyHash)
    && policy?.version === 2 && policy.kind === definition.kind && policy.allowSelfApproval === false
    && policy.distinctAcrossStages === true && Array.isArray(policy.stages) && policy.stages.length === 1 && stage.level === 1 && stage.mode === 'any'
    && stage.threshold === 1 && stage.selector && Object.keys(stage.selector).length === 1
    && Array.isArray(stage.selector.users) && stage.selector.users.length === 1 && stage.selector.users[0] === reviewerId;
}

async function vote(h, g, stage, label, side, workflowId, {format2 = true} = {}) {
  const path = suffix => scope(g, side, suffix), reviewer = session(h, g, 'reviewer');
  const before = entity((await read(h, g, path(`workflows/${workflowId}`), {reviewer: true})).data);
  assert(before.id === workflowId && before.state === 'pending' && before.approvalRequired && before.capabilities?.approve === true,
    'ACTUAL_INDEPENDENT_CURRENT_CANDIDATE_REQUIRED');
  assert(reviewer.user.id !== g.subjects.admin.id, 'INDEPENDENT_PROMOTE_REVIEWER_REQUIRED');
  const active = before.approval?.stages?.find(row => row.state === 'active');
  if (format2 || before.approval) assert(before.approval?.format === 2 && active && Number.isInteger(before.approval.candidateVersion), 'ACTUAL_FROZEN_FORMAT2_CANDIDATE_REQUIRED');
  const body = {revision: before.revision, planHash: before.planHash, confirmed: true, confirm_name: before.kind, execute: false,
    ...(before.approval ? {level: active?.level, stageRevision: active?.revision, candidateVersion: before.approval.candidateVersion} : {})};
  await once(h, g, stage, label, path(`workflows/${workflowId}/approve`), body, {reviewer: true,
    receiptPath: key => path(`workflows/receipts/by-key/${key}`)});
  const after = entity((await read(h, g, path(`workflows/${workflowId}`))).data);
  assert(after.state === 'approved' && (!format2 || hex(after.approval?.approvalSetHmac) || uuid(after.approval?.approvalSetId)), 'ACTUAL_COMPLETE_INDEPENDENT_APPROVAL_SET_REQUIRED'); return after;
}

async function fixtureWorkflow(h, g, stage, side) {
  const path = suffix => scope(g, side, suffix), currentDefinitions = await definitions(h, g, side);
  assert(currentDefinitions.some(value => value.kind === 'native-change' && value.format === 2 && value.status === 'active'), 'FUTURE_NATIVE_FIXTURE_FORMAT2_POLICY_REQUIRED');
  const body = {name: g.serviceName, protocol: 'http', host: `${side}-m11-promote.invalid`, port: 80, retries: side === 'source' ? 1 : 4,
    connect_timeout: side === 'source' ? 3300 : 6600, read_timeout: side === 'source' ? 4300 : 7600,
    write_timeout: side === 'source' ? 5300 : 8600, tags: ['owner:m11-acceptance', 'team:m11-current-promote', g.fixtureTag]};
  const intent = await once(h, g, stage, 'prepare', path('entity-changes/prepare'), {change: {kind: 'entity', action: 'create', entityType: 'services', body}},
    {receiptPath: key => path(`entity-changes/by-prepare-key/${key}`)});
  assert(uuid(intent.id) && Number.isInteger(intent.revision) && hex(intent.materialHmac) && intent.capabilities?.submit === true && intent.nativeExecutionAvailable === false,
    'REAL_FRESH_SERVICE_INTENT_REQUIRED');
  assert(intent.review?.changes?.length === 1 && intent.review.changes[0].entityType === 'services' && intent.review.changes[0].action === 'create'
    && uuid(intent.review.changes[0].nativeId), 'ONE_ORIGINAL_SERVICE_CREATE_PACKET_REQUIRED');
  const record = g.fixtures[side] = {intentId: intent.id, nativeId: intent.review.changes[0].nativeId, requested: body}; h.save();
  const submit = await once(h, g, stage, 'submit', path(`entity-changes/${intent.id}/submit`),
    {revision: intent.revision, materialHmac: intent.materialHmac, confirmed: true, confirm_name: 'native-change'},
    {receiptPath: key => path(`workflows/receipts/by-key/${key}`)});
  assert(uuid(submit.workflowId), 'FRESH_SERVICE_WORKFLOW_REQUIRED'); record.workflowId = submit.workflowId; h.save();
  const approved = await vote(h, g, stage, 'vote', side, submit.workflowId);
  const result = await once(h, g, stage, 'execute', path(`workflows/${submit.workflowId}/execute`),
    {revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: 'native-change'},
    {receiptPath: key => path(`workflows/receipts/by-key/${key}`)});
  assert(result.state === 'succeeded' && uuid(result.executionId), 'ACTUAL_FIXTURE_NATIVE_SUCCESS_REQUIRED'); record.executionId = result.executionId;
  const detail = (await read(h, g, path(`workflows/${submit.workflowId}`))).data;
  assert(detail.entity.state === 'succeeded' && detail.nativeChange?.packets?.length === 1 && detail.nativeChange.packets[0].state === 'succeeded'
    && detail.nativeChange.packets[0].nativeStatus === 201, 'ACTUAL_ORIGINAL_SERVICE_201_RECEIPT_REQUIRED');
  const service = entity((await read(h, g, path(`entities/services/${record.nativeId}`))).data);
  assert(service.id === record.nativeId && service.name === g.serviceName && service.retries === body.retries && service.read_timeout === body.read_timeout,
    'ACTUAL_FRESH_FIXTURE_READBACK_REQUIRED'); record.before = service; h.save();
}

async function stageRun(h, g, stage) {
  if (stage === 'preflight') {
    const source = (await read(h, g, `/clusters/${g.sourceCid}`)).data;
    assert(source.execution_mode === 'approval' && source.status === 'healthy' && /^1\.5\.\d+$/.test(source.version ?? '')
      && new URL(source.admin_url).toString().replace(/\/$/, '') === g.configuration.sourceAdminUrl, 'CURRENT_REAL_APPROVAL_SOURCE_REQUIRED');
    const workspace = (await read(h, g, `/clusters/${g.sourceCid}/workspaces/${g.sourceWid}`)).data;
    assert(workspace.id === g.sourceWid && workspace.status === 'active', 'CURRENT_REAL_SOURCE_WORKSPACE_REQUIRED');
    const clusters = (await read(h, g, '/clusters')).data;
    assert(Array.isArray(clusters) && !clusters.some(row => new URL(row.admin_url).toString().replace(/\/$/, '') === g.configuration.targetAdminUrl),
      'NEW_SECOND_NATIVE_CLUSTER_REGISTRATION_REQUIRED');
    g.sourceRevision = source.revision; g.sourceWorkspaceRevision = workspace.revision; h.save();
  } else if (stage === 'register') {
    finished(g, 'preflight');
    const target = await once(h, g, stage, 'cluster', '/clusters', {name: g.targetName, environment: 'm11-isolated-promote',
      admin_url: g.configuration.targetAdminUrl, execution_mode: 'approval', labels: [g.fixtureTag]});
    assert(uuid(target.id) && target.execution_mode === 'approval', 'NEW_REAL_APPROVAL_TARGET_CLUSTER_REQUIRED'); g.targetCid = target.id; h.save();
    const probe = await once(h, g, stage, 'probe', `/clusters/${g.targetCid}/probe`, {});
    assert(probe.cluster_id === g.targetCid && probe.status === 'healthy' && /^1\.5\.\d+$/.test(probe.version ?? ''), 'ACTUAL_SECOND_KONG15_PROBE_REQUIRED');
    const workspaces = (await read(h, g, `/clusters/${g.targetCid}/workspaces?size=100`)).data;
    assert(Array.isArray(workspaces.items) && !workspaces.nextCursor, 'COMPLETE_CURRENT_TARGET_WORKSPACE_PAGE_REQUIRED');
    const defaults = workspaces.items.filter(row => row.is_default && row.status === 'active'); assert.equal(defaults.length, 1, 'ACTUAL_TARGET_DEFAULT_WORKSPACE_REQUIRED');
    g.targetWid = defaults[0].id; g.targetRevision = target.revision; g.targetWorkspaceRevision = defaults[0].revision; h.save();
    // GET definitions never seeds them. A real public preparation commits the
    // server's default definitions without submission, approval or Native send.
    // Its original key/intent are retained; it is never adopted as a fixture.
    const bootstrap = await once(h, g, stage, 'initialize-definitions', scope(g, 'target', 'entity-changes/prepare'),
      {change: {kind: 'entity', action: 'create', entityType: 'services', body: {name: `${g.serviceName}-definition-init`,
        protocol: 'http', host: 'm11-promote.invalid', port: 80, tags: ['owner:m11-acceptance', g.fixtureTag]}}, ttlHours: 1},
      {receiptPath: key => scope(g, 'target', `entity-changes/by-prepare-key/${key}`)});
    assert(uuid(bootstrap.id) && bootstrap.nativeExecutionAvailable === false && bootstrap.review?.changes?.length === 1
      && bootstrap.review.changes[0].action === 'create', 'REAL_UNSUBMITTED_DEFINITION_BOOTSTRAP_INTENT_REQUIRED');
    g.definitionBootstrapIntentId = bootstrap.id; h.save();
    assert((await definitions(h, g, 'target')).some(row => row.kind === 'configuration_v2'), 'REAL_DEFAULT_TARGET_DEFINITIONS_COMMITTED_REQUIRED');
  } else if (stage === 'policy-requests') {
    finished(g, 'register');
    for (const [side, kind] of [['source', 'native-change'], ['target', 'native-change'], ['target', 'configuration_v2']]) {
      const list = await definitions(h, g, side), matches = list.filter(row => row.kind === kind && row.status === 'active');
      assert.equal(matches.length, 1, 'ONE_ACTIVE_ORIGINAL_POLICY_DEFINITION_REQUIRED'); const definition = matches[0];
      if (singleCurrentReviewerPolicy(definition, g.subjects.reviewer.id)) {
        g.policies.push({side, kind, definitionId: definition.id, originalVersion: definition.version,
          reused: true, originalPolicyHash: definition.policyHash}); h.save(); continue;
      }
      // The source is an existing current acceptance scope. Do not invalidate
      // any of its original intents by replacing a previously frozen policy.
      assert(side === 'target', 'CURRENT_SOURCE_SATISFIABLE_FMT2_REVIEWER_POLICY_REQUIRED_NO_AUTOMATIC_CHANGE');
      const policy = {version: 2, kind, allowSelfApproval: false, distinctAcrossStages: true, intentTtlHours: 24,
        stages: [{level: 1, name: '独立验收审批', mode: 'any', threshold: 1, selector: {users: [g.subjects.reviewer.id]}}]};
      const result = await once(h, g, stage, `${side}-${kind}`, scope(g, side, `workflow-definitions/${definition.id}/versions`),
        {revision: definition.revision, policy, confirmed: true, confirm_name: definition.name},
        {receiptPath: key => scope(g, side, `workflows/receipts/by-key/${key}`)});
      assert(uuid(result.workflowId), 'REAL_POLICY_CHANGE_APPROVAL_WORKFLOW_REQUIRED');
      g.policies.push({side, kind, definitionId: definition.id, originalVersion: definition.version, policy, workflowId: result.workflowId}); h.save();
    }
  } else if (stage === 'policy-approval') {
    finished(g, 'policy-requests');
    for (const record of g.policies) {
      if (record.reused) {
        const current = (await definitions(h, g, record.side)).find(row => row.id === record.definitionId);
        assert(singleCurrentReviewerPolicy(current, g.subjects.reviewer.id) && current.version === record.originalVersion
          && current.policyHash === record.originalPolicyHash, 'ORIGINAL_REUSED_REVIEWER_POLICY_CHANGED'); continue;
      }
      const approved = await vote(h, g, stage, `${record.side}-${record.kind}-vote`, record.side, record.workflowId, {format2: false});
      assert.equal(approved.kind, 'workflow-policy-metadata', 'ONLY_POLICY_METADATA_FIXTURE_EXECUTION_ALLOWED');
      const result = await once(h, g, stage, `${record.side}-${record.kind}-execute`, scope(g, record.side, `workflows/${record.workflowId}/execute`),
        {revision: approved.revision, planHash: approved.planHash, confirmed: true, confirm_name: approved.kind},
        {receiptPath: key => scope(g, record.side, `workflows/receipts/by-key/${key}`)});
      assert(result.state === 'succeeded' && uuid(result.executionId), 'REAL_APPROVED_POLICY_METADATA_SUCCESS_REQUIRED');
      const details = (await read(h, g, scope(g, record.side, `workflows/${record.workflowId}`))).data;
      assert(details.steps.every(row => row.kind === 'metadata' && row.state === 'succeeded' && !row.operationId), 'POLICY_FIXTURE_NATIVE_ZERO_REQUIRED');
      const current = (await definitions(h, g, record.side)).find(row => row.id === record.definitionId);
      assert(current.format === 2 && current.version === record.originalVersion + 1, 'ACTUAL_FUTURE_FORMAT2_POLICY_VERSION_REQUIRED');
      assert.deepEqual(current.policy, record.policy, 'ACTUAL_APPROVED_REVIEWER_POLICY_REQUIRED'); record.executionId = result.executionId; h.save();
    }
  } else if (stage === 'source-fixture' || stage === 'target-fixture') {
    finished(g, stage === 'source-fixture' ? 'policy-approval' : 'source-fixture'); await fixtureWorkflow(h, g, stage, stage === 'source-fixture' ? 'source' : 'target');
    if (stage === 'target-fixture') {
      assert.notEqual(g.fixtures.source.nativeId, g.fixtures.target.nativeId, 'DISTINCT_GATEWAY_NATIVE_IDS_REQUIRED');
      for (const [side, other] of [['source', 'target'], ['target', 'source']]) {
        const absence = await read(h, g, scope(g, side, `entities/services/${g.fixtures[other].nativeId}`), {expected: [404]});
        assert.equal(absence.status, 404, 'SOURCE_AND_TARGET_NATIVE_ID_INVISIBILITY_REQUIRED');
      }
      g.crossGatewayReadVerified = true; h.save();
    }
  } else if (stage === 'compare') {
    finished(g, 'target-fixture'); assert(g.crossGatewayReadVerified, 'ACTUAL_DUAL_GATEWAY_FIXTURE_REQUIRED');
    const response = await once(h, g, stage, 'comparison', scope(g, 'source', 'governance/comparisons'),
      {scope: 'services', serviceIds: [g.fixtures.source.nativeId], target: {clusterId: g.targetCid, workspaceId: g.targetWid,
        scope: 'services', serviceIds: [g.fixtures.target.nativeId]}, threshold: 0, includeEnvironmentFields: false},
      {receiptPath: key => scope(g, 'source', `governance/operations/by-key/${key}`)});
    assert(response.state === 'succeeded' && response.kind === 'comparison' && uuid(response.entity?.id), 'COMPLETE_CURRENT_DUAL_ENVIRONMENT_COMPARISON_REQUIRED'); g.comparisonId = response.entity.id; h.save();
    const detail = (await read(h, g, scope(g, 'source', `governance/comparisons/${g.comparisonId}`, {size: '100'}))).data;
    assert(detail.entity.quality === 'complete' && detail.entity.capabilities?.promotePlan === true && !detail.nextCursor
      && detail.items.some(row => row.entityType === 'services' && row.sourceObjectKey === `services:${g.fixtures.source.nativeId}`), 'EXACT_FRESH_SERVICE_COMPARISON_REQUIRED');
  } else if (stage === 'promote') {
    finished(g, 'compare');
    const result = await once(h, g, stage, 'plan', scope(g, 'source', `governance/comparisons/${g.comparisonId}/promote-plan`),
      {selectedObjectKeys: [`services:${g.fixtures.source.nativeId}`], includeEnvironmentFields: false, includeSecrets: false,
        includeCredentials: false, confirmed: true, confirm_name: `PROMOTE ${g.comparisonId}`},
      {receiptPath: key => scope(g, 'source', `governance/operations/by-key/${key}`)});
    assert(result.state === 'ready' && result.kind === 'promotion-plan' && result.nativeExecutionRequested === false
      && uuid(result.id) && uuid(result.planId) && uuid(result.jobId) && result.targetClusterId === g.targetCid && result.targetWorkspaceId === g.targetWid,
      'REAL_FRESH_PROMOTE_CONFIGURATION_PLAN_REQUIRED');
    g.promotionId = result.id; g.planId = result.planId; g.importPlanId = result.planId; g.importJobId = result.jobId; h.save();
    const plan = (await read(h, g, scope(g, 'target', `configuration/plans/${g.planId}`, {size: '100'}))).data;
    assert(plan.entity.id === g.planId && plan.entity.executionMode === 'approval' && plan.entity.approvalRequired && plan.entity.capabilities?.apply === true
      && plan.entity.deleteCount === 0 && plan.entity.stepCount === 1 && !plan.nextCursor && plan.items.length === 1
      && plan.items[0].entityType === 'services' && plan.items[0].action === 'update', 'ONLY_ONE_REAL_TARGET_SERVICE_UPDATE_PLAN_REQUIRED');
    g.plan = {id: plan.entity.id, planRevision: plan.entity.planRevision, planHash: plan.entity.planHash, name: plan.entity.name}; retainDeadlines(g, plan.entity);
    const job = entity((await read(h, g, scope(g, 'target', `configuration/jobs/${g.importJobId}`))).data); retainDeadlines(g, job);
    assert(g.deadlines.length > 0, 'ACTUAL_ORIGINAL_CONFIGURATION_DEADLINE_REQUIRED');
    g.window = currentPromoteWindow(Date.now(), g.deadlines); h.save();
  } else if (stage === 'apply') {
    finished(g, 'promote'); assertWindow(g);
    const importPlanId = g.importPlanId ?? g.planId;
    assert(uuid(importPlanId) && importPlanId === g.planId && g.plan?.id === importPlanId, 'ORIGINAL_TARGET_IMPORT_PLAN_BINDING_REQUIRED');
    const importPlan = (await read(h, g, scope(g, 'target', `configuration/plans/${importPlanId}`, {size: '100'}))).data;
    currentPromoteImportBinding(g, importPlan);
    const result = await once(h, g, stage, 'register-workflow', scope(g, 'target', `configuration/plans/${importPlanId}/apply`),
      {planRevision: g.plan.planRevision, planHash: g.plan.planHash, confirmed: true, confirm_name: g.plan.name},
      {receiptPath: key => scope(g, 'target', `configuration/jobs/by-key/${key}`)});
    currentPromoteApplyReceipt(g, result);
    g.importPlanId = importPlanId; g.applyPlanId = result.planId; g.applyJobId = result.jobId; g.workflowId = result.workflowId;
    retainDeadlines(g, result); h.save(); assertWindow(g);
    const applyPlan = (await read(h, g, scope(g, 'target', `configuration/plans/${g.applyPlanId}`, {size: '100'}))).data;
    const detail = (await read(h, g, scope(g, 'target', `workflows/${g.workflowId}`))).data;
    currentPromoteApplyBinding(g, result, {importPlan, applyPlan, workflow: detail});
    g.originalWorkflow = {planRevision: detail.entity.planRevision, planHash: detail.entity.planHash, expiresAt: detail.entity.expiresAt,
      stepIds: detail.steps.map(row => row.id)}; retainDeadlines(g, detail.entity); h.save(); assertWindow(g);
  } else if (stage === 'author') {
    finished(g, 'apply'); assertWindow(g); assert(Date.now() + 30_000 < Date.parse(g.window.notBefore), 'ORIGINAL_NOT_BEFORE_TOO_CLOSE_NO_REARM');
    const current = entity((await read(h, g, scope(g, 'target', `workflows/${g.workflowId}`))).data);
    assert(current.state === 'pending' && current.approval?.format === 2 && !current.scheduled
      && current.planHash === g.originalWorkflow.planHash && current.planRevision === g.originalWorkflow.planRevision, 'ORIGINAL_UNVOTED_WRAPPER_REQUIRED');
    const result = await once(h, g, stage, 'schedule', scope(g, 'target', 'workflow-schedules'),
      {workflowId: g.workflowId, revision: current.revision, planRevision: current.planRevision, planHash: current.planHash,
        spec: g.window, confirmed: true, confirm_name: 'schedule-workflow'},
      {receiptPath: key => scope(g, 'target', `workflow-schedules/receipts/by-key/${key}`)});
    const schedule = result.entity;
    assert(result.commandCompleted && uuid(schedule?.id) && schedule.kind === 'configuration_v2' && schedule.workflowId === g.workflowId
      && schedule.state === 'pending-approval' && schedule.nativeAuthority === false && schedule.executorId === g.subjects.admin.id
      && schedule.requesterType === 'console' && schedule.requesterId === g.subjects.admin.id, 'ORIGINAL_BUSINESS_SCHEDULE_DRAFT_REQUIRED');
    for (const key of ['notBefore', 'windowStart', 'windowEnd']) assert.equal(schedule[key], g.window[key], 'ORIGINAL_FIXED_BUSINESS_WINDOW_REQUIRED');
    g.scheduleId = schedule.id; h.save();
    const detail = (await read(h, g, scope(g, 'target', `workflows/${g.workflowId}`))).data, view = detail.entity;
    assert(view.state === 'pending' && view.planRevision === g.originalWorkflow.planRevision + 1 && view.planHash !== g.originalWorkflow.planHash
      && view.expiresAt === g.originalWorkflow.expiresAt && view.approval?.format === 2 && view.approval.stages.every(row => row.votes === 0),
      'NEW_SCHEDULED_REVISION_WITH_UNCHANGED_OLD_DEADLINE_REQUIRED');
    const currentSteps = detail.steps.filter(row => !g.originalWorkflow.stepIds.includes(row.id));
    assert(currentSteps.length === g.originalWorkflow.stepIds.length && currentSteps.every(row => row.state === 'pending' && !row.operationId), 'REGENERATED_UNEXECUTED_SCHEDULE_STEPS_REQUIRED');
    g.scheduledWorkflow = {planRevision: view.planRevision, planHash: view.planHash, stepIds: currentSteps.map(row => row.id)}; h.save();
  } else if (stage === 'approve') {
    finished(g, 'author'); assertWindow(g);
    const approved = await vote(h, g, stage, 'independent-review', 'target', g.workflowId);
    assert(approved.kind === 'configuration_v2' && approved.planHash === g.scheduledWorkflow.planHash
      && approved.planRevision === g.scheduledWorkflow.planRevision, 'EXACT_ORIGINAL_SCHEDULED_REVISION_APPROVAL_REQUIRED');
  } else if (stage === 'activate') {
    finished(g, 'approve'); assertWindow(g); assert(Date.now() + 5_000 < Date.parse(g.window.notBefore), 'ORIGINAL_SCHEDULE_ACTIVATION_MUST_PRECEDE_DUE');
    const current = entity((await read(h, g, scope(g, 'target', `workflow-schedules/${g.scheduleId}`))).data);
    assert(current.id === g.scheduleId && current.workflowPlanHash === g.scheduledWorkflow.planHash && current.state === 'pending-approval'
      && current.nativeAuthority === false, 'ORIGINAL_APPROVED_BUSINESS_SCHEDULE_REQUIRED');
    const result = await once(h, g, stage, 'activate', scope(g, 'target', `workflow-schedules/${g.scheduleId}/activate`),
      {revision: current.revision, confirmed: true, confirm_name: 'activate-schedule'},
      {receiptPath: key => scope(g, 'target', `workflow-schedules/receipts/by-key/${key}`)});
    assert(result.commandCompleted && result.entity?.id === g.scheduleId && result.entity.state === 'active' && result.entity.nativeAuthority === false,
      'REAL_BUSINESS_SCHEDULE_ACTIVATION_REQUIRED');
    const unchanged = entity((await read(h, g, scope(g, 'target', `entities/services/${g.fixtures.target.nativeId}`))).data);
    assert(unchanged.retries === g.fixtures.target.before.retries && unchanged.read_timeout === g.fixtures.target.before.read_timeout, 'NO_TARGET_NATIVE_WRITE_BEFORE_NATURAL_DUE');
  } else if (stage === 'observe') {
    finished(g, 'activate'); assertWindow(g); const deadline = Date.parse(g.window.windowEnd); let terminal;
    while (Date.now() < deadline) {
      const observed = entity((await read(h, g, scope(g, 'target', `workflow-schedules/${g.scheduleId}`))).data);
      assert(observed.id === g.scheduleId && observed.workflowPlanHash === g.scheduledWorkflow.planHash && observed.nativeAuthority === false,
        'ONLY_ORIGINAL_SCHEDULE_READ_OBSERVATION_REQUIRED');
      g.observations.push({observedAt: new Date().toISOString(), state: observed.state, revision: observed.revision,
        claimId: observed.claimId ?? null, reasonCode: observed.reasonCode ?? null}); h.save();
      if (['succeeded', 'failed', 'partial', 'uncertain', 'blocked', 'cancelled', 'expired'].includes(observed.state)) {terminal = observed; break;}
      console.log(JSON.stringify({event: 'm11.current-promote.await-natural-worker', state: observed.state,
        secondsUntilDue: Math.max(0, Math.ceil((Date.parse(g.window.notBefore) - Date.now()) / 1000))})); await pause(5_000);
    }
    assert(terminal?.state === 'succeeded' && uuid(terminal.claimId), 'NATURAL_CURRENT_PROMOTE_WORKER_SUCCESS_REQUIRED_NO_MANUAL_EXECUTE'); g.claimId = terminal.claimId; h.save();
    const detail = (await read(h, g, scope(g, 'target', `workflows/${g.workflowId}`))).data;
    const currentSteps = detail.steps.filter(row => g.scheduledWorkflow.stepIds.includes(row.id));
    assert(detail.entity.state === 'succeeded' && detail.entity.planHash === g.scheduledWorkflow.planHash
      && currentSteps.length === g.scheduledWorkflow.stepIds.length && currentSteps.every(row => row.state === 'succeeded')
      && detail.steps.filter(row => g.originalWorkflow.stepIds.includes(row.id)).every(row => row.state === 'pending' && !row.operationId),
      'ONLY_ORIGINAL_SCHEDULED_WORKFLOW_REVISION_COMPLETED');
    const job = entity((await read(h, g, scope(g, 'target', `configuration/jobs/${g.applyJobId}`))).data);
    assert(job.jobId === g.applyJobId && job.state === 'succeeded' && job.executionCompleted === true && uuid(job.executionId), 'REAL_APPLY_JOB_NATIVE_COMPLETION_REQUIRED');
    const steps = (await read(h, g, scope(g, 'target', `configuration/jobs/${g.applyJobId}/steps`, {size: '100'}))).data;
    assert(Array.isArray(steps.items) && !steps.nextCursor && steps.items.length === 1 && steps.items[0].state === 'succeeded'
      && steps.items[0].type === 'services' && steps.items[0].action === 'update' && steps.items[0].objectId === g.fixtures.target.nativeId
      && uuid(steps.items[0].operationId) && steps.items[0].verified === true, 'REAL_ONE_SERVICE_CONFIGURATION_STEP_SUCCESS_REQUIRED');
    const target = entity((await read(h, g, scope(g, 'target', `entities/services/${g.fixtures.target.nativeId}`))).data);
    const source = entity((await read(h, g, scope(g, 'source', `entities/services/${g.fixtures.source.nativeId}`))).data);
    for (const key of ['retries', 'connect_timeout', 'read_timeout', 'write_timeout']) assert.equal(target[key], g.fixtures.source.before[key], 'ACTUAL_NON_ENVIRONMENT_FIELDS_PROMOTED');
    for (const key of ['id', 'name', 'host', 'port', 'protocol']) assert.equal(target[key], g.fixtures.target.before[key], 'TARGET_IDENTITY_AND_ENVIRONMENT_FIELDS_RETAINED');
    assert.deepEqual(source, g.fixtures.source.before, 'SOURCE_GATEWAY_CONFIGURATION_REMAINS_UNCHANGED');
    g.configurationExecutionId = job.executionId; g.observedSucceeded = true; h.save();
  } else throw Error('EXACT_CURRENT_PROMOTE_STAGE_REQUIRED');
}

function report(h, g, stage, passed, startIndex, errorCode) {
  return {milestone: 'M11', stage, passed, sourceOnly: false, productionDeployment: false, overallM11Accepted: false,
    sourceClusterId: g.sourceCid, sourceWorkspaceId: g.sourceWid, targetClusterId: g.targetCid ?? null, targetWorkspaceId: g.targetWid ?? null,
    topologyProofSha256: g.configuration.topologySha256,
    topology: Object.fromEntries(['topologyProofVersion', 'topologyKind', 'databaseSeparationVerified', 'sharedDatabaseServer', 'sharedStorage',
      'independentPostgresProcesses', 'independentFailureDomains', 'sharedFaultDomain', 'roleIsolationVerified', 'sourceRolePrivileged', 'targetRolePrivileged']
      .map(key => [key, g.configuration[key]])),
    crossGatewayReadVerified: g.crossGatewayReadVerified ?? false,
    comparisonId: g.comparisonId ?? null, promotionId: g.promotionId ?? null, planId: g.planId ?? null,
    importPlanId: g.importPlanId ?? g.planId ?? null, applyPlanId: g.applyPlanId ?? null, applyJobId: g.applyJobId ?? null,
    workflowId: g.workflowId ?? null, scheduleId: g.scheduleId ?? null, claimId: g.claimId ?? null, configurationExecutionId: g.configurationExecutionId ?? null,
    window: g.window ?? null, oldDeadlineExtended: false, workerInvoked: false, manualPromoteExecutionInvoked: false,
    fixtureExecuteKinds: ['workflow-policy-metadata', 'native-change'], includeSecrets: false, includeCredentials: false, includeEnvironmentFields: false,
    credentialsPublished: false, originalResponseRewritten: false,
    requests: h.state.requests.slice(startIndex).map(packet => ({method: packet.method, path: packet.path.split('?')[0],
      label: packet.label ?? null, state: packet.state, status: packet.status ?? null, requestId: packet.requestId ?? null,
      bodyHash: packet.bodyHash, responseHash: packet.responseHash ?? null, errorCode: /^[A-Z][A-Z0-9_]{0,127}$/.test(packet.errorCode ?? '') ? packet.errorCode : null})),
    timerObservations: g.observations, evidenceLimitations: ['This HTTP runner consumes Root topology assertions; it cannot inspect physical Kong databases or establish Docker topology itself.',
      'V2 shares the PostgreSQL server, storage and failure domain. Logical database separation does not certify role ACL isolation, independent PostgreSQL processes or independent disaster recovery. V1 does not itself certify separate host failure domains or database role ACLs.',
      'Root must independently verify deployed BUSINESS_SCHEDULES_ENABLED, worker source/runtime equality, SQL claim/NULL-SID/lease, append-only approvals, persistent source-origin bindings, Native packet/status/ACK and audit chain.',
      'No real runtime execution was performed when this Source runner was authored. A retained failed or unknown request cannot be inferred not sent from a missing receipt.'],
    ...(errorCode ? {errorCode} : {})};
}

export async function main(env = process.env, stage = process.argv[2] ?? 'requirements') {
  assert(CURRENT_PROMOTE_STAGES.includes(stage) || stage === 'recover', 'EXACT_ONE_CURRENT_PROMOTE_STAGE_REQUIRED');
  if (stage === 'requirements') {console.log(JSON.stringify(currentPromoteRequirements(), null, 2)); return;}
  const config = configuration(env), reportPath = resolve(config.reportDirectory, `${stage}-original.json`);
  mkdirSync(dirname(reportPath), {recursive: true}); assert(!existsSync(reportPath), 'ORIGINAL_CURRENT_PROMOTE_STAGE_REPORT_PRESENT_NO_REPLAY');
  const fd = openSync(reportPath, 'wx', 0o644); let h, g, startIndex = 0;
  try {
    h = new ReleaseHarness('M11', {resume: true});
    const originalRequest = h.request.bind(h);
    h.request = (actualSession, path, ...args) => {
      // ReleaseHarness can otherwise refresh recursively at its 90s token
      // threshold. This local deny gate stops that call before journaling or
      // transport, preserving original sessions and the global unknown fence.
      assert(!path.startsWith('/auth/'), 'IMPLICIT_AUTH_TRANSPORT_FORBIDDEN');
      return originalRequest(actualSession, path, ...args);
    };
    if (stage !== 'recover') h.assertWritable();
    assert(uuid(h.state.cid) && uuid(h.state.wid), 'CURRENT_EXISTING_M11_SCOPE_REQUIRED');
    const admin = session(h, null, 'admin'), reviewer = session(h, null, 'reviewer'); assert.notEqual(admin.user.id, reviewer.user.id, 'TWO_DISTINCT_CURRENT_REAL_CONSOLE_ACTORS_REQUIRED');
    if (stage === 'preflight') assert(!h.state.currentPromoteNaturalOriginal, 'NEW_CURRENT_PROMOTE_ORIGINAL_RUN_REQUIRED');
    else assert(h.state.currentPromoteNaturalOriginal?.runs?.preflight?.state === 'succeeded', 'ORIGINAL_CURRENT_PROMOTE_PREFLIGHT_REQUIRED');
    g = h.state.currentPromoteNaturalOriginal ??= {version: 1, sourceCid: h.state.cid, sourceWid: h.state.wid, configuration: config,
      subjects: {admin: {id: admin.user.id, sid: admin.sid}, reviewer: {id: reviewer.user.id, sid: reviewer.sid}},
      targetName: `M11 Promote ${randomUUID().slice(0, 8)}`, serviceName: `m11-current-promote-${randomUUID().slice(0, 8)}`,
      fixtureTag: `m11-promote:${randomUUID()}`, runs: {}, commands: {}, policies: [], fixtures: {}, deadlines: [], observations: []};
    assert(g.version === 1 && g.sourceCid === h.state.cid && g.sourceWid === h.state.wid, 'ORIGINAL_CURRENT_PROMOTE_SCOPE_CHANGED');
    assert.deepEqual(g.configuration, config, 'ORIGINAL_CURRENT_PROMOTE_RESOURCE_CONFIGURATION_CHANGED'); session(h, g, 'admin'); session(h, g, 'reviewer');
    assert(!g.runs[stage], 'ORIGINAL_CURRENT_PROMOTE_STAGE_PRESENT_NO_REPLAY'); startIndex = h.state.requests.length;
    g.runs[stage] = {state: 'started', startedAt: new Date().toISOString()}; h.save();
    if (stage === 'recover') {
      // Read-only discovery only. No resolution, rewrite, retry or automatic
      // continuation follows a receipt, including a receipt-not-found result.
      g.recoveryReads ??= [];
      for (const [identity, command] of Object.entries(g.commands)) {
        if (!command.receiptPath) {
          g.recoveryReads.push({identity, lookupUnavailable: true, knownNoNativeSend: false, originalOutcomeRewritten: false}); h.save(); continue;
        }
        const observed = await read(h, g, command.receiptPath, {reviewer: command.actor === 'reviewer', expected: [200, 400, 401, 403, 404, 409]});
        g.recoveryReads.push({identity, status: observed.status, requestId: observed.requestId ?? null,
          knownNoNativeSend: false, originalOutcomeRewritten: false}); h.save();
      }
    } else await stageRun(h, g, stage);
    g.runs[stage] = {...g.runs[stage], state: 'succeeded', completedAt: new Date().toISOString()}; h.save();
    writeSync(fd, JSON.stringify(report(h, g, stage, true, startIndex), null, 2) + '\n');
    console.log(JSON.stringify({stage, passed: true, currentStageOnly: true, overallM11Accepted: false, credentialsPublished: false}));
  } catch (error) {
    const code = safeCode(error);
    if (g?.runs?.[stage]) {g.runs[stage] = {...g.runs[stage], state: 'stopped', errorCode: code}; try {h.save();} catch {/* Keep original CAS failure. */}}
    writeSync(fd, JSON.stringify(h && g ? report(h, g, stage, false, startIndex, code)
      : {milestone: 'M11', stage, passed: false, errorCode: code, overallM11Accepted: false, credentialsPublished: false}, null, 2) + '\n');
    console.error(JSON.stringify({stage, passed: false, errorCode: code})); process.exitCode = 1;
  } finally {closeSync(fd);}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {await main();} catch (error) {console.error(JSON.stringify({passed: false, errorCode: safeCode(error), overallM11Accepted: false})); process.exitCode = 1;}
}
