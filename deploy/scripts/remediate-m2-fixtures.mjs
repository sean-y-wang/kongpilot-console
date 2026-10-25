import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

// Explicit M2 test-data remediation: bounded cache refresh and one append-only
// audit event. Never alters Kong objects, immutable audit rows, or credentials.
const plan = JSON.parse(readFileSync('artifacts/M2/security-remediation-plan.json', 'utf8'));
if (plan.syntheticOnly !== true || plan.externalCredentials !== false
  || !/^[a-f\d-]{36}$/i.test(plan.clusterId) || !/^m2-security-[a-f\d]+$/.test(plan.testTag)
  || !plan.affectedAliases.every(a => a.refreshable && /^[a-f\d-]{36}$/i.test(a.cluster_id))) {
  throw new Error('Remediation plan does not match the approved synthetic M2 scope');
}
if (existsSync('.env')) process.loadEnvFile('.env');
const base = (process.env.CONSOLE_BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
let cookie = '', csrf = '';
const traces = [];
const refreshes = [];
const priorResults = ['artifacts/M2/security-remediation.json', 'artifacts/M2/security-remediation-failed-first.json']
  .filter(existsSync).map(path => JSON.parse(readFileSync(path, 'utf8')));
async function request(path, method = 'GET', body) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(['GET', 'HEAD'].includes(method) ? {} : { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15_000),
  });
  traces.push({ method, path, status: response.status, requestId: response.headers.get('x-request-id') });
  if (!response.ok) throw new Error(`Remediation request failed: ${method} ${path} HTTP${response.status}`);
  return { response, data: (await response.json()).data };
}
let result;
try {
  const login = await request('/auth/login', 'POST', { username: process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password: process.env.BOOTSTRAP_ADMIN_PASSWORD });
  cookie = login.response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  csrf = login.data.csrfToken;
  for (const alias of plan.affectedAliases) {
    const path = `/clusters/${alias.cluster_id}/inventory/refresh`;
    const previous = priorResults.find(r => r.clusterId === plan.clusterId && (r.traces?.some(t => t.method === 'POST' && t.path === path && t.status >= 200 && t.status < 300) || r.refreshes?.some(r => r.clusterId === alias.cluster_id && r.bounded)));
    if (previous) {
      refreshes.push({ clusterId: alias.cluster_id, bounded: true, reusedPriorSuccessfulRefresh: true });
      continue;
    }
    const response = await request(`/clusters/${alias.cluster_id}/inventory/refresh`, 'POST', {});
    refreshes.push({ clusterId: alias.cluster_id, bounded: true, result: response.data });
  }

  const runtimeScript = String.raw`
require('reflect-metadata');
const { createHash } = require('node:crypto');
const { DbService } = require('./dist/infrastructure/db.service');
const { SecretService, canonicalJson } = require('./dist/infrastructure/secret.service');
const { AuditService } = require('./dist/modules/audit/audit.service');
const plan = JSON.parse(process.argv[1]);
let step='runtime-init';
const rawPredicate = "EXISTS (SELECT 1 FROM jsonb_path_query(jsonb_build_array(e.before,e.after), '$.**.provision_key') AS v WHERE jsonb_typeof(v)='string' AND v#>>'{}' NOT LIKE '[REDACTED%')";
async function verifyChain(db, scope, prefix) {
  let sequence=0n, previous='GENESIS', count=0, prefixIntact=!prefix;
  while (true) {
    const rows=await db.query('SELECT id,chain_scope,sequence::text,actor_id,actor_type,source_ip,cluster_id,workspace_id,entity_type,entity_id,action,before,after,json_patch,workflow_id,result,request_id,prev_hash,event_hash,occurred_at FROM audit_events WHERE chain_scope=$1 AND sequence>$2::bigint ORDER BY audit_events.sequence LIMIT 200',[scope,sequence.toString()]);
    if (!rows.length) break;
    for (const row of rows) {
      const {event_hash,occurred_at,...record}=row;
      record.occurred_at=occurred_at.toISOString();
      const hash=createHash('sha256').update(canonicalJson(record)).digest('hex');
      if (BigInt(row.sequence)!==sequence+1n || row.prev_hash!==previous || hash!==event_hash) {
        const error=new Error('Audit chain validation failed');
        error.safeDiagnostics={scope,sequence:row.sequence,eventId:row.id,sequenceMatches:BigInt(row.sequence)===sequence+1n,previousHashMatches:row.prev_hash===previous,eventHashMatches:hash===event_hash};
        throw error;
      }
      sequence=BigInt(row.sequence); previous=event_hash; count++;
      if (prefix && row.sequence===prefix.lastSequence) prefixIntact=event_hash===prefix.lastHash;
    }
  }
  const head=await db.one('SELECT last_sequence::text,last_hash FROM audit_chain_heads WHERE chain_scope=$1',[scope]);
  if (!head || head.last_sequence!==sequence.toString() || head.last_hash!==previous || !prefixIntact) throw new Error('Audit head or immutable prefix validation failed');
  return {scope,lastSequence:sequence.toString(),lastHash:previous,count,prefixIntact};
}
(async()=>{
 const db=new DbService();
 try {
  await db.onModuleInit();
  const secret=new SecretService();
  step='patched-classifier';
  // Prove this process loads the patched classifier, rather than stale dist.
  const sample=secret.redact({provision_key:'synthetic-remediation-probe',aws_access_key_id:'synthetic-remediation-probe',enable_password_grant:true,credentials:false});
  if (!String(sample.provision_key).startsWith('[REDACTED') || !String(sample.aws_access_key_id).startsWith('[REDACTED') || sample.enable_password_grant!==true || sample.credentials!==false) throw new Error('Patched classifier/public flags are not loaded');
  step='public-cache';
  const remaining=await db.one("SELECT count(*)::int AS count FROM entity_index WHERE document#>>'{config,provision_key}' IS NOT NULL AND document#>>'{config,provision_key}' NOT LIKE '[REDACTED%'");
  if (remaining.count!==0) throw new Error('A raw provisioning key remains in public cache');
  step='fixture-containment';
  const fixture=await db.one("SELECT count(*)::int AS total,count(*) FILTER(WHERE document->>'enabled'='true')::int AS enabled FROM entity_index WHERE cluster_id=$1 AND entity_type='plugins' AND $2=ANY(tags)",[plan.clusterId,plan.testTag]);
  if (fixture.enabled!==0 || fixture.total<plan.fixturePluginCount) throw new Error('Synthetic fixture plugin disable containment was not verified');
  step='immutable-test-history-count';
  const rawBefore=await db.one('SELECT count(*)::int AS count FROM audit_events e WHERE '+rawPredicate);
  if (rawBefore.count!==plan.immutableAuditRowsBefore) throw new Error('Historical raw test audit count changed unexpectedly');
  const scopes=(await db.query('SELECT DISTINCT chain_scope FROM audit_events e WHERE '+rawPredicate)).map(r=>r.chain_scope);
  if (!scopes.includes('cluster:'+plan.clusterId)) scopes.push('cluster:'+plan.clusterId);
  step='audit-chain-before';
  const before=[]; for (const scope of scopes) before.push(await verifyChain(db,scope));
  const existing=await db.one("SELECT id FROM audit_events WHERE cluster_id=$1 AND entity_type='system_security_validation' AND entity_id=$2 AND action='redaction.fixture_remediated' LIMIT 1",[plan.clusterId,plan.testTag]);
  step='append-remediation-event';
  if (!existing) await new AuditService(db,secret).append({actorType:'system_security_validation',clusterId:plan.clusterId,entityType:'system_security_validation',entityId:plan.testTag,action:'redaction.fixture_remediated',after:{syntheticOnly:true,externalCredentials:false,fixturePluginsDisabled:true,indexRowsRemediated:plan.indexRowsBefore,immutableHistoryPreserved:true},result:'success'});
  step='audit-chain-after';
  const after=[];for (const chain of before) after.push(await verifyChain(db,chain.scope,chain));
  const rawAfter=await db.one('SELECT count(*)::int AS count FROM audit_events e WHERE '+rawPredicate);
  if (rawAfter.count!==rawBefore.count) throw new Error('Immutable test audit history was altered');
  const appended=await db.one("SELECT id FROM audit_events WHERE cluster_id=$1 AND entity_type='system_security_validation' AND entity_id=$2 AND action='redaction.fixture_remediated' LIMIT 1",[plan.clusterId,plan.testTag]);
  console.log(JSON.stringify({patchedClassifierLoaded:true,indexRowsRemediated:plan.indexRowsBefore,indexRawRowsAfter:remaining.count,fixturePluginCount:fixture.total,fixturePluginsDisabled:true,immutableRawSyntheticAuditRowsBefore:rawBefore.count,immutableRawSyntheticAuditRowsAfter:rawAfter.count,immutableHistoryPreserved:true,auditChainVerified:true,verifiedChainCount:after.length,remediationAuditEventId:appended.id,remediationEventReused:Boolean(existing),databaseRole:'runtime-app',secretValuesRecorded:false}));
 } finally {await db.onModuleDestroy();}
})().catch(error=>{const expected=['Audit chain validation failed','Audit head or immutable prefix validation failed','Patched classifier/public flags are not loaded','A raw provisioning key remains in public cache','Synthetic fixture plugin disable containment was not verified','Historical raw test audit count changed unexpectedly','Immutable test audit history was altered'];console.error(JSON.stringify({kind:'safe-remediation-failure',failedStep:step,code:error.code||'REMEDIATION_CHECK_FAILED',reason:expected.includes(error.message)?error.message:'External exception details suppressed',...(error.safeDiagnostics?{diagnostics:error.safeDiagnostics}:{})}));process.exit(1);});
`;
  const verification = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '-e', runtimeScript, JSON.stringify(plan)], { encoding: 'utf8', maxBuffer: 2e6 }));
  result = { performedAt: new Date().toISOString(), kind: 'synthetic-M2-redaction-remediation', clusterId: plan.clusterId, allPassed: true, syntheticOnly: true, externalCredentials: false, refreshes, traces, ...verification };
  console.log(`M2 synthetic redaction remediation passed: ${verification.indexRowsRemediated} public-cache rows, ${verification.verifiedChainCount} immutable audit chains; no secret values recorded.`);
} catch (error) {
  let diagnostic;
  try { const value=JSON.parse(String(error.stderr).trim().split('\n').at(-1));if(value.kind==='safe-remediation-failure')diagnostic=value; } catch { /* Never copy an unrecognized response/error body into evidence. */ }
  result = { performedAt: new Date().toISOString(), kind: 'synthetic-M2-redaction-remediation', clusterId: plan.clusterId, allPassed: false, refreshes, traces, secretValuesRecorded: false, ...(diagnostic?{diagnostic}:{}) };
  process.exitCode = 1;
  console.error('M2 synthetic remediation failed; inspect safe step statuses. No raw secrets were logged.');
} finally {
  if (cookie) try { await request('/auth/logout', 'POST', {}); } catch { /* Do not mask remediation failures with logout failure. */ }
  writeFileSync('artifacts/M2/security-remediation.json', JSON.stringify(result, null, 2) + '\n');
}
