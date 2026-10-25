import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

// Approved exact fixture IDs only. Run after the M4 startup/IAM gate, while
// other fixture writers are paused. Deactivation uses the normal audited API;
// all direct PostgreSQL statements below are read-only console-db queries.
const aliases = ['f80cc384-20f5-43ff-961b-c750046be374', 'adfb4fa1-38d7-487f-86bc-d283a30e397b', '13f36a78-5103-467b-b2d3-93c1b22f9377'];
const canonical = 'dff45535-ed8d-4851-b7a6-6376feac7f59';
if (!process.argv.includes('--execute-confirmed-fixtures')) {
  console.log(JSON.stringify({ deploymentPerformed: false, exactApprovedAliases: aliases, canonicalPreserved: canonical, requiresReadyM4Migration: '005_m4_iam.sql', action: 'Evidence archive then revision/name-confirmed audited soft-deactivation; no SQL mutations or native entity changes.' }));
  process.exit(0);
}
process.loadEnvFile('.env');
const traces = [], checks = [];
let cookie = '', csrf = '', result;
const snapshotCode = String.raw`let input='';for await(const c of process.stdin)input+=c;const q=JSON.parse(input);const{Pool}=await import('pg');const p=new Pool({connectionString:process.env.DATABASE_URL});try{const applied=(await p.query("SELECT count(*)::int AS n FROM schema_migrations WHERE name='005_m4_iam.sql'")).rows[0].n;if(applied!==1)process.exit(3);const tables=(await p.query("SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t USING(table_catalog,table_schema,table_name) WHERE c.table_schema='public' AND c.column_name='cluster_id' AND c.table_name<>'audit_events' AND t.table_type='BASE TABLE' ORDER BY c.table_name")).rows.map(r=>r.table_name);if(tables.some(t=>!/^[a-z_]+$/.test(t)))process.exit(4);const out=[];for(const id of q.ids){const row=(await p.query('SELECT id,name,environment,admin_url,revision,status,deleted_at,created_at FROM clusters WHERE id=$1',[id])).rows[0];if(!row)process.exit(5);const counts={};for(const table of tables)counts[table]=(await p.query('SELECT count(*)::int AS n FROM "'+table+'" WHERE cluster_id=$1',[id])).rows[0].n;const scope='cluster:'+id;const max=(await p.query('SELECT coalesce(max(sequence),0)::text AS n FROM audit_events WHERE chain_scope=$1',[scope])).rows[0].n;const upper=q.prefixes?.[id]??max;const prefix=(await p.query("SELECT count(*)::int AS count,md5(coalesce(string_agg(id::text||':'||event_hash,',' ORDER BY sequence),'')) AS fingerprint FROM audit_events WHERE chain_scope=$1 AND sequence<=$2::bigint",[scope,upper])).rows[0];const deactivations=(await p.query("SELECT id,request_id FROM audit_events WHERE cluster_id=$1 AND entity_type='cluster' AND entity_id=$1::text AND action='deactivate' ORDER BY sequence",[id])).rows;out.push({row,counts,auditPrefix:{...prefix,upperSequence:upper},deactivationAuditEvents:deactivations});}console.log(JSON.stringify(out));}finally{await p.end();}`;
function snapshot(ids, prefixes) {
  return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', snapshotCode], {
    input: JSON.stringify({ ids, prefixes }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 2e6,
  }));
}
function check(name, condition) { checks.push({ name, passed: Boolean(condition) }); if (!condition) throw new Error('ALIAS_PRESERVATION_CHECK'); }
async function request(path, method = 'GET', body) {
  const r = await fetch(`http://127.0.0.1:8080/api/v1${path}`, {
    method, redirect: 'manual', signal: AbortSignal.timeout(20_000),
    headers: { ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(['GET', 'HEAD'].includes(method) ? {} : { 'X-CSRF-Token': csrf, 'X-Idempotency-Key': randomUUID() }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const payload = await r.json();
  traces.push({ method, path, status: r.status, requestId: payload?.meta?.requestId });
  if (!r.ok) throw new Error(`BFF_HTTP_${r.status}`);
  return { response: r, data: payload.data };
}
try {
  mkdirSync('artifacts/M4', { recursive: true });
  const archive = 'artifacts/M4/alias-deactivation-archive-before.json';
  const current = snapshot([canonical, ...aliases]);
  const primary = current.find(s => s.row.id === canonical);
  check('canonical primary remains active on the primary physical target', primary && !primary.row.deleted_at && primary.row.admin_url === 'http://kong:8001');
  for (const id of aliases) {
    const row = current.find(s => s.row.id === id)?.row;
    check(`${id}: exact documented e2e fixture ownership matches`, row && row.environment === 'e2e' && /^浏览器验收-\d+$/.test(row.name) && row.admin_url === 'http://kong:8001');
  }
  if (!existsSync(archive)) writeFileSync(archive, JSON.stringify({ archivedAt: new Date().toISOString(), exactApprovedAliases: aliases, canonical, preservedDatabaseRows: true, secretValuesRecorded: false, snapshots: current }, null, 2) + '\n', { flag: 'wx' });
  const before = JSON.parse(readFileSync(archive, 'utf8')).snapshots;
  const login = await request('/auth/login', 'POST', { username: process.env.BOOTSTRAP_ADMIN_USERNAME, password: process.env.BOOTSTRAP_ADMIN_PASSWORD });
  cookie = login.response.headers.getSetCookie().map(c => c.split(';')[0]).join('; '); csrf = login.data.csrfToken;
  for (const id of aliases) {
    const old = current.find(s => s.row.id === id).row;
    if (old.deleted_at) continue; // Reuse the earlier archive; never retry a successful soft-deactivation.
    const authoritative = (await request(`/clusters/${id}`)).data;
    check(`${id}: latest revision/name match the archived fixture`, authoritative.name === old.name && authoritative.revision === old.revision);
    await request(`/clusters/${id}/deactivate`, 'POST', { confirm: true, confirm_name: authoritative.name, revision: authoritative.revision });
  }
  const prefixes = Object.fromEntries(before.map(s => [s.row.id, s.auditPrefix.upperSequence]));
  const after = snapshot([canonical, ...aliases], prefixes);
  for (const old of before) {
    const updated = after.find(s => s.row.id === old.row.id);
    check(`${old.row.id}: dependent metadata row counts remain unchanged`, JSON.stringify(old.counts) === JSON.stringify(updated.counts));
    check(`${old.row.id}: complete historical audit prefix is unchanged`, old.auditPrefix.count === updated.auditPrefix.count && old.auditPrefix.fingerprint === updated.auditPrefix.fingerprint);
    if (aliases.includes(old.row.id)) {
      check(`${old.row.id}: registry row retained and soft-disabled`, Boolean(updated.row.deleted_at) && updated.row.status === 'disabled');
      check(`${old.row.id}: audited deactivation has a request ID`, updated.deactivationAuditEvents.some(e => Boolean(e.request_id)));
    } else check('canonical primary registry state/revision untouched', !updated.row.deleted_at && old.row.revision === updated.row.revision);
  }
  result = { performedAt: new Date().toISOString(), kind: 'M4-exact-test-alias-soft-deactivation', allPassed: true,
    aliases, canonical, archive, snapshotsAfter: after, directSqlMutationsPerformed: false, kongNativeWritesPerformed: false, checks, traces };
} catch (error) {
  result = { performedAt: new Date().toISOString(), kind: 'M4-exact-test-alias-soft-deactivation', allPassed: false,
    code: /^BFF_HTTP_\d{3}$|^[A-Z_]+$/.test(error.message) ? error.message : 'ALIAS_OPERATION_EXCEPTION', aliases, canonical, checks, traces };
  process.exitCode = 1;
} finally {
  if (cookie) try { await request('/auth/logout', 'POST', {}); } catch { /* Preserve failure details safely. */ }
  mkdirSync('artifacts/M4', { recursive: true });
  writeFileSync('artifacts/M4/alias-deactivation-verification.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ allPassed: result.allPassed, passed: checks.filter(c => c.passed).length, failed: checks.filter(c => !c.passed).length, code: result.code }));
}
