#!/usr/bin/env node
/**
 * Console PostgreSQL backup/restore drill (logical pg_dump -Fc / pg_restore).
 * Mode "inplace": production compose project (bridge). Snapshot checksums -> pg_dump -> stop console-api ->
 *   DROP + CREATE database -> pg_restore -> start console-api -> verify checksums, audit chain (SQL linkage +
 *   product /audit/global/integrity), login, and a post-restore write.
 * Mode "scratch": consistent-snapshot dump of an existing lab DB (read-only on source) restored into a
 *   throwaway postgres container with --network none; per-table checksum equality incl. workflows/approvals/audit.
 * Dumps contain encrypted secrets/ciphertexts: they are written only under DRILL_PRIVATE (0700), never committed.
 * Env: DRILL_MODE, DRILL_OUT (evidence dir), DRILL_PRIVATE, PCE_PROJECT, BRIDGE_ENV, BFF_BASE, PUBLIC_ORIGIN,
 *      SRC_CONTAINER, SRC_PSQL_ARGS (scratch mode). Never sets commercialClosed. Prints no secrets.
 */
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, statSync, createReadStream, chmodSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
async function walkIntegrity(fetchPage){const pages=[];let cursor;for(let i=0;i<50;i++){const r=await fetchPage('/api/v1/audit/global/integrity'+(cursor?'?cursor='+encodeURIComponent(cursor):''));const v=r.json?.data??r.json??{};pages.push({status:v.status,checkedRows:v.checkedRows,complete:v.complete,verifiedInterval:v.verifiedInterval,reasonCodes:v.reasonCodes});if(r.status!==200)return{ok:false,httpStatus:r.status,pages};if(v.status==='verified'&&v.complete===true)return{ok:true,httpStatus:200,pages,checkedRows:pages.reduce((n,p)=>n+(p.checkedRows||0),0)};if(v.status!=='partial'||!(v.reasonCodes||[]).includes('AUDIT_BUDGET_REACHED')||typeof v.nextCursor!=='string'||v.nextCursor===cursor)return{ok:false,httpStatus:200,pages};cursor=v.nextCursor;}return{ok:false,pageBudget:true,pages};}

const mode = process.env.DRILL_MODE;
const out = resolve(process.env.DRILL_OUT); const priv = resolve(process.env.DRILL_PRIVATE);
mkdirSync(out, { recursive: true }); mkdirSync(priv, { recursive: true, mode: 0o700 });
const checks = []; const record = (id, passed, d = {}) => { checks.push({ id, passed: !!passed, ...d }); console.log(passed ? 'PASS' : 'FAIL', id); };
const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 256 * 1024 ** 2, ...opts });
const startedAt = new Date().toISOString(); const t = {};
const time = async (k, fn) => { const s = performance.now(); const r = await fn(); t[k] = Math.round(performance.now() - s); return r; };
const sha = (f) => new Promise((ok) => { const h = createHash('sha256'); createReadStream(f).on('data', (c) => h.update(c)).on('end', () => ok(h.digest('hex'))); });

// SQL producing "table|rows|md5" for every public table, ordered.
const CHECKSUM_SQL = `select string_agg(format('select %L, count(*), md5(coalesce(string_agg(x::text, chr(10) order by x::text), '''')) from public.%I x', tablename, tablename), ' union all ' order by tablename) from pg_tables where schemaname='public' \\gexec`;
// Audit chain linkage: per chain_scope, contiguous sequence and prev_hash == previous event_hash.
const CHAIN_SQL = `select count(*), count(distinct chain_scope), coalesce(sum(case when prev_ok then 0 else 1 end),0), coalesce(sum(case when seq_ok then 0 else 1 end),0) from (select chain_scope, (lag(event_hash) over w is null or prev_hash = lag(event_hash) over w) as prev_ok, (lag(sequence) over w is null or sequence = lag(sequence) over w + 1) as seq_ok from audit_events window w as (partition by chain_scope order by sequence)) z`;
const term = (sql) => (/;\s*$/.test(sql) || sql.includes('\\gexec') ? sql : sql + ';');
const parseSums = (txt) => Object.fromEntries(txt.trim().split('\n').filter((l) => l.includes('|')).map((l) => { const [tb, n, h] = l.split('|'); return [tb, { rows: Number(n), md5: h }]; }));
const KEY = ['workflows', 'workflow_approvals', 'workflow_versions', 'workflow_events', 'workflow_executions', 'audit_events', 'audit_chain_heads', 'clusters', 'users', 'roles', 'role_bindings', 'credential_refs', 'auth_sessions'];
const compare = (a, b) => { const tables = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort(); const diff = tables.filter((x) => a[x]?.md5 !== b[x]?.md5 || a[x]?.rows !== b[x]?.rows); return { tables: tables.length, totalRows: tables.reduce((s, x) => s + (a[x]?.rows || 0), 0), mismatched: diff, key: Object.fromEntries(KEY.filter((k) => a[k]).map((k) => [k, { rows: a[k].rows, equal: a[k].md5 === b[k]?.md5 && a[k].rows === b[k]?.rows }])) }; };
const chainObj = (txt) => { const [events, scopes, prevBad, seqBad] = txt.trim().split('|').map(Number); return { events, scopes, prevHashBreaks: prevBad, sequenceGaps: seqBad }; };

if (mode === 'inplace') {
  const project = process.env.PCE_PROJECT || 'kp-bridge';
  const env = Object.fromEntries(readFileSync(process.env.BRIDGE_ENV, 'utf8').split('\n').filter((l) => l.includes('=') && !l.startsWith('#')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  const base = process.env.BFF_BASE || 'https://127.0.0.1:48443', origin = process.env.PUBLIC_ORIGIN || base;
  const dc = (...a) => sh('docker', ['compose', '-p', project, ...a]);
  const psql = (sql, db = '"$POSTGRES_DB"') => dc('exec', '-T', 'console-db', 'sh', '-c', `psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d ${db} -At <<'SQL'\n${term(sql)}\nSQL`);
  const login = async () => { const r = await fetch(`${base}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ username: env.BOOTSTRAP_ADMIN_USERNAME, password: env.BOOTSTRAP_ADMIN_PASSWORD }) }); const j = await r.json().catch(() => ({})); return { status: r.status, cookie: (r.headers.getSetCookie?.() || []).map((c) => c.split(';')[0]).join('; '), csrf: j?.data?.csrfToken }; };
  const get = async (s, p) => { const r = await fetch(`${base}${p}`, { headers: { Cookie: s.cookie, Origin: origin, Accept: 'application/json' } }); return { status: r.status, json: await r.json().catch(() => null) }; };
  const integrityOk = (j) => /"(valid|ok|intact)"\s*:\s*true|"status"\s*:\s*"(ok|valid|intact|verified)"/i.test(JSON.stringify(j || {}));
  const waitReady = async () => { for (let i = 0; i < 90; i++) { const r = await fetch(`${base}/api/v1/health/ready`).then((x) => x.status).catch(() => 0); if (r === 200) return true; await new Promise((x) => setTimeout(x, 2000)); } return false; };

  // quiesce writers so the dump and checksums describe the same state
  await time('quiesce', async () => dc('stop', 'console-api'));
  const before = parseSums(await time('checksumBefore', async () => psql(CHECKSUM_SQL)));
  const chainBefore = chainObj(psql(CHAIN_SQL));
  const dump = join(priv, `console-${Date.now()}.dump`);
  await time('pgDump', async () => sh('sh', ['-c', `docker compose -p ${project} exec -T console-db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -Z6' > '${dump}'`]));
  chmodSync(dump, 0o600);
  const dumpSha = await sha(dump), dumpBytes = statSync(dump).size;
  const toc = sh('sh', ['-c', `docker compose -p ${project} exec -T console-db pg_restore -l < '${dump}' | grep -c 'TABLE DATA'`]).trim();
  record('backup_created', dumpBytes > 0 && Number(toc) > 0, { format: 'pg_dump custom (-Fc -Z6)', bytes: dumpBytes, sha256: dumpSha, tableDataEntries: Number(toc), storedAt: 'private dir (not committed)' });
  const dbName = dc('exec', '-T', 'console-db', 'printenv', 'POSTGRES_DB').trim(), dbUser = dc('exec', '-T', 'console-db', 'printenv', 'POSTGRES_USER').trim();
  // disaster: the console database is dropped entirely
  await time('dropRecreate', async () => { psql(`DROP DATABASE "${dbName}" WITH (FORCE);`, 'postgres'); psql(`CREATE DATABASE "${dbName}" OWNER "${dbUser}";`, 'postgres'); });
  const emptyTables = psql(`select count(*) from pg_tables where schemaname='public'`).trim();
  record('disaster_database_gone', emptyTables === '0', { publicTablesAfterDrop: Number(emptyTables) });
  await time('pgRestore', async () => sh('sh', ['-c', `docker compose -p ${project} exec -T console-db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --exit-on-error --single-transaction' < '${dump}'`]));
  const after = parseSums(await time('checksumAfter', async () => psql(CHECKSUM_SQL)));
  const chainAfter = chainObj(psql(CHAIN_SQL));
  const cmp = compare(before, after);
  record('restore_all_tables_byte_identical', cmp.mismatched.length === 0 && cmp.tables > 100, cmp);
  record('audit_chain_linkage_intact_after_restore', JSON.stringify(chainBefore) === JSON.stringify(chainAfter) && chainAfter.prevHashBreaks === 0 && chainAfter.sequenceGaps === 0, { before: chainBefore, after: chainAfter });
  dc('start', 'console-api');
  const ready = await time('apiReadyAfterRestore', waitReady);
  record('console_api_ready_after_restore', ready);
  const s = await login(); record('admin_login_after_restore', [200, 201].includes(s.status), { status: s.status });
  const integ = await walkIntegrity((p) => get(s, p));
  record('product_audit_integrity_after_restore', integ.ok, integ);
  const cl = await get(s, '/api/v1/clusters'); const cid = cl.json?.data?.[0]?.id;
  const users = await get(s, '/api/v1/iam/users?size=100');
  record('config_and_iam_visible_after_restore', cl.status === 200 && !!cid && users.status === 200, { clusters: cl.json?.data?.length, users: users.json?.data?.items?.length ?? users.json?.data?.length });
  // post-restore write continues the audit chain
  const w = await fetch(`${base}/api/v1/clusters/${cid}/entities/consumers`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: s.cookie, 'X-CSRF-Token': s.csrf, 'X-Idempotency-Key': `drill-${randomBytes(4).toString('hex')}` }, body: JSON.stringify({ username: `drill-post-restore-${randomBytes(3).toString('hex')}` }) });
  const integ2 = await walkIntegrity((p) => get(s, p)); const chain2 = chainObj(psql(CHAIN_SQL));
  record('post_restore_write_and_chain_continues', [200, 201].includes(w.status) && integ2.ok && chain2.events > chainAfter.events && chain2.prevHashBreaks === 0, { writeStatus: w.status, eventsAfterRestore: chainAfter.events, eventsAfterWrite: chain2.events });
  finish({ mode, project, timingsMs: t, dump: { bytes: dumpBytes, sha256: dumpSha } });
} else if (mode === 'scratch') {
  const src = process.env.SRC_CONTAINER, srcArgs = (process.env.SRC_PSQL_ARGS || '').split(' ').filter(Boolean);
  // One REPEATABLE READ session exports a snapshot; pg_dump and the checksums both read exactly that snapshot.
  const sess = spawn('docker', ['exec', '-i', src, 'psql', ...srcArgs, '-At', '-v', 'ON_ERROR_STOP=1'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = ''; sess.stdout.on('data', (d) => { buf += d; });
  const until = async (marker) => { for (let i = 0; i < 1200; i++) { const k = buf.indexOf(marker); if (k >= 0) { const r = buf.slice(0, k); buf = buf.slice(k + marker.length); return r; } await new Promise((x) => setTimeout(x, 50)); } throw new Error('psql session timeout'); };
  sess.stdin.write("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nselect pg_export_snapshot();\n\\echo __SNAP__\n");
  const snap = (await until('__SNAP__')).trim().split('\n').filter((l) => /^[0-9A-F]+-[0-9A-F]+-\d+$/.test(l.trim())).pop().trim();
  const dump = join(priv, `scratch-src-${Date.now()}.dump`);
  await time('pgDump', async () => sh('sh', ['-c', `docker exec ${src} pg_dump ${srcArgs.join(' ')} --snapshot=${snap} -Fc -Z6 > '${dump}'`]));
  chmodSync(dump, 0o600);
  sess.stdin.write(CHECKSUM_SQL + "\n\\echo __SUMS__\n"); const before = parseSums(await until('__SUMS__'));
  sess.stdin.write(CHAIN_SQL + ";\n\\echo __CHAIN__\n"); const chainBefore = chainObj((await until('__CHAIN__')).trim().split('\n').pop());
  sess.stdin.write('COMMIT;\n\\q\n'); sess.stdin.end();
  const dumpSha = await sha(dump), dumpBytes = statSync(dump).size;
  record('backup_created_from_consistent_snapshot', dumpBytes > 0 && !!snap, { bytes: dumpBytes, sha256: dumpSha, snapshot: 'exported (id omitted)', sourceAccess: 'read-only transaction' });
  const name = `kp-restore-drill-${randomBytes(3).toString('hex')}`;
  sh('docker', ['run', '-d', '--rm', '--network', 'none', '--name', name, '-e', `POSTGRES_PASSWORD=${randomBytes(16).toString('hex')}`, '-e', 'POSTGRES_DB=restored', 'postgres:16-alpine']);
  try {
    for (let i = 0; i < 60; i++) { try { sh('docker', ['exec', name, 'pg_isready', '-U', 'postgres', '-d', 'restored']); sh('docker', ['exec', name, 'psql', '-U', 'postgres', '-d', 'restored', '-Atc', 'select 1']); break; } catch { await new Promise((x) => setTimeout(x, 1000)); } }
    await time('pgRestore', async () => sh('sh', ['-c', `docker exec -i ${name} pg_restore -U postgres -d restored --no-owner --no-acl --exit-on-error --single-transaction < '${dump}'`]));
    const q = (sql) => sh('sh', ['-c', `docker exec -i ${name} psql -U postgres -d restored -At -v ON_ERROR_STOP=1 <<'SQL'\n${term(sql)}\nSQL`]);
    const after = parseSums(await time('checksumAfter', async () => q(CHECKSUM_SQL)));
    const chainAfter = chainObj(q(CHAIN_SQL).trim().split('\n').pop());
    const cmp = compare(before, after);
    record('restore_all_tables_byte_identical', cmp.mismatched.length === 0 && cmp.tables > 100, cmp);
    record('approvals_and_workflows_present', (before.workflow_approvals?.rows || 0) > 0 && (before.workflows?.rows || 0) > 0 && cmp.key.workflow_approvals?.equal && cmp.key.workflows?.equal, { workflows: before.workflows?.rows, approvals: before.workflow_approvals?.rows });
    record('audit_chain_linkage_intact_after_restore', JSON.stringify(chainBefore) === JSON.stringify(chainAfter) && chainAfter.prevHashBreaks === 0 && chainAfter.sequenceGaps === 0, { before: chainBefore, after: chainAfter });
    const restoreHost = q("select current_setting('server_version')").trim();
    finish({ mode, source: 'existing full-validation lab console DB (read-only)', scratch: { image: 'postgres:16-alpine', network: 'none', serverVersion: restoreHost, removedAfter: true }, timingsMs: t, dump: { bytes: dumpBytes, sha256: dumpSha } });
  } finally { try { sh('docker', ['rm', '-f', name]); } catch {} }
} else { console.error('DRILL_MODE=inplace|scratch'); process.exit(2); }

function finish(extra) {
  const passed = checks.filter((c) => c.passed).length;
  const ev = { schemaVersion: 1, kind: 'm11-console-pg-backup-restore-drill', commercialClosed: false, startedAt, completedAt: new Date().toISOString(), timezoneNote: 'UTC; report Asia/Shanghai', secretsPrinted: false, dumpCommitted: false, ...extra, totals: { total: checks.length, passed, failed: checks.length - passed }, checks };
  writeFileSync(join(out, `pg-backup-restore-${mode}-evidence.json`), JSON.stringify(ev, null, 2) + '\n');
  console.log(JSON.stringify({ mode, passed, total: checks.length, timingsMs: t }));
  process.exitCode = passed === checks.length ? 0 : 1;
}
