import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

// Disposable local PostgreSQL only; never DATABASE_URL or a live console DB.
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const docker = (args: string[], input?: string): string => execFileSync('docker', ['--host', 'unix:///var/run/docker.sock', ...args], {
  env: dockerEnv, ...(input !== undefined ? { input } : {}), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
});
const directory = 'apps/console-api/src/infrastructure/migrations';
const sql041 = readFileSync(`${directory}/041_m11_metadata_schedules.sql`, 'utf8');
const functions = ['m11_business_schedule_pointer_advance(workflows,workflows)', 'm11_business_schedule_revision_complete()', 'm11_business_origin_permission()'];

describe('SQL041 metadata business schedules on real PostgreSQL', () => {
  const container = `kongos-m11-sql041-${randomUUID().slice(0, 8)}`;
  let started = false;
  const query = (sql: string): string => docker(['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'], sql).trim();
  const catalog = () => query(`SELECT string_agg(conname||'='||pg_get_constraintdef(oid),E'\\n' ORDER BY conname) FROM pg_constraint
      WHERE conrelid IN('workflow_executor_delegations'::regclass,'workflow_schedules'::regclass);
    ${functions.map(f => `SELECT md5(pg_get_functiondef('public.${f}'::regprocedure));`).join('\n')}`);
  const fnDef = (f: string) => query(`SELECT pg_get_functiondef('public.${f}'::regprocedure);`);

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    docker(['run', '-d', '--name', container, '--network', 'none', '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine']);
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable SQL041 PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|40)_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(41);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 120_000);
  afterAll(() => { if (started) docker(['rm', '-f', container]); });

  it('rolls back completely inside an explicit transaction', () => {
    const before = catalog();
    query(`BEGIN;\n${sql041}\nROLLBACK;`);
    expect(catalog()).toBe(before);
    expect(fnDef(functions[0])).not.toContain('entity-annotation');
  });

  it('applies once, extends only the kind sets and pins search_path on rewritten functions', () => {
    const originals = functions.map(fnDef);
    query(sql041);
    for (const [n, f] of functions.entries()) {
      const def = fnDef(f);
      expect(def).toContain("'entity-annotation'");
      expect(def).toMatch(/SET search_path TO 'pg_catalog', 'public', 'pg_temp'/);
      // Every original validation line survives.
      const body = (s: string) => s.slice(s.indexOf('$function$'));
      for (const line of body(originals[n]).split('\n').map(l => l.trim()).filter(l => l && !l.includes("NOT IN('configuration_v2','portal-credential-issue')"))) expect(body(def)).toContain(line);
    }
    expect(query(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='workflow_schedules_kind_check';`)).toContain('entity-annotation');
    // Re-applying fails: migrations are not idempotent and must not double-insert branches.
    expect(() => query(`BEGIN;\n${sql041}\nROLLBACK;`)).toThrow();
  });

  it('enforces Console-only, same-owner, same-epoch delegations for entity-annotation', () => {
    const def = query(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='workflow_executor_delegations_metadata_subject_check';`);
    const owner = randomUUID(), other = randomUUID();
    const run = (row: string) => query(`BEGIN;CREATE TEMP TABLE d(kind text,subject_type text,requester_type text,requester_id uuid,owner_id uuid,requester_credential_epoch bigint,owner_credential_epoch bigint);
      ALTER TABLE d ADD CONSTRAINT c ${def};INSERT INTO d VALUES(${row});ROLLBACK;`);
    expect(() => run(`'entity-annotation','entity_annotation_requests','console','${owner}','${owner}',3,3`)).not.toThrow();
    expect(() => run(`'entity-annotation','entity_annotation_requests','developer','${owner}','${owner}',3,3`)).toThrow(/violates check constraint/);
    expect(() => run(`'entity-annotation','entity_annotation_requests','console','${other}','${owner}',3,3`)).toThrow(/violates check constraint/);
    expect(() => run(`'entity-annotation','entity_annotation_requests','console','${owner}','${owner}',3,4`)).toThrow(/violates check constraint/);
    expect(() => run(`'entity-annotation','configuration_jobs','console','${owner}','${owner}',3,3`)).toThrow(/violates check constraint/);
    expect(() => run(`'configuration_v2','configuration_jobs','console','${owner}','${owner}',3,3`)).not.toThrow();
    // Slice 2: every remaining metadata kind is bound to exactly its validator's subject types.
    const subjects: Record<string, string[]> = {
      'control-metadata': ['control_metadata_requests'], 'configuration-metadata': ['config_snapshots', 'config_snapshot_schedules', 'configuration_gitops_runs'],
      'governance-metadata': ['governance_metadata_requests'], 'workflow-policy-metadata': ['workflow_policy_requests'], 'iam-metadata': ['iam_metadata_requests'],
      'portal-metadata': ['portal_settings', 'portal_developers', 'portal_applications', 'portal_publications', 'portal_content'],
      'portal-developer-review': ['portal_developers'], 'event-metadata': ['notification_channels', 'event_subscriptions', 'event_deliveries'],
    };
    const all = [...new Set(Object.values(subjects).flat().concat('entity_annotation_requests', 'configuration_jobs'))];
    // One psql round-trip for the whole matrix: each row is checked in its own exception block.
    const cases: [string, boolean][] = [];
    for (const [kind, ok] of Object.entries(subjects)) {
      for (const st of all) cases.push([`'${kind}','${st}','console','${owner}','${owner}',3,3`, ok.includes(st)]);
      cases.push([`'${kind}','${ok[0]}','developer','${owner}','${owner}',3,3`, false]);
      cases.push([`'${kind}','${ok[0]}','console','${other}','${owner}',3,3`, false]);
      cases.push([`'${kind}','${ok[0]}','console','${owner}','${owner}',3,4`, false]);
    }
    const out = query(`BEGIN;CREATE TEMP TABLE d(kind text,subject_type text,requester_type text,requester_id uuid,owner_id uuid,requester_credential_epoch bigint,owner_credential_epoch bigint);
      ALTER TABLE d ADD CONSTRAINT c ${def};
      CREATE FUNCTION pg_temp.ok(r text) RETURNS boolean LANGUAGE plpgsql AS $f$BEGIN EXECUTE 'INSERT INTO d VALUES('||r||')';RETURN true;EXCEPTION WHEN check_violation THEN RETURN false;END$f$;
      SELECT string_agg(pg_temp.ok(r)::text,',' ORDER BY n) FROM unnest(ARRAY[${cases.map(([r]) => `$r$${r}$r$`).join(',')}]) WITH ORDINALITY AS t(r,n);ROLLBACK;`);
    expect(out.split(',')).toEqual(cases.map(([, ok]) => String(ok)));
    expect(() => run(`'portal-credential-issue','portal_application_grants','developer','${owner}','${other}',3,4`)).not.toThrow();
  });

  it('advances the first schedule pointer only for approval-mode entity-annotation workflows', () => {
    // Anchor every window to the disposable container clock (not host Date.now):
    // CI docker clocks can drift so a host ISO window_end is already past when
    // Postgres evaluates window_end<=clock_timestamp().
    const origin = Date.parse(query('SELECT clock_timestamp();'));
    expect(Number.isFinite(origin)).toBe(true);
    const at = (m: number) => `'${new Date(origin + m * 60_000).toISOString()}'`;
    const id = randomUUID(), cid = randomUUID(), wid = randomUUID();
    const wf = (kind: string, mode: string, extra = '') => `jsonb_populate_record(NULL::workflows, jsonb_build_object('id','${id}','cluster_id','${cid}','workspace_id','${wid}',
      'kind','${kind}','execution_mode','${mode}','approval_format',2,'state','pending','approval_required',true,'plan_revision',1,'revision',1,'plan_hash',repeat('a',64),
      'candidate_version',1,'candidate_manifest_hmac',repeat('b',64),'expires_at',${at(120)},'updated_at',${at(0)}${extra}))`;
    const next = `,'plan_revision',2,'revision',2,'plan_hash',repeat('c',64),'candidate_version',NULL,'candidate_manifest_hmac',NULL,'not_before',${at(10)},'window_start',${at(5)},'window_end',${at(60)},'updated_at',${at(1)}`;
    const advance = (kind: string, mode: string) => query(`SELECT m11_business_schedule_pointer_advance(${wf(kind, mode)}, ${wf(kind, mode, next)});`);
    expect(advance('configuration_v2', 'approval')).toBe('t');
    expect(advance('entity-annotation', 'approval')).toBe('t');
    expect(advance('entity-annotation', 'direct')).toBe('f');
    expect(advance('configuration_v2', 'approval')).toBe('t');
    expect(advance('configuration_v2', 'direct')).toBe('f');
    for (const kind of ['control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata']) {
      expect(advance(kind, 'approval')).toBe('t');
      expect(advance(kind, 'direct')).toBe('f');
    }
    expect(advance('toolbox-operation', 'approval')).toBe('f');
    expect(advance('portal-publication', 'approval')).toBe('f');
  });
});
