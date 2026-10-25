import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { provisionRuntimeRole } from '../../apps/console-api/src/infrastructure/migrate';
import { releaseUnusedPortalReservations } from '../../apps/console-api/src/modules/portal/portal-grant-lifecycle';
import { AuditService } from '../../apps/console-api/src/modules/audit/audit.service';
import { PortalAuthService } from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';

interface Scope { cid: string; wid: string; }
interface Flow { id: string; hash: string; steps: string[]; definition: string; scope: Scope; approval: boolean; mode: 'direct' | 'approval'; }
async function main(): Promise<void> {
  const container = `kongos-m6-schema-${randomUUID().slice(0, 8)}`;
  const checks: Array<{ name: string; passed: boolean }> = [];
  let db: DbService | undefined, runtime: DbService | undefined;
  const assert = (condition: unknown): void => { if (!condition) throw new Error('M6 schema assertion failed'); };
  const check = async (name: string, fn: () => Promise<void>): Promise<void> => {
    try { await fn(); checks.push({ name, passed: true }); }
    catch (error) { console.error(`Failed safe check: ${name}`); throw error; }
  };
  const rejected = async (fn: () => Promise<unknown>, codes: string | string[]): Promise<void> => {
    try { await fn(); }
    catch (error: any) {
      if ((Array.isArray(codes) ? codes : [codes]).includes(error.code)) return;
      throw new Error(`Expected SQL constraint rejection; received ${error.code ?? 'unknown'}`);
    }
    throw new Error('Expected SQL constraint rejection');
  };
  try {
    execFileSync('docker', ['run', '-d', '--name', container, '-p', '127.0.0.1::5432', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16-alpine'], { stdio: 'ignore' });
    const port = execFileSync('docker', ['port', container, '5432'], { encoding: 'utf8' }).trim().split(':').pop();
    process.env.DATABASE_URL = `postgres://postgres@127.0.0.1:${port}/postgres`;
    process.env.CONSOLE_ENCRYPTION_KEY = 'f6'.repeat(32);
    process.env.BOOTSTRAP_ADMIN_USERNAME = 'portal-schema-bootstrap';
    process.env.BOOTSTRAP_ADMIN_PASSWORD = 'Synthetic!Portal2026Password';
    db = new DbService();
    for (let i = 0; i < 80; i++) {
      try { await db.one('SELECT 1'); break; }
      catch { if (i === 79) throw new Error('Disposable M6 PostgreSQL unavailable'); await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    await db.migrateAndSeed();
    const secrets = new SecretService(), hash = secrets.fingerprint({ synthetic: true }), encrypted = secrets.encrypt({ synthetic: true }, 'schema-test');
    const user = (await db.one<any>('SELECT id FROM users WHERE super_admin'))!.id, approver = randomUUID();
    await db.exec("INSERT INTO users(id,username,password_hash) VALUES($1,'portal-schema-approver',$2)", [approver, `$2b$12$${'a'.repeat(53)}`]);
    const c1 = randomUUID(), c2 = randomUUID(), alias = randomUUID(), w1 = randomUUID(), w2 = randomUUID(), w3 = randomUUID(), wa = randomUUID();
    const s1 = { cid: c1, wid: w1 }, s2 = { cid: c1, wid: w2 }, s3 = { cid: c2, wid: w3 }, sa = { cid: alias, wid: wa };
    const transport = 'a'.repeat(64), otherTransport = 'b'.repeat(64);
    await db.exec("INSERT INTO clusters(id,name,admin_url) VALUES($1,'portal-schema-a','http://schema-kong-a:8001'),($2,'portal-schema-b','http://schema-kong-b:8001'),($3,'portal-schema-alias','http://schema-kong-a:8001')", [c1, c2, alias]);
    await db.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'pay','pay'),($3,$2,'ops','ops'),($4,$5,'pay','pay'),($6,$7,'pay','pay')", [w1, c1, w2, w3, c2, wa, alias]);
    const setting = async (scope: Scope): Promise<string> => {
      const id = randomUUID();
      await db!.exec("INSERT INTO portal_settings(id,cluster_id,workspace_id,slug,name,published,registration_enabled,public_proxy_origin) VALUES($1,$2,$3,$4,'Synthetic portal',true,true,'https://api.example.test')", [id, scope.cid, scope.wid, `schema-${id}`]); return id;
    };
    const setting1 = await setting(s1), setting2 = await setting(s2), setting3 = await setting(s3); await setting(sa);
    const developer = async (scope: Scope, status = 'active'): Promise<string> => {
      const id = randomUUID();
      await db!.exec('INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,\'Synthetic developer\',$6,$7)', [id, scope.cid, scope.wid, `dev-${id}`, `${id}@example.test`, `$2b$12$${'a'.repeat(53)}`, status]); return id;
    };
    const dev1 = await developer(s1), dev2 = await developer(s1), devOtherWorkspace = await developer(s2), devOtherCluster = await developer(s3), devAlias = await developer(sa);
    const application = async (scope: Scope, owner: string): Promise<string> => {
      const id = randomUUID(); await db!.exec("INSERT INTO portal_applications(id,cluster_id,workspace_id,developer_id,name) VALUES($1,$2,$3,$4,$5)", [id, scope.cid, scope.wid, owner, `app-${id}`]); return id;
    };
    const app1 = await application(s1, dev1), app2 = await application(s1, dev2), appAlias = await application(sa, devAlias);
    const publication = async (scope: Scope, service = randomUUID(), physical = transport): Promise<string> => {
      const id = randomUUID();
      await db!.transaction(async tx => {
        await tx.exec("INSERT INTO portal_publications(id,cluster_id,workspace_id,transport_scope,slug,name,service_id,acl_group,created_by,updated_by) VALUES($1,$2,$3,$4,$5,'Synthetic publication',$6,$7,$8,$8)", [id, scope.cid, scope.wid, physical, `api-${id}`, service, `kos-portal-api-${id}`, user]);
        await tx.exec("INSERT INTO portal_publication_revisions(cluster_id,workspace_id,publication_id,revision,service_id,title,version_label,openapi_document,document_hash,created_by) VALUES($1,$2,$3,1,$4,'Synthetic API','1.0',$5::jsonb,$6,$7)", [scope.cid, scope.wid, id, service, JSON.stringify({ openapi: '3.0.3', info: { title: 'Synthetic API', version: '1.0' }, paths: {} }), hash, user]);
      }); return id;
    };
    const service1 = randomUUID(), pub1 = await publication(s1, service1), pub2 = await publication(s1), pubAlias = await publication(sa);
    const page = randomUUID();
    await db.transaction(async tx => {
      await tx.exec("INSERT INTO portal_content(id,cluster_id,workspace_id,slug,title,created_by,updated_by) VALUES($1,$2,$3,'schema-page','Synthetic page',$4,$4)", [page, c1, w1, user]);
      await tx.exec("INSERT INTO portal_content_revisions(cluster_id,workspace_id,content_id,revision,title,markdown,content_hash,created_by) VALUES($1,$2,$3,1,'Synthetic page','# Safe content',$4,$5)", [c1, w1, page, hash, user]);
    });
    const flow = async (scope = s1, opts: { approval?: boolean; mode?: 'direct' | 'approval'; native?: number; nativeConsumer?: string; nativeId?: string; mutationAction?:'create'|'delete'; subject?: string; subjectType?: string; kind?: string; requester?: string; dependencies?: string[][]; state?: string; definitionStage?: boolean } = {}): Promise<Flow> => {
      const id = randomUUID(), def = randomUUID(), steps = Array.from({ length: Math.max(1, opts.native ?? 0) }, () => randomUUID());
      const approval = opts.approval ?? false, mode = opts.mode ?? 'direct', kind = opts.kind ?? 'portal-metadata', subject = opts.subject ?? setting1;
      await db!.transaction(async tx => {
        await tx.exec("INSERT INTO workflow_definitions(id,cluster_id,workspace_id,code,name,kind,created_by) VALUES($1,$2,$3,$4,'Synthetic definition',$5,$6)", [def, scope.cid, scope.wid, `flow-${def}`, kind, user]);
        await tx.exec("INSERT INTO workflow_definition_versions(cluster_id,workspace_id,definition_id,version,policy_hash,created_by) VALUES($1,$2,$3,1,$4,$5)", [scope.cid, scope.wid, def, hash, user]);
        if (opts.definitionStage !== false) await tx.exec("INSERT INTO workflow_definition_stages(cluster_id,workspace_id,definition_id,definition_version,level,name) VALUES($1,$2,$3,1,1,'Synthetic approval')", [scope.cid, scope.wid, def]);
        await tx.exec(`INSERT INTO workflows(id,cluster_id,workspace_id,kind,subject_type,subject_id,requester_type,requester_developer_id,requester_user_id,definition_id,definition_version,plan_hash,execution_mode,approval_required,state,request_hash,idempotency_key,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$13,$14,$11,$15,now()+interval '1 hour')`, [id, scope.cid, scope.wid, kind, opts.subjectType ?? 'portal_settings', subject, opts.requester ? 'developer' : 'console', opts.requester ?? null, opts.requester ? null : user, def, hash, mode, approval, opts.state ?? 'pending', `schema-${id}`]);
        await tx.exec(`INSERT INTO workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,payload_secret,policy_version,step_count,native_request_count,steps_hash,expires_at,created_by,created_by_developer_id)
          VALUES($1,$2,$3,1,$4,$5,$6,$7,1,$8,$9,$4,now()+interval '1 hour',$10,$11)`, [scope.cid, scope.wid, id, hash, mode, approval, encrypted, steps.length, opts.native ?? 0, opts.requester ? null : user, opts.requester ?? null]);
        for (const [i, step] of steps.entries()) {
          if (opts.native) await tx.exec(`INSERT INTO workflow_steps(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,step_key,step_order,kind,entity_type,entity_id,parent_id,credential_kind,permission_action,mutation_action,mutation_payload_hmac,mutation_idempotency_key,before_fingerprint,native_requests,dependencies)
            VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,'native','credentials',$10,$11,'key-auth',$15,$16,$5,$12,$5,$13::jsonb,$14::uuid[])`, [step, scope.cid, scope.wid, id, hash, mode, approval, `step-${i + 1}`, i + 1, opts.nativeId ?? randomUUID(), opts.nativeConsumer ?? randomUUID(), `mutation-${step}`, JSON.stringify([{ method: opts.mutationAction==='delete'?'DELETE':'POST', path_hash: hash, native_type: 'key-auth', body_hmac: hash }]), opts.dependencies?.[i] ?? (i > 0 ? [steps[i - 1]] : []),opts.mutationAction==='delete'?'delete':'write',opts.mutationAction??'create']);
          else await tx.exec(`INSERT INTO workflow_steps(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,step_key,step_order,kind,handler,entity_type,entity_id,permission_action,metadata_before_hmac,metadata_revision,metadata_payload_hmac)
            VALUES($1,$2,$3,$4,1,$5,$6,$7,'metadata',1,'metadata','portal.settings.update',$8,$9,'write',$5,1,$5)`, [step, scope.cid, scope.wid, id, hash, mode, approval, opts.subjectType ?? 'portal_settings', subject]);
        }
        if (approval) await tx.exec("INSERT INTO workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,state) VALUES($1,$2,$3,1,$4,1,'active')", [scope.cid, scope.wid, id, hash]);
      }); return { id, hash, steps, definition: def, scope, approval, mode };
    };
    const direct = await flow(), approved = await flow(s1, { approval: true, mode: 'approval', native: 2 }), credentialApprovalDirect = await flow(s1, { approval: true, mode: 'direct' });
    const approve = async (f: Flow): Promise<void> => {
      await db!.transaction(async tx => {
        await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)", [f.scope.cid, f.scope.wid, f.id, f.hash, approver, `approval-${f.id}`]);
        await tx.exec("UPDATE workflows SET state='approved',approved_by=$2,approved_at=now(),revision=revision+1 WHERE id=$1", [f.id, approver]);
        await tx.exec("UPDATE workflow_stages SET state='approved',completed_at=now() WHERE workflow_id=$1", [f.id]);
      });
    };
    const execution = async (f: Flow, ready = false, state = 'claimed'): Promise<string> => {
      const id = randomUUID();
      await db!.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at)
        VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$5,$14,now()+interval '30 minutes')`, [id, f.scope.cid, f.scope.wid, f.id, f.hash, f.mode, f.approval, f.approval ? approver : null, approver, state, ready ? 'ready' : 'pending', ready ? encrypted : null, ready ? hash : null, `execution-${id}`]); return id;
    };
    await approve(approved); await approve(credentialApprovalDirect);
    const execution1 = await execution(approved), directExecution = await execution(direct), credentialDirectExecution = await execution(credentialApprovalDirect);
    const reserveGrant = async (scope: Scope, owner: string, app: string, pub: string, consumer = randomUUID(), physical = transport): Promise<string> => {
      const id = randomUUID();
      await db!.exec(`INSERT INTO portal_application_grants(id,cluster_id,workspace_id,transport_scope,application_id,publication_id,developer_id,consumer_id,acl_group,acl_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [id, scope.cid, scope.wid, physical, app, pub, owner, consumer, `kos-portal-api-${pub}`, randomUUID()]); return id;
    };
    const consumer = randomUUID(), grant = await reserveGrant(s1, dev1, app1, pub1, consumer);
    const issuedKeyId = randomUUID();
    const issueFlow = await flow(s1, { approval: true, mode: 'direct', native: 1, nativeConsumer: consumer, nativeId: issuedKeyId, subject: grant, subjectType: 'portal_application_grants', kind: 'portal-credential-issue', requester: dev1 });
    await approve(issueFlow); const issueExecution = await execution(issueFlow);
    const allocate = async (f: Flow, execId: string, step: string, opts: { operation?: string; consumer?: string; kongId?: string; reciprocal?: boolean } = {}): Promise<string> => {
      const op = opts.operation ?? randomUUID();
      const stepRow = (await db!.one<any>('SELECT entity_id,parent_id,mutation_action FROM workflow_steps WHERE id=$1', [step]))!;
      await db!.transaction(async tx => {
        await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id,entity_type,entity_id,parent_id,credential_kind)
          VALUES($1,$2,$3,$4,$12,$5,$6,'running',$7,$8,1,$6,$9,'credentials',$10,$11,'key-auth')`, [op, f.scope.cid, f.scope.wid, approver, `allocation-${op}`, f.hash, f.id, execId, step, opts.kongId ?? stepRow.entity_id, opts.consumer ?? stepRow.parent_id,stepRow.mutation_action??'create']);
        if (opts.reciprocal !== false) await tx.exec("UPDATE workflow_steps SET operation_id=$2,state='running',started_at=now(),revision=revision+1 WHERE id=$1", [step, op]);
      }); return op;
    };

    await check('all migrations through SQL008 execute without touching the primary console database', async () => {
      assert((await db!.one<any>("SELECT count(*)::int AS n FROM schema_migrations WHERE name='008_m6_portal.sql'"))!.n === 1);
      const tables = await db!.query<any>("SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE 'portal_%' OR tablename LIKE 'workflow%')"); assert(tables.length === 23);
    });
    await check('same username may independently register in a different tenant, but never twice in one tenant', async () => {
      const username = `same-${randomUUID()}`;
      await db!.exec("INSERT INTO portal_developers(cluster_id,workspace_id,username,email,display_name,password_hash) VALUES($1,$2,$3,'same@example.test','same',$4),($1,$5,$3,'same@example.test','same',$4)", [c1, w1, username, `$2b$12$${'a'.repeat(53)}`, w2]);
      await rejected(() => db!.exec("INSERT INTO portal_developers(cluster_id,workspace_id,username,email,display_name,password_hash) VALUES($1,$2,$3,'other@example.test','same',$4)", [c1, w1, username, `$2b$12$${'a'.repeat(53)}`]), '23505');
    });
    await check('cross-cluster and cross-workspace developer references fail at the database boundary', async () => {
      await rejected(() => application(s1, devOtherCluster), '23503'); await rejected(() => application(s1, devOtherWorkspace), '23503');
      await rejected(() => db!.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name) VALUES($1,$2,'wrong-scope','wrong')", [c2, w1]), '23503');
    });
    await check('application owner cannot be replaced with another same-tenant developer', async () => {
      await rejected(() => db!.exec('UPDATE portal_applications SET developer_id=$2 WHERE id=$1', [app1, dev2]), '23514');
      await rejected(() => reserveGrant(s1, dev2, app1, pub2), '23503');
    });
    await check('Service publication is unique across logical aliases of its captured physical gateway', async () => {
      await rejected(() => publication(sa, service1), '23505');
      await publication(s3, service1, otherTransport);
    });
    await check('captured publication and grant physical identity survive CID remapping and cannot be edited', async () => {
      await db!.exec("UPDATE clusters SET admin_url='http://schema-new-gateway:8001',revision=revision+1 WHERE id=$1", [c1]);
      assert((await db!.one<any>('SELECT transport_scope FROM portal_publications WHERE id=$1', [pub1]))!.transport_scope === transport);
      assert((await db!.one<any>('SELECT transport_scope FROM portal_application_grants WHERE id=$1', [grant]))!.transport_scope === transport);
      await rejected(() => db!.exec('UPDATE portal_publications SET transport_scope=$2 WHERE id=$1', [pub1, otherTransport]), '23514');
      await rejected(() => db!.exec('UPDATE portal_application_grants SET transport_scope=$2 WHERE id=$1', [grant, otherTransport]), '23514');
      await rejected(() => reserveGrant(sa, devAlias, appAlias, pubAlias, consumer), '23505');
    });
    await check('reserved Consumer, ACL UUID and group are non-null and immutably owned', async () => {
      await rejected(() => db!.exec('UPDATE portal_application_grants SET acl_id=NULL WHERE id=$1', [grant]), ['23514', '23502']);
      for (const field of ['consumer_id', 'acl_id']) await rejected(() => db!.exec(`UPDATE portal_application_grants SET ${field}=$2 WHERE id=$1`, [grant, randomUUID()]), '23514');
      await rejected(() => db!.exec("UPDATE portal_application_grants SET acl_group='attacker-group' WHERE id=$1", [grant]), '23514');
    });
    await check('generation-zero grant cannot claim an active credential or an unrelated current pointer', async () => {
      await rejected(() => db!.exec("UPDATE portal_application_grants SET state='active' WHERE id=$1", [grant]), '23514');
      await rejected(() => db!.exec('UPDATE portal_application_grants SET current_credential_id=$2,current_generation=1 WHERE id=$1', [grant, randomUUID()]), '23503');
    });
    await check('approval mode requires approval; direct credential issuance still requires an actual approval', async () => {
      await rejected(() => flow(s1, { mode: 'approval', approval: false }), '23514');
      await rejected(() => flow(s1, { kind: 'portal-credential-issue', subjectType: 'portal_application_grants', subject: grant, approval: false }), '23514');
      assert((await db!.one<any>('SELECT approval_required,execution_mode FROM workflow_executions WHERE id=$1', [credentialDirectExecution]))!.approval_required);
    });
    await check('direct compound workflow has no stages, decisions, approved actor or approved state', async () => {
      assert((await db!.one<any>('SELECT count(*)::int AS n FROM workflow_stages WHERE workflow_id=$1', [direct.id]))!.n === 0);
      await rejected(() => db!.exec("UPDATE workflows SET state='approved',approved_by=$2,approved_at=now() WHERE id=$1", [direct.id, approver]), '23514');
      await rejected(() => db!.exec("INSERT INTO workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level) VALUES($1,$2,$3,1,$4,1)", [c1, w1, direct.id, hash]), '23514');
      await rejected(() => db!.exec('UPDATE workflow_executions SET approved_by=$2 WHERE id=$1', [directExecution, approver]), '23514');
    });
    await check('version, scope, hash and approval-mode changes cannot mutate normalized steps', async () => {
      for (const [field, value] of [['plan_hash', 'c'.repeat(64)], ['cluster_id', c2], ['workspace_id', w2], ['execution_mode', 'direct'], ['approval_required', false]]) {
        await rejected(() => db!.exec(`UPDATE workflow_steps SET ${field}=$2 WHERE id=$1`, [approved.steps[0], value]), '23514');
      }
    });
    await check('scope-correct but missing or wrong workflow subjects cannot be submitted', async () => {
      await rejected(() => flow(s1, { subject: setting2 }), '23503');
      await rejected(() => flow(s1, { subject: setting3 }), '23503');
      await rejected(() => flow(s1, { kind: 'portal-publication', subject: setting1 }), '23514');
      await rejected(() => flow(s1, { kind: 'portal-credential-issue', subjectType: 'portal_application_grants', subject: grant, requester: dev2, approval: true }), '23514');
    });
    await check('definition stages, immutable step counts and ordering are checked at COMMIT', async () => {
      await rejected(() => flow(s1, { definitionStage: false }), '23514');
      await rejected(() => db!.transaction(async tx => {
        const id = randomUUID(); await tx.exec("INSERT INTO workflow_steps(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,step_key,step_order,kind,handler,entity_type,permission_action,metadata_before_hmac,metadata_revision,metadata_payload_hmac) VALUES($1,$2,$3,$4,1,$5,'direct',false,'extra',2,'metadata','portal.settings.update','portal_settings','write',$5,1,$5)", [id, c1, w1, direct.id, hash]);
      }), '23514');
    });
    await check('cross-version, self and forward dependencies are rejected rather than silently ignored', async () => {
      await rejected(() => flow(s1, { native: 2, dependencies: [[approved.steps[0]], []] }), '23514');
      await rejected(() => db!.exec('UPDATE workflow_steps SET dependencies=ARRAY[id] WHERE id=$1', [approved.steps[0]]), '23514');
    });
    await check('execution with a forged approved_by cannot exist without its real matching decision', async () => {
      const unapproved = await flow(s1, { approval: true });
      await rejected(() => execution(unapproved), '23514');
      await rejected(() => db!.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)", [c1, w1, unapproved.id, hash, user, `self-${unapproved.id}`]), '23514');
    });
    await check('approved operation and exact step allocate in one deferred-FK transaction', async () => {
      const op = await allocate(approved, execution1, approved.steps[0]);
      assert((await db!.one<any>('SELECT operation_id FROM workflow_steps WHERE id=$1', [approved.steps[0]]))!.operation_id === op);
      assert((await db!.one<any>('SELECT workflow_step_id FROM mutation_operations WHERE id=$1', [op]))!.workflow_step_id === approved.steps[0]);
      await rejected(() => db!.exec('UPDATE mutation_operations SET workflow_plan_hash=$2 WHERE id=$1', [op, 'c'.repeat(64)]), '23514');
      await rejected(() => db!.exec('UPDATE workflow_steps SET operation_id=$2 WHERE id=$1', [approved.steps[0], randomUUID()]), '23514');
    });
    await check('operation-only allocation without reciprocal step CAS rolls back', async () => {
      await rejected(() => allocate(approved, execution1, approved.steps[1], { reciprocal: false }), '23503');
      assert((await db!.one<any>('SELECT operation_id FROM workflow_steps WHERE id=$1', [approved.steps[1]]))!.operation_id === null);
    });
    await check('an execution from another workflow cannot bind a scope-correct approved step', async () => {
      await rejected(() => allocate(approved, credentialDirectExecution, approved.steps[1]), '23503');
    });
    await check('ordinary native ledgers keep four binding columns null and cannot later acquire approval authority', async () => {
      const ordinary = randomUUID(); await db!.exec("INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,workflow_id) VALUES($1,$2,$3,$4,'create',$5,$6,'running',$7)", [ordinary, c1, w1, user, `ordinary-${ordinary}`, hash, randomUUID()]);
      await rejected(() => db!.exec('UPDATE mutation_operations SET workflow_step_id=$2,workflow_execution_id=$3,workflow_plan_revision=1,workflow_plan_hash=$4,workflow_id=$5 WHERE id=$1', [ordinary, approved.steps[1], execution1, hash, approved.id]), '23514');
      await rejected(() => db!.exec('UPDATE workflow_steps SET operation_id=$2 WHERE id=$1', [direct.steps[0], ordinary]), '23514');
      await rejected(() => db!.exec('INSERT INTO mutation_operations(id,cluster_id,action,idempotency_key,request_hash,workflow_execution_id) VALUES($1,$2,\'create\',$3,$4,$5)', [randomUUID(), c1, `partial-${randomUUID()}`, hash, execution1]), '23514');
    });
    await check('direct native steps and approved metadata steps both reject native operation pointers', async () => {
      const directNative = await flow(s1, { native: 1 }), directNativeExecution = await execution(directNative);
      await rejected(() => allocate(directNative, directNativeExecution, directNative.steps[0]), '23514');
      await rejected(() => allocate(credentialApprovalDirect, credentialDirectExecution, credentialApprovalDirect.steps[0]), '23514');
    });
    await check('approved allocation rejects forged native parent, executor and hash tuples', async () => {
      await rejected(() => allocate(approved, execution1, approved.steps[1], { consumer: randomUUID() }), '23514');
      await rejected(() => db!.transaction(async tx => {
        const op = randomUUID(), row = (await tx.one<any>('SELECT entity_id,parent_id FROM workflow_steps WHERE id=$1', [approved.steps[1]]))!;
        await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id,entity_type,entity_id,parent_id,credential_kind)
          VALUES($1,$2,$3,$4,'create',$5,$6,'running',$7,$8,1,$6,$9,'credentials',$10,$11,'key-auth')`, [op, c1, w1, user, `forged-${op}`, hash, approved.id, execution1, approved.steps[1], row.entity_id, row.parent_id]);
        await tx.exec('UPDATE workflow_steps SET operation_id=$2 WHERE id=$1', [approved.steps[1], op]);
      }), '23514');
      await rejected(() => db!.transaction(async tx => {
        const op = randomUUID(), row = (await tx.one<any>('SELECT entity_id,parent_id FROM workflow_steps WHERE id=$1', [approved.steps[1]]))!;
        await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id,entity_type,entity_id,parent_id,credential_kind)
          VALUES($1,$2,$3,$4,'create',$5,$6,'running',$7,$8,1,$12,$9,'credentials',$10,$11,'key-auth')`, [op, c1, w1, approver, `hash-forged-${op}`, hash, approved.id, execution1, approved.steps[1], row.entity_id, row.parent_id, 'd'.repeat(64)]);
        await tx.exec('UPDATE workflow_steps SET operation_id=$2 WHERE id=$1', [approved.steps[1], op]);
      }), '23503');
    });
    await check('execution snapshots seal once and cannot be replaced by another encrypted graph', async () => {
      await db!.exec("UPDATE workflow_executions SET snapshot_state='ready',snapshot_secret=$2,snapshot_hash=$3,revision=revision+1 WHERE id=$1", [execution1, encrypted, hash]);
      await rejected(() => db!.exec('UPDATE workflow_executions SET snapshot_secret=$2 WHERE id=$1', [execution1, secrets.encrypt({ changed: true })]), '23514');
      await rejected(() => db!.exec("UPDATE workflow_executions SET snapshot_state='pending',snapshot_secret=NULL,snapshot_hash=NULL WHERE id=$1", [execution1]), '23514');
    });
    await check('a public revision requires its exact successful immutable proof and parent terminal state', async () => {
      await rejected(() => db!.exec("UPDATE portal_publications SET state='published',published_revision=1,key_auth_plugin_id=$2,acl_plugin_id=$3 WHERE id=$1", [pub1, randomUUID(), randomUUID()]), '23514');
      const publishing = await flow(s1, { kind: 'portal-publication', subjectType: 'portal_publications', subject: pub1 });
      const publishingExecution = await execution(publishing, true);
      const proofSql = `INSERT INTO portal_publication_proofs(cluster_id,workspace_id,publication_id,publication_revision,transport_scope,publication_proof_secret,publication_proof_hmac,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,1,$6)`;
      const params = [c1, w1, pub1, transport, encrypted, hash, publishing.id, publishingExecution];
      await rejected(() => db!.exec(proofSql, params), '23514');
      await rejected(() => db!.exec(proofSql, [c1, w1, pub1, otherTransport, encrypted, hash, publishing.id, publishingExecution]), '23503');
      await db!.transaction(async tx => {
        await tx.exec(proofSql, params);
        await tx.exec("UPDATE workflow_steps SET state='succeeded',started_at=now(),completed_at=now(),revision=revision+1 WHERE workflow_id=$1", [publishing.id]);
        await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1 WHERE id=$1", [publishingExecution]);
        await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1 WHERE id=$1", [publishing.id]);
        await tx.exec("UPDATE portal_publications SET state='published',published_revision=1,workflow_id=$2,key_auth_plugin_id=$3,acl_plugin_id=$4,revision=revision+1 WHERE id=$1", [pub1, publishing.id, randomUUID(), randomUUID()]);
      });
    });
    await check('used refresh history belongs to the complete scope and preserves replay evidence until expiry', async () => {
      const sid = randomUUID();
      await db!.exec("INSERT INTO portal_sessions(id,cluster_id,workspace_id,developer_id,family_id,credential_epoch,refresh_token_hash,csrf_token_hash,expires_at) VALUES($1,$2,$3,$4,$1,1,$5,$5,now()+interval '1 hour')", [sid, c1, w1, dev1, hash]);
      await rejected(() => db!.exec("INSERT INTO portal_refresh_history(cluster_id,workspace_id,session_id,token_hash,generation,expires_at) VALUES($1,$2,$3,$4,0,now()+interval '1 hour')", [c1, w2, sid, hash]), '23503');
      await db!.exec("INSERT INTO portal_refresh_history(cluster_id,workspace_id,session_id,token_hash,generation,expires_at) VALUES($1,$2,$3,$4,0,now()+interval '1 hour')", [c1, w1, sid, hash]);
      await rejected(() => db!.exec('DELETE FROM portal_refresh_history WHERE session_id=$1', [sid]), '42501');
      await rejected(() => db!.exec("UPDATE portal_sessions SET refresh_token_hash=$2 WHERE id=$1", [sid, 'c'.repeat(64)]), '23514');
      await db!.exec('UPDATE portal_sessions SET refresh_token_hash=$2,csrf_token_hash=$2,refresh_generation=refresh_generation+1 WHERE id=$1', [sid, 'c'.repeat(64)]);
      await rejected(() => db!.exec("UPDATE portal_developers SET status='disabled',credential_epoch=credential_epoch+1 WHERE id=$1", [dev1]), '23514');
      await db!.transaction(async tx => {
        await tx.exec("UPDATE portal_developers SET status='disabled',credential_epoch=credential_epoch+1,revision=revision+1 WHERE id=$1", [dev1]);
        await tx.exec('UPDATE portal_sessions SET revoked_at=now() WHERE developer_id=$1 AND revoked_at IS NULL', [dev1]);
      });
      await rejected(() => db!.exec('UPDATE portal_sessions SET revoked_at=NULL WHERE id=$1', [sid]), '23514');
    });
    await check('pending developer cannot obtain a database session and password cannot be retained in its operation', async () => {
      const pending = await developer(s1, 'pending');
      await rejected(() => db!.exec("INSERT INTO portal_sessions(cluster_id,workspace_id,developer_id,family_id,credential_epoch,refresh_token_hash,csrf_token_hash,expires_at) VALUES($1,$2,$3,$4,1,$5,$5,now()+interval '1 hour')", [c1, w1, pending, randomUUID(), hash]), '23514');
      await rejected(() => db!.exec("INSERT INTO portal_operations(cluster_id,workspace_id,developer_id,idempotency_key,request_hash,module,action,payload_secret) VALUES($1,$2,$3,$4,$5,'password','change',$6)", [c1, w1, dev1, `password-${randomUUID()}`, hash, encrypted]), '23514');
    });
    await check('encrypted key and CredentialStore references retain same Consumer and credential kind', async () => {
      const keyId = issuedKeyId, keyRef = randomUUID(), aclRef = randomUUID(), unrelatedRef = randomUUID();
      const grantRow = (await db!.one<any>('SELECT acl_id FROM portal_application_grants WHERE id=$1', [grant]))!;
      await db!.exec(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,recovery_capability)
        VALUES($1,$2,$3,'key-auth',$4,$5,'synthetic'),($6,$2,$3,'acls',$7,$5,'synthetic'),($8,$2,$9,'key-auth',$10,$5,'synthetic')`, [keyRef, c1, consumer, keyId, encrypted, aclRef, grantRow.acl_id, unrelatedRef, randomUUID(), randomUUID()]);
      await rejected(() => db!.exec('UPDATE portal_application_grants SET acl_credential_ref_id=$2 WHERE id=$1', [grant, keyRef]), '23503');
      await db!.exec('UPDATE portal_application_grants SET acl_credential_ref_id=$2 WHERE id=$1', [grant, aclRef]);
      const cred = randomUUID();
      const credentialSql = `INSERT INTO portal_credentials(id,cluster_id,workspace_id,grant_id,developer_id,consumer_id,kong_id,generation,key_secret,key_fingerprint,workflow_id,credential_ref_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11)`;
      await rejected(() => db!.exec(credentialSql, [cred, c1, w1, grant, dev2, consumer, keyId, encrypted, hash, issueFlow.id, keyRef]), '23503');
      await rejected(() => db!.exec(credentialSql, [cred, c1, w1, grant, dev1, consumer, keyId, encrypted, hash, issueFlow.id, unrelatedRef]), '23503');
      await db!.exec(credentialSql, [cred, c1, w1, grant, dev1, consumer, keyId, encrypted, hash, issueFlow.id, keyRef]);
      await rejected(() => db!.exec('UPDATE portal_credentials SET key_secret=$2 WHERE id=$1', [cred, secrets.encrypt({ key: 'replacement' })]), '23514');
      await rejected(() => db!.exec('UPDATE portal_application_grants SET current_generation=2,current_credential_id=$2 WHERE id=$1', [grant, cred]), '23503');
      await rejected(() => db!.exec("UPDATE portal_credentials SET state='active' WHERE id=$1", [cred]), '23514');
      const op = await allocate(issueFlow, issueExecution, issueFlow.steps[0], { consumer, kongId: keyId });
      await db!.transaction(async tx => {
        await tx.exec("UPDATE mutation_operations SET state='succeeded',remote_started=true,remote_completed=true WHERE id=$1", [op]);
        await tx.exec("UPDATE workflow_steps SET state='succeeded',completed_at=now(),revision=revision+1 WHERE id=$1", [issueFlow.steps[0]]);
        await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1 WHERE id=$1", [issueExecution]);
        await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1 WHERE id=$1", [issueFlow.id]);
        await tx.exec("UPDATE portal_credentials SET state='active',issue_operation_id=$2,revision=revision+1 WHERE id=$1", [cred, op]);
        await tx.exec("UPDATE portal_application_grants SET state='active',workflow_id=$2,current_credential_id=$3,current_generation=1,revision=revision+1 WHERE id=$1", [grant, issueFlow.id, cred]);
      });
      assert((await db!.one<any>('SELECT state FROM portal_application_grants WHERE id=$1', [grant]))!.state === 'active');
    });
    await check('revoked grant/key cannot drop active risk without exact successful DELETE and terminal revoke parent',async()=>{
      const credential=(await db!.one<any>('SELECT id,kong_id FROM portal_credentials WHERE grant_id=$1',[grant]))!;
      await rejected(()=>db!.exec("UPDATE portal_credentials SET state='revoked',revoked_at=now() WHERE id=$1",[credential.id]),'23514');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET state='revoked',revoked_at=now() WHERE id=$1",[grant]),'23514');
      const revoke=await flow(s1,{approval:true,mode:'direct',native:1,nativeConsumer:consumer,nativeId:credential.kong_id,mutationAction:'delete',subject:grant,subjectType:'portal_application_grants',kind:'portal-credential-revoke',requester:dev1});
      await approve(revoke);const execId=await execution(revoke),op=await allocate(revoke,execId,revoke.steps[0],{consumer,kongId:credential.kong_id});
      await rejected(()=>db!.exec("UPDATE portal_credentials SET state='revoked',revoked_at=now(),revoke_workflow_id=$2,revoke_operation_id=$3 WHERE id=$1",[credential.id,revoke.id,op]),'23514');
      await db!.transaction(async tx=>{
        await tx.exec("UPDATE mutation_operations SET state='succeeded',remote_started=true,remote_completed=true WHERE id=$1",[op]);
        await tx.exec("UPDATE workflow_steps SET state='succeeded',completed_at=now(),revision=revision+1 WHERE id=$1",[revoke.steps[0]]);
        await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1 WHERE id=$1",[execId]);
        await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1 WHERE id=$1",[revoke.id]);
        await tx.exec("UPDATE portal_credentials SET state='revoked',revoked_at=now(),revoke_workflow_id=$2,revoke_operation_id=$3,revision=revision+1 WHERE id=$1",[credential.id,revoke.id,op]);
        await tx.exec("UPDATE portal_application_grants SET state='revoked',revoked_at=now(),workflow_id=$2,revision=revision+1 WHERE id=$1",[grant,revoke.id]);
      });
      assert((await db!.one<any>('SELECT state FROM portal_application_grants WHERE id=$1',[grant]))!.state==='revoked');
      await rejected(()=>db!.exec("UPDATE portal_credentials SET state='active',revoked_at=NULL WHERE id=$1",[credential.id]),'23514');
    });
    await check('workflow event actor, version and step tuples cannot reference another tenant', async () => {
      await db!.exec("INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_type,actor_id,action,result) VALUES($1,$2,$3,1,$4,'user',$5,'test','success')", [c1, w1, approved.id, hash, approver]);
      await rejected(() => db!.exec("INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_type,actor_id,developer_id,action,result) VALUES($1,$2,$3,1,$4,'developer',$5,$6,'test','success')", [c1, w1, approved.id, hash, approver, dev1]), '23514');
      await rejected(() => db!.exec("INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_type,developer_id,action,result) VALUES($1,$2,$3,1,$4,'developer',$5,'test','success')", [c1, w1, approved.id, hash, devOtherWorkspace]), '23503');
      await rejected(() => db!.exec("INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,step_id,actor_type,action,result) VALUES($1,$2,$3,1,$4,$5,'system','test','success')", [c1, w1, approved.id, hash, direct.steps[0]]), '23503');
    });
    await check('new workflow audit requires a real same-scope parent while immutable legacy rows remain untouched', async () => {
      const sql = `INSERT INTO audit_events(id,chain_scope,sequence,actor_id,cluster_id,workspace_id,entity_type,action,workflow_id,prev_hash,event_hash,occurred_at) VALUES($1,'m6-schema',1,$2,$3,$4,'portal','schema',$5,'GENESIS',$6,now())`;
      await db!.exec("INSERT INTO audit_chain_heads(chain_scope) VALUES('m6-schema')");
      await rejected(() => db!.exec(sql, [randomUUID(), approver, c1, w2, approved.id, 'c'.repeat(64)]), '23503');
      await db!.exec(sql, [randomUUID(), approver, c1, w1, approved.id, 'c'.repeat(64)]);
    });
    const reservation = async (terminal?: 'cancelled'|'rejected'|'expired', approvedFirst=false,owner=dev1) => {
      const app=await application(s1,owner), consumerId=randomUUID(), id=await reserveGrant(s1,owner,app,pub2,consumerId), keyId=randomUUID(), credentialId=randomUUID();
      const parent=await flow(s1,{approval:true,mode:'direct',native:1,nativeConsumer:consumerId,nativeId:keyId,
        subject:id,subjectType:'portal_application_grants',kind:'portal-credential-issue',requester:owner});
      await db!.exec(`INSERT INTO portal_credentials(id,cluster_id,workspace_id,grant_id,developer_id,consumer_id,kong_id,generation,key_secret,key_fingerprint,workflow_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)`,[credentialId,c1,w1,id,owner,consumerId,keyId,encrypted,hash,parent.id]);
      await db!.exec('UPDATE portal_application_grants SET workflow_id=$2 WHERE id=$1',[id,parent.id]);
      if(approvedFirst)await approve(parent);
      if(terminal)await db!.exec("UPDATE workflows SET state=$2,cancelled_at=CASE WHEN $2='cancelled' THEN now() ELSE NULL END,revision=revision+1 WHERE id=$1",[parent.id,terminal]);
      return {id,app,consumerId,keyId,credentialId,parent};
    };
    type Reservation=Awaited<ReturnType<typeof reservation>>;
    const release = async (r:Reservation) => db!.exec("UPDATE portal_application_grants SET state='disabled',reservation_released_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",[r.id]);
    const rawReference = async (r:Reservation,scope=s1) => db!.exec(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,recovery_capability)
      VALUES($1,$2,$3,'key-auth',$4,$5,'synthetic')`,[randomUUID(),scope.cid,r.consumerId,r.keyId,encrypted]);
    const rawOperation = async (r:Reservation,scope=s1,withParent=true) => db!.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,workflow_id,entity_type,entity_id,parent_id,credential_kind)
      VALUES($1,$2,$3,$4,'create',$5,$6,'failed',$7,'credentials',$8,$9,'key-auth')`,[randomUUID(),scope.cid,scope.wid,approver,`unused-${randomUUID()}`,hash,withParent?r.parent.id:null,r.keyId,r.consumerId]);
    let released:Reservation;
    await check('cancelled, rejected and expired unused reservations free the live pair without erasing historical ownership',async()=>{
      for(const terminal of ['cancelled','rejected','expired'] as const){
        const r=await reservation(terminal);
        assert(await db!.transaction(tx=>releaseUnusedPortalReservations(tx,{clusterId:c1,workspaceId:w1,applicationId:r.app}))===1);released=r;
        const replacementConsumer=randomUUID(),replacement=await reserveGrant(s1,dev1,r.app,pub2,replacementConsumer);
        const old=(await db!.one<any>('SELECT consumer_id,acl_id,reservation_released_at,state FROM portal_application_grants WHERE id=$1',[r.id]))!;
        assert(old.consumer_id===r.consumerId&&old.reservation_released_at!==null&&old.state==='disabled');
        assert((await db!.one<any>('SELECT kong_id,key_secret,state FROM portal_credentials WHERE id=$1',[r.credentialId]))!.kong_id===r.keyId);
        assert((await db!.one<any>('SELECT consumer_id FROM portal_application_grants WHERE id=$1',[replacement]))!.consumer_id===replacementConsumer);
        await rejected(()=>reserveGrant(s1,dev1,r.app,pub2),'23505');
        const historyApp=await application(s1,dev1);await rejected(()=>reserveGrant(s1,dev1,historyApp,pub2,r.consumerId),'23505');
      }
    });
    await check('a proved revoked pair can receive a fresh grant while old key and Consumer history remain irrevocable',async()=>{
      const next=await reserveGrant(s1,dev1,app1,pub1);
      assert(next!==grant&&(await db!.one<any>('SELECT state FROM portal_application_grants WHERE id=$1',[grant]))!.state==='revoked');
      assert((await db!.one<any>("SELECT count(*)::int AS n FROM portal_credentials WHERE grant_id=$1 AND state='revoked'",[grant]))!.n===1);
      await rejected(()=>reserveGrant(s1,dev1,app1,pub1),'23505');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET state='disabled',revoked_at=NULL WHERE id=$1",[grant]),'23514');
    });
    await check('pending, failed, partial and uncertain issue parents never qualify as unused terminal reservations',async()=>{
      for(const state of ['pending','failed','partial','uncertain']){
        const r=await reservation();if(state!=='pending')await db!.exec('UPDATE workflows SET state=$2 WHERE id=$1',[r.parent.id,state]);
        await rejected(()=>release(r),'23514');
        assert((await db!.one<any>('SELECT reservation_released_at FROM portal_application_grants WHERE id=$1',[r.id]))!.reservation_released_at===null);
      }
    });
    await check('release requires its exact issue parent and an entirely unissued generation-zero grant',async()=>{
      const r=await reservation('cancelled'), other=await reservation('cancelled');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET workflow_id=$2,state='disabled',reservation_released_at=clock_timestamp() WHERE id=$1",[r.id,other.parent.id]),'23514');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET current_generation=1,current_credential_id=$2,state='disabled',reservation_released_at=clock_timestamp() WHERE id=$1",[r.id,r.credentialId]),'23514');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET workflow_id=NULL,state='disabled',reservation_released_at=clock_timestamp() WHERE id=$1",[r.id]),'23514');
    });
    await check('any execution history including claimed, failed and uncertain prevents reservation release',async()=>{
      for(const state of ['claimed','failed','uncertain']){
        const r=await reservation(undefined,true);await execution(r.parent,false,state);
        await db!.exec("UPDATE workflows SET state='cancelled',cancelled_at=now() WHERE id=$1",[r.parent.id]);
        await rejected(()=>release(r),'23514');
      }
    });
    await check('historical sibling workflows and legacy native receipts cannot hide behind the current issue pointer',async()=>{
      const r=await reservation('cancelled');
      await flow(s1,{approval:true,mode:'direct',subject:r.id,subjectType:'portal_application_grants',kind:'portal-credential-issue',requester:dev1});
      await rejected(()=>release(r),'23514');
      const op=await reservation('cancelled');await rawOperation(op);await rejected(()=>release(op),'23514');
    });
    await check('pristine pending steps are required even when no execution or operation row exists',async()=>{
      for(const field of ['state','receipt_secret','safe_result','started_at','after_fingerprint']){
        const r=await reservation('cancelled');
        const expression:Record<string,string>={state:"'uncertain'",receipt_secret:'$2',safe_result:"'{\"nativeOperationId\":\"synthetic\"}'::jsonb",started_at:'now()',after_fingerprint:'$2'};
        await db!.exec(`UPDATE workflow_steps SET ${field}=${expression[field]} WHERE id=$1`,field==='receipt_secret'?[r.parent.steps[0],encrypted]:field==='after_fingerprint'?[r.parent.steps[0],hash]:[r.parent.steps[0]]);
        await rejected(()=>release(r),'23514');
      }
    });
    await check('same-gateway alias native receipts and CredentialStore facts forbid unused release',async()=>{
      const op=await reservation('cancelled');await rawOperation(op,sa,false);await rejected(()=>release(op),'23514');
      const ref=await reservation('cancelled');await rawReference(ref,sa);await rejected(()=>release(ref),'23514');
      await rejected(()=>db!.exec('DELETE FROM credential_refs WHERE cluster_id=$1 AND consumer_id=$2',[alias,ref.consumerId]),'42501');
      await rejected(()=>db!.exec('UPDATE credential_refs SET consumer_id=$3 WHERE cluster_id=$1 AND consumer_id=$2',[alias,ref.consumerId,randomUUID()]),'23514');
    });
    await check('credential uncertainty, reveal and revoke facts prevent release without a linked active key',async()=>{
      for(const field of ['state','last_revealed_at','revoke_workflow_id']){
        const r=await reservation('cancelled');
        if(field==='state')await db!.exec("UPDATE portal_credentials SET state='uncertain' WHERE id=$1",[r.credentialId]);
        else if(field==='last_revealed_at')await db!.exec('UPDATE portal_credentials SET last_revealed_at=now() WHERE id=$1',[r.credentialId]);
        else await db!.exec('UPDATE portal_credentials SET revoke_workflow_id=$2 WHERE id=$1',[r.credentialId,r.parent.id]);
        await rejected(()=>release(r),'23514');
      }
    });
    await check('released timestamp, terminal parent and reserved identities cannot be cleared, changed or rebound',async()=>{
      await rejected(()=>db!.exec('UPDATE portal_application_grants SET reservation_released_at=NULL WHERE id=$1',[released!.id]),'23514');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET reservation_released_at=reservation_released_at+interval '1 second' WHERE id=$1",[released!.id]),'23514');
      await rejected(()=>db!.exec('UPDATE portal_application_grants SET workflow_id=$2 WHERE id=$1',[released!.id,issueFlow.id]),'23514');
      await rejected(()=>db!.exec("UPDATE portal_application_grants SET state='pending' WHERE id=$1",[released!.id]),'23514');
    });
    await check('later references, operations, credential facts and allocations cannot invalidate a released proof',async()=>{
      await rejected(()=>rawReference(released!,sa),'23514');await rejected(()=>rawOperation(released!,sa,false),'23514');
      await rejected(()=>db!.exec("UPDATE portal_credentials SET state='uncertain' WHERE id=$1",[released!.credentialId]),'23514');
      await rejected(()=>db!.exec("UPDATE workflow_steps SET state='running',started_at=now() WHERE id=$1",[released!.parent.steps[0]]),'23514');
      await rejected(()=>flow(s1,{approval:true,mode:'direct',subject:released!.id,subjectType:'portal_application_grants',kind:'portal-credential-issue',requester:dev1}),'23514');
      await rejected(()=>db!.exec(`INSERT INTO portal_credentials(cluster_id,workspace_id,grant_id,developer_id,consumer_id,kong_id,generation,key_secret,key_fingerprint,workflow_id)
        VALUES($1,$2,$3,$4,$5,$6,2,$7,$8,$9)`,[c1,w1,released!.id,dev1,released!.consumerId,randomUUID(),encrypted,hash,released!.parent.id]),'23514');
    });
    await check('later execution of an approved-but-cancelled released plan is rejected',async()=>{
      const r=await reservation('cancelled',true);await release(r);await rejected(()=>execution(r.parent),'23514');
    });
    await check('repeatable-read snapshots cannot authorize a stale release proof',async()=>{
      const r=await reservation('cancelled');await rejected(()=>db!.transaction(async tx=>{
        await tx.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        await tx.exec("UPDATE portal_application_grants SET state='disabled',reservation_released_at=clock_timestamp() WHERE id=$1",[r.id]);
      }),'25001');
    });
    await check('concurrent release wins safely: execution, native operation and reference commits are rejected',async()=>{
      for(const kind of ['execution','operation','reference'] as const){
        const r=await reservation('cancelled',kind==='execution');
        let locked!:()=>void,continueCommit!:()=>void;
        const rowLocked=new Promise<void>(resolve=>{locked=resolve;}),allowCommit=new Promise<void>(resolve=>{continueCommit=resolve;});
        const releasing=db!.transaction(async tx=>{
          await tx.exec("UPDATE portal_application_grants SET state='disabled',reservation_released_at=clock_timestamp(),revision=revision+1 WHERE id=$1",[r.id]);locked();await allowCommit;
        });
        await rowLocked;
        const fact=kind==='execution'?execution(r.parent):kind==='operation'?rawOperation(r,sa,false):rawReference(r,sa);
        const rejection=rejected(()=>fact,'23514');
        await new Promise(resolve=>setTimeout(resolve,50));continueCommit();await releasing;await rejection;
        assert((await db!.one<any>('SELECT reservation_released_at FROM portal_application_grants WHERE id=$1',[r.id]))!.reservation_released_at!==null);
      }
    });
    await check('concurrent fact wins safely: a waiting release observes committed evidence and rolls back',async()=>{
      for(const kind of ['operation','reference'] as const){
        const r=await reservation('cancelled');let locked!:()=>void,continueCommit!:()=>void;
        const rowLocked=new Promise<void>(resolve=>{locked=resolve;}),allowCommit=new Promise<void>(resolve=>{continueCommit=resolve;});
        const writing=db!.transaction(async tx=>{
          await tx.exec(`SET CONSTRAINTS ${kind==='operation'?'mutation_operations':'credential_refs'}_reservation_history IMMEDIATE`);
          if(kind==='reference')await tx.exec(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,recovery_capability)
            VALUES($1,$2,$3,'key-auth',$4,$5,'synthetic')`,[randomUUID(),alias,r.consumerId,r.keyId,encrypted]);
          else await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,entity_type,entity_id,parent_id,credential_kind)
            VALUES($1,$2,$3,$4,'create',$5,$6,'uncertain','credentials',$7,$8,'key-auth')`,[randomUUID(),alias,wa,approver,`concurrent-${randomUUID()}`,hash,r.keyId,r.consumerId]);
          locked();await allowCommit;
        });
        await rowLocked;const rejection=rejected(()=>release(r),'23514');
        await new Promise(resolve=>setTimeout(resolve,50));continueCommit();await writing;await rejection;
        assert((await db!.one<any>('SELECT reservation_released_at FROM portal_application_grants WHERE id=$1',[r.id]))!.reservation_released_at===null);
      }
    });
    const portalAuth=new PortalAuthService(db,{} as any,secrets,new AuditService(db,secrets,new AuditOutboxWriter(db,secrets)),
      {assertWholeWorkspace:async()=>undefined} as any,{assertStep:async()=>{throw new Error('Approval cannot be bypassed');}});
    const metadataActor={user:{id:user,username:'portal-schema-bootstrap',superAdmin:true}},metadataScope={clusterId:c1,workspaceId:w1};
    await check('actual PortalAuth archive closes an unused reservation and developer epoch in the same audited SQL transaction',async()=>{
      const owner=await developer(s1),r=await reservation('cancelled',false,owner);
      const result=await portalAuth.reviewDeveloper(metadataActor,owner,metadataScope,{revision:1,status:'disabled'},{requestId:'schema-unused-archive'});
      assert(result.status==='disabled');
      const grantRow=(await db!.one<any>('SELECT state,reservation_released_at FROM portal_application_grants WHERE id=$1',[r.id]))!;
      assert(grantRow.state==='disabled'&&grantRow.reservation_released_at!==null);
      assert(Number((await db!.one<any>('SELECT credential_epoch FROM portal_developers WHERE id=$1',[owner]))!.credential_epoch)===2);
      const audit=(await db!.one<any>("SELECT after FROM audit_events WHERE entity_id=$1 AND request_id='schema-unused-archive'",[owner]))!;
      assert(audit.after.releasedReservations===1&&!JSON.stringify(audit.after).includes(encrypted));
    });
    await check('actual PortalAuth refuses an unresolved grant and rolls back release, account epoch and audit together',async()=>{
      const owner=await developer(s1),unused=await reservation('cancelled',false,owner),unknown=await reservation('cancelled',false,owner);
      await rawOperation(unknown,sa,false);
      try{await portalAuth.reviewDeveloper(metadataActor,owner,metadataScope,{revision:1,status:'deleted'},{requestId:'schema-unknown-archive'});throw new Error('Expected unresolved grant refusal');}
      catch(error:any){assert(error.getStatus?.()===409&&error.getResponse?.().code==='PORTAL_CREDENTIALS_ACTIVE');}
      const account=(await db!.one<any>('SELECT status,credential_epoch,revision FROM portal_developers WHERE id=$1',[owner]))!;
      assert(account.status==='active'&&Number(account.credential_epoch)===1&&account.revision===1);
      assert((await db!.one<any>('SELECT reservation_released_at FROM portal_application_grants WHERE id=$1',[unused.id]))!.reservation_released_at===null);
      assert((await db!.one<any>("SELECT count(*)::int AS n FROM audit_events WHERE request_id='schema-unknown-archive'"))!.n===0);
    });
    const appendOnly = ['workflow_definition_versions', 'workflow_definition_stages', 'workflow_versions', 'workflow_approvals', 'workflow_events', 'portal_publication_revisions', 'portal_publication_proofs', 'portal_content_revisions', 'audit_events'];
    process.env.CONSOLE_DB_RUNTIME_USER = 'm6_schema_runtime';
    process.env.CONSOLE_DB_RUNTIME_PASSWORD = 'Synthetic!M6DatabaseRolePassword';
    await provisionRuntimeRole(db);
    process.env.DATABASE_URL = `postgres://m6_schema_runtime@127.0.0.1:${port}/postgres`; runtime = new DbService();
    await check('runtime role is non-superuser, non-owner and cannot disable or replace historical triggers', async () => {
      assert((await runtime!.one<any>('SELECT rolsuper,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user'))!.rolsuper === false);
      assert((await runtime!.one<any>("SELECT has_schema_privilege(current_user,'public','CREATE') AS allowed"))!.allowed === false);
      await rejected(() => runtime!.exec('ALTER TABLE workflow_versions DISABLE TRIGGER ALL'), '42501');
      await rejected(() => runtime!.exec('DROP TRIGGER workflow_versions_append_only ON workflow_versions'), '42501');
    });
    for (const table of appendOnly) {
      await check(`non-superuser ${table} UPDATE/DELETE/TRUNCATE are all denied`, async () => {
        assert((await runtime!.one<any>(`SELECT count(*)::int AS n FROM ${table}`))!.n > 0);
        for (const privilege of ['SELECT', 'INSERT']) assert((await runtime!.one<any>('SELECT has_table_privilege(current_user,$1,$2) AS allowed', [table, privilege]))!.allowed === true);
        for (const privilege of ['UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) assert((await runtime!.one<any>('SELECT has_table_privilege(current_user,$1,$2) AS allowed', [table, privilege]))!.allowed === false);
        await rejected(() => runtime!.exec(`UPDATE ${table} SET ${table === 'audit_events' ? 'action=action' : table === 'workflow_approvals' ? 'reason=reason' : 'created_at=created_at'}`), '42501');
        await rejected(() => runtime!.exec(`DELETE FROM ${table}`), '42501');
        await rejected(() => runtime!.exec(`TRUNCATE TABLE ${table} CASCADE`), '42501');
      });
    }
    for (const table of appendOnly) await db.exec(`GRANT UPDATE,DELETE,TRUNCATE ON ${table} TO m6_schema_runtime`);
    await db.exec('GRANT TRUNCATE ON ALL TABLES IN SCHEMA public TO m6_schema_runtime');
    for (const table of appendOnly) {
      await check(`misgranted CRUD still cannot mutate append-only ${table}`, async () => {
        await rejected(() => runtime!.exec(`UPDATE ${table} SET ${table === 'audit_events' ? 'action=action' : table === 'workflow_approvals' ? 'reason=reason' : 'created_at=created_at'}`), '42501');
        await rejected(() => runtime!.exec(`DELETE FROM ${table}`), '42501');
        await rejected(() => runtime!.exec(`TRUNCATE TABLE ${table} CASCADE`), '42501');
      });
    }
    await check('historical keys and root resources cannot be physically removed', async () => {
      await rejected(() => db!.exec('DELETE FROM portal_applications WHERE id=$1', [app2]), '42501');
      await rejected(() => db!.exec('DELETE FROM portal_application_grants WHERE id=$1', [grant]), '42501');
      await rejected(() => db!.exec('DELETE FROM workflows WHERE id=$1', [direct.id]), '42501');
    });
    mkdirSync('artifacts/M6', { recursive: true });
    writeFileSync('artifacts/M6/storage-lifecycle-postgres.json', JSON.stringify({ milestone: 'M6', baselineEvidence: 'storage-postgres.json (49/49 preserved)', database: 'isolated disposable PostgreSQL16; no primary runtime or native calls', passed: checks.length, checks }, null, 2));
    console.log(`Portal PostgreSQL schema: ${checks.length}/${checks.length} passed`);
  } finally {
    await runtime?.onModuleDestroy(); await db?.onModuleDestroy();
    execFileSync('docker', ['rm', '-f', container], { stdio: 'ignore' });
  }
}
main().catch(error => { console.error(`Portal PostgreSQL schema verification failed (${error.code ?? 'assertion'})`); process.exitCode = 1; });
