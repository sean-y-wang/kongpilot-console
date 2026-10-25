import 'reflect-metadata';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { provisionRuntimeRole } from '../../apps/console-api/src/infrastructure/migrate';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { ObservationAuthorityService } from '../../apps/console-api/src/modules/event-observers/observation-authority.service';
import { MetricsWriteFenceService } from '../../apps/console-api/src/modules/metrics/metrics-write-fence.service';

/** Disposable PG16 only. Actual migration/runtime permissions, Authority SQL,
 * private proof, workspace resolver, context, and pre-send fence repository.
 * Kong responses are deterministic GET-only doubles: no existing runtime,
 * native network request, native write or external observation is accessed. */
async function main() {
  const container = 'kongos-m7-observation-parent-' + randomUUID().slice(0, 8), runId = new Date().toISOString().replace(/[:.]/g, '-');
  const env = { ...process.env }; for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[key];
  const docker = (args: string[]) => execFileSync('docker', ['--host=unix:///var/run/docker.sock', ...args], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const code = (error: any) => String(error?.getResponse?.()?.code ?? error?.code ?? 'ASSERTION_FAILED').replace(/[^A-Za-z0-9_]/g, '_').slice(0, 128);
  const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
  const productFile = 'apps/console-api/src/modules/event-observers/observation-authority.service.ts', productSha = sha(readFileSync(productFile));
  const checks: Array<{ name: string; passed: boolean; errorCode?: string }> = [];
  let owner: DbService | undefined, db: DbService | undefined, competing: DbService | undefined, phase = 'init', failure: string | undefined;
  let simulatedReads = 0, nativeWrites = 0, corruptOwnerFixtures = 0;
  const check = async (name: string, fn: () => Promise<void>) => { phase = name; try { await fn(); checks.push({ name, passed: true }); } catch (error) { checks.push({ name, passed: false, errorCode: code(error) }); throw error; } };
  const denied = async (fn: () => Promise<unknown>, expected: string) => { try { await fn(); } catch (error) { assert.equal(code(error), expected); return; } throw Error('EXPECTED_REJECTION'); };
  try {
    docker(['run', '-d', '--pull=never', '--name', container, '-p', '127.0.0.1::5432', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16-alpine']);
    const port = docker(['port', container, '5432']).trim().split(':').pop();
    process.env.DATABASE_URL = `postgres://postgres@127.0.0.1:${port}/postgres`;
    process.env.CONSOLE_ENCRYPTION_KEY = '7d'.repeat(32); process.env.APP_SECRET = 'SyntheticObservationParentSigning2026!';
    process.env.BOOTSTRAP_ADMIN_USERNAME = 'observation-parent-bootstrap'; process.env.BOOTSTRAP_ADMIN_PASSWORD = 'Synthetic!ObservationParentBootstrap2026';
    owner = new DbService();
    for (let attempt = 0; attempt < 80; attempt++) { try { await owner.one('SELECT 1'); break; } catch { if (attempt === 79) throw Error('DISPOSABLE_DATABASE_UNAVAILABLE'); await new Promise(resolve => setTimeout(resolve, 100)); } }
    await owner.migrateAndSeed();
    process.env.CONSOLE_DB_RUNTIME_USER = 'm7_observation_parent_runtime'; process.env.CONSOLE_DB_RUNTIME_PASSWORD = 'Synthetic!ObservationParentRuntime2026';
    await provisionRuntimeRole(owner); process.env.DATABASE_URL = `postgres://m7_observation_parent_runtime@127.0.0.1:${port}/postgres`;
    db = new DbService(); competing = new DbService(); const sql = db, ownerSql = owner, second = competing;
    const execution = new KongExecutionContextService(), secrets = new SecretService(), workspaces = new WorkspaceResolverService(sql);
    await check('all real migrations and nonowner nonsuper runtime role with genuine FOR SHARE privileges', async () => {
      const migrations = await sql.query<any>('SELECT name,checksum FROM schema_migrations'); assert.equal(migrations.length, 11);
      for (const row of migrations) assert.equal(row.checksum, sha(readFileSync('apps/console-api/src/infrastructure/migrations/' + row.name)));
      const role = (await sql.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user'))!;
      assert(Object.values(role).every(value => value === false));
      const owns = (await sql.one<any>("SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname IN('clusters','mutation_operations','metrics_write_fences') AND relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)) AS owns"))!;
      assert.equal(owns.owns, false);
      for (const table of ['clusters', 'mutation_operations', 'workspaces']) assert.equal((await sql.one<any>('SELECT has_table_privilege(current_user,$1,\'SELECT,UPDATE\') AS permitted', [table]))!.permitted, true);
      await denied(() => sql.exec('ALTER TABLE metrics_write_fences ADD COLUMN ownership_bypass boolean'), '42501');
    });
    interface Fixture { cid: string; wid: string; aliasId: string; foreignId: string; scope: string; foreignScope: string; upstreamId: string; targetId: string }
    const fixture = async (): Promise<Fixture> => {
      const cid = randomUUID(), wid = randomUUID(), aliasId = randomUUID(), foreignId = randomUUID(), url = `http://observation-${cid}.invalid:8001`, foreignUrl = `http://foreign-${foreignId}.invalid:8001`;
      const scope = transportScopeFor(url), foreignScope = transportScopeFor(foreignUrl);
      await sql.transaction(async tx => {
        for (const [id, address] of [[cid, url], [aliasId, url + '/'], [foreignId, foreignUrl]]) await tx.exec("INSERT INTO clusters(id,name,admin_url,execution_mode,version,status) VALUES($1,$2,$3,'direct','1.5.1','healthy')", [id, `Synthetic ${id}`, address]);
        await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name,status) VALUES($1,$2,'pay','Synthetic pay','active')", [wid, cid]);
      });
      return { cid, wid, aliasId, foreignId, scope, foreignScope, upstreamId: randomUUID(), targetId: randomUUID() };
    };
    const operation = async (f: Fixture, state: string, scope: string | null = f.scope, cid = f.cid, tx: DbService = sql): Promise<string> => {
      const id = randomUUID(); await tx.exec("INSERT INTO mutation_operations(id,cluster_id,action,idempotency_key,request_hash,state,entity_type,transport_scope,remote_started,remote_completed) VALUES($1,$2,'update',$3,$4,$5,'upstreams',$6,true,$7)", [id, cid, `synthetic-${id}`, 'a'.repeat(64), state, scope, state === 'succeeded']); return id;
    };
    const fence = async (f: Fixture, operationId: string, state = 'pending', scope = f.scope, cid = f.cid, tx: DbService = sql): Promise<string> => {
      const id = randomUUID(); await tx.exec("INSERT INTO metrics_write_fences(id,cluster_id,transport_scope,operation_id,request_fingerprint,entity_type,entity_id,method,path_hash,state,settled_at,cluster_ids) VALUES($1,$2,$3,$4,$5,'upstreams',$6,'PATCH',$7,$8,CASE WHEN $8='pending' THEN NULL ELSE now() END,$9::uuid[])", [id, cid, scope, operationId, sha(id), f.upstreamId, 'b'.repeat(64), state, [f.cid, f.aliasId]]); return id;
    };
    const authority = (f: Fixture) => {
      const upstream = { id: f.upstreamId, name: 'synthetic-upstream', tags: ['kos-ws-pay'] }, target = { id: f.targetId, upstream: { id: f.upstreamId }, target: 'fixture.invalid:80', weight: 100, created_at: 1 };
      const kong: any = { request: async (cid: string, method: string, path: string) => {
        assert.equal(cid, f.cid); if (method !== 'GET') { nativeWrites++; throw Error('NATIVE_WRITE_FORBIDDEN'); } simulatedReads++;
        return path === '/' ? { version: '1.5.1', node_id: 'synthetic-node' } : structuredClone(upstream);
      }, list: async (cid: string, path: string) => { assert.equal(cid, f.cid); simulatedReads++; return { items: [{ ...target, ...(path.endsWith('/health') ? { health: 'healthy' } : {}) }], nextCursor: null }; } };
      return new ObservationAuthorityService(sql, secrets, kong, execution, workspaces);
    };
    const snapshot = (service: ObservationAuthorityService, f: Fixture, tx: DbService = sql, locked = false): Promise<any> => (service as any).snapshot(f.cid, tx, locked);
    for (const parentState of ['succeeded', 'failed']) await check(`historical pending fence with ${parentState} parent allows new real-source proof and preserves continuity stamp`, async () => {
      const f = await fixture(), op = await operation(f, parentState), id = await fence(f, op), service = authority(f);
      assert.deepEqual(await snapshot(service, f), { revision: 1, transportScope: f.scope, endpointHmac: (await snapshot(service, f)).endpointHmac, fenceCount: '1', latestFence: id });
      const capture = await service.observe(f.cid, 'upstreams', f.upstreamId); assert.equal(capture.input.quality, 'verified');
      await sql.transaction(tx => service.assertCurrent(capture.input, tx)); capture.release(true);
      assert.equal((await sql.one<any>('SELECT state,settled_at FROM metrics_write_fences WHERE id=$1', [id]))!.state, 'pending');
    });
    for (const parentState of ['pending', 'running', 'uncertain', 'blocked']) await check(`acknowledged fence never permits ${parentState} parent`, async () => {
      const f = await fixture(), op = await operation(f, parentState); await fence(f, op, 'acknowledged'); const service = authority(f);
      await denied(() => snapshot(service, f), 'OBSERVATION_NATIVE_CHANGE_PENDING'); await denied(() => sql.transaction(tx => snapshot(service, f, tx, true)), 'OBSERVATION_NATIVE_CHANGE_PENDING');
    });
    await check('missing parent is rejected by real LEFT JOIN despite an acknowledged corrupt owner fixture', async () => {
      const f = await fixture(); await ownerSql.transaction(async tx => { await tx.exec("SET LOCAL session_replication_role='replica'"); await fence(f, randomUUID(), 'acknowledged', f.scope, f.cid, tx); }); corruptOwnerFixtures++;
      await denied(() => snapshot(authority(f), f), 'OBSERVATION_NATIVE_CHANGE_PENDING');
    });
    await check('wrong parent cluster cannot pass by matching global operation UUID', async () => {
      const f = await fixture(), op = await operation(f, 'succeeded', f.scope, f.aliasId);
      await ownerSql.transaction(async tx => { await tx.exec("SET LOCAL session_replication_role='replica'"); await fence(f, op, 'pending', f.scope, f.cid, tx); }); corruptOwnerFixtures++;
      await denied(() => snapshot(authority(f), f), 'OBSERVATION_NATIVE_CHANGE_PENDING');
    });
    for (const mismatch of ['null', 'different']) await check(`${mismatch} parent physical scope remains fail closed even after parent success`, async () => {
      const f = await fixture(), op = await operation(f, 'succeeded', mismatch === 'null' ? null : f.foreignScope); await fence(f, op);
      await denied(() => snapshot(authority(f), f), 'OBSERVATION_NATIVE_CHANGE_PENDING');
    });
    await check('legacy NULL-scope unresolved alias without a fence blocks its canonical physical cluster', async () => {
      const f = await fixture(); await operation(f, 'running', null, f.aliasId); await denied(() => snapshot(authority(f), f), 'OBSERVATION_NATIVE_CHANGE_PENDING');
    });
    await check('unresolved exact physical scope without a fence blocks before any native send', async () => {
      const f = await fixture(); await operation(f, 'uncertain'); await denied(() => snapshot(authority(f), f), 'OBSERVATION_NATIVE_CHANGE_PENDING');
    });
    await check('unrelated physical pending parents and fences do not contaminate the selected source', async () => {
      const f = await fixture(), foreign = await operation(f, 'running', f.foreignScope, f.foreignId); await fence(f, foreign, 'pending', f.foreignScope, f.foreignId);
      await operation(f, 'uncertain', null, f.foreignId); const service = authority(f), captured = await snapshot(service, f); assert.equal(captured.fenceCount, '0');
      const proof = await service.observe(f.cid, 'upstreams', f.upstreamId); await sql.transaction(tx => service.assertCurrent(proof.input, tx)); proof.release(true);
    });
    await check('fresh terminal fence in the same final SQL transaction invalidates old private proof and rolls back', async () => {
      const f = await fixture(), op = await operation(f, 'succeeded'); await fence(f, op); const service = authority(f), capture = await service.observe(f.cid, 'upstreams', f.upstreamId);
      await denied(() => sql.transaction(async tx => { const fresh = await operation(f, 'succeeded', f.scope, f.cid, tx); await fence(f, fresh, 'pending', f.scope, f.cid, tx); await service.assertCurrent(capture.input, tx); }), 'OBSERVATION_PROOF_INVALID');
      assert.equal((await snapshot(service, f)).fenceCount, '1'); await sql.transaction(tx => service.assertCurrent(capture.input, tx)); capture.release(true);
    });
    await check('final derived-table FOR SHARE really blocks a competing parent downgrade until observation commit', async () => {
      const f = await fixture(), op = await operation(f, 'succeeded'); await fence(f, op); const service = authority(f), capture = await service.observe(f.cid, 'upstreams', f.upstreamId);
      await sql.transaction(async tx => {
        await service.assertCurrent(capture.input, tx);
        await denied(() => second.transaction(async other => { await other.exec("SET LOCAL lock_timeout='150ms'"); await other.exec("UPDATE mutation_operations SET state='uncertain' WHERE id=$1", [op]); }), '55P03');
        assert.equal((await tx.one<any>('SELECT state FROM mutation_operations WHERE id=$1', [op]))!.state, 'succeeded');
        await service.assertCurrent(capture.input, tx);
      });
      assert.equal(await second.exec("UPDATE mutation_operations SET state='uncertain' WHERE id=$1", [op]), 1);
      await denied(() => sql.transaction(tx => service.assertCurrent(capture.input, tx)), 'OBSERVATION_NATIVE_CHANGE_PENDING'); capture.release(false);
    });
    await check('shared final transport transaction lock prevents actual beforeNativeWrite fence until source commit', async () => {
      const f = await fixture(), service = authority(f); let freshOperation: string | undefined;
      await sql.transaction(async tx => {
        assert.equal((await snapshot(service, f, tx, true)).fenceCount, '0');
        freshOperation = await operation(f, 'running', f.scope, f.cid, second);
        await denied(() => second.transaction(async other => { await other.exec("SET LOCAL lock_timeout='150ms'"); await new MetricsWriteFenceService(other).beforeNativeWrite({ cid: f.cid, transportScope: f.scope, operationId: freshOperation!, requestFingerprint: 'c'.repeat(64), entityType: 'upstreams', entityId: f.upstreamId, method: 'PATCH', path: `/upstreams/${f.upstreamId}`, body: { name: 'changed' } }); }), '55P03');
        assert.equal((await tx.one<any>('SELECT count(*)::text AS count FROM metrics_write_fences WHERE transport_scope=$1', [f.scope]))!.count, '0');
      });
      const receipt = await new MetricsWriteFenceService(second).beforeNativeWrite({ cid: f.cid, transportScope: f.scope, operationId: freshOperation!, requestFingerprint: 'c'.repeat(64), entityType: 'upstreams', entityId: f.upstreamId, method: 'PATCH', path: `/upstreams/${f.upstreamId}`, body: { name: 'changed' } }); assert.equal(receipt.operationId, freshOperation);
      await denied(() => snapshot(service, f), 'OBSERVATION_NATIVE_CHANGE_PENDING');
      await second.exec("UPDATE mutation_operations SET state='failed' WHERE id=$1", [freshOperation]); assert.equal((await snapshot(service, f)).fenceCount, '1');
    });
    await check('product source remains identical and no native write or existing runtime was accessed', async () => { assert.equal(sha(readFileSync(productFile)), productSha); assert.equal(nativeWrites, 0); assert(simulatedReads > 0); });
  } catch (error) { failure = code(error); }
  finally {
    await competing?.onModuleDestroy().catch(() => undefined); await db?.onModuleDestroy().catch(() => undefined); await owner?.onModuleDestroy().catch(() => undefined);
    try { docker(['rm', '-f', container]); } catch { if (!failure) failure = 'DISPOSABLE_CONTAINER_CLEANUP_FAILED'; }
    const report = { milestone: 'M7', performedAt: new Date().toISOString(), allPassed: failure === undefined, failureCode: failure ?? null, failurePhase: failure ? phase : null,
      database: 'disposable PostgreSQL16, real migrations000-010, genuine nonowner runtime role', productSource: productFile, productSha256: productSha,
      actual: ['ObservationAuthorityService snapshot and private proof', 'real SQL aggregate derived-table FOR SHARE and LEFT JOIN', 'same transaction proof rejection and rollback', 'two-connection parent update and transport advisory lock', 'actual MetricsWriteFenceService'],
      explicitFixtures: ['deterministic Kong GET responses, no native network', 'migration owner injects two FK-corrupt rows only in the disposable database'],
      corruptOwnerFixtures, simulatedNativeReads: simulatedReads, nativeWrites, existingRuntimeAccess: false, containerRemoved: true, checks,
      passed: checks.filter(value => value.passed).length, failed: checks.filter(value => !value.passed).length };
    mkdirSync('artifacts/M7', { recursive: true }); const artifact = `artifacts/M7/observation-parent-fence-postgres-${runId}.json`;
    writeFileSync(artifact, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
    process.stdout.write(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, failureCode: report.failureCode, artifact }) + '\n');
    if (failure) process.exitCode = 1;
  }
}
main().catch(() => { process.stderr.write('M7 disposable observation-parent integration failed safely\n'); process.exitCode = 1; });
