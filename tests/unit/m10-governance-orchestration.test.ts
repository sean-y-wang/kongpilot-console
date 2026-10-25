import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { GovernanceRepositoryService } from '../../apps/console-api/src/modules/governance/governance-repository.service';
import { GovernanceSchedulerService } from '../../apps/console-api/src/modules/governance/governance-scheduler.service';
import { GovernanceMetadataService } from '../../apps/console-api/src/modules/governance/governance-metadata.service';
import { GovernanceService } from '../../apps/console-api/src/modules/governance/governance.service';
import { assertGovernanceOriginalDomain, governanceOriginalLock } from '../../apps/console-api/src/modules/governance/governance-original-key';
import { comparisonInput, governanceObject, inspectionInput, promotionInput, ruleInput, scheduleInput } from '../../apps/console-api/src/modules/governance/governance-input';
import { compareLogicalEnvironments } from '../../apps/console-api/src/modules/governance/drift-engine';
import type { ComparisonInventory } from '../../apps/console-api/src/modules/governance/comparison-types';
import { graph, schemas, id } from './m8-config-transfer.fixture';

let previousKey: string | undefined;
beforeEach(() => { previousKey = process.env.CONSOLE_ENCRYPTION_KEY; process.env.CONSOLE_ENCRYPTION_KEY = 'ad'.repeat(32); });
afterEach(() => { if (previousKey === undefined) delete process.env.CONSOLE_ENCRYPTION_KEY; else process.env.CONSOLE_ENCRYPTION_KEY = previousKey; });

describe('M10 server DTO and actual merged policy boundaries', () => {
  it.each(['approved', 'sourceProof', 'ownerId', 'owner_user_id', 'superAdmin', '__proto__', 'constructor', 'prototype'])('rejects nested server control property %s', property => {
    const malicious = JSON.parse(`{"fieldOverrides":{"services:original":{"${property}":true}}}`);
    expect(() => governanceObject(malicious)).toThrow(BadRequestException);
  });
  it('never evaluates getters or callable / Symbol DTO material', () => {
    const getter = vi.fn(); const payload = {}; Object.defineProperty(payload, 'scope', { enumerable: true, get: getter });
    expect(() => inspectionInput(payload)).toThrow(BadRequestException); expect(getter).not.toHaveBeenCalled();
    expect(() => governanceObject({ scope: () => true })).toThrow(BadRequestException);
    expect(() => governanceObject({ [Symbol('proof')]: true })).toThrow(BadRequestException);
  });
  it('requires actual finite rooted scopes rather than inventing scope authority', () => {
    expect(() => inspectionInput({ scope: 'services', serviceIds: [] })).toThrow(BadRequestException);
    const root = randomUUID(); expect(() => inspectionInput({ scope: 'services', serviceIds: [root, root] })).toThrow(BadRequestException);
    expect(() => comparisonInput({ scope: 'cluster', target: { clusterId: randomUUID(), workspaceId: randomUUID() } })).toThrow(BadRequestException);
    expect(() => promotionInput({ confirmed: true, confirm_name: 'PROMOTE synthetic', includeSecrets: 'true' })).toThrow(BadRequestException);
  });
  it('supports a roots-only update and validates it in the actual persisted service policy', () => {
    const patch = scheduleInput({ revision: 2, serviceIds: [id(2)] }, true);
    expect(patch).toEqual({ revision: 2, serviceIds: [id(2)] });
    const policy = { name: 'Services', kind: 'inspection', scope: 'services', serviceIds: [id(1)], intervalMinutes: 5, timezone: 'UTC', paused: false };
    expect(scheduleInput({ ...policy, serviceIds: patch.serviceIds }).serviceIds).toEqual([id(2)]);
    expect(() => scheduleInput({ ...policy, serviceIds: [] })).toThrow(BadRequestException);
  });
  it('aligns DTO code and optional description limits with the typed DSL', () => {
    const body = { code: 'a'.repeat(96), name: 'Policy', severity: 'warn', given: { entityTypes: ['services'] }, then: { path: 'tags', op: 'required' } };
    expect(ruleInput(body).code).toHaveLength(96); expect(ruleInput(body).description).toBe('');
    expect(() => ruleInput({ ...body, code: 'a'.repeat(97) })).toThrow(BadRequestException);
    expect(ruleInput({ ...body, description: 'd'.repeat(500) }).description).toHaveLength(500);
    expect(() => ruleInput({ ...body, description: 'd'.repeat(501) })).toThrow(BadRequestException);
  });
});

function comparisonFixture(): ComparisonInventory {
  const original = graph(), bundle = schemas();
  return { scope: original.scope, objects: original.objects.filter(object=>object.entityType!=='credentials').map(object => ({ ...object, objectWorkspaceId: original.scope.workspaceId, sensitiveFields: [] })),
    schemas: bundle.entities, pluginSchemas: bundle.plugins, enabledPlugins: bundle.enabledPlugins, version: '1.5.1', adapterVersion: 'kong-1.5', completeness: 'complete', projection: false, consistency: 'console_fenced_best_effort' };
}

describe('M10 authenticated repository integration seams', () => {
  it('stores the actual pure engine completeness and threshold result, including incomplete observations', async () => {
    const source = comparisonFixture(), target = structuredClone(source);
    target.objects.find(object => object.entityType === 'services')!.payload.retries = 9;
    const result = compareLogicalEnvironments(source, target, { threshold: { maxChangedObjects: 0 } });
    expect(result.completeness).toBe('complete'); expect(result.threshold.exceeded).toBe(true);
    const db: any = { exec: vi.fn(async () => 1) }, secrets = new SecretService(), repo = new GovernanceRepositoryService(db, secrets), comparisonId = randomUUID();
    const input = { id: comparisonId, run: { id: randomUUID(), cluster_id: source.scope.clusterId, workspace_id: source.scope.workspaceId }, source, target, sourceNativeFingerprints:Object.fromEntries(source.objects.map(o=>[`${o.entityType}:${o.nativeId}`,secrets.fingerprint(o.payload)])),targetNativeFingerprints:Object.fromEntries(target.objects.map(o=>[`${o.entityType}:${o.nativeId}`,secrets.fingerprint(o.payload)])),policy: {}, result, threshold: 0 };
    await repo.saveComparison(input, db);
    const bindings = db.exec.mock.calls[0][1]; expect(bindings[12]).toBe('complete'); expect(bindings[15]).toBe(true);
    expect(secrets.decrypt(bindings[6], `governance:comparison-source:${comparisonId}`)).toEqual({version:2,inventory:source,nativeFingerprints:input.sourceNativeFingerprints});
    target.completeness = 'incomplete'; const incomplete = compareLogicalEnvironments(source, target);
    await repo.saveComparison({ ...input, result: incomplete }, db);
    expect(db.exec.mock.calls[1][1][12]).toBe('incomplete');
  });
  it('authenticates the original child descriptor and refuses cross-parent encrypted material', () => {
    const db: any = {}, secrets = new SecretService(), repo = new GovernanceRepositoryService(db, secrets), parent = randomUUID();
    const descriptor = { version: 1, domain: 'configuration', kind: 'import', requestHmac: 'a'.repeat(64) };
    const row = { id: parent, child_kind: 'configuration', child_request_hmac: descriptor.requestHmac, child_request_secret: secrets.encrypt(descriptor, `governance:fix-child:${parent}`) };
    expect(repo.fixChild(row)).toEqual(descriptor);
    expect(() => repo.fixChild({ ...row, id: randomUUID() })).toThrow();
    expect(() => repo.fixChild({ ...row, child_request_hmac: 'b'.repeat(64) })).toThrow();
    expect(() => repo.fixChild({ ...row, child_kind: 'metadata' })).toThrow();
  });
  it('blocks a due policy while an original occurrence is unresolved without inserting or advancing it', async () => {
    const cid = randomUUID(), wid = randomUUID(), sid = randomUUID();
    const db: any = { one: vi.fn(async (sql: string) => sql.includes('governance_schedules') ? {
      id: sid, cluster_id: cid, workspace_id: wid, state: 'active', revision: 3, current_version: 1, next_run_at: new Date(0), content: { intervalMinutes: 5 },
    } : { id: randomUUID(), state: 'uncertain' }), exec: vi.fn(async () => 1) };
    const repo = new GovernanceRepositoryService(db, new SecretService());
    expect(await repo.claimSchedule({ id: sid, cluster_id: cid, workspace_id: wid, revision: 3, current_version: 1 }, db)).toBeNull();
    expect(db.exec).not.toHaveBeenCalled();
  });
  it('never interpolates a caller-selected directory table into SQL', async () => {
    const db: any = { query: vi.fn() }, repo = new GovernanceRepositoryService(db, new SecretService());
    await expect(repo.directory('users; DELETE FROM users' as any, randomUUID(), randomUUID(), {}, 'binding')).rejects.toThrow();
    expect(db.query).not.toHaveBeenCalled();
  });
});

function schedulerFixture(options: { expired?: boolean; error?: Error; incomplete?: boolean } = {}) {
  const cid = randomUUID(), wid = randomUUID(), uid = randomUUID(), sid = randomUUID(), occurrence = randomUUID(), run = randomUUID();
  const locator = { scheduleId: sid, clusterId: cid, workspaceId: wid, ownerUserId: uid, version: 2, revision: 3, scheduledAt: new Date().toISOString(), runId: occurrence, leaseGeneration: 1 };
  const db: any = { transaction: vi.fn(async (fn: any) => fn(db)), one: vi.fn(async (sql: string) => sql.includes('governance_schedule_runs') ? { state: 'running' } : { id: run }) };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()) };
  const repo: any = {
    expiredScheduleRuns: vi.fn(async () => options.expired ? [{ id: occurrence, schedule_id: sid, cluster_id: cid, workspace_id: wid, creator_id: uid, lease_generation: 1 }] : []),
    markExpiredScheduleRun: vi.fn(async () => true), dueSchedules: vi.fn(async () => options.expired ? [] : [{ id: sid }]),
    claimSchedule: vi.fn(async () => ({ locator, payload: { kind: 'inspection' } })), finishSchedule: vi.fn(async () => undefined),
  };
  const service: any = { runScheduled: vi.fn(async () => { if (options.error) throw options.error; return { runId: run, state: options.incomplete ? 'incomplete' : 'succeeded' }; }) };
  const audit: any = { append: vi.fn(async () => undefined) }, scheduler = new GovernanceSchedulerService(db, redis, repo, service, audit);
  return { db, redis, repo, service, audit, scheduler, occurrence, locator, run };
}

describe('M10 timer original-occurrence safety', () => {
  it('marks an expired real occurrence uncertain with audit and never starts a new capture', async () => {
    const f = schedulerFixture({ expired: true }); await f.scheduler.tick();
    expect(f.repo.markExpiredScheduleRun).toHaveBeenCalledOnce(); expect(f.audit.append.mock.calls[0][0]).toMatchObject({ entityId: f.occurrence, action: 'governance.schedule.lease_expired', result: 'uncertain' });
    expect(f.service.runScheduled).not.toHaveBeenCalled(); expect(f.repo.claimSchedule).not.toHaveBeenCalled();
  });
  it('preserves an ambiguous persistence failure as uncertain under the original occurrence', async () => {
    const f = schedulerFixture({ error: new Error('synthetic COMMIT response lost') }); await f.scheduler.tick();
    expect(f.repo.finishSchedule.mock.calls[0][0]).toEqual(f.locator); expect(f.repo.finishSchedule.mock.calls[0][1]).toBe('uncertain');
    expect(f.service.runScheduled).toHaveBeenCalledOnce(); expect(f.audit.append.mock.calls.at(-1)[0].result).toBe('uncertain');
  });
  it('records revoked authority as paused_authority instead of borrowing a session to retry', async () => {
    const f = schedulerFixture({ error: new ForbiddenException({ code: 'GOVERNANCE_OWNER_INACTIVE' }) }); await f.scheduler.tick();
    expect(f.repo.finishSchedule.mock.calls[0][1]).toBe('paused_authority'); expect(f.service.runScheduled).toHaveBeenCalledOnce();
  });
  it('does not label an incomplete inventory as successful complete inspection', async () => {
    const f = schedulerFixture({ incomplete: true }); await f.scheduler.tick();
    expect(f.repo.finishSchedule).toHaveBeenCalledWith(f.locator, 'incomplete', f.run, undefined, f.db);
  });
});

describe('M10 public metadata validation status', () => {
  it.each([{ path: 'config.redis_password', op: 'required' }, { path: 'host', op: 'eval' }])('returns safe HTTP400 before writes for invalid DSL %j', async then => {
    const cid = randomUUID(), wid = randomUUID(), uid = randomUUID();
    const db: any = { query: vi.fn(async () => []), one: vi.fn(async (sql: string) => sql.includes('clusters') ? { admin_url: 'http://registered-kong:8001', revision: 1, execution_mode: 'direct', version: '1.5.1', status: 'active' } : null), exec: vi.fn(), transaction: vi.fn() };
    const authz: any = { assertWholeWorkspace: vi.fn(async () => undefined), permissionVersion: vi.fn(async () => 'current') };
    const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()) }, workspaces: any = { get: vi.fn(async () => ({ id: wid, revision: 1, status: 'active' })) };
    const iam: any = { execute: vi.fn() }, repo: any = { resource: vi.fn(async () => null) };
    const service = new GovernanceMetadataService(db, redis, new SecretService(), authz, workspaces, {} as any, iam, {} as any, repo, {} as any, {} as any, {} as any, {} as any);
    const promise = service.mutate(cid, 'governance_rules', undefined, 'create', { code: 'invalid.example', name: 'Invalid', severity: 'warn', given: { entityTypes: ['services'] }, then }, { user: { id: uid, username: 'reviewer', superAdmin: false }, workspaceId: wid, idempotencyKey: randomUUID() });
    await expect(promise).rejects.toBeInstanceOf(BadRequestException); expect(iam.execute).not.toHaveBeenCalled(); expect(db.exec).not.toHaveBeenCalled(); expect(db.transaction).not.toHaveBeenCalled();
  });
});

describe('M10 fixed original-key registration domain', () => {
  it.each(['analysis','fix','promotion','metadata'] as const)('allows only the existing same %s domain and conflicts on another kind', async domain => {
    const actor = randomUUID(), key = randomUUID(), db: any = { query: vi.fn(async () => [{ domain }]) };
    await expect(assertGovernanceOriginalDomain(db, actor, key, domain)).resolves.toBeUndefined();
    const foreign = domain === 'fix' ? 'analysis' : 'fix';
    await expect(assertGovernanceOriginalDomain(db, actor, key, foreign)).rejects.toMatchObject({ status: 409 });
    expect(db.query.mock.calls[0][1]).toEqual([actor,key]);
  });
  it('rejects historical cross-domain ambiguity rather than selecting the first ledger', async () => {
    const db: any = { query: vi.fn(async () => [{ domain: 'analysis' }, { domain: 'metadata' }]) };
    await expect(assertGovernanceOriginalDomain(db, randomUUID(), randomUUID(), 'analysis')).rejects.toMatchObject({ status: 409 });
  });
  it('serializes a rule registration and inspection using the same original key, then rejects the other domain', async () => {
    const cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),key=randomUUID(),secret=new SecretService();let iamRow:any=null;
    let release!:()=>void,entered!:()=>void;const registered=new Promise<void>(r=>entered=r),completion=new Promise<void>(r=>release=r),locks=new Map<string,Promise<void>>();
    const redis:any={withLock:vi.fn(async(lock:string,fn:any)=>{const earlier=locks.get(lock)??Promise.resolve();let unlock!:()=>void;const finished=new Promise<void>(r=>unlock=r);locks.set(lock,earlier.then(()=>finished));await earlier;try{return await fn();}finally{unlock();}})};
    const db:any={query:vi.fn(async()=>iamRow?[{domain:'metadata'}]:[]),one:vi.fn(async(sql:string)=>sql.includes('clusters')?{admin_url:'http://registered-kong:8001',revision:1,execution_mode:'direct',version:'1.5.1',status:'active'}:sql.includes('iam_operations')?iamRow:null)};
    const actor={user:{id:uid,username:'original-owner',superAdmin:false},workspaceId:wid,idempotencyKey:key},authz:any={assertWholeWorkspace:async()=>undefined,assertCluster:async()=>undefined,permissionVersion:async()=> 'epoch'},workspaces:any={get:async()=>({id:wid,revision:1,status:'active'}),resolve:async()=>({id:wid})};
    const iam:any={execute:vi.fn(async(ctx:any)=>{entered();await completion;const id=randomUUID();iamRow={id,actor_id:uid,cluster_id:cid,workspace_id:wid,module:'lint',state:'succeeded',remote_completed:true,payload_secret:secret.encrypt(ctx.payload,`iam:${id}:payload`),result_secret:secret.encrypt({entity:{id:ctx.payload.resourceId}},`iam:${id}:result`)};return{};})};
    const repo:any={beginRun:vi.fn(),resource:async()=>null},capture:any={captureActor:vi.fn()},metadata=new GovernanceMetadataService(db,redis,secret,authz,workspaces,{} as any,iam,{} as any,repo,{} as any,{} as any,{} as any,{} as any);
    const governance=new GovernanceService(db,redis,secret,{} as any,authz,workspaces,{} as any,capture,repo,metadata,{} as any,{} as any);
    const first=metadata.mutate(cid,'governance_rules',undefined,'create',{code:'tags.required',name:'Tags',severity:'warn',given:{entityTypes:['services']},then:{path:'tags',op:'required'}},actor);
    await registered;const second=governance.inspect(cid,{},actor).catch(error=>error);release();await expect(first).resolves.toMatchObject({domain:'iam',configurationCommitted:true});
    expect(await second).toMatchObject({status:409});expect(redis.withLock.mock.calls[0][0]).toBe(redis.withLock.mock.calls[1][0]);expect(capture.captureActor).not.toHaveBeenCalled();expect(repo.beginRun).not.toHaveBeenCalled();
  });
});

function historyFixture(objects:any[], native:(type:string,entity:any)=>void = () => undefined) {
  const cid = randomUUID(), wid = id(100), uid = randomUUID(), reportId = randomUUID();
  const actor = { user: { id: uid, username: 'history-reader', superAdmin: false }, workspaceId: wid };
  const inv = { scope: { kind: 'workspace', clusterId: cid, workspaceId: wid }, objects: objects.map(o => ({ ...o, objectWorkspaceId: wid })) };
  const row = { id: reportId, cluster_id: cid, workspace_id: wid, quality: 'complete', projection: false, object_count: objects.length, finding_count: 1, counts: {warn:1,error:0,info:0}, observed_from:new Date(),observed_until:new Date(),created_at:new Date() };
  const authz: any = { assertCluster: vi.fn(async () => undefined), permissionVersion: vi.fn(async () => 'epoch'), hasWholeWorkspace: vi.fn(async () => true), hasWholeCluster: vi.fn(async () => true),
    assertScopedResource: vi.fn(async (_u:any,_c:string,_m:string,_a:string,type:string) => { if(type==='targets')throw new BadRequestException({code:'INVALID_NATIVE_TYPE'}); }),
    assertEntity: vi.fn(async (_u:any,_c:string,type:string,_a:string,entity:any) => native(type,entity)) };
  const context: any = { runInternalRead: vi.fn(async (_c:string,_origin:string,fn:any) => fn()) }, kong:any = { request: vi.fn(async () => { throw new NotFoundException({code:'NOT_FOUND'}); }) };
  const service = new GovernanceService({} as any,{} as any,new SecretService(),context,authz,{resolve:async()=>({id:wid})} as any,{} as any,{} as any,{report:async()=>row,inventory:()=>inv} as any,{} as any,{} as any,{} as any,kong);
  return { service, actor, cid, reportId, authz, context, kong };
}

describe('M10 native history permission inheritance', () => {
  it('checks operational Target access against its actual Upstream and still native-checks the child', async () => {
    const upstream=id(2), target=id(3), f=historyFixture([{entityType:'upstreams',nativeId:upstream,payload:{id:upstream,name:'pool',tags:[]}}, {entityType:'targets',nativeId:target,parentId:upstream,payload:{id:target,target:'127.0.0.1:8080',upstream:{id:upstream},tags:[]}}]);
    await expect(f.service.report(f.cid,f.reportId,f.actor)).resolves.toMatchObject({entity:{objectCount:2}});
    expect(f.authz.assertScopedResource.mock.calls.every(args=>args[4]!=='targets')).toBe(true);
    expect(f.authz.assertEntity.mock.calls.some(args=>args[2]==='targets'&&args[4].upstream.id===upstream)).toBe(true);
  });
  it('rejects mismatched Target parent instead of granting by child tags', async () => {
    const f=historyFixture([{entityType:'upstreams',nativeId:id(2),payload:{id:id(2),tags:[]}}, {entityType:'targets',nativeId:id(3),parentId:id(2),payload:{id:id(3),upstream:{id:id(9)},tags:[]}}]);
    await expect(f.service.report(f.cid,f.reportId,f.actor)).rejects.toMatchObject({status:409});
  });
  it('reads owned orphan Plugin diagnostics only after a fresh exact GET404 and native authorization', async () => {
    const parent=id(9), f=historyFixture([{entityType:'plugins',nativeId:id(3),payload:{id:id(3),name:'key-auth',service:{id:parent},tags:[]}}],(_type,entity)=>{expect(entity.service).toBeUndefined();});
    await expect(f.service.report(f.cid,f.reportId,f.actor)).resolves.toBeDefined();
    expect(f.kong.request).toHaveBeenCalledWith(f.cid,'GET',`/services/${parent}`); expect(f.context.runInternalRead).toHaveBeenCalledOnce();
  });
  it('keeps an existing foreign Plugin binding in the native permission check', async () => {
    const parent=id(9), f=historyFixture([{entityType:'plugins',nativeId:id(3),payload:{id:id(3),name:'key-auth',service:{id:parent},tags:[]}}],(_type,entity)=>{expect(entity.service.id).toBe(parent);throw new ForbiddenException({code:'FOREIGN_WORKSPACE'});});
    f.kong.request.mockResolvedValue({id:parent,tags:['workspace:foreign']});
    await expect(f.service.report(f.cid,f.reportId,f.actor)).rejects.toBeInstanceOf(ForbiddenException);
  });
  it('does not treat a failed parent GET or native permission revocation as absence', async () => {
    const f=historyFixture([{entityType:'plugins',nativeId:id(3),payload:{id:id(3),service:{id:id(9)},tags:[]}}]);f.kong.request.mockRejectedValue(new Error('synthetic transport failure'));
    await expect(f.service.report(f.cid,f.reportId,f.actor)).rejects.toThrow('synthetic transport failure');expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });
});

describe('M10 persisted rule to actual inspection engine', () => {
  it('creates metadata with a name, then projects only the strict six DSL properties into public inspection', async () => {
    const cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),secret=new SecretService();let iamRow:any=null,stored:any=null,report:any=null;const runs=new Map<string,any>();
    const db:any={query:vi.fn(async()=>[]),one:vi.fn(async(sql:string,params:any[])=>sql.includes('clusters')?{admin_url:'http://registered-kong:8001',revision:1,execution_mode:'direct',version:'1.5.1',status:'active'}:sql.includes('iam_operations')&&iamRow?.idempotency_key===params[1]?iamRow:null),transaction:async(fn:any)=>fn(db)};
    const redis:any={withLock:async(_lock:string,fn:any)=>fn()},authz:any={assertWholeWorkspace:async()=>undefined,assertCluster:async()=>undefined,permissionVersion:async()=> 'epoch',assertScopedResource:async()=>undefined,assertEntity:async()=>undefined},workspaces:any={get:async()=>({id:wid,revision:1,status:'active'}),resolve:async()=>({id:wid})};
    const repo:any={resource:vi.fn(async()=>stored),saveResource:vi.fn(async(_type:string,resourceId:string,_cid:string,_wid:string,_actor:string,_op:string,_before:any,payload:any)=>{stored={id:resourceId,cluster_id:cid,workspace_id:wid,code:payload.code,name:payload.name,enabled:true,state:'active',revision:1,current_version:1,content:structuredClone(payload),created_at:new Date(),updated_at:new Date()};return stored;}),ruleContents:async()=>[{code:stored.code,enabled:true,content:stored.content}],
      runByKey:async(_actor:string,key:string)=>runs.get(key)??null,beginRun:async(input:any)=>{const row={id:randomUUID(),cluster_id:cid,workspace_id:wid,actor_id:uid,idempotency_key:input.key,kind:'inspection',state:'running'};runs.set(input.key,row);return{row,existing:false};},
      saveReport:async(input:any)=>{report={id:input.id,cluster_id:cid,workspace_id:wid,quality:input.result.complete?'complete':'incomplete',projection:false,object_count:input.inventory.objects.length,finding_count:input.findings.length,counts:{error:0,warn:input.findings.length,info:0},observed_from:input.inventory.observedFrom,observed_until:input.inventory.observedUntil,created_at:new Date(),inventory:input.inventory,rule_results:input.result.ruleResults};},finishRun:async(id:string,state:string)=>{[...runs.values()].find(row=>row.id===id).state=state;},run:async(id:string)=>[...runs.values()].find(row=>row.id===id),reportForRun:async()=>({id:report.id}),report:async()=>report,inventory:(row:any)=>row.inventory};
    const iam:any={execute:async(ctx:any,fn:any)=>{const id=randomUUID(),result=await fn(db,id,vi.fn());iamRow={id,actor_id:uid,cluster_id:cid,workspace_id:wid,module:'lint',idempotency_key:ctx.actor.idempotencyKey,state:'succeeded',remote_completed:true,payload_secret:secret.encrypt(ctx.payload,`iam:${id}:payload`),result_secret:secret.encrypt(result,`iam:${id}:result`)};return result;}};
    const actor={user:{id:uid,username:'stored-rule-reader',superAdmin:false},workspaceId:wid,idempotencyKey:randomUUID()},metadata=new GovernanceMetadataService(db,redis,secret,authz,workspaces,{} as any,iam,{} as any,repo,{} as any,{} as any,{} as any,{} as any);
    await expect(metadata.mutate(cid,'governance_rules',undefined,'create',{code:'team.tags_presence',name:'Named persisted metadata rule',description:'Check Service tags',severity:'warn',given:{entityTypes:['services']},then:{path:'tags',op:'required'}},actor)).resolves.toMatchObject({configurationCommitted:true});
    expect(stored.content.name).toBe('Named persisted metadata rule');
    const now=new Date().toISOString(),inv:any={id:randomUUID(),scope:{clusterId:cid,workspaceId:wid,kind:'workspace',rootIds:[],transportScope:'a'.repeat(64)},objects:[{entityType:'services',nativeId:randomUUID(),objectWorkspaceId:wid,payload:{name:'valid-service',host:'example.test',port:80,protocol:'http',tags:[],connect_timeout:60000,read_timeout:60000,write_timeout:60000}}],schemas:schemas().entities,pluginSchemas:{},enabledPlugins:[],version:'1.5.1',coverage:{services:{state:'complete',extent:'workspace',eof:true,pages:1,records:1,reasonCodes:[]}},completeness:'complete',projection:false,observedFrom:now,observedUntil:now,reasonCodes:[]};
    const capture:any={captureActor:async()=>({inventory:inv,handle:{}})},audit:any={append:async()=>undefined},service=new GovernanceService(db,redis,secret,{current:()=>({sessionId:randomUUID()})} as any,authz,workspaces,{assertCurrent:async()=>undefined} as any,capture,repo,metadata,{} as any,audit);
    await expect(service.inspect(cid,{ruleCodes:['team.tags_presence']},{...actor,idempotencyKey:randomUUID()})).resolves.toMatchObject({kind:'inspection',entity:{objectCount:1}});
    expect(report.rule_results).toContainEqual(expect.objectContaining({ruleCode:'team.tags_presence',state:'evaluated'}));
  });
});
