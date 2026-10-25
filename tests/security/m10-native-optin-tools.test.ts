import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertKeyAuthOptinPlan, assertNoOptinSecrets, assertOptinDefaultApplyGate, assertOptinExecutionSteps, assertOptinOriginalReceipt, assertOptinSession, assertOptinSourceObject,
  assertOptinZeroNativeProof, assertSensitivePluginOptinPlan, optinLedger, optinPhase, optinPublicReport } from './lib/m10-native-optin-helper.mjs';
import { optinDistFingerprint, optinObserverProgram } from './lib/m10-native-optin-observer.mjs';

const id = (n: number) => `${n.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`;
const cid = id(1), wid = id(2), actor = id(3), sid = id(4), consumer = id(5), sourceCredential = id(6), oldCredential = id(7), allocated = id(8);
const session = () => ({ user: { id: actor }, sid, cookie: `kongos_access=h.${Buffer.from(JSON.stringify({sub:actor,sid,exp:Math.floor(Date.now()/1000)+600})).toString('base64url')}.s; kongos_csrf=synthetic` });
const bodyHash = (body: any) => createHash('sha256').update(JSON.stringify(body)).digest('hex');
const harness = () => {
  const h: any = { state: { phase: 'native-m10-core-passed', requests: [], fixtures: {}, checks: [] }, save: vi.fn() };
  h.request = vi.fn(async (s: any, path: string, method: string, body: any, options: any) => {
    h.state.requests.push({path,method,body,bodyHash:bodyHash(body),actorId:s.user.id,key:options.key,state:'response_observed',status:201,responseData:{id:id(9)},requestId:'original'});
    return {status:201,data:{id:id(9)},requestId:'original'};
  }); return h;
};

describe('M10 opt-in actual tool immutable WAL boundary', () => {
  const defaultGate = (fresh = false) => {
    const label = fresh ? 'm10-promote-default-apply-after-outer-origin-anchor' : 'm10-promote-default-apply';
    const planId=id(60),jobId=id(61),executionId=id(62),key=id(63),summary={id:planId,name:`配置计划 ${planId}`,clusterId:cid,workspaceId:wid,executionMode:'direct',planRevision:1,planHash:'c'.repeat(64)};
    const body={planRevision:1,planHash:summary.planHash,confirmed:true,confirm_name:summary.name};
    const packet={label,path:`/clusters/${cid}/configuration/plans/${planId}/apply?workspaceId=${wid}`,method:'POST',actorId:actor,state:'response_observed',status:201,key,requestId:'actual-default',body,bodyHash:bodyHash(body),
      responseData:{domain:'configuration',kind:'apply',actorId:actor,clusterId:cid,workspaceId:wid,idempotencyKey:key,state:'succeeded',executionCompleted:true,registrationCompleted:true,executionId,jobId}};
    const state:any={governanceFixtures:{promoteApplyLabel:label,promoteApplyJobId:jobId},acceptancePlanSummaries:{[label]:summary},requests:[packet]};
    if(fresh){state.requests.unshift({...packet,label:'m10-promote-default-apply',key:id(64),requestId:'actual-forbidden-original',status:403,responseData:null});state.freshDefaultApplyIntent={label,planId,bodyHash:packet.bodyHash,originalRequestId:'actual-forbidden-original',originalKey:id(64)};}
    return state;
  };
  it.each([false,true])('requires an actually successful original or distinct approved fresh default execution: fresh=%s',fresh=>{
    const state=defaultGate(fresh),before=JSON.stringify(state);expect(assertOptinDefaultApplyGate(state,{actorId:actor,clusterId:cid,workspaceId:wid}).label).toBe(state.governanceFixtures.promoteApplyLabel);expect(JSON.stringify(state)).toBe(before);
    if(fresh)expect(state.requests[0].status).toBe(403);
  });
  it.each(['old403','unknown','suffix','no-fixture-label','foreign-actor','foreign-cluster','foreign-workspace','foreign-path','partial-execution','wrong-job','wrong-key','missing-execution-id'])('blocks opt-in when default acceptance lacks exact actual success: %s',failure=>{
    const state=defaultGate(),p=state.requests[0];
    if(failure==='old403')p.status=403;if(failure==='unknown')p.state='response_unknown';if(failure==='suffix')state.governanceFixtures.promoteApplyLabel='m10-promote-default-apply-beforefix-success';if(failure==='no-fixture-label')delete state.governanceFixtures.promoteApplyLabel;
    if(failure==='foreign-actor')p.actorId=id(91);if(failure==='foreign-cluster')p.responseData.clusterId=id(92);if(failure==='foreign-workspace')p.responseData.workspaceId=id(93);if(failure==='foreign-path')p.path=p.path.replace(cid,id(94));
    if(failure==='partial-execution')p.responseData.state='partial';if(failure==='wrong-job')state.governanceFixtures.promoteApplyJobId=id(95);if(failure==='wrong-key')p.responseData.idempotencyKey=id(96);if(failure==='missing-execution-id')p.responseData.executionId=null;
    expect(()=>assertOptinDefaultApplyGate(state,{actorId:actor,clusterId:cid,workspaceId:wid})).toThrow();
  });
  it.each(['missing-intent','reused-key','rewritten-original','unknown-original'])('does not convert a forbidden original to a successful fresh fact: %s',failure=>{
    const state=defaultGate(true);if(failure==='missing-intent')delete state.freshDefaultApplyIntent;
    if(failure==='reused-key'){state.requests[1].key=state.requests[0].key;state.requests[1].responseData.idempotencyKey=state.requests[0].key;}
    if(failure==='rewritten-original')state.requests[0].status=201;if(failure==='unknown-original')state.requests[0].state='response_unknown';
    expect(()=>assertOptinDefaultApplyGate(state,{actorId:actor,clusterId:cid,workspaceId:wid})).toThrow();
  });
  it.each(['key-auth','sensitive-plugin','stale-source','rollback'])('requires one explicit known phase: %s', phase => expect(optinPhase(['--phase',phase])).toBe(phase));
  it.each([[],['--phase','other'],['--phase','key-auth','--phase','rollback'],['--resume','--phase','rollback']])('rejects an ambiguous runner argument list', args => expect(()=>optinPhase(args)).toThrow());
  it('binds actual actor and SID and requires enough live time before any automatic refresh', () => {
    expect(()=>assertOptinSession(session())).not.toThrow();
    const s = session();s.sid=id(22);expect(()=>assertOptinSession(s)).toThrow('ORIGINAL_SESSION_SID_CHANGED');
    expect(()=>assertOptinSession(session(),Date.now()+550000)).toThrow('ROOT_MUST_REFRESH_ORIGINAL_SESSION_BEFORE_RESUME');
  });
  it('freezes input before the native request and consumes an observed original without another send', async () => {
    const h = harness(), l = optinLedger(h), s = session(), body = l.freeze('secret-input',()=>({key:'SyntheticIssuedKey!2026'}));
    const result = await l.once('m10-optin-key-auth-create',s,'/fixed','POST',body);
    expect(h.state.optin.inputs['m10-optin-key-auth-create:identity'].key).toBe(h.state.requests[0].key);
    expect(h.save).toHaveBeenCalled(); expect(result.status).toBe(201);
    await l.once('m10-optin-key-auth-create',s,'/fixed','POST',body); expect(h.request).toHaveBeenCalledTimes(1);
    expect(h.state.requests[0].label).toBe('m10-optin-key-auth-create');expect(h.state.phase).toBe('native-m10-core-passed');
  });
  it.each(['prepared','response_unknown','observed-500'])('labels even a failed original and refuses to replace its key: %s', async outcome => {
    const h = harness(), l = optinLedger(h), s = session(), body = {confirmed:true};
    h.request.mockImplementationOnce(async (_s:any,path:string,method:string,body:any,options:any)=>{
      h.state.requests.push({path,method,body,bodyHash:bodyHash(body),actorId:actor,key:options.key,state:outcome==='observed-500'?'response_observed':outcome,status:outcome==='observed-500'?500:undefined,requestId:'failed-original'});
      throw Error('ORIGINAL_FAILURE');
    });
    await expect(l.once('m10-optin-stale-source-apply',s,'/fixed','POST',body)).rejects.toThrow('ORIGINAL_FAILURE');
    const before=JSON.stringify(h.state.requests);expect(h.state.requests[0].label).toBe('m10-optin-stale-source-apply');
    await expect(l.once('m10-optin-stale-source-apply',s,'/fixed','POST',body)).rejects.toThrow();
    expect(h.request).toHaveBeenCalledTimes(1);expect(JSON.stringify(h.state.requests)).toBe(before);
  });
  it('retains an observed expected 409 as a denial and rejects a later body or success reinterpretation', async () => {
    const h = harness(),l=optinLedger(h),s=session(),body={confirmed:true};
    h.request.mockImplementationOnce(async (_s:any,path:string,method:string,body:any,options:any)=>{
      h.state.requests.push({path,method,body,bodyHash:bodyHash(body),actorId:actor,key:options.key,state:'response_observed',status:409,responseData:null,requestId:'denied'});return {status:409,data:null,requestId:'denied'};
    });
    await l.onceExpected('m10-optin-stale-source-denied',s,'/fixed','POST',body,[409]);
    await l.onceExpected('m10-optin-stale-source-denied',s,'/fixed','POST',body,[409]);expect(h.request).toHaveBeenCalledTimes(1);
    await expect(l.once('m10-optin-stale-source-denied',s,'/fixed','POST',body)).rejects.toThrow('ORIGINAL_UNSUCCESSFUL_OPTIN_WRITE_NO_REPLAY');
    await expect(l.onceExpected('m10-optin-stale-source-denied',s,'/fixed','POST',{confirmed:false},[409])).rejects.toThrow();
  });
  it('consumes the exact observed 409 with no data after a tool failure without another apply, and preserves its original error/key',async()=>{
    const h=harness(),l=optinLedger(h),s=session(),body={confirmed:true};
    h.request.mockImplementationOnce(async(_s:any,path:string,method:string,body:any,options:any)=>{
      h.state.requests.push({path,method,body,bodyHash:bodyHash(body),actorId:actor,key:options.key,state:'response_observed',status:409,responseData:undefined,errorCode:'CONFIGURATION_ORIGIN_SOURCE_CHANGED',requestId:'actual-denied-no-data'});
      return {status:409,data:undefined,requestId:'actual-denied-no-data'};
    });
    const original=await l.onceExpected('m10-optin-stale-source-apply-denied',s,'/fixed','POST',body,[409]);
    expect(()=>assertNoOptinSecrets(original.data,['SyntheticActualSecret!2026'])).not.toThrow();
    const before=JSON.stringify(h.state.requests),key=h.state.requests[0].key;
    const resumed=await l.onceExpected('m10-optin-stale-source-apply-denied',s,'/fixed','POST',body,[409]);
    expect(resumed.status).toBe(409);expect(resumed.data).toBeUndefined();expect(h.request).toHaveBeenCalledTimes(1);expect(JSON.stringify(h.state.requests)).toBe(before);
    expect(h.state.requests[0]).toMatchObject({key,status:409,state:'response_observed',errorCode:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'});
  });
});

describe('M10 opt-in actual response assertions', () => {
  it('binds observer projections to the real immutable SQL011 table schema rather than a made-up jobs execution column',()=>{
    const sql=readFileSync('apps/console-api/src/infrastructure/migrations/011_m8_configuration.sql','utf8');
    const code=optinObserverProgram({mode:'no-native'});
    const table=(name:string)=>{const block=sql.match(new RegExp(`CREATE TABLE ${name} \\(([\\s\\S]*?)\\n\\);`));expect(block).not.toBeNull();return block![1];};
    const actualJobDDL=table('configuration_jobs');expect(actualJobDDL).not.toMatch(/(?:^|[,\n])\s*execution_id\s+uuid\b/);
    const originDDL=readFileSync('apps/console-api/src/infrastructure/migrations/018_m10_configuration_origins.sql','utf8');
    for(const name of ['configuration_jobs','configuration_executions']) {
      const projections=[...code.matchAll(new RegExp(`SELECT ([a-z_,]+) FROM ${name} WHERE`,'g'))];expect(projections.length).toBeGreaterThan(0);
      for(const statement of projections)for(const column of statement[1].split(',')) {
        const columnDDL=table(name).match(new RegExp(`(?:^|[,\\n])\\s*${column}\\s+(?:uuid|text|integer|jsonb|boolean|timestamptz)\\b`));
        const addedDDL=name==='configuration_jobs'&&originDDL.match(new RegExp(`ADD COLUMN ${column} (?:uuid|text|integer|jsonb|boolean|timestamptz)\\b`));expect(Boolean(columnDDL||addedDDL)).toBe(true);
      }
    }
    expect(code).toContain('FROM configuration_executions WHERE job_id=$1 AND actor_id=$2 AND cluster_id=$3 AND workspace_id=$4');
    expect(code).toContain('assert.equal(x.id, input.executionId)');expect(code).toContain('assert.equal(job.safe_progress.executionId, x.id)');
    const projection=readFileSync('apps/console-api/src/modules/configuration/configuration-job-queries.ts','utf8');expect(projection).toMatch(/e\.id AS execution_id/);expect(projection).toMatch(/JOIN configuration_executions e/);
  });
  it('outputs one parseable JSON record with an actual LF from the generated program without running the observer or accessing SQL',()=>{
    const input={mode:'no-native',requestId:'synthetic-observer-output'},expression=`await runOptinObserver(${JSON.stringify(input)})`;
    const program=optinObserverProgram(input);expect(program.split(expression)).toHaveLength(2);
    const framingOnly=program.replace(expression,'({passed:true,source:"synthetic-framing-only"})');
    const result=spawnSync(process.execPath,['--input-type=module'],{input:framingOnly,encoding:'utf8'});expect(result.status).toBe(0);expect(result.stderr).toBe('');
    expect(result.stdout.endsWith('\n')).toBe(true);expect(result.stdout.endsWith('\\n')).toBe(false);expect(JSON.parse(result.stdout)).toEqual({passed:true,source:'synthetic-framing-only'});
  });
  it('uses actual receipt execution ID as required authority and steps only to corroborate it',()=>{
    const page={nextCursor:null,items:[{state:'succeeded',verified:true,operationId:id(52),executionId:id(51)}]};
    expect(assertOptinExecutionSteps(page,1,id(51))).toBe(id(51));
    expect(()=>assertOptinExecutionSteps(page,1,null)).toThrow('ACTUAL_RECEIPT_EXECUTION_ID_REQUIRED');
    expect(()=>assertOptinExecutionSteps(page,1,id(53))).toThrow();
    expect(()=>assertOptinExecutionSteps({...page,nextCursor:'another-page'},1,id(51))).toThrow();
    expect(()=>assertOptinExecutionSteps({...page,items:[...page.items,{...page.items[0],executionId:id(53)}]},2,id(51))).toThrow();
  });
  it('compares both compiled trees across the separate SQL bind mount while preserving all other compiled bytes in the fingerprint',()=>{
    const directory=mkdtempSync(join(tmpdir(),'kongpilot-optin-dual-mount-'));
    try {
      const host=join(directory,'host'),runtime=join(directory,'runtime');
      for(const root of [host,runtime]) {
        mkdirSync(join(root,'infrastructure/migrations'),{recursive:true});mkdirSync(join(root,'infrastructure/migrations-extra'),{recursive:true});mkdirSync(join(root,'modules/infrastructure/migrations'),{recursive:true});
        for(let n=0;n<21;n++)writeFileSync(join(root,`module-${n}.js`),`export const value=${n};\n`);
        writeFileSync(join(root,'infrastructure/migrations-extra/keep.js'),'compiled extra subtree\n');
        writeFileSync(join(root,'modules/infrastructure/migrations/keep.js'),'compiled nested subtree\n');
      }
      const before=optinDistFingerprint(host);
      writeFileSync(join(runtime,'infrastructure/migrations/017_m10_governance.sql'),'synthetic separately mounted SQL017\n');
      writeFileSync(join(runtime,'infrastructure/migrations/018_m10_configuration_origins.sql'),'synthetic separately mounted SQL018\n');
      expect(optinDistFingerprint(runtime)).toBe(before);
      writeFileSync(join(runtime,'infrastructure/migrations/018_m10_configuration_origins.sql'),'synthetic changed mounted SQL018\n');
      expect(optinDistFingerprint(runtime)).toBe(before);
      const worker=optinObserverProgram({mode:'no-native'});expect(worker).toContain("assert.equal(input.migrations[name], actual)");expect(worker).toContain("SELECT checksum FROM schema_migrations WHERE name=$1");
      writeFileSync(join(runtime,'infrastructure/migrations-extra/keep.js'),'changed compiled extra subtree\n');expect(optinDistFingerprint(runtime)).not.toBe(before);
      writeFileSync(join(runtime,'infrastructure/migrations-extra/keep.js'),'compiled extra subtree\n');
      writeFileSync(join(runtime,'modules/infrastructure/migrations/keep.js'),'changed compiled nested subtree\n');expect(optinDistFingerprint(runtime)).not.toBe(before);
      writeFileSync(join(runtime,'modules/infrastructure/migrations/keep.js'),'compiled nested subtree\n');
      writeFileSync(join(runtime,'module-20.js'),'changed actual compiled code\n');expect(optinDistFingerprint(runtime)).not.toBe(before);
    } finally { rmSync(directory,{recursive:true,force:true}); }
  });
  it('creates valid standalone ESM for the owned API readonly observer without running it or opening any database',()=>{
    const code=optinObserverProgram({mode:'no-native',actorId:actor,clusterId:cid,workspaceId:wid,key:id(12),requestId:'synthetic-refused',runtimeSourceSha256:'a'.repeat(64),runtimeDistSha256:'b'.repeat(64),migrations:{}});
    const syntax=spawnSync(process.execPath,['--check','--input-type=module'],{input:code,encoding:'utf8'});expect(syntax.status).toBe(0);expect(syntax.stderr).toBe('');
    expect(code).not.toContain("from './m10-release-evidence.mjs'");expect(code).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  });
  const plan = () => ({entity:{clusterId:cid,workspaceId:wid,executionMode:'direct',capabilities:{apply:true},deleteCount:0,stepCount:1},nextCursor:null,items:[{entityType:'credentials',credentialKind:'key-auth',action:'create',parentId:consumer,allocatedNativeId:allocated}]});
  const bound = {clusterId:cid,workspaceId:wid,consumerId:consumer,sourceCredentialId:sourceCredential,oldTargetCredentialId:oldCredential};
  it('allows only one actual key-auth create with independent server allocation and target Consumer binding',()=>expect(assertKeyAuthOptinPlan(plan(),bound).allocatedNativeId).toBe(allocated));
  it.each(['reuse-source','reuse-target','foreign-consumer','oauth-child','extra-native','physical-delete'])('rejects an unsafe credential plan: %s',change=>{
    const p:any=plan();if(change==='reuse-source')p.items[0].allocatedNativeId=sourceCredential;if(change==='reuse-target')p.items[0].allocatedNativeId=oldCredential;
    if(change==='foreign-consumer')p.items[0].parentId=id(90);if(change==='oauth-child')p.items[0].credentialKind='oauth2';if(change==='extra-native')p.items.push({...p.items[0]});if(change==='physical-delete')p.entity.deleteCount=1;
    expect(()=>assertKeyAuthOptinPlan(p,bound)).toThrow();
  });
  it('binds a single plugin update to the original target UUID',()=>{
    const p:any=plan();p.items=[{entityType:'plugins',action:'update',nativeId:id(10)}];expect(assertSensitivePluginOptinPlan(p,{clusterId:cid,workspaceId:wid,targetPluginId:id(10)}).nativeId).toBe(id(10));
    expect(()=>assertSensitivePluginOptinPlan(p,{clusterId:cid,workspaceId:wid,targetPluginId:id(11)})).toThrow();
  });
  const descriptor=()=>({items:[{objectKey:`consumers:${consumer}`,entityType:'consumers',nativeId:consumer,objectWorkspaceId:wid,eligible:true,referenceOnly:false}]});
  it('selects actual eligible metadata with exact workspace and native object identity',()=>expect(assertOptinSourceObject(descriptor(),{entityType:'consumers',nativeId:consumer,workspaceId:wid}).nativeId).toBe(consumer));
  it.each(['foreign-workspace','unqualified','payload','duplicate'])('refuses an unsafe metadata picker response: %s',change=>{
    const p:any=descriptor();if(change==='foreign-workspace')p.items[0].objectWorkspaceId=id(99);if(change==='unqualified')p.items[0].eligible=false;if(change==='payload')p.items[0].payload={secret:'synthetic'};if(change==='duplicate')p.items.push({...p.items[0]});
    expect(()=>assertOptinSourceObject(p,{entityType:'consumers',nativeId:consumer,workspaceId:wid})).toThrow();
  });
  it('matches an original receipt to actor, scope and original key rather than its status alone',()=>{
    const packet={actorId:actor,key:id(21),state:'response_observed'},receipt={actorId:actor,clusterId:cid,workspaceId:wid,idempotencyKey:id(21),kind:'apply',state:'succeeded',registrationCompleted:true};
    expect(()=>assertOptinOriginalReceipt(receipt,packet,{clusterId:cid,workspaceId:wid,kind:'apply',state:'succeeded'})).not.toThrow();
    expect(()=>assertOptinOriginalReceipt({...receipt,idempotencyKey:id(22)},packet,{clusterId:cid,workspaceId:wid,kind:'apply',state:'succeeded'})).toThrow();
  });
  const zero=()=>({passed:true,mode:'no-native',consoleReadOnly:true,requestId:'refused-original',actorId:actor,clusterId:cid,workspaceId:wid,runtimeSourceSha256:'a'.repeat(64),configurationJobCount:0,mutationCount:0,nativeStartedCount:0,nativeCompletedCount:0,migrationChecksumsMatched:true,runtimeDistMatched:true,independentWireLogClaim:false});
  it('requires actual console proof of all zero native counters bound to the exact refused request and deployed candidate',()=>{
    expect(()=>assertOptinZeroNativeProof(zero(),{requestId:'refused-original',actorId:actor},{clusterId:cid,workspaceId:wid,runtimeSourceSha256:'a'.repeat(64)})).not.toThrow();
    for(const patch of [{requestId:'another'},{nativeStartedCount:1},{mutationCount:1},{configurationJobCount:1},{runtimeDistMatched:false},{migrationChecksumsMatched:false},{independentWireLogClaim:true},{runtimeSourceSha256:'b'.repeat(64)}])
      expect(()=>assertOptinZeroNativeProof({...zero(),...patch},{requestId:'refused-original',actorId:actor},{clusterId:cid,workspaceId:wid,runtimeSourceSha256:'a'.repeat(64)})).toThrow();
  });
  it('checks the actual plaintext, URL and base64 variants without a failed-password exception',()=>{
    const secret='SyntheticOptinPrivateSecret!2026';expect(()=>assertNoOptinSecrets({masked:'[REDACTED]'},[secret])).not.toThrow();
    for(const value of [secret,encodeURIComponent(secret),Buffer.from(secret).toString('base64'),Buffer.from(secret).toString('base64url')])expect(()=>assertNoOptinSecrets({value},[secret])).toThrow();
  });
  it('scans legitimate absent or null data while refusing other non-JSON values',()=>{
    expect(()=>assertNoOptinSecrets(undefined,['SyntheticActualSecret!2026'])).not.toThrow();
    expect(()=>assertNoOptinSecrets(null,['SyntheticActualSecret!2026'])).not.toThrow();
    expect(()=>assertNoOptinSecrets(()=>undefined,['SyntheticActualSecret!2026'])).toThrow('PUBLIC_OPTIN_RESPONSE_MUST_BE_JSON_OR_ABSENT');
  });
  it('publishes phase-only results while omitting all private request body and key material',()=>{
    const h=harness(),l=optinLedger(h);h.state.requests.push({label:'m10-optin-key-auth-plan',method:'POST',path:'/fixed?workspaceId=synthetic',actorId:actor,body:{key:'Synthetic!2026'},key:id(31),state:'response_observed',status:201});
    l.state.phases['key-auth']={state:'passed',nativeVerified:true};l.check('key-auth','actual isolated phase passed',{nativeStepCount:1});
    const report=optinPublicReport(h,'key-auth',true);expect(report.commercialAcceptance).toBe(false);expect(report.mainReleasePhasePreserved).toBe(true);expect(JSON.stringify(report)).not.toContain('Synthetic!2026');expect(report.attempts[0]).not.toHaveProperty('key');expect(h.state.phase).toBe('native-m10-core-passed');
    expect(()=>l.check('key-auth','unsafe',{sourceSecret:'synthetic'})).toThrow();
  });
});
