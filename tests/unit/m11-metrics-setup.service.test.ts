import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {describe,expect,it,vi} from 'vitest';
import {metricsSetupFixture} from './fixtures/m11-metrics-setup';
import {metricsSetupAad} from '../../apps/console-api/src/modules/vitals/vitals-setup.types';
const response=(error:any)=>error?.getResponse?.()?.code;
async function prepared(f:ReturnType<typeof metricsSetupFixture>){return f.service.prepare(f.cid,f.query,f.body,f.actor) as Promise<any>;}
async function submitted(f:ReturnType<typeof metricsSetupFixture>){const preview=await prepared(f),body={revision:1,materialHmac:preview.materialHmac,confirmed:true,confirm_name:preview.preview.confirmationName},actor={...f.actor,idempotencyKey:'submit-key-unique-1'};
 const receipt:any=await f.service.submit(f.cid,preview.intentId,f.query,body,actor),plan=f.savedPlans.get(receipt.workflowId);return{preview,body,actor,receipt,plan};}
async function executing(f:ReturnType<typeof metricsSetupFixture>){const result=await submitted(f),executionId=randomUUID(),byPath=new Map<string,any>();
 for(const s of result.plan.steps.slice(0,-1)){const id=randomUUID(),raw={...s.mutationPayload,id:s.entityId,name:s.key.endsWith('prometheus')?'prometheus':'http-log',service:null,route:null,consumer:null},receipt={operationId:id,state:'succeeded',remoteStarted:true,remoteCompleted:true,entityId:s.entityId};
  f.mutations.push({id,step_state:'succeeded',state:'succeeded',remote_started:true,remote_completed:true,actor_id:f.uid,cluster_id:f.cid,workspace_id:f.wid,workflow_id:result.plan.workflowId,
   workflow_execution_id:executionId,workflow_step_id:s.id,workflow_plan_revision:1,workflow_plan_hash:f.secrets.fingerprint(result.plan),entity_type:'plugins',entity_id:s.entityId,action:s.mutationAction,idempotency_key:s.mutationIdempotencyKey,
   before_secret:f.secrets.encrypt(s.before,`mutation:${id}:before`),payload_secret:f.secrets.encrypt(s.mutationPayload,`mutation:${id}:payload`),result_secret:f.secrets.encrypt(raw,`mutation:${id}:result`),
   after_fingerprint:f.secrets.fingerprint(raw),step_receipt_secret:f.secrets.encrypt({receipt},`workflow:${executionId}:${s.id}:receipt`)});byPath.set(`/plugins/${s.entityId}`,raw);
 }
 f.kong.request.mockImplementation(async(_cid:any,method:any,path:any)=>{if(method!=='GET'||!byPath.has(path))throw Error('SOURCE forbids native request');return structuredClone(byPath.get(path));});
 const bridge={verify:vi.fn(async()=>undefined)};f.service.installExecutionBridge(bridge);return{...result,executionId,byPath,bridge,input:{plan:result.plan,step:result.plan.steps.at(-1),actor:f.actor,executionId,transaction:f.db}};
}
describe('M11 metrics prepare/submit SOURCE contracts (not runtime acceptance)',()=>{
 it.each(['native_prometheus','collector'] as const)('prepares encrypted immutable %s intention with zero remote writes',async mode=>{const f=metricsSetupFixture(mode),value=await prepared(f),row=f.intents.get(value.intentId);
  expect(value.state).toBe('prepared');expect(value.workflowId).toBeNull();expect(value.revision).toBe(1);expect(value.planHash).toBeNull();expect(value.preview.nativeRequestsPlanned).toBe(mode==='collector'?2:1);
  expect(value.preview.scope).toMatchObject({defaultWorkspaceOnly:true,affectsAllWorkspaces:true});expect(row.material_secret).toMatch(/^v1\./);expect(f.secrets.fingerprint(f.secrets.decrypt(row.material_secret,metricsSetupAad(row.id)))).toBe(row.material_hmac);
  expect(JSON.stringify(value)).not.toMatch(/source-fixture-ingest-token|source-fixture-private-password|telemetry-collector|http:\/\/prometheus/);expect(f.kong.request).not.toHaveBeenCalled();expect(f.execution.runManagedMetricsProvision).not.toHaveBeenCalled();expect(f.audit.append).toHaveBeenCalled();});
 it('same prepare key returns original intention; different selector cannot allocate another',async()=>{const f=metricsSetupFixture(),a=await prepared(f),b=await prepared(f);expect(b.intentId).toBe(a.intentId);expect(f.intents.size).toBe(1);
  await expect(f.service.prepare(f.cid,f.query,{...f.body,mode:'native_prometheus'},f.actor)).rejects.toSatisfy((e:any)=>response(e)==='IDEMPOTENCY_CONFLICT');expect(f.intents.size).toBe(1);});
 it('by-key unknown is closed and authenticates the original workspace; missing never means success',async()=>{const f=metricsSetupFixture();expect(await f.service.byKey(f.cid,'missing-key-unique',f.query,f.actor)).toEqual({state:'not_prepared',intentId:null});
  await expect(f.service.byKey(f.cid,'missing-key-unique',{workspaceId:randomUUID()},f.actor)).rejects.toThrow();});
 it('submits exact original canonical selector HMA once and exposes only safe receipt',async()=>{const f=metricsSetupFixture(),s=await submitted(f),intent=f.intents.get(s.preview.intentId),call=f.plans.persist.mock.calls[0];
  expect(s.receipt).toMatchObject({intentId:s.preview.intentId,clusterId:f.cid,workspaceId:f.wid,materialHmac:s.preview.materialHmac,state:'submitted'});expect(f.secrets.fingerprint(call[2])).toBe(intent.request_hmac);
  expect(s.plan.steps).toHaveLength(3);expect(s.plan.steps[0].nativeRequests[0].method).toBe('POST');expect(s.plan.steps.at(-1).nativeRequests).toEqual([]);
  const again=await f.service.submit(f.cid,s.preview.intentId,f.query,s.body,s.actor);expect(again.workflowId).toBe(s.receipt.workflowId);expect(f.plans.persist).toHaveBeenCalledTimes(1);
  expect((await f.service.receipt(f.cid,s.preview.intentId,f.query,f.actor)).state).toBe('submitted');expect(f.kong.request).not.toHaveBeenCalled();});
 it.each(['actorId','handler','approved','token','http_endpoint','executorId','workflowId','nativeRequests'])('refuses caller %s before storing or sending',async field=>{const f=metricsSetupFixture();await expect(f.service.prepare(f.cid,f.query,{...f.body,[field]:'injected'},f.actor)).rejects.toThrow();expect(f.intents.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();});
 it.each([
  ['readonly',(f:any)=>f.user.super_admin=false],['forced password',(f:any)=>f.user.force_password_change=true],['disabled principal',(f:any)=>f.user.status='disabled'],
  ['foreign SID',(f:any)=>f.frame.sessionId=randomUUID()],['NULL scheduled SID',(f:any)=>{f.frame.sessionId=null;f.setNamespace(true);}],['operation frame',(f:any)=>f.frame.operation={}],
  ['direct cluster',(f:any)=>f.cluster.execution_mode='direct'],['nondefault workspace',(f:any)=>f.workspace.is_default=false],['Kong 2',(f:any)=>f.cluster.version='2.8.0'],
  ['wrong confirmation',(f:any)=>f.body.confirm_name='different'],['Loki source',(f:any)=>f.source.type='loki'],['missing collector credential',(f:any)=>f.setCredential(false)],
  ['missing plugin',(f:any)=>f.cluster.enabled_plugins=['prometheus']],['original uncertain legacy',(f:any)=>f.setLegacy(true)],
 ] as Array<[string,(f:any)=>void]>)('keeps %s closed with zero Native',async(_label,change)=>{const f=metricsSetupFixture();change(f);await expect(prepared(f)).rejects.toThrow();expect(f.intents.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();});
 it('rejects globals in another workspace without implicit tag rewrite',async()=>{const f=metricsSetupFixture();f.globalRows.push({id:randomUUID(),name:'prometheus',enabled:true,config:{},tags:['other']});
  await expect(prepared(f)).rejects.toSatisfy((e:any)=>response(e)==='METRICS_SETUP_PLUGIN_WORKSPACE_REQUIRED');expect(f.entities.prepareCore).not.toHaveBeenCalled();});
 it('rejects duplicate global plugins or incomplete bounded EOF instead of assuming absence',async()=>{for(const kind of ['duplicate','incomplete']){const f=metricsSetupFixture();if(kind==='duplicate')f.globalRows.push(...[1,2].map(()=>({id:randomUUID(),name:'prometheus',config:{}})));
   else f.kong.list.mockImplementation(async()=>({items:[],nextCursor:'more'}));await expect(prepared(f)).rejects.toThrow();expect(f.intents.size).toBe(0);expect(f.kong.list.mock.calls.length).toBeLessThanOrEqual(10);}});
 it.each([
  ['IAM change',(f:any)=>f.setEpoch(2)],['source revision',(f:any)=>f.source.revision++],['source auth',(f:any)=>f.source.auth.password='changed'],
  ['settings CAS',(f:any)=>f.control.revision++],['credential generation',(f:any)=>f.control.credential_generation++],['default scope',(f:any)=>f.workspace.revision++],
  ['cluster policy',(f:any)=>f.cluster.execution_mode='direct'],['cluster revision',(f:any)=>f.cluster.revision++],['current author session',(f:any)=>f.frame.sessionId=randomUUID()],
 ] as Array<[string,(f:any)=>void]>)('requires current %s at submission, with no Native',async(_label,change)=>{const f=metricsSetupFixture(),preview=await prepared(f);change(f);
  await expect(f.service.submit(f.cid,preview.intentId,f.query,{revision:1,materialHmac:preview.materialHmac,confirmed:true,confirm_name:'生产'},{...f.actor,idempotencyKey:'submit-key-unique-1'})).rejects.toThrow();expect(f.requests.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();});
 it.each(['native_id','before_hmac','payload_hmac','schema_hmac','path_hmac','workspace_id','material_hmac'])('rejects tampered persistent plugin manifest %s',async field=>{const f=metricsSetupFixture(),preview=await prepared(f);f.materials[0][field]=field.endsWith('id')?randomUUID():'f'.repeat(64);
  await expect(f.service.get(f.cid,preview.intentId,f.query,f.actor)).rejects.toSatisfy((e:any)=>response(e)==='METRICS_SETUP_MATERIAL_MANIFEST_INVALID');});
 it('authenticates AEAD with the actual intention AAD, rejects swapped ciphertext, and denies another owner',async()=>{const f=metricsSetupFixture(),preview=await prepared(f),row=f.intents.get(preview.intentId);row.material_secret=f.secrets.encrypt(f.secrets.decrypt(row.material_secret,metricsSetupAad(row.id)),'wrong-intention-aad');
  await expect(f.service.get(f.cid,preview.intentId,f.query,f.actor)).rejects.toSatisfy((e:any)=>response(e)==='METRICS_SETUP_INTENT_INVALID');});
 it('ignores volatile catalog observation fields but preserves collector when native-only is selected',async()=>{const f=metricsSetupFixture('native_prometheus');f.control.collector_enabled=true;const s=await submitted(f);f.control.catalog_status='ready';f.control.catalog_revision=100;f.control.last_verified_at=new Date().toISOString();
  await expect(f.service.verifyReviewer(f.uid,s.plan)).resolves.toBeUndefined();const full:any=await f.service.get(f.cid,s.preview.intentId,f.query,f.actor);expect(full.preview.after.settings.collectorEnabled).toBe(true);});
 it('revalidates an actual distinct SQL reviewer without copying their SID into HTTP context',async()=>{const f=metricsSetupFixture(),s=await submitted(f),reviewer=randomUUID();f.users.set(reviewer,{...f.user,id:reviewer,permissions_epoch:3});const before={...f.frame};
  await expect(f.service.verifyReviewer(reviewer,s.plan)).resolves.toBeUndefined();expect(f.frame).toEqual(before);f.users.get(reviewer).super_admin=false;await expect(f.service.verifyReviewer(reviewer,s.plan)).rejects.toThrow();});
 it('requires the mandatory once-installed original execution bridge before Native callback',async()=>{const f=metricsSetupFixture(),s=await submitted(f),fn=vi.fn();await expect(f.service.runManagedNative(s.plan,randomUUID(),fn)).rejects.toSatisfy((e:any)=>response(e)==='METRICS_SETUP_EXECUTION_BRIDGE_REQUIRED');expect(fn).not.toHaveBeenCalled();
  f.service.installExecutionBridge({verify:async()=>{throw Error('foreign private handle');}});expect(()=>f.service.installExecutionBridge({verify:async()=>{}})).toThrow();await expect(f.service.runManagedNative(s.plan,randomUUID(),fn)).rejects.toThrow('foreign private handle');expect(fn).not.toHaveBeenCalled();});
 it('safe workflow review masks managed endpoints and arbitrary headers on both diff sides',async()=>{const f=metricsSetupFixture(),s=await submitted(f),preview:any=await f.service.reviewPreview(s.plan,f.actor);expect(JSON.stringify(preview)).not.toMatch(/source-fixture-ingest-token|telemetry-collector/);
  expect(preview.diff[1].after.config.http_endpoint).toBe('[MANAGED_ENDPOINT]');expect(preview.impact.nativeRequests).toBe(2);});
});
describe('M11 monitoring metadata completion SOURCE acknowledgement contracts',()=>{
 it('only configures settings after every exact known-success packet and current readback',async()=>{const f=metricsSetupFixture(),x=await executing(f),result=await(f.service as any).apply(x.input);
  expect(result).toMatchObject({mode:'collector',settingsRevision:4,sourceId:f.source.id});expect(f.settings.configure).toHaveBeenCalledTimes(1);expect(f.facts).toHaveLength(1);expect(f.facts[0][10]).toEqual(f.mutations.map(m=>m.id));expect(f.facts[0][14]).toBe(f.secrets.fingerprint(result));
  expect(f.kong.request.mock.calls.every(c=>c[1]==='GET')).toBe(true);expect(x.bridge.verify).toHaveBeenCalledTimes(2);});
 it.each(['uncertain','failed','running'])('retains %s original Native outcome and never configures or replays it',async state=>{const f=metricsSetupFixture(),x=await executing(f);f.mutations[0].state=state;await expect((f.service as any).apply(x.input)).rejects.toThrow();expect(f.settings.configure).not.toHaveBeenCalled();expect(f.facts).toHaveLength(0);expect(f.mutations[0].state).toBe(state);});
 it.each(['workflow_execution_id','workflow_id','workflow_step_id','workspace_id','actor_id','entity_id','idempotency_key','after_fingerprint'])('refuses wrong actual Native %s facts',async field=>{const f=metricsSetupFixture(),x=await executing(f);f.mutations[0][field]='wrong';await expect((f.service as any).apply(x.input)).rejects.toThrow();expect(f.settings.configure).not.toHaveBeenCalled();});
 it('rejects wrong original encrypted receipt or late readback drift and rolls settings closed',async()=>{for(const mode of ['receipt','drift']){const f=metricsSetupFixture(),x=await executing(f),m=f.mutations[0];if(mode==='receipt')m.step_receipt_secret=f.secrets.encrypt({receipt:{operationId:randomUUID()}},`workflow:${x.executionId}:${m.workflow_step_id}:receipt`);
   else x.byPath.values().next().value.enabled=false;await expect((f.service as any).apply(x.input)).rejects.toThrow();expect(f.settings.configure).not.toHaveBeenCalled();expect(f.facts).toHaveLength(0);}});
 it('does not pretend uninitialized settings revision zero advances to one',async()=>{const f=metricsSetupFixture('native_prometheus');f.control.revision=0;const x=await executing(f),result=await(f.service as any).apply(x.input);expect(result.settingsRevision).toBe(2);expect(f.facts[0].slice(11,13)).toEqual([0,2]);});
 it('refuses terminal success if the immutable intention expires during the last settings transaction await',async()=>{const f=metricsSetupFixture(),x=await executing(f),original=f.settings.configure.getMockImplementation()!;
  f.settings.configure.mockImplementation(async(...args:any[])=>{const result=await original(...args);vi.spyOn(Date,'now').mockReturnValue(Date.parse(x.plan.expiresAt)+1);return result;});
  try{await expect((f.service as any).apply(x.input)).rejects.toSatisfy((e:any)=>response(e)==='METRICS_SETUP_INTENT_EXPIRED');}finally{vi.restoreAllMocks();}
  // The production caller owns the SQL transaction and rolls these writes back.
  // This fixture does not claim to execute a real rollback or change W/E outcomes.
 });
 it('turns terminal partial receipt into honest read-only state with no preview or retry',async()=>{const f=metricsSetupFixture(),s=await submitted(f);f.workflowRows.get(s.plan.workflowId).state='partial';const r:any=await f.service.get(f.cid,s.preview.intentId,f.query,f.actor);expect(r.state).toBe('partial');expect(r.preview).toBeNull();expect(r.workflowId).toBe(s.plan.workflowId);});
});
