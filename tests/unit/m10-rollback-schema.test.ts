import 'reflect-metadata';
import {readFileSync} from 'node:fs';
import {AsyncLocalStorage} from 'node:async_hooks';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {SecretService,canonicalJson} from '../../apps/console-api/src/infrastructure/secret.service';
import {normalizeCaptureGraph,diffTransferGraphs,compileTransferDag} from '../../apps/console-api/src/modules/config-transfer';
import {graph,id} from './m8-config-transfer.fixture';
import {rollbackSchemasCompatible} from '../../apps/console-api/src/modules/config-transfer/rollback-schema-comparison';

const awsSchema=()=>JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/plugin-schema-aws-lambda.json','utf8'));
const bind=(g:any,label:string)=>{g.schemas.schemaHmac=g.schemaHmac=label;g.objects.forEach((o:any)=>o.schemaHmac=label);};
function pair(){
 const current=graph(),historic=graph();for(const g of [current,historic])g.schemas.enabledPlugins=['aws-lambda','correlation-id'];
 current.schemas.plugins['aws-lambda']=awsSchema();const original=current.objects.find(o=>o.entityType==='plugins')!;
 current.objects.push({...structuredClone(original),objectKey:`plugins:${id(40)}`,nativeId:id(40),payload:{id:id(40),name:'aws-lambda',enabled:false,service:{id:id(1)},route:null,consumer:null,tags:original.payload.tags,config:{function_name:'fixture-function',aws_region:'us-east-1',aws_key:'synthetic-aws-key',aws_secret:'synthetic-aws-secret'}},dependencies:[`services:${id(1)}`]});
 bind(current,'current-captured-schema');return{current,historic};
}
const target=(g:any)=>normalizeCaptureGraph(g,{[g.scope.workspaceId]:'test'});
const rollback=(current:any,historic:any)=>diffTransferGraphs(current,target(historic),{mode:'rollback',rollbackBaselineVerified:true});
const mismatch=(fn:()=>unknown)=>expect(fn).toThrowError(expect.objectContaining({code:'CONFIGURATION_DIFF_SCOPE_MISMATCH'}));
describe('M10 actual schema bundle membership during rollback',()=>{
 it('deletes a later configured AWS plugin without altering either immutable graph or requiring its definition in the old snapshot',()=>{
  const f=pair(),before=canonicalJson(f),diff=rollback(f.current,f.historic);expect(diff.changes).toHaveLength(1);expect(diff.changes[0]).toMatchObject({entityType:'plugins',nativeId:id(40),action:'delete'});
  const plan=compileTransferDag(diff,{stepIds:{[`plugins:${id(40)}`]:id(501)},sourceManifestHmac:'original-historic-manifest',baselineManifestHmac:'actual-current-manifest',expiresAt:'2026-10-13T12:00:00Z',fingerprint:canonicalJson,redact:()=>null});
  expect(plan.schemaHmac).toBe('current-captured-schema');expect(plan.steps[0].nativeRequests[0]).toMatchObject({method:'DELETE',canonicalPath:`/plugins/${id(40)}`,body:null});expect(canonicalJson(f)).toBe(before);
 });
 it('restores a formerly deleted plugin only with a fresh actual matching schema and preserves original native ID',()=>{
  const f=pair();f.current.objects=f.current.objects.filter(o=>o.nativeId!==id(4));delete f.current.schemas.plugins['correlation-id'];bind(f.current,'current-with-deleted-plugin');
  mismatch(()=>rollback(f.current,f.historic));f.current.schemas.plugins['correlation-id']=structuredClone(f.historic.schemas.plugins['correlation-id']);bind(f.current,'fresh-capture-including-restoration-schema');
  const before=canonicalJson(f),diff=rollback(f.current,f.historic);expect(diff.changes.find(c=>c.nativeId===id(4))).toMatchObject({action:'create',writePayload:{id:id(4),name:'correlation-id'}});expect(canonicalJson(f)).toBe(before);
 });
 it.each(['default','required','constraint']as const)('rejects a changed common %s definition despite unchanged payload and opaque digest',kind=>{
  const f=pair(),field=(f.current.schemas.plugins['correlation-id']as any).fields[0].header_name;
  if(kind==='default')field.default='X-Changed';if(kind==='required')field.required=true;if(kind==='constraint')field.len_min=2;mismatch(()=>rollback(f.current,f.historic));
 });
 it('rejects changed fresh restoration definitions instead of trusting old defaults',()=>{
  const f=pair();f.current.objects=f.current.objects.filter(o=>o.nativeId!==id(4));delete f.current.schemas.plugins['correlation-id'];bind(f.current,'current-with-deleted-plugin');
  const changed:any=structuredClone(f.historic.schemas.plugins['correlation-id']);changed.fields[0].header_name.default='Changed';f.current.schemas.plugins['correlation-id']=changed;bind(f.current,'fresh-changed-restoration-definition');mismatch(()=>rollback(f.current,f.historic));
 });
 it.each(['kong','adapter','enabled','scope','malformed-current-only']as const)('keeps %s fail-closed instead of relaxing global schema checks',kind=>{
  const f=pair();if(kind==='kong'){f.historic.kongVersion=f.historic.schemas.kongVersion='1.5.2';}if(kind==='adapter')f.historic.schemas.adapterVersion='different';if(kind==='enabled')f.historic.schemas.enabledPlugins=['correlation-id'];if(kind==='scope')f.historic.scope.transportScope='different-physical';if(kind==='malformed-current-only')f.current.schemas.plugins['aws-lambda']={fields:[{broken:5}]};mismatch(()=>rollback(f.current,f.historic));
 });
 it.each(['merge','sync']as const)('retains whole-bundle equivalence for ordinary %s',mode=>{
  const f=pair();mismatch(()=>diffTransferGraphs(f.current,target(f.historic),{mode,syncConfirmed:true}));
 });
 it('requires a verified current rollback baseline even for the narrow membership difference',()=>{const f=pair();expect(()=>diffTransferGraphs(f.current,target(f.historic),{mode:'rollback'})).toThrowError(expect.objectContaining({code:'CONFIGURATION_FRESH_ROLLBACK_BASELINE_REQUIRED'}));});
 it('bounds unique schema names after deduplicating many legitimate instances',()=>{const f=pair();expect(rollbackSchemasCompatible(f.current.schemas,f.historic.schemas,Array.from({length:201},()=> 'correlation-id'))).toBe(true);});
});
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','da'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M10 rollback facade required schema binding',()=>{
 it('derives bounded plugin names from the authenticated historical graph and includes them in the new real baseline capture request',async()=>{
  const f=pair(),oldBytes=canonicalJson(f.historic),handle=Object.freeze({}),actor={user:{id:id(501),username:'rollback-owner',superAdmin:false},workspaceId:f.current.scope.workspaceId,idempotencyKey:'actual-new-intent'},compareJob={id:id(502),existing:false,handle,scope:f.current.scope,job:{id:id(502)}};
  const captureBaseline=vi.fn(async()=>({graph:f.current,snapshotId:id(503),version:1})),persistDiff=vi.fn(async(_h:any,_id:any,diff:any)=>({deleteCount:diff.changes.filter((c:any)=>c.action==='delete').length}));
  const service=Object.assign(Object.create(ConfigurationService.prototype),{secrets:new SecretService(),withActor:async(_c:any,_a:any,_op:any,fn:any)=>fn(),snapshotScope:async()=>({scope:f.historic.scope,row:{name:'pre-key-auth',revision:1,current_version:1}}),newJob:async()=>compareJob,
   repo:{readSnapshot:async()=>f.historic},access:{assertHistoricalGraph:vi.fn()},captureBaseline,workspaceCodes:async()=>({[f.current.scope.workspaceId]:'test'}),persistDiff});
  await expect(service.rollbackPreview(f.current.scope.clusterId,id(504),{revision:1,confirmed:true,confirm_deletes:true,confirm_name:'pre-key-auth'},actor)).resolves.toEqual({deleteCount:1});
  expect(captureBaseline.mock.calls[0][5]).toEqual(['correlation-id']);expect(persistDiff.mock.calls[0][2].baseline).toBe(f.current);expect(canonicalJson(f.historic)).toBe(oldBytes);
 });
 it('actual apply and execution keep the preview sealed schema bundle and exact before-snapshot identity for a missing-plugin restore',async()=>{
  // Real façade and execution methods; storage, authorization and native wire
  // are explicit synthetic seams. No HTTP, database or real gateway is used.
  const f=pair();f.current.objects=f.current.objects.filter(o=>o.nativeId!==id(4));bind(f.current,'fresh-baseline-with-restoration-schema');const schemasBytes=canonicalJson(f.current.schemas),beforeId=id(600),handle=Object.freeze({}),actor={user:{id:id(601),username:'schema-lifecycle',superAdmin:false},workspaceId:f.current.scope.workspaceId,idempotencyKey:'fresh-rollback-apply'};
  const diff=rollback(f.current,f.historic),compiled=compileTransferDag(diff,{stepIds:Object.fromEntries(diff.changes.map((c,i)=>[c.objectKey,id(700+i)])),sourceManifestHmac:'old-original-manifest',baselineManifestHmac:'fresh-current-manifest',expiresAt:new Date(Date.now()+300000).toISOString(),fingerprint:canonicalJson,redact:()=>null});
  const secrets=new SecretService(),planId=id(602),copyId=id(603),jobId=id(604),binding={baselineSnapshotId:beforeId,baselineVersion:1},job:any={id:jobId,plan_id:copyId,plan_revision:1,plan_hash:secrets.fingerprint(compiled),safe_progress:{},revision:1};
  const summary={mode:'rollback',name:'配置计划',deleteCount:1,planHash:job.plan_hash,planRevision:1,executionMode:'direct'},steps=compiled.steps.map((s,i)=>({id:id(800+i),planStepId:s.stepId,state:'pending',revision:1}));
  const db:any={one:vi.fn(async(sql:string,p:any[])=>{if(sql.startsWith('SELECT j.* FROM configuration_plans'))return{scope_kind:'workspace',root_ids:[],safe_progress:binding};if(sql.startsWith('SELECT j.safe_progress FROM configuration_jobs'))return{safe_progress:binding};if(sql.startsWith('SELECT execution_mode FROM clusters'))return{execution_mode:'direct'};if(sql.startsWith('SELECT * FROM configuration_jobs'))return job;if(sql.startsWith('SELECT * FROM configuration_job_steps'))return steps.find(s=>s.id===p[0]);if(sql.startsWith('SELECT revision FROM configuration_job_steps'))return{revision:2};throw Error('Unrecognized schema lifecycle SQL');}),exec:vi.fn(async()=>1)};
  const repo:any={readPlan:vi.fn(async()=>compiled),freezePlan:vi.fn(async(_h:any,input:any)=>{expect(input.plan).toBe(compiled);return{planId:copyId,planRevision:1,planHash:job.plan_hash};}),initializeExecutionProgress:vi.fn(async(_h:any,input:any)=>{job.safe_progress=input.safeProgress;}),claimJob:vi.fn(),createExecution:vi.fn(async()=>({executionId:id(605)})),initializeSteps:vi.fn(async()=>steps),recordStepEvidence:vi.fn(),readSnapshot:vi.fn(async(_h:any,input:any)=>{expect(input.snapshotId).toBe(beforeId);expect(input.version).toBe(1);return f.current;})};
  const capture={capture:vi.fn()},captureBaseline=vi.fn(),access:any={isWorkflowScheduledConfigurationJob:vi.fn(()=>false),acquire:async()=>handle,description:async()=>({scope:f.current.scope,actor:actor.user}),assertCurrent:vi.fn(),runJob:async(_h:any,fn:any)=>fn(),runStep:async(_h:any,_step:any,_id:any,fn:any)=>fn()};
  const native:any={execute:vi.fn(async(_h:any,step:any)=>({receipt:{operationId:id(900)},after:step.mutationAction==='delete'?null:{...step.body,id:step.nativeId},result:step.mutationAction==='delete'?{entryId:id(901)}:{},effectiveNativeId:step.nativeId}))};
  const service=Object.assign(Object.create(ConfigurationService.prototype),{db,secrets,repo,capture,captureBaseline,access,native,logger:{warn:vi.fn()},claims:new AsyncLocalStorage(),authz:{snapshot:async()=>({user:{superAdmin:true},grants:[]})},redis:{withLock:async(_k:any,fn:any)=>fn(),assertLeaseOwnership:vi.fn()},failureLedger:{arm:async()=>Object.freeze({}),release:vi.fn()},
   withActor:async(_cid:any,_a:any,_op:any,fn:any)=>fn(),plan:async()=>({entity:summary}),newJob:async()=>({existing:false,handle,scope:f.current.scope,job}),finish:async()=>({state:'succeeded'}),jobProjection:async(_h:any,value:any)=>value});
  await expect(service.apply(f.current.scope.clusterId,planId,{confirmed:true,confirm_name:summary.name,confirm_deletes:true,planHash:summary.planHash,planRevision:1},actor)).resolves.toMatchObject({state:'succeeded'});
  expect(access.isWorkflowScheduledConfigurationJob).toHaveBeenCalledWith(handle);expect((service as any).logger.warn).not.toHaveBeenCalled();
  expect(repo.createExecution.mock.calls[0][1]).toMatchObject({beforeSnapshotId:beforeId,beforeSnapshotVersion:1,planId:copyId});expect(job.safe_progress).toMatchObject(binding);expect(compiled.schemaHmac).toBe(f.current.schemaHmac);expect(repo.readSnapshot).toHaveBeenCalled();
  expect(native.execute.mock.calls.some(([,step]:any)=>step.mutationAction==='create'&&step.body.name==='correlation-id')).toBe(true);expect(capture.capture).not.toHaveBeenCalled();expect(captureBaseline).not.toHaveBeenCalled();expect(canonicalJson(f.current.schemas)).toBe(schemasBytes);
 });
});
