import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException,ServiceUnavailableException} from '@nestjs/common';
import {MutationService} from '../../apps/console-api/src/modules/mutations/mutation.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {readTargetHealthObservation} from '../../apps/console-api/src/infrastructure/kong/target-health-observation';
import {workspaceFixture} from './workspace-test-fixture';
import {executionFixture} from './execution-test-fixture';

/** Actual Mutation/Secret/health-reader with declared domain SQL/grant/read
 * adapters. The callback supplies protocol data, not a real transport204,
 * approval or Root-issued packet. Runtime acceptance remains separate. */
function fixture(){
  const cid=randomUUID(),upstream=randomUUID(),targetId=randomUUID(),secrets=new SecretService(),workspace=workspaceFixture(cid),records=new Map<string,any>(),
    before={id:targetId,target:'echo.internal:8080',weight:80,tags:['owner:unit'],upstream:{id:upstream},created_at:1};
  const state={posted:false,healthBefore:'HEALTHY',healthAfter:'UNHEALTHY',nodeBefore:'unit-node',nodeAfter:'unit-node',denyAfter:false,nativeError:false,synthetic:false,received:false};
  const db:any={one:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM clusters')?{id:cid,version:'1.5.1',execution_mode:'direct'}:sql.includes('FROM mutation_operations')?records.get(p[1])??[...records.values()].find(row=>row.id===p[0]):null),
    query:vi.fn(async()=>[...records.values()].filter(row=>['running','uncertain'].includes(row.state))),exec:vi.fn(async(sql:string,p:any[])=>{
      if(sql.startsWith('INSERT INTO mutation_operations')){records.set(p[4],{id:p[0],cluster_id:p[1],actor_id:p[2],action:p[3],idempotency_key:p[4],request_hash:p[5],entity_type:p[8],entity_id:p[9],before_secret:p[10],payload_secret:p[11],workspace_id:p[12],transport_scope:p[13],impact:JSON.parse(p[14]),state:'running'});return 1;}
      const row=[...records.values()].find(row=>row.id===p[0]);if(!row)throw Error('Unexpected domain mutation SQL');
      if(sql.includes('remote_started=true'))row.remote_started=true;else if(sql.includes('remote_completed=true'))Object.assign(row,{remote_completed:true,entity_id:p[1],result_secret:p[2]});
      else if(sql.includes('SET result_secret=$2'))row.result_secret=p[1];
      else if(sql.includes("state='succeeded'"))Object.assign(row,{state:'succeeded',safe_result:JSON.parse(p[1])});
      else if(sql.includes('SET state=$2'))Object.assign(row,{state:p[1],error_code:p[2],safe_result:JSON.parse(p[3])});return 1;
    }),transaction:vi.fn(async(fn:any)=>fn(db))};
  const kong:any={transportScope:vi.fn(async()=>cid),consumeTargetHealthTransportReceipt:vi.fn((frame:any)=>state.received?{version:1,kind:'original-target-health-transport-response',clusterId:cid,operationId:frame.operation.operationId,upstreamId:upstream,targetId,
      action:'mark_unhealthy',nativeStatus:204,rawResponse:null,responseHmac:secrets.fingerprint(null),responseBytes:0,emptyBody:true,contractValid:true}:undefined),
    request:vi.fn(async(_cid:string,_method:string,path:string)=>path==='/'?{version:'1.5.1',node_id:state.posted?state.nodeAfter:state.nodeBefore}:path===`/upstreams/${upstream}`?{id:upstream,name:'source-upstream',tags:[]}:structuredClone(before)),
    list:vi.fn(async(_cid:string,path:string,q:any)=>({items:path.endsWith('/health')?[{...structuredClone(before),health:state.posted?state.healthAfter:state.healthBefore}]:[structuredClone(before)],size:q.size,nextCursor:null}))};
  const authz:any={assertCluster:vi.fn(async()=>{if(state.posted&&state.denyAfter)throw new ForbiddenException({code:'CURRENT_GRANT_REVOKED'});}),assertEntity:vi.fn(async()=>undefined),isPlatformAdmin:vi.fn(async()=>true)},
    audit:any={append:vi.fn(async()=>undefined)},redis:any={withLock:vi.fn(async(_key:string,fn:any)=>fn())},execution=executionFixture(),
    service=new MutationService(db,redis,secrets,audit,kong,authz,workspace.resolver,execution),
    context:any={clusterId:cid,actor:{id:randomUUID(),username:'unit',superAdmin:true},entityType:'targets',entityId:targetId,parentId:upstream,action:'mark_unhealthy',before,payload:{state:'unhealthy'},idempotencyKey:'target-health-original-key'},
    callback=vi.fn(async()=>{state.posted=true;if(state.nativeError)throw new ServiceUnavailableException({code:'KONG_WRITE_RESULT_UNKNOWN'});state.received=true;return state.synthetic?{entity:{...before,health_override:'unhealthy'}}:null;});
  return{service,secrets,records,kong,audit,authz,context,before,state,callback,execute:()=>service.execute({...context},callback),
    baseline:()=>readTargetHealthObservation(kong,secrets,{clusterId:cid,upstreamId:upstream,target:before})};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ac'.repeat(32));vi.stubEnv('APP_SECRET','target-health-mutation-source-fixture-'.repeat(2));});afterEach(()=>vi.unstubAllEnvs());
describe('Target health stores null acknowledgement and actual observations separately',()=>{
  it('keeps original result ciphertext null and records independent before/after node-health facts',async()=>{
    const f=fixture();expect(await f.execute()).toBeNull();const row=f.records.get(f.context.idempotencyKey);
    expect(row).toMatchObject({state:'succeeded',remote_started:true,remote_completed:true,entity_id:f.before.id});expect(f.secrets.decrypt(row.result_secret,`mutation:${row.id}:result`)).toBeNull();
    expect(row.safe_result).toMatchObject({kind:'target-health-acknowledgement',nativeResult:null,requestedState:'unhealthy',overrideRecovery:'unavailable',healthBefore:{health:'HEALTHY'},healthAfter:{health:'UNHEALTHY'}});
    expect(row.safe_result.entity).toBeUndefined();expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'mark_unhealthy',result:'success',after:expect.objectContaining({nativeResult:null,healthObservation:expect.objectContaining({health:'UNHEALTHY'}),overrideRecovery:'unavailable'})}),expect.any(Object));
    expect(f.callback).toHaveBeenCalledOnce();
  });
  it('does not claim requested state equals subsequent health when a probe reports another state',async()=>{
    const f=fixture();f.state.healthAfter='HEALTHY';expect(await f.execute()).toBeNull();const row=f.records.get(f.context.idempotencyKey);
    expect(row.safe_result.requestedState).toBe('unhealthy');expect(row.safe_result.healthAfter.health).toBe('HEALTHY');
  });
  it('blocks checks-off before allocating a mutation or invoking a native callback',async()=>{
    const f=fixture();f.state.healthBefore='HEALTHCHECKS_OFF';await expect(f.execute()).rejects.toMatchObject({response:{code:'TARGET_HEALTH_CHECKS_DISABLED'}});
    expect(f.callback).not.toHaveBeenCalled();expect(f.records.size).toBe(0);
  });
  it('fails closed before any callback or mutation when the fixed original transport bridge is missing',async()=>{
    const f=fixture();delete f.kong.consumeTargetHealthTransportReceipt;
    await expect(f.execute()).rejects.toMatchObject({response:{code:'TARGET_HEALTH_TRANSPORT_BRIDGE_UNAVAILABLE'}});expect(f.callback).not.toHaveBeenCalled();expect(f.records.size).toBe(0);
  });
  it('binds original sealed health baseline and rejects changed state without sending',async()=>{
    const f=fixture();f.context.targetHealthBefore=await f.baseline();f.state.healthBefore='UNHEALTHY';
    await expect(f.execute()).rejects.toMatchObject({response:{code:'TARGET_HEALTH_BASELINE_CHANGED'}});expect(f.callback).not.toHaveBeenCalled();expect(f.records.size).toBe(0);
  });
  it.each(['grant-revoked','node-changed','checks-off','native-unknown','synthetic-entity'])('keeps %s uncertain and never repeats the original key',async defect=>{
    const f=fixture();if(defect==='grant-revoked')f.state.denyAfter=true;if(defect==='node-changed')f.state.nodeAfter='different-node';
    if(defect==='checks-off')f.state.healthAfter='HEALTHCHECKS_OFF';if(defect==='native-unknown')f.state.nativeError=true;if(defect==='synthetic-entity')f.state.synthetic=true;
    await expect(f.execute()).rejects.toBeDefined();const row=f.records.get(f.context.idempotencyKey);expect(row.state).toBe('uncertain');expect(row.remote_started).toBe(true);
    if(!['native-unknown','synthetic-entity'].includes(defect)){expect(row.remote_completed).toBe(true);expect(f.secrets.decrypt(row.result_secret,`mutation:${row.id}:result`)).toBeNull();}
    const original=structuredClone(row);await expect(f.execute()).rejects.toBeDefined();expect(f.callback).toHaveBeenCalledOnce();expect(row).toEqual(original);
  });
});
