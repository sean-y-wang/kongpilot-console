import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { workspaceFixture } from './workspace-test-fixture';
import { executionFixture } from './execution-test-fixture';

/** Real Mutation service/crypto/readback helper, isolated domain SQL/current
 * scope/callback adapters. No real Root permit, HTTP, SQL or Native201 receipt. */
function fixture(wrapped=false){
  const cid=randomUUID(),upstream=randomUUID(),oldId=randomUUID(),nativeId=randomUUID(),secrets=new SecretService(),workspace=workspaceFixture(cid),records=new Map<string,any>();
  const before={id:oldId,target:'echo:8080',weight:80,upstream:{id:upstream},tags:['owner:unit'],created_at:1791927030.456},
    payload={id:nativeId,target:before.target,weight:0,tags:['owner:unit']},raw={...payload,upstream:{id:upstream},created_at:1791927041.513};
  let posted=false,denyReads=false,activeAfter=false,pruned=false;
  const db:any={one:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM clusters')?{id:cid,version:'1.5.1',execution_mode:'direct'}:sql.includes('FROM mutation_operations')?records.get(p[1])??[...records.values()].find(r=>r.id===p[0]):null),
    query:vi.fn(async()=>[...records.values()].filter(r=>r.state==='running'||r.state==='uncertain')),exec:vi.fn(async(sql:string,p:any[])=>{
      if(sql.startsWith('INSERT INTO mutation_operations')){records.set(p[4],{id:p[0],cluster_id:p[1],actor_id:p[2],action:p[3],idempotency_key:p[4],request_hash:p[5],workflow_id:p[6],entity_type:p[8],entity_id:p[9],before_secret:p[10],payload_secret:p[11],workspace_id:p[12],transport_scope:p[13],impact:JSON.parse(p[14]),state:'running'});return 1;}
      const row=[...records.values()].find(r=>r.id===p[0]);if(!row)throw Error('Unexpected controlled mutation');
      if(sql.includes('remote_started=true'))row.remote_started=true;
      else if(sql.includes('remote_completed=true'))Object.assign(row,{remote_completed:true,entity_id:p[1],result_secret:p[2]});
      else if(sql.includes("state='succeeded'"))Object.assign(row,{state:'succeeded',safe_result:JSON.parse(p[1])});
      else if(sql.includes('SET state=$2'))Object.assign(row,{state:p[1],error_code:p[2],safe_result:JSON.parse(p[3])});
      return 1;
    }),transaction:vi.fn(async(fn:any)=>fn(db))};
  const kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn(async()=>{throw new BadRequestException({code:'KONG_VALIDATION_ERROR',message:'Inactive Target cannot be retrieved through effective UUID endpoint'});}),
    list:vi.fn(async(_c:string,path:string,q:any)=>{if(posted&&denyReads)throw new ForbiddenException({code:'CURRENT_SCOPE_REVOKED'});
      return{items:posted&&pruned?[]:path.endsWith('/all')?[before,raw]:posted&&!activeAfter?[]:[before],size:q.size,nextCursor:null};})};
  const execution=executionFixture(),runRead=execution.runInternalRead;execution.runInternalRead=vi.fn(runRead);
  const audit:any={append:vi.fn(async()=>undefined)},authz:any={assertCluster:vi.fn(async()=>undefined),assertEntity:vi.fn(async()=>undefined),isPlatformAdmin:vi.fn(async()=>true)},redis:any={withLock:vi.fn(async(_key:string,fn:any)=>fn())};
  const service=new MutationService(db,redis,secrets,audit,kong,authz,workspace.resolver,execution),context:any={clusterId:cid,actor:{id:randomUUID(),username:'unit',superAdmin:true},entityType:'targets',entityId:oldId,parentId:upstream,action:'update',before,payload,idempotencyKey:'original-disabled-target-key'};
  const callback=vi.fn(async()=>{posted=true;return wrapped?{entity:raw,propagation:'pending'}:raw;}),execute=()=>service.execute({...context},callback);
  return{service,records,secrets,db,audit,kong,execution,context,payload,raw,upstream,callback,execute,deny:()=>{denyReads=true;},drift:()=>{activeAfter=true;},prune:()=>{pruned=true;}};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ae'.repeat(32));vi.stubEnv('APP_SECRET','target-zero-mutation-source-unit-'.repeat(2));});
afterEach(()=>vi.unstubAllEnvs());
describe('future zero-weight mutation retains its original result and key',()=>{
  it('completes post-callback readback using only private bounded history/effective paths and preserves raw encrypted result',async()=>{
    const f=fixture();expect(await f.execute()).toEqual(f.raw);const row=f.records.get(f.context.idempotencyKey);
    expect(row).toMatchObject({state:'succeeded',remote_started:true,remote_completed:true,entity_id:f.raw.id});expect(f.secrets.decrypt(row.result_secret,`mutation:${row.id}:result`)).toEqual(f.raw);
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.callback).toHaveBeenCalledOnce();
    expect(f.execution.runInternalRead).toHaveBeenCalledWith(f.context.clusterId,'operation-check',expect.any(Function),expect.objectContaining({paths:[`/upstreams/${f.upstream}/targets/all`,`/upstreams/${f.upstream}/targets`],maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000}));
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'update',result:'success',after:f.raw}),expect.any(Object));
  });
  it.each(['denied','drift'])('keeps the observed result uncertain after %s, and refuses original-key replay without another callback',async reason=>{
    const f=fixture();if(reason==='denied')f.deny();else f.drift();
    await expect(f.execute()).rejects.toMatchObject({response:{code:'MUTATION_RESULT_UNCERTAIN'}});const row=f.records.get(f.context.idempotencyKey);
    expect(row).toMatchObject({state:'uncertain',remote_started:true,remote_completed:true});expect(f.secrets.decrypt(row.result_secret,`mutation:${row.id}:result`)).toEqual(f.raw);
    const original=structuredClone(row);await expect(f.execute()).rejects.toMatchObject({response:{code:'MUTATION_RESULT_UNCERTAIN'}});expect(f.callback).toHaveBeenCalledOnce();expect(row).toEqual(original);
  });
  it.each([false,true])('uses the real native Target inside a configuration callback envelope (pruned=%s)',async pruned=>{
    const f=fixture(true);if(pruned)f.prune();const result=await f.execute(),row=f.records.get(f.context.idempotencyKey);
    expect(result).toEqual({entity:f.raw,propagation:'pending'});
    expect(row).toMatchObject({state:'succeeded',remote_started:true,remote_completed:true,entity_id:f.raw.id});
    expect(f.secrets.decrypt(row.result_secret,`mutation:${row.id}:result`)).toEqual(result);
    expect(row.safe_result._kongpilotReadback).toMatchObject({historyRetention:pruned?'native-pruned':'retained',
      nativeHistoryRecordObserved:!pruned,originalResponseHmac:f.secrets.fingerprint(f.raw)});
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'update',result:'success',after:pruned?null:f.raw}),expect.any(Object));
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.callback).toHaveBeenCalledOnce();
  });
  it('keeps the real POST cipher after native clean_history pruning while auditing actual current absence',async()=>{
    const f=fixture();f.prune();expect(await f.execute()).toEqual(f.raw);const row=f.records.get(f.context.idempotencyKey);
    expect(row).toMatchObject({state:'succeeded',remote_started:true,remote_completed:true});
    expect(f.secrets.decrypt(row.result_secret,`mutation:${row.id}:result`)).toEqual(f.raw);
    expect(row.safe_result._kongpilotReadback).toMatchObject({historyRetention:'native-pruned',currentEffectiveAbsent:true,nativeHistoryRecordObserved:false});
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'update',result:'success',after:null}),expect.any(Object));
    expect(f.callback).toHaveBeenCalledOnce();expect(f.kong.request).not.toHaveBeenCalled();
  });
});
