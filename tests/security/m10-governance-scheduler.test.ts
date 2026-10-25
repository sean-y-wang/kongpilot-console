import 'reflect-metadata';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {ForbiddenException,ConflictException} from '@nestjs/common';
import {GovernanceSchedulerService} from '../../apps/console-api/src/modules/governance/governance-scheduler.service';
import {GovernanceService} from '../../apps/console-api/src/modules/governance/governance.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {GOVERNANCE_ENTITY_TYPES} from '../../apps/console-api/src/modules/governance/governance-inventory.types';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {GovernanceRepositoryService} from '../../apps/console-api/src/modules/governance/governance-repository.service';

const cid='bba06df1-aa34-4575-8ef0-251a253fe29f',wid='124d5643-2e4c-4fa1-8630-11c8694e764f',uid='81e7fafe-609d-46cb-a8ea-edb09ad5ea9d',scheduleId='dbb38d41-47c9-4f9e-bec3-a02ae68d2f22',occurrenceId='b9f09e50-3c56-48be-8f8a-578c47c79d16',runId='752c2816-8758-4ef7-b6d1-8e297c19c2c9';
const locator={scheduleId,clusterId:cid,workspaceId:wid,ownerUserId:uid,version:2,revision:4,scheduledAt:'2026-10-13T02:00:00.000Z',runId:occurrenceId,leaseGeneration:1};

describe('M10 independent timer scheduler orchestration without fake sessions',()=>{
 let scheduler:GovernanceSchedulerService,db:any,redis:any,repo:any,service:any,audit:any,occurrence:any;
 beforeEach(()=>{
  occurrence={id:occurrenceId,schedule_id:scheduleId,cluster_id:cid,workspace_id:wid,creator_id:uid,lease_generation:1,state:'running'};
  db={transaction:vi.fn(async(fn:any)=>fn(db)),one:vi.fn(async(sql:string)=>sql.includes('SELECT state')?{state:occurrence.state}:null)};
  redis={withLock:vi.fn(async(_key:string,fn:any)=>fn())};audit={append:vi.fn(async()=>({}))};
  repo={expiredScheduleRuns:vi.fn(async()=>[]),markExpiredScheduleRun:vi.fn(async()=>true),dueSchedules:vi.fn(async()=>[{id:scheduleId}]),claimSchedule:vi.fn(async()=>({locator,payload:{kind:'inspection'}})),finishSchedule:vi.fn(async(_locator:any,state:string)=>{occurrence.state=state;})};
  service={runScheduled:vi.fn(async()=>({runId,state:'succeeded'}))};scheduler=new GovernanceSchedulerService(db,redis,repo,service,audit);
 });
 it('uses exact claimed owner/version/lease locator and commits finish with audit',async()=>{await scheduler.tick();expect(service.runScheduled).toHaveBeenCalledWith(locator,{kind:'inspection'});expect(repo.finishSchedule).toHaveBeenCalledWith(locator,'succeeded',runId,undefined,db);expect(audit.append.mock.calls.map((call:any)=>call[0].action)).toEqual(['governance.schedule.claim','governance.schedule.finish']);expect(db.transaction).toHaveBeenCalledTimes(2);});
 it('does not invent a successful complete state for incomplete analytical evidence',async()=>{service.runScheduled.mockResolvedValue({runId,state:'incomplete'});await scheduler.tick();expect(repo.finishSchedule).toHaveBeenCalledWith(locator,'incomplete',runId,undefined,db);});
 it('permission loss pauses original policy authority, with no retry or actor substitution',async()=>{service.runScheduled.mockRejectedValue(new ForbiddenException({code:'GOVERNANCE_PERMISSIONS_CHANGED'}));await scheduler.tick();expect(service.runScheduled).toHaveBeenCalledOnce();expect(repo.finishSchedule.mock.calls[0][1]).toBe('paused_authority');expect(repo.finishSchedule.mock.calls[0][0]).toEqual(locator);});
 it('an unknown persistence exception retains uncertain occurrence and never immediately reclaims it',async()=>{service.runScheduled.mockRejectedValue(new Error('synthetic SQL response lost'));await scheduler.tick();expect(repo.finishSchedule.mock.calls[0][1]).toBe('uncertain');expect(service.runScheduled).toHaveBeenCalledOnce();expect(repo.claimSchedule).toHaveBeenCalledOnce();});
 it('expired lease is audited as uncertain before any new due claim, never reruns expired diagnostic',async()=>{repo.expiredScheduleRuns.mockResolvedValue([occurrence]);repo.dueSchedules.mockResolvedValue([]);await scheduler.tick();expect(repo.markExpiredScheduleRun).toHaveBeenCalledWith(occurrence,db);expect(service.runScheduled).not.toHaveBeenCalled();expect(audit.append.mock.calls[0][0]).toMatchObject({action:'governance.schedule.lease_expired',result:'uncertain',entityId:occurrenceId});});
 it('a failed stale-lease CAS cannot emit a false expiry audit',async()=>{repo.expiredScheduleRuns.mockResolvedValue([occurrence]);repo.markExpiredScheduleRun.mockResolvedValue(false);repo.dueSchedules.mockResolvedValue([]);await scheduler.tick();expect(audit.append).not.toHaveBeenCalled();});
 it('a lost schedule CAS does not create a run, finish or successful audit',async()=>{repo.claimSchedule.mockResolvedValue(null);await scheduler.tick();expect(service.runScheduled).not.toHaveBeenCalled();expect(repo.finishSchedule).not.toHaveBeenCalled();expect(audit.append).not.toHaveBeenCalled();});
 it('concurrent ticks are non-reentrant while original claim is active',async()=>{let finish:()=>void=()=>{};service.runScheduled.mockImplementation(()=>new Promise(resolve=>{finish=()=>resolve({runId,state:'succeeded'});}));const first=scheduler.tick();await vi.waitFor(()=>expect(service.runScheduled).toHaveBeenCalledOnce());await scheduler.tick();expect(repo.claimSchedule).toHaveBeenCalledOnce();finish();await first;});
 it('already terminal occurrence is not rewritten when response bookkeeping throws',async()=>{service.runScheduled.mockImplementation(async()=>{occurrence.state='succeeded';throw new Error('synthetic post-terminal response lost');});await scheduler.tick();expect(repo.finishSchedule).not.toHaveBeenCalled();});
});

// Real GovernanceService and pure Lint/drift engines; explicit synthetic
// repository/readonly authority providers isolate lifecycle ordering. Live
// grant/WeakMap/DNS/120s fences execute in the independent authority suites.
describe('M10 scheduled analysis persists only after current readonly authority',()=>{
 let service:GovernanceService,db:any,repo:any,authority:any,inventory:any,audit:any,source:any,target:any,sourceHandle:object,targetHandle:object,terminal:string,secrets:SecretService,storage:GovernanceRepositoryService;
 let receipts:WeakMap<object,{handle:object;publicHmac:string;fingerprints:Readonly<Record<string,string>>}>,nativeRows:Map<object,any[]>;
 beforeEach(()=>{
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY','72'.repeat(32));secrets=new SecretService();sourceHandle=Object.freeze({scope:'source'});targetHandle=Object.freeze({scope:'target'});terminal='running';receipts=new WeakMap();nativeRows=new Map();
  const now=new Date().toISOString(),scope={clusterId:cid,workspaceId:wid,kind:'workspace',rootIds:[],transportScope:'a'.repeat(64)};
  source={id:runId,scope,version:'1.5.1',objects:[],schemas:Object.fromEntries(GOVERNANCE_ENTITY_TYPES.map(type=>[type,{fields:[]}])) ,pluginSchemas:{},enabledPlugins:[],coverage:Object.fromEntries(GOVERNANCE_ENTITY_TYPES.map(type=>[type,{state:'complete',extent:'workspace',eof:true,pages:1,records:0,reasonCodes:[]}])) ,completeness:'complete',projection:false,consistency:'console_fenced_best_effort',observedFrom:now,observedUntil:now,usage:{calls:10,pages:8,records:0,bytes:500},reasonCodes:[]};
  target={...source,scope:{...scope,clusterId:'d5b8c6b6-e675-4244-be51-7027fef7ad43',workspaceId:'709afc98-e580-407c-aa7a-640897b302e1',transportScope:'b'.repeat(64)}};
  db={transaction:vi.fn(async(fn:any)=>fn(db)),one:vi.fn(async()=>null),exec:vi.fn(async()=>1)};audit={append:vi.fn(async()=>({}))};
  authority={acquireDueSchedule:vi.fn(async(l:any)=>l.side==='target'?targetHandle:sourceHandle),description:vi.fn(async()=>({actor:{user:{id:uid,username:'synthetic-owner',superAdmin:false},workspaceId:wid,requestId:`governance-schedule-${occurrenceId}`}})),assertCurrent:vi.fn(async()=>{})};
  inventory={capture:vi.fn(async(handle:object)=>{if(handle!==sourceHandle&&handle!==targetHandle)throw new ForbiddenException({code:'GOVERNANCE_AUTHORITY_REQUIRED'});const value=handle===sourceHandle?source:target,rows=nativeRows.get(handle)??[];
   // This synthetic wire boundary records evidence only when the exact
   // original side is captured. A generic caller-provided inventory cannot
   // manufacture the private receipt or borrow its peer's native map.
   const fingerprints=Object.freeze(Object.fromEntries(rows.map(row=>[`${row.entityType}:${row.payload.id}`,secrets.fingerprint(row.payload)])));
   receipts.set(value,{handle,publicHmac:secrets.fingerprint(value),fingerprints});return value;
  }),privateFingerprints:vi.fn(async(handle:object,value:object)=>{await authority.assertCurrent(handle);const receipt=receipts.get(value);
   if(!receipt||receipt.handle!==handle||receipt.publicHmac!==secrets.fingerprint(value))throw new ForbiddenException({code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'});
   return Object.freeze({...receipt.fingerprints});
  })};
  storage=new GovernanceRepositoryService(db,secrets);
  repo={beginRun:vi.fn(async()=>({existing:false,row:{id:runId,cluster_id:cid,workspace_id:wid,actor_id:uid,kind:'inspection'}})),ruleContents:vi.fn(async()=>[]),saveReport:vi.fn(async()=>{}),saveComparison:vi.fn(async(input:any,tx:any)=>storage.saveComparison(input,tx)),finishRun:vi.fn(async(_id:string,state:string)=>{terminal=state;}),run:vi.fn(async()=>({id:runId,state:terminal}))};
  service=new GovernanceService(db,{} as any,secrets,new KongExecutionContextService(),{} as any,{} as any,authority,inventory,repo,{} as any,{} as any,audit);
 });
 afterEach(()=>vi.unstubAllEnvs());
 it('missing current owner grants stops before run registration or inventory',async()=>{authority.acquireDueSchedule.mockRejectedValue(new ForbiddenException({code:'PERMISSION_DENIED'}));await expect(service.runScheduled(locator,{kind:'inspection'})).rejects.toBeInstanceOf(ForbiddenException);expect(repo.beginRun).not.toHaveBeenCalled();expect(inventory.capture).not.toHaveBeenCalled();});
 it('existing original analytical run is never recomputed under the same occurrence',async()=>{repo.beginRun.mockResolvedValue({existing:true,row:{id:runId}});await expect(service.runScheduled(locator,{kind:'inspection'})).rejects.toMatchObject({response:{code:'GOVERNANCE_SCHEDULE_ORIGINAL_RUN_EXISTS'}});expect(inventory.capture).not.toHaveBeenCalled();expect(repo.saveReport).not.toHaveBeenCalled();});
 it('inspection uses claimed occurrence as permanent source and no browser SID',async()=>{const result=await service.runScheduled(locator,{kind:'inspection'});expect(result.runId).toBe(runId);expect(repo.beginRun.mock.calls[0][0]).toMatchObject({origin:'schedule',actorId:uid,scheduleRunId:occurrenceId,key:`governance-schedule-${occurrenceId}`});expect(repo.beginRun.mock.calls[0][0].sessionId).toBeUndefined();expect(repo.saveReport).toHaveBeenCalledOnce();expect(authority.assertCurrent).toHaveBeenCalledWith(sourceHandle);});
 it('drift obtains separate actual target locator and rechecks both before seal',async()=>{await service.runScheduled(locator,{kind:'drift',threshold:0});expect(authority.acquireDueSchedule.mock.calls).toEqual([[locator],[{...locator,side:'target'}]]);expect(inventory.capture.mock.calls).toEqual([[sourceHandle],[targetHandle]]);expect(inventory.privateFingerprints.mock.calls).toEqual([[sourceHandle,source],[targetHandle,target]]);expect(authority.assertCurrent.mock.calls).toEqual([[sourceHandle],[targetHandle],[sourceHandle],[targetHandle]]);expect(repo.saveComparison).toHaveBeenCalledOnce();});
 it('target owner revocation cannot produce a drift comparison or threshold event',async()=>{authority.acquireDueSchedule.mockImplementation(async(l:any)=>{if(l.side==='target')throw new ForbiddenException({code:'GOVERNANCE_OWNER_INACTIVE'});return sourceHandle;});await expect(service.runScheduled(locator,{kind:'drift',threshold:0})).rejects.toBeInstanceOf(ForbiddenException);expect(repo.saveComparison).not.toHaveBeenCalled();expect(db.exec).not.toHaveBeenCalled();expect(audit.append.mock.calls.some((call:any)=>call[0].action==='governance.drift.threshold_crossed')).toBe(false);});
 it('120s authority expiry following capture prevents report sealing and records failed original',async()=>{authority.assertCurrent.mockRejectedValue(new ForbiddenException({code:'GOVERNANCE_AUTHORITY_EXPIRED'}));await expect(service.runScheduled(locator,{kind:'inspection'})).rejects.toBeInstanceOf(ForbiddenException);expect(repo.saveReport).not.toHaveBeenCalled();expect(repo.finishRun.mock.calls.at(-1)[1]).toBe('failed');});
 it('a changed permission epoch on either drift side prevents immutable comparison',async()=>{authority.assertCurrent.mockImplementation(async(handle:any)=>{if(handle===targetHandle)throw new ConflictException({code:'GOVERNANCE_PERMISSIONS_CHANGED'});});await expect(service.runScheduled(locator,{kind:'drift',threshold:0})).rejects.toBeInstanceOf(ConflictException);expect(repo.saveComparison).not.toHaveBeenCalled();expect(db.exec).not.toHaveBeenCalled();});
 const roots=()=>{const sourceId='06ce0d11-6ee2-4487-bc91-5f522f78f7f2',targetId='714fb290-d659-4c68-8093-b0ea727526a3';
  source.schemas.services={fields:[{name:{type:'string'}},{host:{type:'string'}},{tags:{type:'set',elements:{type:'string'}}}]};
  const add=(value:any,handle:object,id:string,host:string)=>{const payload={id,name:'owned-service',host,tags:[]};value.objects=[{entityType:'services',nativeId:id,objectWorkspaceId:value.scope.workspaceId,payload:structuredClone(payload),sensitiveFields:[]}];nativeRows.set(handle,[{entityType:'services',payload}]);};
  add(source,sourceHandle,sourceId,'source-fixture.invalid');add(target,targetHandle,targetId,'target-fixture.invalid');return{sourceId,targetId};
 };
 it('seals the exact two captured private maps inside actual encrypted V2 repository envelopes',async()=>{const ids=roots();await service.runScheduled(locator,{kind:'drift',threshold:0});
  const input=repo.saveComparison.mock.calls[0][0],bindings=db.exec.mock.calls.find(([sql]:any)=>sql.startsWith('INSERT INTO governance_comparisons'))[1];
  const expectedSource={[`services:${ids.sourceId}`]:secrets.fingerprint(nativeRows.get(sourceHandle)![0].payload)},expectedTarget={[`services:${ids.targetId}`]:secrets.fingerprint(nativeRows.get(targetHandle)![0].payload)};
  expect(input.source).toBe(source);expect(input.target).toBe(target);expect(input.sourceNativeFingerprints).toEqual(expectedSource);expect(input.targetNativeFingerprints).toEqual(expectedTarget);
  const sourceEnvelope=secrets.decrypt<any>(bindings[6],`governance:comparison-source:${input.id}`),targetEnvelope=secrets.decrypt<any>(bindings[7],`governance:comparison-target:${input.id}`);
  expect(sourceEnvelope).toEqual({version:2,inventory:source,nativeFingerprints:expectedSource});expect(targetEnvelope).toEqual({version:2,inventory:target,nativeFingerprints:expectedTarget});
  expect(bindings[8]).toBe(secrets.fingerprint(sourceEnvelope));expect(bindings[9]).toBe(secrets.fingerprint(targetEnvelope));expect(sourceEnvelope.nativeFingerprints).not.toHaveProperty(`services:${ids.targetId}`);
  const row={id:input.id,policy:input.policy,policy_hmac:bindings[11],source_inventory_secret:bindings[6],target_inventory_secret:bindings[7],source_inventory_hmac:bindings[8],target_inventory_hmac:bindings[9]},publicHistory=storage.comparisonInventories(row);
  expect(publicHistory).toEqual({source,target});expect(publicHistory.source).not.toHaveProperty('nativeFingerprints');expect(JSON.stringify(publicHistory)).not.toContain(expectedSource[`services:${ids.sourceId}`]);
  expect(()=>storage.comparisonInventories({...row,source_inventory_secret:bindings[7],target_inventory_secret:bindings[6]})).toThrow(ConflictException);
 });
 it.each(['copied-inventory','copied-handle','peer-inventory']as const)('cannot request a private raw map with %s',async change=>{roots();const captured=await inventory.capture(sourceHandle);await inventory.capture(targetHandle);
  const handle=change==='copied-handle'?{...sourceHandle}:sourceHandle,value=change==='copied-inventory'?structuredClone(captured):change==='peer-inventory'?target:captured;
  await expect(inventory.privateFingerprints(handle,value)).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});expect(repo.saveComparison).not.toHaveBeenCalled();expect(db.exec).not.toHaveBeenCalled();
 });
 it('mutating an originally captured public inventory cannot keep its old private native proof',async()=>{roots();const captured=await inventory.capture(sourceHandle);captured.objects[0].payload.host='forged-fixture.invalid';
  await expect(inventory.privateFingerprints(sourceHandle,captured)).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});expect(repo.saveComparison).not.toHaveBeenCalled();
 });
 it('a scheduler source/target private-map swap is rejected before encrypted comparison INSERT',async()=>{roots();const original=inventory.privateFingerprints.getMockImplementation()!;
  inventory.privateFingerprints.mockImplementation(async(handle:object,value:object)=>original(handle===sourceHandle?targetHandle:sourceHandle,value));
  await expect(service.runScheduled(locator,{kind:'drift',threshold:0})).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});expect(repo.saveComparison).not.toHaveBeenCalled();expect(db.exec).not.toHaveBeenCalled();expect(terminal).toBe('failed');
 });
});
