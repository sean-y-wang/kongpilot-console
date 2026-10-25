import {createHash} from 'node:crypto';
import {describe,it,expect} from 'vitest';
import {buildM10TimerScheduleFixture,validateM10TimerManifest,validateM10TimerCurrentBFF,assertM10TimerRoot,decodeM10TimerInventory} from '../security/lib/m10-native-timer-worker.mjs';

/** Pure evidence-contract tests. No clock manipulation, SQL, HTTP, claimed
 * real schedules, private lab files or native runtime acceptance. */
const uid='11111111-1111-4111-8111-111111111111',cid='22222222-2222-4222-8222-222222222222',wid='33333333-3333-4333-8333-333333333333',tcid='44444444-4444-4444-8444-444444444444',twid='55555555-5555-4555-8555-555555555555',scheduleId='66666666-6666-4666-8666-666666666666',driftId='77777777-7777-4777-8777-777777777777';
const created='2026-10-13T00:56:14.773Z',observed='2026-10-13T06:24:07.000Z',due='2026-10-13T06:27:01.213Z';
const fingerprint=(value:unknown)=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(){
 const entity:any={id:scheduleId,name:'Natural inspection',kind:'inspection',ownerUserId:uid,currentVersion:3,revision:67,createdAt:created,nextRunAt:due,state:'active',enabled:true,executionBlocked:false,
  scope:'workspace',serviceIds:[],intervalMinutes:5,timezone:'UTC',threshold:0,includeEnvironmentFields:false,paused:false,capabilities:{read:true}};
 const receipt={data:{entity},requestId:'actual-bff-seed-request'},seed=buildM10TimerScheduleFixture(receipt,{observedAt:observed,actorId:uid,id:scheduleId,kind:'inspection'});
 const driftEntity={...entity,id:driftId,name:'Natural drift',kind:'drift',currentVersion:1,revision:65,nextRunAt:'2026-10-13T06:27:34.631Z',target:{clusterId:tcid,workspaceId:twid,scope:'workspace',serviceIds:[]}};
 const drift=buildM10TimerScheduleFixture({data:{entity:driftEntity},requestId:'actual-bff-drift-seed'},{observedAt:observed,actorId:uid,id:driftId,kind:'drift'});
 const manifest={version:2,milestone:'M10',actorId:uid,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:tcid,targetWorkspaceId:twid,schedules:[seed,drift]};
 const occurrence:any={id:'88888888-8888-4888-8888-888888888888',schedule_id:scheduleId,cluster_id:cid,workspace_id:wid,creator_id:uid,schedule_version:3,state:'succeeded',scheduled_at:due,created_at:'2026-10-13T06:27:02.000Z'};
 const root:any={id:scheduleId,cluster_id:cid,workspace_id:wid,owner_user_id:uid,state:'active',current_version:3,policy_version:3,revision:68,created_at:new Date(created),policy_created_at:'2026-10-13T01:00:00.000Z',next_run_at:'2026-10-13T06:32:02.000Z',payload:structuredClone(seed.policy),policy_hmac:fingerprint(seed.policy)};
 return{entity,receipt,seed,drift,manifest,occurrence,root};
}
describe('M10 current BFF schedule observation contract',()=>{
 it('binds actual resumed version 3 and drift version 1 without inventing a registration reset or five-minute observation wait',()=>{
  const f=fixture();expect(validateM10TimerManifest(f.manifest)).toBe(f.manifest);expect(f.seed.currentVersion).toBe(3);expect(f.seed.revision).toBe(67);expect(Date.parse(due)-Date.parse(observed)).toBeLessThan(295000);
  expect(f.seed).not.toHaveProperty('policyHash');expect(f.seed.policy).not.toHaveProperty('capabilities');expect(f.seed.policy).not.toHaveProperty('revision');
 });
 it.each(['version','owner','blocked','paused','past-due','missing-request']as const)('rejects an unproven %s public seed instead of defaulting its facts',change=>{
  const f=fixture();if(change==='version')delete f.entity.currentVersion;if(change==='owner')f.entity.ownerUserId=tcid;if(change==='blocked')f.entity.executionBlocked=true;if(change==='paused')f.entity.state='paused';if(change==='past-due')f.entity.nextRunAt=observed;if(change==='missing-request')f.receipt.requestId='';
  expect(()=>buildM10TimerScheduleFixture(f.receipt,{observedAt:observed,actorId:uid,id:scheduleId,kind:'inspection'})).toThrow();
 });
 it('allows a natural revision increase while requiring the exact frozen version and policy',()=>{
  const f=fixture(),current={data:{entity:{...f.entity,revision:68,nextRunAt:f.root.next_run_at}},requestId:'natural-observation'};
  expect(validateM10TimerCurrentBFF(f.seed,current,'2026-10-13T06:27:03Z')).toEqual({advanced:true,executionBlocked:false});
  current.data.entity.currentVersion=4;expect(()=>validateM10TimerCurrentBFF(f.seed,current,'2026-10-13T06:27:03Z')).toThrow(/CURRENT_TIMER_VERSION_CHANGED/);
 });
 it('rejects an apparent nextRunAt advance before the observed natural due',()=>{
  const f=fixture();expect(()=>validateM10TimerCurrentBFF(f.seed,{data:{entity:{...f.entity,revision:68,nextRunAt:f.root.next_run_at}}},observed)).toThrow(/TIMER_ADVANCED_BEFORE_NATURAL_DUE/);
 });
});
describe('M10 exact current immutable version and real occurrence evidence',()=>{
 it('accepts only the observed current version and a revision explained by the actual new claim',()=>{
  const f=fixture();expect(()=>assertM10TimerRoot(f.seed,f.root,f.manifest,[f.occurrence],fingerprint)).not.toThrow();
  f.root.revision=67;expect(()=>assertM10TimerRoot(f.seed,f.root,f.manifest,[f.occurrence],fingerprint)).toThrow(/TIMER_REVISION_NOT_EXPLAINED/);
 });
 it('accounts for multiple naturally completed claims without accepting arbitrary revision changes',()=>{
  const f=fixture(),second={...f.occurrence,id:'99999999-9999-4999-8999-999999999999',scheduled_at:f.root.next_run_at,created_at:'2026-10-13T06:32:03Z'};f.root.revision=69;f.root.next_run_at='2026-10-13T06:37:03Z';
  expect(()=>assertM10TimerRoot(f.seed,f.root,f.manifest,[f.occurrence,second],fingerprint)).not.toThrow();f.root.revision=70;expect(()=>assertM10TimerRoot(f.seed,f.root,f.manifest,[f.occurrence,second],fingerprint)).toThrow();
 });
 it.each(['stale-version','closed-policy','changed-version','foreign-owner','changed-policy','changed-created-at','early-occurrence','unresolved']as const)('refuses %s even with otherwise successful historical material',change=>{
  const f=fixture();if(change==='stale-version')f.occurrence.schedule_version=1;if(change==='closed-policy')f.root.state='paused';if(change==='changed-version')f.root.current_version=4;if(change==='foreign-owner')f.occurrence.creator_id=tcid;
  if(change==='changed-policy'){f.root.payload.intervalMinutes=10;f.root.policy_hmac=fingerprint(f.root.payload);}if(change==='changed-created-at')f.root.created_at='2026-10-13T01:00:00Z';if(change==='early-occurrence')f.occurrence.created_at=observed;if(change==='unresolved')f.occurrence.state='uncertain';
  expect(()=>assertM10TimerRoot(f.seed,f.root,f.manifest,[f.occurrence],fingerprint)).toThrow();
 });
});
describe('M10 current candidate comparison envelope requirements',()=>{
 const current=()=>{const value={version:'1.5.1',objects:[{entityType:'services',nativeId:scheduleId}]},envelope={version:2,inventory:value,nativeFingerprints:{[`services:${scheduleId}`]:'a'.repeat(64)}};return{value,envelope};};
 it('requires authenticated V2 private raw-map membership while keeping inspection in its own native format',()=>{
  const f=current();expect(decodeM10TimerInventory('drift',f.envelope,fingerprint(f.envelope),fingerprint)).toEqual({value:f.value,version:2});
  expect(decodeM10TimerInventory('inspection',f.value,fingerprint(f.value),fingerprint)).toEqual({value:f.value,version:null});
 });
 it('does not let an authenticated legacy V1 comparison stand in for this new candidate acceptance',()=>{
  const f=current();expect(()=>decodeM10TimerInventory('drift',f.value,fingerprint(f.value),fingerprint)).toThrow(/CURRENT_TIMER_V2_COMPARISON_REQUIRED/);
 });
 it.each(['missing-map','extra-map','duplicate-object','bad-digest','bad-hmac','extra-envelope-field']as const)('rejects %s V2 evidence',change=>{
  const f:any=current();if(change==='missing-map')f.envelope.nativeFingerprints={};if(change==='extra-map')f.envelope.nativeFingerprints[`services:${driftId}`]='b'.repeat(64);if(change==='duplicate-object')f.value.objects.push({...f.value.objects[0]});if(change==='bad-digest')f.envelope.nativeFingerprints[`services:${scheduleId}`]='abc';if(change==='extra-envelope-field')f.envelope.authorized=true;
  expect(()=>decodeM10TimerInventory('drift',f.envelope,change==='bad-hmac'?'c'.repeat(64):fingerprint(f.envelope),fingerprint)).toThrow();
 });
});
