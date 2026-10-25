import 'reflect-metadata';
import {describe,expect,it} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {assertMetricsSetupPlan,metricsSetupSteps,metricsSetupPublicProjection} from '../../apps/console-api/src/modules/vitals/vitals-setup-plan';
import type {MetricsSetupIntent} from '../../apps/console-api/src/modules/vitals/vitals-setup.types';

function prepared(mode:'native_prometheus'|'collector'='collector',update=false){process.env.CONSOLE_ENCRYPTION_KEY='52'.repeat(32);const secrets=new SecretService(),intent:any={version:1,id:randomUUID(),workflowId:randomUUID(),clusterId:randomUUID(),workspaceId:randomUUID(),actorId:randomUUID(),mode,
 source:{id:randomUUID()},settings:{revision:4,enabled:false,collectorEnabled:true,credentialGeneration:1},plugins:(mode==='collector'?['prometheus','http-log']:['prometheus']).map(name=>{
  const nativeId=randomUUID(),config=name==='http-log'?{http_endpoint:'http://kongos:unit-private-token@telemetry-collector:9093/ingest/unit',headers:{Authorization:'private-text'}}:{};
  return{name,nativeId,action:update?'update':'create',before:update?{id:nativeId,name,enabled:false,config:structuredClone(config),service:null,route:null,consumer:null}:null,payload:update?{enabled:true,config}:{id:nativeId,name,enabled:true,config,tags:['kos-ws-default']}};})};
 const plan:any={version:1,kind:'metrics-setup',subject:{type:'metrics_setup_requests',id:intent.id},requester:{type:'console',id:intent.actorId},workflowId:intent.workflowId,clusterId:intent.clusterId,workspaceId:intent.workspaceId,
  planRevision:1,executionMode:'approval',approvalRequired:true,prerequisites:[],steps:metricsSetupSteps(intent as MetricsSetupIntent,v=>secrets.fingerprint(v),randomUUID)};
 return{intent,plan,secrets};}
describe('M11 typed monitoring SOURCE packet plan',()=>{
 it.each(['native_prometheus','collector'] as const)('plans actual fixed Native count and final settings for %s',mode=>{for(const update of [false,true]){const {plan}=prepared(mode,update);expect(assertMetricsSetupPlan(plan)).toBe(plan.steps.at(-1));
  expect(plan.steps.filter((s:any)=>s.kind==='native')).toHaveLength(mode==='collector'?2:1);expect(plan.steps.at(-1).nativeRequests).toEqual([]);}});
 it.each([
  ['foreign kind',(p:any)=>p.kind='iam-metadata'],['foreign subject',(p:any)=>p.subject.type='iam_metadata_requests'],['developer',(p:any)=>p.requester.type='developer'],
  ['direct',(p:any)=>p.executionMode='direct'],['no approval',(p:any)=>p.approvalRequired=false],['revision',(p:any)=>p.planRevision=2],['hidden timer',(p:any)=>p.scheduling={}],
  ['hidden prereq',(p:any)=>p.prerequisites.push({})],['generated token',(p:any)=>p.generated={}],['migration',(p:any)=>p.migration={}],
  ['other plugin',(p:any)=>p.steps[0].mutationPayload.name='jwt'],['foreign entity',(p:any)=>p.steps[0].entityType='consumers'],['delete',(p:any)=>p.steps[0].mutationAction='delete'],
  ['2x schema',(p:any)=>p.steps[0].nativeRequests[0].canonicalPath='/schemas/plugins/prometheus'],['wrong method',(p:any)=>p.steps[0].nativeRequests[0].method='PUT'],
  ['foreign native id',(p:any)=>p.steps[0].nativeRequests[0].nativeId=randomUUID()],['missing native',(p:any)=>p.steps[0].nativeRequests=[]],['extra native',(p:any)=>p.steps[0].nativeRequests.push(p.steps[0].nativeRequests[0])],
  ['reuse key',(p:any)=>p.steps[0].mutationIdempotencyKey='replay-original-key'],['null config',(p:any)=>p.steps[0].mutationPayload.config=null],['user endpoint selector',(p:any)=>p.steps[0].mutationPayload.endpoint='http://untrusted'],
  ['service binding',(p:any)=>p.steps[0].mutationPayload.service={id:randomUUID()}],['hidden native handler',(p:any)=>p.steps[0].handler='metrics.setup.settings'],
  ['swapped dependencies',(p:any)=>p.steps[1].dependencies=[]],['foreign metadata',(p:any)=>p.steps.at(-1).metadata.sourceId=randomUUID().slice(3)],
  ['extra metadata',(p:any)=>p.steps.at(-1).metadata.actorId=randomUUID()],['wrong mode',(p:any)=>p.steps.at(-1).metadata.mode='native_prometheus'],['metadata native',(p:any)=>p.steps.at(-1).nativeRequests=[p.steps[0].nativeRequests[0]]],
  ['wrong metadata handler',(p:any)=>p.steps.at(-1).handler='iam.metadata'],['duplicate step',(p:any)=>p.steps.at(-1).id=p.steps[0].id],['wrong metadata digest',(p:any)=>p.steps.at(-1).metadata.materialHmac='bad'],
  ['changed metadata order',(p:any)=>p.steps.at(-1).order=2],['wrong final dependency',(p:any)=>p.steps.at(-1).dependencies=[p.steps[0].id]],
 ] as Array<[string,(p:any)=>void]>)('rejects %s without minting any capability',(_name,mutate)=>{const {plan}=prepared();mutate(plan);expect(()=>assertMetricsSetupPlan(plan)).toThrow();});
 it('retains before and desired private token only in sealed material; masks endpoint and all headers on both sides',()=>{const {plan,secrets}=prepared('collector',true),raw=JSON.stringify(plan),safe=metricsSetupPublicProjection(plan.steps,secrets);
  expect(raw).toContain('unit-private-token');expect(JSON.stringify(safe)).not.toMatch(/unit-private-token|telemetry-collector|private-text/);expect(safe[1].before.config.http_endpoint).toBe('[MANAGED_ENDPOINT]');expect(safe[1].mutationPayload.config.headers).toBe('[REDACTED]');
  expect(JSON.stringify(plan)).toBe(raw);});
 it('binds private payload/body/before with genuine keyed HMACs and allocates distinct logical steps',()=>{const {plan,secrets}=prepared();for(const s of plan.steps.slice(0,-1)){expect(s.mutationPayloadHmac).toBe(secrets.fingerprint(s.mutationPayload));expect(s.nativeRequests[0].bodyHmac).toBe(s.mutationPayloadHmac);expect(s.beforeFingerprint).toBe(secrets.fingerprint(s.before));}
  expect(new Set(plan.steps.map((s:any)=>s.id)).size).toBe(3);expect(plan.steps.at(-1).metadataPayloadHmac).toBe(secrets.fingerprint(plan.steps.at(-1).metadata));});
});
