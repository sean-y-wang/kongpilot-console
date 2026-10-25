import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {assertDurableConfigurationEquivalent} from '../../apps/console-api/src/modules/configuration/configuration-durable-equivalence';
import type {ConfigPlan,ConfigurationPlanStep} from '../../apps/console-api/src/modules/configuration/configuration.types';

/** Strict synthetic authoring plans; these tests mint no HTTP, SQL, claim or
 * Native execution authority and do not represent real runtime acceptance. */
function fixture(){
 const secrets=new SecretService(),clusterId=randomUUID(),workspaceId=randomUUID(),ownerId=randomUUID();
 const ids={upstream:randomUUID(),target:randomUUID(),service:randomUUID(),route:randomUUID(),plugin:randomUUID()};
 const stepIds=Object.fromEntries(Object.keys(ids).map(key=>[key,randomUUID()]));
 const make=(key:keyof typeof ids,entityType:ConfigurationPlanStep['entityType'],order:number,path:string,body:Record<string,unknown>,deps:string[],extra:Partial<ConfigurationPlanStep>={}):ConfigurationPlanStep=>({
  stepId:stepIds[key],stepOrder:order,objectKey:`${entityType}:${ids[key]}`,entityType,objectWorkspaceId:workspaceId,clearMap:[],nativeId:null,allocatedNativeId:ids[key],
  permissionAction:'write',mutationAction:'create',dependencies:deps,body,before:null,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(null),
  nativeRequests:[{method:'POST',canonicalPath:path,body,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(null)}],referenceOnly:false,blockerCodes:[],maskedDiff:[],...extra});
 const steps=[
  make('upstream','upstreams',1,'/upstreams',{id:ids.upstream,name:'equivalence-upstream',algorithm:'round-robin',tags:['workspace:fixture']},[]),
  make('target','targets',2,`/upstreams/${ids.upstream}/targets`,{target:'echo:8080',weight:100},[stepIds.upstream],{parentType:'upstreams',parentId:ids.upstream}),
  make('service','services',3,'/services',{id:ids.service,name:'equivalence-service',host:'equivalence-upstream',port:80,protocol:'http',tags:['workspace:fixture']},[stepIds.upstream]),
  make('route','routes',4,'/routes',{id:ids.route,name:'equivalence-route',service:{id:ids.service},paths:['/fixture'],protocols:['https'],tags:['workspace:fixture']},[stepIds.service],{parentType:'services',parentId:ids.service}),
  make('plugin','plugins',5,'/plugins',{id:ids.plugin,name:'rate-limiting',service:{id:ids.service},route:{id:ids.route},config:{policy:'redis',redis_password:'synthetic-secret-original'},tags:['workspace:fixture']},[stepIds.service,stepIds.route]),
 ];
 const original:ConfigPlan={scope:{clusterId,workspaceId,transportScope:secrets.fingerprint('strict-fixture-transport'),kind:'workspace',rootIds:[]},mode:'merge',steps,
  sourceManifestHmac:secrets.fingerprint('original-source-material'),baselineManifestHmac:secrets.fingerprint('original-baseline-material'),schemaHmac:secrets.fingerprint({services:{},routes:{},plugins:{}}),
  permissionVersion:`${ownerId}:1:1`,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt:'2026-10-15T20:10:00.000Z'};
 const remap=new Map(original.steps.map(step=>[step.stepId,randomUUID()]));
 const fresh:ConfigPlan={...structuredClone(original),steps:original.steps.map(step=>({...structuredClone(step),stepId:remap.get(step.stepId)!,dependencies:step.dependencies.map(id=>remap.get(id)!)})),
  durableRef:{version:1,domain:'durable-configuration-v1',issueId:randomUUID()},expiresAt:'2026-10-16T20:00:00.000Z',
  sourceManifestHmac:secrets.fingerprint('new-source-material'),baselineManifestHmac:secrets.fingerprint('new-baseline-material')};
 const rehash=(step:ConfigurationPlanStep)=>{
  step.bodyHmac=secrets.fingerprint(step.body);step.beforeHmac=secrets.fingerprint(step.before);
  for(const packet of step.nativeRequests){packet.bodyHmac=secrets.fingerprint(packet.body);packet.beforeHmac=secrets.fingerprint(step.before);}
 };
 return{secrets,ids,ownerId,original,fresh,rehash};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','8b'.repeat(32));});
afterEach(()=>{vi.unstubAllEnvs();});
describe('M11 durable configuration consent equivalence (strict synthetic plans, actual keyed fingerprints)',()=>{
 it('permits only new console step IDs with exact dependency mapping and new expiry, durableRef and material manifests',()=>{
  const f=fixture();for(let i=0;i<f.original.steps.length;i++)expect(f.fresh.steps[i].stepId).not.toBe(f.original.steps[i].stepId);
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).not.toThrow();
  expect(f.fresh.steps.map(s=>s.allocatedNativeId)).toEqual(f.original.steps.map(s=>s.allocatedNativeId));
  expect(f.fresh.steps.map(s=>s.nativeRequests)).toEqual(f.original.steps.map(s=>s.nativeRequests));
 });
 it('does not mutate either original or fresh plan while mapping dependency identities',()=>{
  const f=fixture(),before=f.secrets.fingerprint([f.original,f.fresh]);assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets);
  expect(f.secrets.fingerprint([f.original,f.fresh])).toBe(before);
 });
 it.each(['native-create','target-allocation','native-existing','parent','foreign-key','secret','clear-map','method','path','body','before','body-hma','before-hma','packet-hma'])('rejects a changed approved Native fact: %s',change=>{
  const f=fixture(),service=f.fresh.steps[2] as any,target=f.fresh.steps[1] as any,plugin=f.fresh.steps[4] as any;
  if(change==='native-create'){service.allocatedNativeId=randomUUID();service.body.id=service.allocatedNativeId;f.rehash(service);}
  if(change==='target-allocation')target.allocatedNativeId=randomUUID();
  if(change==='native-existing')service.nativeId=randomUUID();
  if(change==='parent')target.parentId=randomUUID();
  if(change==='foreign-key'){plugin.body.service.id=randomUUID();f.rehash(plugin);}
  if(change==='secret'){plugin.body.config.redis_password='synthetic-secret-substituted';f.rehash(plugin);}
  if(change==='clear-map')service.clearMap=['client_certificate'];
  if(change==='method')service.nativeRequests[0].method='PATCH';
  if(change==='path')service.nativeRequests[0].canonicalPath=`/services/${randomUUID()}`;
  if(change==='body'){service.body.host='another-upstream';f.rehash(service);}
  if(change==='before'){service.before={id:f.ids.service,host:'changed-current-before'};f.rehash(service);}
  if(change==='body-hma')service.bodyHmac=f.secrets.fingerprint('different-sealed-body');
  if(change==='before-hma')service.beforeHmac=f.secrets.fingerprint('different-sealed-before');
  if(change==='packet-hma')service.nativeRequests[0].bodyHmac=f.secrets.fingerprint('different-packet');
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
 it.each(['edge-removal','edge-addition','edge-order','clear-map-order','step-array-order','step-order','object-key','entity-type','permission-action','mutation-action','parent-type'])('retains exact DAG and packet semantics: %s',change=>{
  const f=fixture(),plugin=f.fresh.steps[4] as any;
  if(change==='edge-removal')plugin.dependencies=plugin.dependencies.slice(0,1);
  if(change==='edge-addition')plugin.dependencies=[...plugin.dependencies,f.fresh.steps[1].stepId];
  if(change==='edge-order')plugin.dependencies.reverse();
  if(change==='clear-map-order'){(f.original.steps[2] as any).clearMap=['client_certificate','path'];(f.fresh.steps[2] as any).clearMap=['path','client_certificate'];}
  if(change==='step-array-order'){const steps=f.fresh.steps as ConfigurationPlanStep[];[steps[0],steps[1]]=[steps[1],steps[0]];}
  if(change==='step-order')plugin.stepOrder=6;
  if(change==='object-key')plugin.objectKey=`plugins:${randomUUID()}`;
  if(change==='entity-type')plugin.entityType='consumers';
  if(change==='permission-action')plugin.permissionAction='delete';
  if(change==='mutation-action')plugin.mutationAction='update';
  if(change==='parent-type')f.fresh.steps[1].parentType='services';
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
 it.each(['workspace','cluster','transport','rootIds','scope-kind','object-workspace','mode','schema','kong-version','cluster-revision','workspace-revision','recovery','permission','reference-only','blocker','masked-diff','wire-envelope','wire-set-fields'])('rejects a changed scope, authority or recovery fact: %s',change=>{
  const f=fixture(),p=f.fresh as any;
  if(change==='workspace')p.scope.workspaceId=randomUUID();if(change==='cluster')p.scope.clusterId=randomUUID();
  if(change==='transport')p.scope.transportScope=f.secrets.fingerprint('another-transport');if(change==='rootIds')p.scope.rootIds=[f.ids.service];
  if(change==='scope-kind')p.scope.kind='services';if(change==='object-workspace')p.steps[0].objectWorkspaceId=randomUUID();
  if(change==='mode')p.mode='sync';if(change==='schema')p.schemaHmac=f.secrets.fingerprint({changed:'schema'});
  if(change==='kong-version')p.kongVersion='1.5.2';if(change==='cluster-revision')p.clusterRevision=2;if(change==='workspace-revision')p.workspaceRevision=2;
  if(change==='recovery')p.recoveryComplete=false;if(change==='permission')p.permissionVersion=`${f.ownerId}:2:1`;
  if(change==='reference-only')p.steps[0].referenceOnly=true;if(change==='blocker')p.steps[0].blockerCodes=['REQUIRES_ROTATION'];
  if(change==='masked-diff')p.steps[0].maskedDiff=[{op:'replace',path:'/host',value:'unapproved'}];
  if(change==='wire-envelope')p.steps[0].deckWirePayload={unapproved:true};if(change==='wire-set-fields')p.steps[0].deckWireSetFields=['tags'];
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
 it.each(['original','fresh'])('rejects an unknown dependency in the %s plan',side=>{
  const f=fixture();(side==='original'?f.original:f.fresh).steps[4].dependencies=[randomUUID()];
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
 it.each(['original','fresh'])('rejects duplicate object keys in the %s plan',side=>{
  const f=fixture(),plan=side==='original'?f.original:f.fresh;plan.steps[1].objectKey=plan.steps[0].objectKey;
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
 it.each(['original','fresh'])('rejects duplicate console step IDs in the %s plan',side=>{
  const f=fixture(),plan=side==='original'?f.original:f.fresh;plan.steps[1].stepId=plan.steps[0].stepId;
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
 it('maps every dependency by its actual object key rather than merely ignoring its console ID',()=>{
  const f=fixture();f.fresh.steps[4].dependencies=[f.fresh.steps[0].stepId,f.fresh.steps[3].stepId];
  expect(()=>assertDurableConfigurationEquivalent(f.original,f.fresh,f.secrets)).toThrow();
 });
});
