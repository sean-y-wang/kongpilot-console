import { createHmac } from 'node:crypto';
import {readFileSync} from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { graph, id, schemas } from './m8-config-transfer.fixture';
import type { ComparisonInventory, ComparisonObject, PromoteOptions } from '../../apps/console-api/src/modules/governance/comparison-types';
import { GovernanceComparisonError } from '../../apps/console-api/src/modules/governance/comparison-types';
import { normalizeLogicalGraph, objectIdentity } from '../../apps/console-api/src/modules/governance/logical-graph';
import { compareLogicalEnvironments } from '../../apps/console-api/src/modules/governance/drift-engine';
import { compilePromoteDocument } from '../../apps/console-api/src/modules/governance/promote-compiler';
import { normalizeDeckDocument, parseDeckDocument } from '../../apps/console-api/src/modules/config-transfer';

function inventory(target = false): ComparisonInventory {
  const original = graph(), replacements = new Map(original.objects.map(object => [object.nativeId,id(parseInt(object.nativeId.slice(0,8),16) + 1000)]));
  const rewrite = (value: unknown): any => {
    if (typeof value === 'string') return replacements.get(value) ?? value;
    if (Array.isArray(value)) return value.map(rewrite);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key,child]) => [key,rewrite(child)]));
    return value;
  };
  return { scope:{...original.scope,...(target?{clusterId:id(201),workspaceId:id(200),transportScope:'synthetic-target'}:{})},
    objects:original.objects.map(object => ({entityType:object.entityType,nativeId:target?replacements.get(object.nativeId)!:object.nativeId,
      payload:target?rewrite(object.payload):structuredClone(object.payload),parentId:target&&object.parentId?replacements.get(object.parentId):object.parentId,
      credentialKind:object.credentialKind,objectWorkspaceId:target?id(200):id(100),sensitiveFields:[] as string[]})),
    schemas:schemas().entities,pluginSchemas:schemas().plugins,enabledPlugins:schemas().enabledPlugins,version:'1.5.1',adapterVersion:'kong-1.5',
    completeness:'complete',projection:false,consistency:'console_fenced_best_effort' };
}
const entity = (source: ComparisonInventory,type:string):ComparisonObject => source.objects.find(object => object.entityType===type)!;
const keyed=(value:unknown):string=>createHmac('sha256','synthetic-comparison-test-key').update(JSON.stringify(value)).digest('hex');
const compilation = (source=inventory(),target=inventory(true),options:Partial<PromoteOptions>={}) => compilePromoteDocument(source,target,{targetWorkspaceCode:'prod',...options});
const reject=(fn:()=>unknown,code:string):void=>{
  expect(fn).toThrow(GovernanceComparisonError);try{fn();}catch(error){expect((error as GovernanceComparisonError).code).toBe(code);}
};

describe('M10 logical identity and bounded public projection',()=>{
  it('normalizes UUIDs, timestamps, workspace tags and schema set ordering independently',()=>{
    const source=inventory(),target=inventory(true);
    entity(target,'services').payload.created_at=99;
    entity(target,'services').payload.updated_at=100;
    for(const object of target.objects)object.payload.tags=['workspace:prod','team:pay'];
    entity(target,'routes').payload.protocols=['http'];
    const result=compareLogicalEnvironments(source,target);
    expect(result.completeness).toBe('complete');expect(result.changes).toEqual([]);expect(result.counts.unchanged).toBe(5);
  });
  it('excludes backend origins, target addresses, private credentials, PEM and match headers by default',()=>{
    const source=inventory(),target=inventory(true);
    entity(target,'services').payload.host='prod-secret-internal.invalid';
    entity(target,'services').payload.port=8443;
    entity(target,'routes').payload.headers={authorization:['Bearer fixture-never-export']};
    entity(target,'targets').payload.target='192.0.2.5:8080';
    entity(target,'certificates').payload.key='-----BEGIN PRIVATE KEY-----fixture-----END PRIVATE KEY-----';
    const logical=normalizeLogicalGraph(target);
    expect(JSON.stringify(logical.objects)).not.toContain('fixture-never-export');expect(JSON.stringify(logical.objects)).not.toContain('PRIVATE KEY');
    expect(compareLogicalEnvironments(source,target).changes).toEqual([]);
    expect(logical.exclusions.some(item=>item.reason==='credential')).toBe(true);
  });
  it('accepts certificates represented only by authorized public fingerprints',()=>{
    const source=inventory(),target=inventory(true);
    for(const current of [source,target])for(const certificate of current.objects.filter(object=>['certificates','ca_certificates'].includes(object.entityType))){
      certificate.certificate={state:'valid',fingerprint:'ab'.repeat(32)};delete certificate.payload.cert;delete certificate.payload.key;
    }
    const result=compareLogicalEnvironments(source,target,{sourcePolicy:{includeEnvironmentFields:true},targetPolicy:{includeEnvironmentFields:true}});
    expect(result.completeness).toBe('complete');expect(result.changes).toEqual([]);
    const promoted=compilation(source,target,{includeEnvironmentFields:true});expect(promoted.state).toBe('ready');
    expect((promoted.document!.certificates as any[])[0]).toMatchObject({id:id(1007)});expect(promoted.yaml).not.toContain('cert:');expect(promoted.yaml).not.toContain('key:');
  });
  it('treats credentials embedded in URL query strings as secrets even when environment copy is enabled',()=>{
    const source=inventory(),target=inventory(true);
    const plugin=entity(source,'plugins');plugin.payload.config={header_name:'X-Fixture',echo_downstream:false,http_endpoint:'https://logs.invalid/?api_key=fixture-query-secret'};
    (source.pluginSchemas['correlation-id'] as any).fields.push({http_endpoint:{type:'string'}});target.pluginSchemas=structuredClone(source.pluginSchemas);
    const result=normalizeLogicalGraph(source,{includeEnvironmentFields:true});expect(JSON.stringify(result.objects)).not.toContain('fixture-query-secret');
    expect(result.exclusions.some(item=>item.field==='/config/http_endpoint'&&item.reason==='secret')).toBe(true);
  });
  it('rejects duplicate logical names without choosing the first native UUID',()=>{
    const source=inventory();source.objects=[...source.objects,{...structuredClone(entity(source,'services')),nativeId:id(700),payload:{...entity(source,'services').payload,id:id(700)}}];
    const result=normalizeLogicalGraph(source);
    expect(result.complete).toBe(false);expect(result.issues.some(item=>item.code==='GOVERNANCE_LOGICAL_IDENTITY_AMBIGUOUS')).toBe(true);
    expect(compilation(source).state).toBe('blocked');
  });
  it('requires explicit aliases for anonymous Service and permits unambiguous matching across environments',()=>{
    const source=inventory(),target=inventory(true);delete entity(source,'services').payload.name;delete entity(target,'services').payload.name;
    expect(normalizeLogicalGraph(source).issues.some(item=>item.code==='GOVERNANCE_LOGICAL_IDENTITY_REQUIRED')).toBe(true);
    const aliases={[objectIdentity(entity(source,'services'))]:'payments',[objectIdentity(entity(target,'services'))]:'payments'};
    const result=compareLogicalEnvironments(source,target,{sourcePolicy:{identityAliases:aliases},targetPolicy:{identityAliases:aliases}});
    expect(result.completeness).toBe('complete');expect(result.changes).toEqual([]);
  });
  it('identifies anonymous Routes by a unique logical matcher, refusing same-path host-only collisions',()=>{
    const source=inventory(),target=inventory(true);delete entity(source,'routes').payload.name;delete entity(target,'routes').payload.name;
    expect(compareLogicalEnvironments(source,target).changes).toEqual([]);
    const route=entity(source,'routes');source.objects=[...source.objects,{...structuredClone(route),nativeId:id(710),payload:{...route.payload,id:id(710),hosts:['other.invalid']}}];
    expect(normalizeLogicalGraph(source).complete).toBe(false);
  });
  it('resolves Plugin bindings and rejects duplicate plugin binding tuples',()=>{
    const source=inventory(),plugin=entity(source,'plugins');
    const logical=normalizeLogicalGraph(source).objects.find(object=>object.entityType==='plugins')!;
    expect(logical.payload.service).toEqual({logical_ref:'services:svc'});
    source.objects=[...source.objects,{...structuredClone(plugin),nativeId:id(711),payload:{...plugin.payload,id:id(711)}}];
    expect(normalizeLogicalGraph(source).issues.some(item=>item.code==='GOVERNANCE_LOGICAL_IDENTITY_AMBIGUOUS')).toBe(true);
  });
  it('treats Kong 1.5 auth-plugin config.anonymous as a logical Consumer reference and remaps its scalar UUID',()=>{
    const source=inventory(),target=inventory(true),schema=JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/plugin-schema-key-auth.json','utf8'));
    source.pluginSchemas={...source.pluginSchemas,'key-auth':schema};target.pluginSchemas={...target.pluginSchemas,'key-auth':schema};
    source.enabledPlugins=[...source.enabledPlugins,'key-auth'];target.enabledPlugins=[...target.enabledPlugins,'key-auth'];
    const plugin=entity(source,'plugins');plugin.payload.name='key-auth';plugin.payload.consumer=null;plugin.payload.config={key_names:['apikey'],anonymous:id(3)};
    const logical=normalizeLogicalGraph(source).objects.find(object=>object.entityType==='plugins')!;
    expect((logical.payload.config as any).anonymous).toEqual({logical_ref:'consumers:username%3Aconsumer'});
    const result=compilation(source,target,{selectedObjectKeys:[objectIdentity(plugin)],allocateNativeId:()=>id(950)});
    expect(result.blockers).toEqual([]);expect(result.state).toBe('ready');expect((result.document!.plugins as any[])[0].config.anonymous).toBe(id(1003));expect(result.yaml).not.toContain(id(3));
    source.objects=source.objects.filter(object=>object.entityType!=='consumers');
    const missing=compilation(source,target,{selectedObjectKeys:[objectIdentity(plugin)],allocateNativeId:()=>id(950)});
    expect(missing.state).toBe('blocked');expect(missing.blockers).toContainEqual(expect.objectContaining({code:'GOVERNANCE_REFERENCE_UNRESOLVED',field:'/config/anonymous'}));
  });
  it.each(['key-auth','jwt','oauth2','hmac-auth','basic-auth','ldap-auth'])('remaps %s anonymous Consumers using its recorded Kong 1.5 schema and rejects source UUID overrides',name=>{
    const source=inventory(),target=inventory(true),schema=JSON.parse(readFileSync(`tests/fixtures/kong-1.5.1/plugin-schema-${name}.json`,'utf8'));
    const config={...Object.fromEntries(schema.fields.flatMap((field:Record<string,any>)=>Object.entries(field).filter(([,definition])=>Object.hasOwn(definition,'default')).map(([key,definition])=>[key,definition.default]))),
      ...(name==='ldap-auth'?{ldap_host:'fixture-ldap.invalid',ldap_port:389,base_dn:'ou=fixture,dc=invalid',attribute:'uid'}:{}),
      ...(name==='oauth2'?{provision_key:'fixture-not-a-live-provision-key',enable_client_credentials:true}:{})};
    for(const [current,consumerId]of [[source,id(3)],[target,id(1003)]]as const){
      current.pluginSchemas={...current.pluginSchemas,[name]:schema};current.enabledPlugins=[...current.enabledPlugins,name];
      const plugin=entity(current,'plugins');Object.assign(plugin.payload,{name,consumer:null,config:{...structuredClone(config),anonymous:consumerId}});
    }
    const plugin=entity(source,'plugins'),selectedObjectKeys=[objectIdentity(plugin)],result=compilation(source,target,{selectedObjectKeys});
    expect(result.blockers).toEqual([]);expect(result.state).toBe('ready');expect((result.document!.plugins as any[])[0].config.anonymous).toBe(id(1003));
    for(const anonymous of [id(3),id(777)]){
      const forged=compilation(source,target,{selectedObjectKeys,fieldOverrides:{[objectIdentity(plugin)]:{config:{...config,anonymous}}}});
      expect(forged.state).toBe('blocked');expect(forged.blockers).toContainEqual(expect.objectContaining({code:'GOVERNANCE_PROMOTE_REFERENCE_NOT_CAPTURED',field:'/config/anonymous'}));
    }
    const explicitTarget=compilation(source,target,{selectedObjectKeys,fieldOverrides:{[objectIdentity(plugin)]:{config:{...config,anonymous:id(1003)}}},includeSecrets:true,privateSourceObjects:source.objects});
    expect(explicitTarget.state).toBe('ready');expect((explicitTarget.document!.plugins as any[])[0].config.anonymous).toBe(id(1003));
    source.objects=source.objects.filter(object=>object.entityType!=='consumers');
    const missing=compilation(source,target,{selectedObjectKeys});expect(missing.state).toBe('blocked');expect(missing.blockers).toContainEqual(expect.objectContaining({code:'GOVERNANCE_REFERENCE_UNRESOLVED',field:'/config/anonymous'}));
  });
  it('does not mistake unauthorized/incomplete references for absence',()=>{
    const source=inventory();source.objects=source.objects.filter(object=>object.entityType!=='services');source.projection=true;
    const result=compareLogicalEnvironments(source,inventory(true));
    expect(result.completeness).toBe('incomplete');expect(result.threshold).toEqual({evaluated:false,exceeded:false,notify:false});expect(result.fingerprint).toBeNull();
  });
  it.each(['clustering','vaults','keys','key-sets','event-hooks'])('does not infer unsupported native entity %s',type=>{
    const source=inventory();source.objects=[{entityType:type as any,nativeId:id(712),payload:{id:id(712),name:'not-supported'}}];
    expect(normalizeLogicalGraph(source).complete).toBe(false);
  });
  it('rejects getters without invoking them, prototypes, cycles and oversized arrays',()=>{
    const source=inventory();let getterCalled=false;Object.defineProperty(entity(source,'services').payload,'host',{enumerable:true,get:()=>{getterCalled=true;return 'evil';}});
    reject(()=>normalizeLogicalGraph(source),'GOVERNANCE_COMPARISON_INVALID_JSON');expect(getterCalled).toBe(false);
    const cyclic=inventory();(entity(cyclic,'services').payload as any).loop=entity(cyclic,'services').payload;
    reject(()=>normalizeLogicalGraph(cyclic),'GOVERNANCE_COMPARISON_INVALID_JSON');
    const polluted=inventory();entity(polluted,'services').payload=Object.create({host:'evil'});
    reject(()=>normalizeLogicalGraph(polluted),'GOVERNANCE_COMPARISON_INVALID_JSON');
    const enormous=inventory();enormous.objects=Array.from({length:10_001},()=>entity(enormous,'services'));
    reject(()=>normalizeLogicalGraph(enormous),'GOVERNANCE_COMPARISON_OBJECT_LIMIT');
  });
});

describe('M10 bidirectional drift and safe threshold decisions',()=>{
  it('reports source-only, target-only and field differences with target -> source direction',()=>{
    const source=inventory(),target=inventory(true);entity(source,'services').payload.retries=2;
    source.objects=source.objects.filter(object=>object.entityType!=='consumers'&&object.entityType!=='plugins'&&object.entityType!=='credentials');
    target.objects=target.objects.filter(object=>object.entityType!=='upstreams'&&object.entityType!=='targets'&&object.entityType!=='plugins');
    const result=compareLogicalEnvironments(source,target);
    expect(result.counts).toMatchObject({sourceOnly:1,targetOnly:1,changed:1,changedObjects:3});
    expect(result.changes.find(item=>item.entityType==='services')!.fields).toContainEqual({path:'/retries',action:'replace',before:0,after:2,redacted:false});
  });
  it('notifies only for complete new differences exceeding a fixed threshold',()=>{
    const source=inventory(),target=inventory(true);entity(source,'services').payload.retries=2;
    const result=compareLogicalEnvironments(source,target,{threshold:{maxChangedObjects:0}});
    expect(result.threshold).toEqual({evaluated:true,exceeded:true,notify:true});
    expect(compareLogicalEnvironments(source,target,{previousFingerprint:result.fingerprint}).threshold.notify).toBe(false);
    expect(compareLogicalEnvironments(source,target,{threshold:{maxChangedObjects:1}}).threshold.exceeded).toBe(false);
    source.completeness='incomplete';expect(compareLogicalEnvironments(source,target).threshold.evaluated).toBe(false);
  });
  it('does not expose secret changes or permit a public unkeyed secret fingerprint',()=>{
    const source=inventory(),target=inventory(true);entity(source,'plugins').payload.config={header_name:'Authorization',echo_downstream:false,token:'fixture-sensitive-one'};
    entity(target,'plugins').payload.config={header_name:'Authorization',echo_downstream:false,token:'fixture-sensitive-two'};
    // Explicit synthetic schema extension keeps a typed test for plugin secrets.
    (source.pluginSchemas['correlation-id'] as any).fields.push({token:{type:'string'}});target.pluginSchemas=structuredClone(source.pluginSchemas);
    reject(()=>compareLogicalEnvironments(source,target,{sourcePolicy:{includeSecrets:true}}),'GOVERNANCE_KEYED_FINGERPRINT_REQUIRED');
    const result=compareLogicalEnvironments(source,target,{sourcePolicy:{includeSecrets:true},targetPolicy:{includeSecrets:true},fingerprint:keyed});
    expect(JSON.stringify(result)).not.toContain('fixture-sensitive-one');expect(JSON.stringify(result)).not.toContain('fixture-sensitive-two');
    expect(result.changes[0].fields.some(field=>field.redacted)).toBe(true);
  });
  it('keeps incompatible scope comparison incomplete and rejects invalid threshold values',()=>{
    const target=inventory(true);target.scope.kind='services';target.scope.rootIds=[entity(target,'services').nativeId];
    expect(compareLogicalEnvironments(inventory(),target).completeness).toBe('incomplete');
    reject(()=>compareLogicalEnvironments(inventory(),inventory(true),{threshold:{maxChangedObjects:-1}}),'GOVERNANCE_DRIFT_THRESHOLD_INVALID');
  });
  it('does not claim complete comparable capability across different version/adapters or absent source Plugin',()=>{
    const source=inventory(),target=inventory(true);target.version='1.5.2';expect(compareLogicalEnvironments(source,target).completeness).toBe('incomplete');
    target.version='1.5.1';target.adapterVersion='unexpected-adapter';expect(compareLogicalEnvironments(source,target).threshold.evaluated).toBe(false);
    source.enabledPlugins=[];expect(normalizeLogicalGraph(source).issues.some(item=>item.code==='GOVERNANCE_PLUGIN_UNAVAILABLE')).toBe(true);
  });
});

describe('M10 target-side Promote compiler',()=>{
  it('emits real target IDs, remapped FK bindings and target workspace tags in a merge document',()=>{
    const source=inventory(),target=inventory(true);entity(source,'services').payload.retries=3;
    const result=compilation(source,target);
    expect(result.blockers).toEqual([]);expect(result.state).toBe('ready');expect(result.mode).toBe('merge');
    const doc=parse(result.yaml!);expect(doc._format_version).toBe('1.1');expect(doc.services[0]).toMatchObject({id:id(1001),retries:3,tags:['team:pay','workspace:prod']});
    expect(doc.routes[0].service).toEqual({id:id(1001)});expect(doc.plugins[0].route).toEqual({id:id(1002)});
    expect(doc).not.toHaveProperty('targets');expect(doc).not.toHaveProperty('certificates');expect(doc.consumers[0]).not.toHaveProperty('keyauth_credentials');
    expect(result.yaml).not.toContain('fixture-not-a-live-key');expect(doc.services[0]).not.toHaveProperty('host');expect(doc.services[0]).not.toHaveProperty('client_certificate');
    const baseline=graph();baseline.scope=target.scope;baseline.objects=baseline.objects.map((object,index)=>({...object,...target.objects[index],objectKey:objectIdentity(target.objects[index]),objectWorkspaceId:target.scope.workspaceId,dependencies:object.dependencies.map(dependency=>dependency.replace(/([\da-f]{8})-0000-4000-8000-000000000000/g,(_all,hex)=>id(parseInt(hex,16)+1000)))}));
    const normalized=normalizeDeckDocument(parseDeckDocument(result.yaml!),schemas(),{scope:target.scope,workspaceCode:'prod',references:baseline});
    expect(normalized.objects.find(object=>object.entityType==='routes')!.payload.service).toEqual({id:id(1001)});
  });
  it('never erases unselected target entities or credentials and defaults to safe field omissions',()=>{
    const source=inventory(),target=inventory(true),svc=entity(source,'services');
    const result=compilation(source,target,{selectedServiceIds:[svc.nativeId]});
    expect(result.state).toBe('ready');expect(result.document).not.toHaveProperty('upstreams');
    expect(result.document).not.toHaveProperty('certificates');expect(result.yaml).not.toContain('delete');
  });
  it('maps Service-scope reference-only parents without mutating or creating them',()=>{
    const source=inventory(),target=inventory(true);
    for(const current of [source,target]){
      current.scope.kind='services';current.scope.rootIds=[entity(current,'services').nativeId];
      for(const object of current.objects)object.referenceOnly=!['services','routes','plugins'].includes(object.entityType);
    }
    const result=compilation(source,target);expect(result.state).toBe('ready');expect(result.document).not.toHaveProperty('consumers');
    expect((result.document!.plugins as any[])[0].consumer).toEqual({id:id(1003)});
    target.objects=target.objects.filter(object=>object.entityType!=='consumers');
    expect(compilation(source,target).state).toBe('blocked');
  });
  it('requires explicit target host for a new Service and rejects source UUID allocation',()=>{
    const source=inventory();source.objects=[entity(source,'services')];entity(source,'services').payload.client_certificate=null;
    const target=inventory(true);target.objects=[];
    const blocked=compilation(source,target);expect(blocked.blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_TARGET_HOST_REQUIRED')).toBe(true);
    const key=objectIdentity(entity(source,'services'));
    const result=compilation(source,target,{fieldOverrides:{[key]:{host:'target-app.internal',port:8080}},allocateNativeId:()=>id(720)});
    expect(result.state).toBe('ready');expect((result.document!.services as any[])[0]).toMatchObject({id:id(720),host:'target-app.internal',port:8080});
    reject(()=>compilation(source,target,{allocateNativeId:()=>entity(source,'services').nativeId}),'GOVERNANCE_PROMOTE_ALLOCATED_ID_INVALID');
  });
  it('blocks creating an empty Upstream while environment Targets are excluded',()=>{
    const source=inventory();source.objects=[entity(source,'upstreams'),entity(source,'targets')];const target=inventory(true);target.objects=[];
    expect(compilation(source,target).blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_TARGETS_REQUIRED')).toBe(true);
    const result=compilation(source,target,{includeEnvironmentFields:true,allocateNativeId:key=>key.includes('/targets:')?id(722):id(721)});
    expect(result.state).toBe('ready');expect((result.document!.upstreams as any[])[0].targets[0]).toMatchObject({id:id(722),target:'fixture.invalid:8081'});
  });
  it('maps Service.host through the promoted Upstream name and captures its target closure',()=>{
    const source=inventory();entity(source,'services').payload.host='upstream';entity(source,'services').payload.client_certificate=null;
    const target=inventory(true);target.objects=[];const service=entity(source,'services'),upstream=entity(source,'upstreams');
    const allocate=(key:string):string=>key.startsWith('services:')?id(740):key.startsWith('routes:')?id(741):key.startsWith('plugins:')?id(742):key.startsWith('consumers:')?id(743):key.includes('/targets:')?id(745):id(744);
    const result=compilation(source,target,{includeEnvironmentFields:true,selectedServiceIds:[service.nativeId],fieldOverrides:{[objectIdentity(upstream)]:{name:'target-upstream'}},allocateNativeId:allocate});
    expect(result.state).toBe('ready');expect((result.document!.services as any[])[0].host).toBe('target-upstream');expect((result.document!.upstreams as any[])[0].targets).toHaveLength(1);
  });
  it('keeps environment and secret inclusion independent and rejects unavailable private material',()=>{
    const result=compilation(inventory(),inventory(true),{includeEnvironmentFields:true});
    expect(result.yaml).not.toContain('fixture-not-a-live-key');
    expect(compilation(inventory(),inventory(true),{includeSecrets:true}).blockers.some(item=>item.code==='GOVERNANCE_SECRET_MATERIAL_UNAVAILABLE')).toBe(true);
    expect(compilation(inventory(),inventory(true),{includeCredentials:true}).blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_CREDENTIAL_SECRET_CONFIRMATION_REQUIRED')).toBe(true);
  });
  it('rejects redacted secret placeholders even if every include flag is enabled',()=>{
    const source=inventory(),privateSource=structuredClone(source.objects);entity(source,'certificates').payload.key='[REDACTED:fixture]';
    privateSource.find(object=>object.entityType==='certificates')!.payload.key='[REDACTED:fixture]';
    const result=compilation(source,inventory(true),{includeSecrets:true,includeCredentials:true,includeEnvironmentFields:true,privateSourceObjects:privateSource,identityAliases:{[objectIdentity(privateSource.find(object=>object.credentialKind==='key-auth')!)]:'credential'}});
    expect(result.state).toBe('blocked');expect(result.yaml).toBeNull();expect(result.blockers.some(item=>item.code==='GOVERNANCE_SECRET_MATERIAL_UNAVAILABLE')).toBe(true);
  });
  it('requires a separate exact private source observation and can compile credential recovery only with explicit flags',()=>{
    const source=inventory(),target=inventory(true),privateSource=structuredClone(source.objects),aliases:Record<string,string>={};
    for(const credential of privateSource.filter(object=>object.entityType==='credentials'))credential.recovery={state:'complete',blockerCodes:[],restorePayload:{...credential.payload,...(credential.credentialKind==='basic-auth'?{password:'fixture-original-basic-plaintext'}:{})}};
    for(const current of [source,target])for(const credential of current.objects.filter(object=>object.entityType==='credentials'))aliases[objectIdentity(credential)]=`fixture-${credential.credentialKind}`;
    for(const credential of source.objects.filter(object=>object.entityType==='credentials')){
      credential.sensitiveFields=['/key','/password','/secret','/client_secret'];
      for(const field of ['key','password','secret','client_secret'])if(Object.hasOwn(credential.payload,field))delete credential.payload[field];
    }
    const result=compilation(source,target,{includeSecrets:true,includeCredentials:true,privateSourceObjects:privateSource,identityAliases:aliases});
    expect(result.state).toBe('ready');expect((result.document!.consumers as any[])[0].keyauth_credentials[0]).toMatchObject({id:id(1010),key:'fixture-not-a-live-key'});
    expect((result.document!.consumers as any[])[0].basicauth_credentials[0].password).toBe('fixture-original-basic-plaintext');
    expect(result.basicPasswordIntents).toHaveProperty(`credentials:basic-auth:${id(1003)}:${id(1011)}`,'replace');
    const wrong=structuredClone(privateSource);wrong.find(object=>object.entityType==='services')!.payload.retries=99;
    reject(()=>compilation(source,target,{includeSecrets:true,privateSourceObjects:wrong}),'GOVERNANCE_PRIVATE_MATERIAL_OBSERVATION_MISMATCH');
  });
  it('never treats the Basic-auth native password hash as credential recovery material',()=>{
    const source=inventory(),privateSource=structuredClone(source.objects),aliases:Record<string,string>={};
    for(const current of [source,inventory(true)])for(const credential of current.objects.filter(object=>object.entityType==='credentials'))aliases[objectIdentity(credential)]=`fixture-${credential.credentialKind}`;
    const result=compilation(source,inventory(true),{includeSecrets:true,includeCredentials:true,privateSourceObjects:privateSource,identityAliases:aliases});
    expect(result.state).toBe('blocked');expect(result.blockers.some(item=>item.code==='GOVERNANCE_CREDENTIAL_RECOVERY_UNAVAILABLE')).toBe(true);expect(result.yaml).toBeNull();
  });
  it('promotes explicit credential-type batches without demanding Basic-auth material from an unselected type',()=>{
    const source=inventory(),target=inventory(true),privateSource=structuredClone(source.objects),aliases:Record<string,string>={};
    for(const object of privateSource.filter(object=>object.entityType==='credentials'))object.recovery={state:'complete',blockerCodes:[],restorePayload:{...object.payload}};
    delete privateSource.find(object=>object.credentialKind==='basic-auth')!.recovery;
    for(const inv of [source,target])for(const object of inv.objects.filter(object=>object.entityType==='credentials'))aliases[objectIdentity(object)]=`fixture-${object.credentialKind}`;
    const result=compilation(source,target,{includeSecrets:true,includeCredentials:true,credentialKinds:['key-auth','jwt','acls'],
      selectedObjectKeys:[objectIdentity(entity(source,'consumers'))],privateSourceObjects:privateSource,identityAliases:aliases});
    expect(result.state).toBe('ready');const consumer=(result.document!.consumers as any[])[0];
    expect(consumer.keyauth_credentials[0]).toMatchObject({id:id(1010),key:'fixture-not-a-live-key'});
    expect(consumer.jwt_secrets[0]).toMatchObject({id:id(1012)});expect(consumer.acls[0]).toMatchObject({id:id(1015)});
    expect(consumer).not.toHaveProperty('basicauth_credentials');expect(consumer).not.toHaveProperty('oauth2_credentials');expect(consumer).not.toHaveProperty('hmacauth_credentials');
    expect(result.selectedObjectKeys.filter(key=>key.startsWith('credentials:'))).toHaveLength(3);
    expect(result.yaml).not.toContain('fixture-native-basic-hash');
  });
  it('keeps credential selection and secret-only entity promotion independent',()=>{
    const source=inventory(),target=inventory(true),privateSource=structuredClone(source.objects);
    const result=compilation(source,target,{includeSecrets:true,includeCredentials:false,selectedObjectKeys:[objectIdentity(entity(source,'certificates'))],privateSourceObjects:privateSource});
    expect(result.state).toBe('ready');expect((result.document!.certificates as any[])[0]).toMatchObject({id:id(1007),key:'fixture-not-a-real-private-key'});
    expect(result.document).not.toHaveProperty('consumers');
  });
  it('preserves existing OAuth target redirects unless environment copy was separately selected',()=>{
    const source=inventory(),target=inventory(true),privateSource=structuredClone(source.objects);
    for(const object of privateSource.filter(object=>object.entityType==='credentials'))object.recovery={state:'complete',blockerCodes:[],restorePayload:{...object.payload}};
    const selectedObjectKeys=[objectIdentity(source.objects.find(object=>object.credentialKind==='oauth2')!)],options={includeSecrets:true,includeCredentials:true,credentialKinds:['oauth2'] as const,selectedObjectKeys,privateSourceObjects:privateSource};
    const existing=compilation(source,target,options);expect(existing.state).toBe('ready');
    expect((existing.document!.consumers as any[])[0]).toEqual({id:id(1003),oauth2_credentials:[expect.not.objectContaining({redirect_uris:expect.anything()})]});
    const copy=compilation(source,target,{...options,includeEnvironmentFields:true});expect(copy.state).toBe('ready');
    expect((copy.document!.consumers as any[])[0].oauth2_credentials[0].redirect_uris).toEqual(['https://fixture.invalid/callback']);
    target.objects=target.objects.filter(object=>object.credentialKind!=='oauth2');
    const missing=compilation(source,target,{...options,allocateNativeId:()=>id(900)});expect(missing.state).toBe('blocked');
    const explicit=compilation(source,target,{...options,allocateNativeId:()=>id(900),fieldOverrides:{[selectedObjectKeys[0]]:{redirect_uris:['https://target.invalid/callback']}}});
    expect(explicit.state).toBe('ready');expect((explicit.document!.consumers as any[])[0].oauth2_credentials[0]).toMatchObject({id:id(900),redirect_uris:['https://target.invalid/callback']});
  });
  it.each([[],['key-auth','key-auth'],['unknown'],['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls','key-auth']].map(credentialKinds=>({credentialKinds})))('rejects malformed credential-type selections $credentialKinds',({credentialKinds})=>{
    reject(()=>compilation(inventory(),inventory(true),{includeCredentials:true,credentialKinds:credentialKinds as any}),'GOVERNANCE_COMPARISON_INVALID_CREDENTIAL_KINDS');
  });
  it('requires explicit credential inclusion before accepting a credential-type selection',()=>{
    reject(()=>compilation(inventory(),inventory(true),{credentialKinds:['key-auth']}),'GOVERNANCE_COMPARISON_INVALID_CREDENTIAL_KINDS');
  });
  it('does not accept secret target overrides through default safe policy',()=>{
    const source=inventory(),plugin=entity(source,'plugins');(source.pluginSchemas['correlation-id']as any).fields.push({token:{type:'string'}});const target=inventory(true);target.pluginSchemas=structuredClone(source.pluginSchemas);
    const result=compilation(source,target,{fieldOverrides:{[objectIdentity(plugin)]:{config:{token:'fixture-override-secret'}}}});
    expect(result.state).toBe('blocked');expect(result.yaml).toBeNull();expect(result.blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_SECRET_OVERRIDE_CONFIRMATION_REQUIRED')).toBe(true);
  });
  it('requires explicit match criteria when a new Route only had omitted environment matchers',()=>{
    const source=inventory();source.objects=[entity(source,'services'),entity(source,'routes')];entity(source,'services').payload.client_certificate=null;
    entity(source,'routes').payload.paths=[];entity(source,'routes').payload.hosts=['source.invalid'];entity(source,'routes').payload.headers={};entity(source,'routes').payload.sources=[];
    const target=inventory(true);target.objects=[];
    const result=compilation(source,target,{fieldOverrides:{[objectIdentity(entity(source,'services'))]:{host:'target.invalid'}},allocateNativeId:key=>key.startsWith('services:')?id(750):id(751)});
    expect(result.blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_ROUTE_MATCH_REQUIRED')).toBe(true);
  });
  it('blocks parent/address rewrites for an existing Target even when aliases or explicit mappings align it',()=>{
    const source=inventory(),target=inventory(true),sourceTarget=entity(source,'targets'),targetTarget=entity(target,'targets');
    targetTarget.payload.target='target.internal:80';
    const aliases={[objectIdentity(sourceTarget)]:'backend',[objectIdentity(targetTarget)]:'backend'};
    const result=compilation(source,target,{includeEnvironmentFields:true,identityAliases:aliases});
    expect(result.blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_TARGET_ADDRESS_IMMUTABLE')).toBe(true);
  });
  it('rejects forged mapping, overrides outside selection, read-only identity and duplicate ID allocation',()=>{
    const source=inventory(),target=inventory(true),svc=entity(source,'services'),key=objectIdentity(svc);
    expect(compilation(source,target,{mapping:{[key]:id(9999)}}).blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_MAPPING_NOT_CAPTURED')).toBe(true);
    reject(()=>compilation(source,target,{selectedServiceIds:[svc.nativeId],fieldOverrides:{'consumers:missing':{username:'x'}}}),'GOVERNANCE_PROMOTE_OVERRIDE_OUTSIDE_SELECTION');
    reject(()=>compilation(source,target,{fieldOverrides:{[key]:{id:id(730)}}}),'GOVERNANCE_PROMOTE_OVERRIDE_IDENTITY');
    const empty=inventory(true);empty.objects=[];
    reject(()=>compilation(source,empty,{allocateNativeId:()=>id(730)}),'GOVERNANCE_PROMOTE_ALLOCATED_ID_INVALID');
  });
  it('rejects cross-version/schema mismatch and plugins absent from the actual target enabled list',()=>{
    const source=inventory(),target=inventory(true);target.version='2.8.0';
    expect(compilation(source,target).blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_VERSION_CAPABILITY_MISMATCH')).toBe(true);
    target.version='1.5.1';(target.schemas.services as any).fields.find((field:any)=>field.retries).retries.one_of=[0];
    expect(compilation(source,target).blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_SCHEMA_INCOMPATIBLE')).toBe(true);
    target.schemas=schemas().entities;target.enabledPlugins=[];
    expect(compilation(source,target).blockers.some(item=>item.code==='GOVERNANCE_PLUGIN_UNAVAILABLE'||item.code==='GOVERNANCE_PROMOTE_PLUGIN_UNAVAILABLE')).toBe(true);
  });
  it('requires full authorized source and target coverage and rejects a same-scope promotion',()=>{
    const source=inventory(),target=inventory(true);target.projection=true;
    expect(compilation(source,target).state).toBe('blocked');expect(compilation(source,source).blockers.some(item=>item.code==='GOVERNANCE_PROMOTE_SAME_SCOPE')).toBe(true);
  });
  it('does not promote unknown custom plugin config or scripts as harmless strings',()=>{
    const source=inventory(),target=inventory(true),plugin=entity(source,'plugins');
    plugin.payload.name='synthetic-custom';plugin.payload.config={code:'return secret',endpoint:'https://source.invalid',opaque:'sensitive'};
    entity(target,'plugins').payload.name='synthetic-custom';entity(target,'plugins').payload.config={};
    const custom={fields:[{opaque:{type:'string'}},{endpoint:{type:'string'}},{code:{type:'string'}}]};source.pluginSchemas={'synthetic-custom':custom};target.pluginSchemas=structuredClone(source.pluginSchemas);
    source.enabledPlugins=['synthetic-custom'];target.enabledPlugins=['synthetic-custom'];
    const result=compilation(source,target);expect(result.state).toBe('ready');expect(result.yaml).not.toContain('sensitive');expect(result.yaml).not.toContain('return secret');
    expect(result.exclusions.some(item=>item.reason==='unknown_plugin')).toBe(true);
  });
});
