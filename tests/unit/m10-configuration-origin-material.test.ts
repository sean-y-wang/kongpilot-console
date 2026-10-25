import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ConfigurationOriginService} from '../../apps/console-api/src/modules/configuration/configuration-origin.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {encodeTag} from '../../apps/console-api/src/infrastructure/kong/tags';
import {compilePromoteDocument,promotionConsumerClosure} from '../../apps/console-api/src/modules/governance/promote-compiler';
import {objectIdentity} from '../../apps/console-api/src/modules/governance/logical-graph';
import {graph,id} from './m8-config-transfer.fixture';
import type {ConfigPlan} from '../../apps/console-api/src/modules/configuration/configuration.types';
import type {ComparisonInventory} from '../../apps/console-api/src/modules/governance/comparison-types';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
const ref={version:1 as const,kind:'governance-promote' as const,originId:id(300),materialHmac:'d'.repeat(64)};
function component(usage:Record<string,number>={calls:40,pages:8,records:30,bytes:5000}){
  const secrets=new SecretService(),context={peek:()=>null,promotionRecoveryUsage:vi.fn(async()=>({calls:20,pages:6,records:20,bytes:5000,deadline:Date.now()+120000}))},origin=new ConfigurationOriginService({}as any,secrets,context as any);
  // This is exclusively a compiler/budget fixture. It cannot mint a genuine
  // origin or ConfigAccess proof; the dedicated security tests exercise those.
  vi.spyOn(origin as any,'current').mockReturnValue({compilationInputs:{source:{usage}}});return{origin,secrets,context};
}
const plan=(packets:number):ConfigPlan=>({steps:Array.from({length:packets},()=>({nativeRequests:[{method:'PATCH'}]}))}as any);

describe('M10 private comparison material view',()=>{
  it.each(['source','target']as const)('accepts the actual %s Governance/M8 adapter labels while preserving every sealed raw observation',side=>{
    const{origin,secrets}=component(),captured=graph();captured.adapterVersion='kong-oss-1.5-v1';captured.schemas.adapterVersion=captured.adapterVersion;
    for(const object of captured.objects)object.beforeHmac=secrets.fingerprint(object.payload);
    const roots=captured.objects.filter(object=>object.entityType!=='credentials'),inventory={objects:structuredClone(roots),scope:structuredClone(captured.scope),version:captured.kongVersion},
      seals=Object.fromEntries(roots.map(object=>[`${object.entityType}:${object.nativeId}`,object.beforeHmac])),loaded={[side]:inventory,[`${side}NativeFingerprints`]:seals},before=structuredClone({captured,inventory,seals});
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,captured,side)).not.toThrow();expect({captured,inventory,seals}).toEqual(before);
    const certificate=captured.objects.find(object=>object.entityType==='certificates')!;certificate.payload.key='fixture-real-label-hidden-native-rotation';certificate.beforeHmac=secrets.fingerprint(certificate.payload);
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,captured,side)).toThrow(expect.objectContaining({response:expect.objectContaining({code:side==='source'?'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED':'CONFIGURATION_ORIGIN_TARGET_CHANGED'})}));
  });
  it.each(['unknown-capture','unknown-comparison','matching-unknown','capture-cross-version','comparison-cross-version','matching-non-1.5-version']as const)('refuses %s despite otherwise exact real adapter raw material',mode=>{
    const{origin,secrets}=component(),captured=graph();captured.adapterVersion='kong-oss-1.5-v1';for(const object of captured.objects)object.beforeHmac=secrets.fingerprint(object.payload);
    const roots=captured.objects.filter(object=>object.entityType!=='credentials'),inventory={objects:structuredClone(roots),scope:structuredClone(captured.scope),version:captured.kongVersion,adapterVersion:'kong-1.5'},
      loaded={source:inventory,sourceNativeFingerprints:Object.fromEntries(roots.map(object=>[`${object.entityType}:${object.nativeId}`,object.beforeHmac]))};
    if(mode==='unknown-capture'||mode==='matching-unknown')captured.adapterVersion='unverified-adapter';if(mode==='unknown-comparison'||mode==='matching-unknown')inventory.adapterVersion='unverified-adapter';
    if(mode==='capture-cross-version')captured.kongVersion='1.5.2';if(mode==='comparison-cross-version')inventory.version='1.5.2';if(mode==='matching-non-1.5-version')captured.kongVersion=inventory.version='2.0.0';
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,captured)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED'})}));
  });
  it('decodes actual native ownership tags for private comparison while preserving raw source and recovery HMAC material',()=>{
    const {origin}=component(),source=graph();
    for(const object of source.objects){object.payload.tags=[encodeTag('workspace:source'),encodeTag('team:pay')];if(object.recovery.restorePayload)object.recovery.restorePayload.tags=structuredClone(object.payload.tags);}
    const raw=structuredClone(source),view=(origin as any).privateObjects(source);
    expect(view[0].payload.tags).toEqual(['workspace:source','team:pay']);
    expect(view.find((object:any)=>object.credentialKind==='basic-auth').recovery.restorePayload.tags).toEqual(['workspace:source','team:pay']);expect(source).toEqual(raw);
    const publicInventory:ComparisonInventory={scope:source.scope,objects:view.filter((object:any)=>object.entityType!=='credentials').map((object:any)=>({...object,payload:{...object.payload},sensitiveFields:[]})),
      schemas:source.schemas.entities,pluginSchemas:source.schemas.plugins,enabledPlugins:source.schemas.enabledPlugins,version:source.kongVersion,completeness:'complete',projection:false};
    const target=structuredClone(publicInventory);target.scope={...target.scope,clusterId:id(401),workspaceId:id(400),transportScope:'test-target'};
    const consumer=publicInventory.objects.find(object=>object.entityType==='consumers')!;
    const result=compilePromoteDocument(publicInventory,target,{targetWorkspaceCode:'target',includeSecrets:true,includeCredentials:true,credentialKinds:['basic-auth'],privateSourceObjects:view,selectedObjectKeys:[objectIdentity(consumer)],allocateNativeId:()=>id(402)});
    expect(result.state).toBe('ready');expect((result.document!.consumers as any[])[0].basicauth_credentials[0]).toMatchObject({id:id(402),password:'fixture-not-a-live-password',tags:['team:pay','workspace:target']});
    expect(source).toEqual(raw);
  });
  it('keeps username and custom_id identity namespaces separate in keyed credential aliases',()=>{
    const {origin}=component(),make=(custom:boolean)=>({objects:[{entityType:'consumers',nativeId:id(custom?2:1),payload:custom?{username:null,custom_id:'same'}:{username:'same',custom_id:null}},
      {entityType:'credentials',credentialKind:'key-auth',nativeId:id(custom?4:3),parentId:id(custom?2:1),payload:{key:'fixture-only-key'}}]});
    const source=make(false),target=make(true),aliases=(origin as any).credentialAliases(source,target),values=Object.values(aliases);
    expect(new Set(values).size).toBe(2);expect(JSON.stringify(aliases)).not.toContain('fixture-only-key');expect(JSON.stringify(aliases)).not.toContain('same');
  });
  it('rejects a secret-only native change between the original safe comparison and the private M8 capture',()=>{
    const {origin,secrets}=component(),source=graph();for(const object of source.objects)object.beforeHmac=secrets.fingerprint(object.payload);
    const roots=source.objects.filter(object=>object.entityType!=='credentials'),nativeFingerprints=Object.fromEntries(roots.map(object=>[`${object.entityType}:${object.nativeId}`,object.beforeHmac]));
    const safe=roots.map(object=>({entityType:object.entityType,nativeId:object.nativeId,payload:object.entityType==='certificates'?{id:object.nativeId,tags:object.payload.tags}:structuredClone(object.payload)}));
    const loaded={source:{objects:safe,scope:source.scope,version:source.kongVersion,adapterVersion:source.adapterVersion},sourceNativeFingerprints:nativeFingerprints};
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,source)).not.toThrow();
    const certificate=source.objects.find(object=>object.entityType==='certificates')!;certificate.payload.key='fixture-changed-native-key';certificate.beforeHmac=secrets.fingerprint(certificate.payload);
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,source)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED'})}));
    expect(JSON.stringify(safe)).not.toContain('fixture-changed-native-key');
  });
  it('verifies the private target baseline against the original target raw seal before keeping or replacing protected fields',()=>{
    const {origin,secrets}=component(),target=graph();for(const object of target.objects)object.beforeHmac=secrets.fingerprint(object.payload);
    const roots=target.objects.filter(object=>object.entityType!=='credentials'),nativeFingerprints=Object.fromEntries(roots.map(object=>[`${object.entityType}:${object.nativeId}`,object.beforeHmac]));
    const safe=roots.map(object=>({entityType:object.entityType,nativeId:object.nativeId,payload:object.entityType==='certificates'?{id:object.nativeId,tags:object.payload.tags}:structuredClone(object.payload)}));
    const loaded={target:{objects:safe,scope:target.scope,version:target.kongVersion,adapterVersion:target.adapterVersion},targetNativeFingerprints:nativeFingerprints};
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,target,'target')).not.toThrow();
    const certificate=target.objects.find(object=>object.entityType==='certificates')!;certificate.payload.key='fixture-target-changed-native-key';certificate.beforeHmac=secrets.fingerprint(certificate.payload);
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,target,'target')).toThrow(expect.objectContaining({response:expect.objectContaining({code:'CONFIGURATION_ORIGIN_TARGET_CHANGED'})}));
    expect(JSON.stringify(safe)).not.toContain('fixture-target-changed-native-key');
  });
  it.each(['missing-object','missing-seal','changed-payload']as const)('rejects %s for every original private root including read-only references',mode=>{
    const {origin,secrets}=component(),source=graph();for(const object of source.objects)object.beforeHmac=secrets.fingerprint(object.payload);
    const roots=source.objects.filter(object=>object.entityType!=='credentials'),reference=roots.find(object=>object.entityType==='certificates')!;reference.referenceOnly=true;
    const nativeFingerprints=Object.fromEntries(roots.map(object=>[`${object.entityType}:${object.nativeId}`,object.beforeHmac])),loaded={source:{objects:structuredClone(roots),scope:source.scope,version:source.kongVersion,adapterVersion:source.adapterVersion},sourceNativeFingerprints:nativeFingerprints};
    if(mode==='missing-object')source.objects=source.objects.filter(object=>object!==reference);
    if(mode==='missing-seal')delete nativeFingerprints[`certificates:${reference.nativeId}`];
    if(mode==='changed-payload')reference.payload.key='fixture-raw-tamper-with-old-before-hmac';
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,source)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED'})}));
  });
  it.each(['cluster','workspace','transport','roots','incomplete','unverified','version']as const)('rejects a private target with changed %s even when raw objects are identical',mode=>{
    const {origin,secrets}=component(),target=graph();for(const object of target.objects)object.beforeHmac=secrets.fingerprint(object.payload);
    const roots=target.objects.filter(object=>object.entityType!=='credentials'),loaded={target:{objects:structuredClone(roots),scope:structuredClone(target.scope),version:target.kongVersion,adapterVersion:target.adapterVersion},targetNativeFingerprints:Object.fromEntries(roots.map(object=>[`${object.entityType}:${object.nativeId}`,object.beforeHmac]))};
    if(mode==='cluster')target.scope.clusterId=id(555);if(mode==='workspace')target.scope.workspaceId=id(555);if(mode==='transport')target.scope.transportScope='foreign-native-plane';if(mode==='roots')target.scope.rootIds=[id(555)];
    if(mode==='incomplete')target.completeness='incomplete';if(mode==='unverified')target.consistency='unverified';if(mode==='version')target.kongVersion='1.5.2';
    expect(()=>(origin as any).assertRecoveryRootObservation(loaded,target,'target')).toThrow(expect.objectContaining({response:expect.objectContaining({code:'CONFIGURATION_ORIGIN_TARGET_CHANGED'})}));
  });
  it('narrows private credentials to the selected Consumer while keeping the six-kind child graph available',()=>{
    const source=graph(),inventory:ComparisonInventory={scope:source.scope,objects:source.objects.filter(object=>object.entityType!=='credentials'),schemas:source.schemas.entities,
      pluginSchemas:source.schemas.plugins,enabledPlugins:source.schemas.enabledPlugins,version:source.kongVersion,completeness:'complete',projection:false};
    const selected=new Set(promotionConsumerClosure(inventory,{targetWorkspaceCode:'target',includeSecrets:true,includeCredentials:true,credentialKinds:['key-auth'],selectedObjectKeys:[`consumers:${id(3)}`]}));
    expect([...selected]).toEqual([id(3)]);
    const credentialKinds=source.objects.filter(object=>object.entityType==='credentials'&&selected.has(object.parentId!)).map(object=>object.credentialKind);
    expect(credentialKinds).toEqual(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
  });
});

describe('M10 origin preflight budget reserve',()=>{
  it('accepts a bounded packet and rejects a larger plan while reserving all three future GET attempts',async()=>{
    const {origin}=component();await expect(origin.assertExecutionBudget(ref,plan(1))).resolves.toBeUndefined();
    await expect(origin.assertExecutionBudget(ref,plan(2))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED',budget:{nativePackets:2,readRetriesReserved:3,estimated:{calls:520},limits:{calls:500}}}});
  });
  it('uses exact existing private counters and includes point reads plus every credential EOF round before the first write',async()=>{
    const {origin,context}=component({calls:50,pages:8,records:30,bytes:5000}),opaque=Object.freeze({}),source=graph();
    source.collections=[...source.collections,...['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].map(kind=>({entityType:'credentials',parentId:id(3),pageCount:1,credentialKind:kind})) as any];
    const collections=new Map(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].map(kind=>[`/consumers/${id(3)}/${kind}`,new Set()]));
    (origin as any).recoveryClaims.set(opaque,{graph:source,collections,points:new Map(source.objects.filter(object=>object.entityType==='credentials').map(object=>[`/consumers/${object.parentId}/${object.credentialKind}/${object.nativeId}`,object.beforeHmac]))});
    await (origin as any).recoveryByRun.run(new Map([[ref.originId,opaque]]),async()=>{
      await expect(origin.assertExecutionBudget(ref,plan(1))).resolves.toBeUndefined();
      context.promotionRecoveryUsage.mockResolvedValue({calls:40,pages:99,records:20,bytes:5000,deadline:Date.now()+120000});
      await expect(origin.assertExecutionBudget(ref,plan(1))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED',budget:{privateUsage:{pages:99},estimated:{pages:135}}}});
    });expect(context.promotionRecoveryUsage).toHaveBeenCalledWith(opaque);
  });
  it('approved selected-object fence: a 5-service multi-packet promote fits the unchanged 500-call cap, larger plans still fail closed',async()=>{
    const {origin}=component({calls:37,pages:12,records:40,bytes:20000});
    const services=Array.from({length:5},(_,i)=>({entityType:'services',nativeId:`0000000${i}-0000-4000-8000-000000000000`,payload:{name:`svc-${i}`,host:'h'}}));
    vi.spyOn(origin as any,'current').mockReturnValue({compilationInputs:{source:{usage:{calls:37,pages:12,records:40,bytes:20000},objects:services}}});
    vi.spyOn(origin as any,'selectedSourceObjects').mockReturnValue(services.map(({entityType,nativeId})=>({entityType,nativeId})));
    await expect(origin.assertExecutionBudget(ref,plan(5))).resolves.toBeUndefined(); // previous full-rescan estimate: 37*31=1147 > 500
    await expect(origin.assertExecutionBudget(ref,plan(80))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED',budget:{nativePackets:80,readRetriesReserved:3,estimated:{calls:37+160*3},limits:{calls:500}}}});
  });
  it('without a selected-object fence the full-rescan reserve is unchanged',async()=>{
    const {origin}=component({calls:37,pages:12,records:40,bytes:20000});
    await expect(origin.assertExecutionBudget(ref,plan(5))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED',budget:{estimated:{calls:37*31}}}});
  });
  it('rejects an expired private meter without creating or extending a recovery handle',async()=>{
    const {origin,context}=component(),opaque=Object.freeze({});(origin as any).recoveryClaims.set(opaque,{graph:graph(),points:new Map(),collections:new Map()});
    context.promotionRecoveryUsage.mockResolvedValue({calls:0,pages:0,records:0,bytes:0,deadline:Date.now()-1});
    await (origin as any).recoveryByRun.run(new Map([[ref.originId,opaque]]),async()=>{
      await expect(origin.assertExecutionBudget(ref,plan(1))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED'}});
    });expect(context.promotionRecoveryUsage).toHaveBeenCalledOnce();
  });
});
