import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import { PRODUCTION_UI_ACTIONS, PRODUCTION_PLUGIN_NAMES, productionPluginConfigurations } from './lib/production-ui-fixtures.mjs';
import { assertSchemaInput, schemaUiTrace, schemaDomKind, schemaMarker } from './lib/production-schema-fill.mjs';
import { productionExpectedBody, productionEditorSchema } from './lib/production-form-model';
import { augmentFormSchema, pluginMetadata } from '../../apps/console-api/src/modules/plugin-center/plugin-metadata';
import { analyzeKongSchema } from '../../apps/console-web/src/components/kong-schema-rules';
import { canonicalUi, productionSha, validateProductionHandoff, createProductionUiJournal, proveProductionActor, revalidateProductionAuthority, armProductionUi, beforeProductionUiPacket, observeProductionUiAck, productionAttemptFor, confirmProductionUiReceipt, productionReceiptPath, productionUiSecrets, proveProductionIsolation, armProductionUiToggle } from './lib/production-ui-journal.mjs';
import { productionCookies } from './lib/production-ui-storage.mjs';
import { assertProductionKnownPrefix, pauseProductionUiIfNeeded, prepareProductionUnusedTail, productionActionAlreadyCompleted, PRODUCTION_UI_PAUSE_CODE } from './lib/production-ui-continuation.mjs';

const id = (n:number) => `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const read = (path:string) => readFileSync(path,'utf8');
const now=Date.parse('2026-10-11T00:00:00Z');
function reference(){
  const report={allPassed:true,failed:0,unknownWrites:0,testTag:'prod-ui-aabbccdd',origin:'https://synthetic-console.invalid',clusterId:id(1),workspaceId:id(2),actorId:id(3),sessionId:id(4),sessionExpiresAt:new Date(now+900000).toISOString(),m8ClosureComplete:true,productionHttpsVerified:true,freshScopeVerified:true},bytes=Buffer.from(JSON.stringify(report));
  const ref={version:1,milestone:'M0-M8-production-ui',phase:'ready',inFlight:null,testTag:report.testTag,requests:[],secrets:[],pem:{certificate:'-----BEGIN CERTIFICATE----- synthetic source',privateKey:'-----BEGIN PRIVATE KEY----- synthetic source',caCertificate:'-----BEGIN CERTIFICATE----- synthetic CA'},
    uiHandoff:{version:1,phase:'ready',exclusiveRuntimeOwner:'production-ui',testTag:report.testTag,origin:report.origin,clusterId:id(1),workspaceId:id(2),clusterLabel:'Synthetic source cluster',workspaceName:'Synthetic source workspace',executionMode:'direct',isolatedAcceptanceCluster:true,approvedActions:[...PRODUCTION_UI_ACTIONS],securityReportPath:'artifacts/production/production-ui-handoff.json',securityReportSha256:productionSha(bytes)},
    session:{user:{id:id(3),permissionsVersion:'source-v1',capabilities:{platformAdmin:true}},sid:id(4),cookie:'kongos_access=source-access; kongos_refresh=source-refresh; kongos_csrf=source-csrf',csrf:'synthetic-csrf-0123456789',expiresAt:new Date(now+900000).toISOString(),currentSessionVerified:true,signedAccessVerified:true,currentUserProven:true}};
  return {ref,report,bytes};
}
function journal(){const f=reference(),config=validateProductionHandoff(f.ref,f.report,f.bytes,now),j=createProductionUiJournal(config,now);proveProductionActor(j,{user:f.ref.session.user,csrfToken:j.session.csrf});return j;}
function armed(j:any){armProductionUi(j,{action:'carrier.create',method:'POST',path:`/api/v1/clusters/${j.cid}/entities/services`,body:{name:'source-carrier',host:'127.0.0.1',port:9},entityType:'services',mutationAction:'create'},()=>{});return j;}
function packet(j:any,key=id(10)){return {method:'POST',url:`${j.origin}/api/v1/clusters/${j.cid}/entities/services?workspaceId=${j.wid}`,rawBody:JSON.stringify({name:'source-carrier',host:'127.0.0.1',port:9}),headers:{'x-idempotency-key':key,'x-csrf-token':j.session.csrf,cookie:'kongos_access=source-access; kongos_csrf=source-csrf'}};}
function ack(j:any,p:any){const a=beforeProductionUiPacket(j,p,productionCookies(j.origin,j.session.cookie),()=>{},now);observeProductionUiAck(j,a,{status:201,requestId:id(11),data:{entity:{id:id(12),name:'source-carrier',host:'127.0.0.1',port:9}}},()=>{});return a;}
function receipt(j:any){return{id:id(20),actor_id:j.actorId,cluster_id:j.cid,workspace_id:j.wid,entity_type:'services',entity_id:id(12),action:'create',state:'succeeded',remote_started:true,remote_completed:true,error_code:null,safe_result:{id:id(12),name:'source-carrier'}};}

describe('fresh production UI source-only acceptance',()=>{
  it('accepts catalog revision drift only after actual current identity and unchanged full grants are proven',()=>{
    const j=journal(),old=j.session.user.permissionsVersion,data={user:{...j.session.user,permissionsVersion:'catalog-v2'},csrfToken:j.session.csrf};
    revalidateProductionAuthority(j,data,id(100),'catalog-v2');expect(j.currentPermissionsVersion).toBe('catalog-v2');expect(j.session.user.permissionsVersion).toBe(old);expect(j.authorityRevalidations).toHaveLength(1);
    for(const mutate of[(d:any)=>d.user.id=id(99),(d:any)=>d.csrfToken='changed',(d:any)=>d.user.capabilities={platformAdmin:true,modules:{services:['read']}},(d:any)=>d.user.permissionsVersion='another-revision']){
      const changed=structuredClone(data);mutate(changed);expect(()=>revalidateProductionAuthority(j,changed,id(101),'catalog-v2')).toThrow('PRODUCTION_CURRENT_UNCHANGED_AUTHORITY_REQUIRED');
    }
    expect(j.authorityRevalidations).toHaveLength(1);
  });
  it('derives exactly actual 34 fixtures without executing historical entry or environment',()=>{
    const source=read('tests/security/live-m2.mjs'),file=ts.createSourceFile('live-m2.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS),node=file.statements.find((row:any)=>ts.isFunctionDeclaration(row)&&row.name?.text==='configurations')!;
    const actual=vm.runInNewContext(`(${node.getText(file)})()`,{secret:(label:string)=>`synthetic-${label}`}),fresh=productionPluginConfigurations((label:string)=>`synthetic-${label}`);
    for(const pair of Object.values(actual) as any[])for(const config of pair){
      for(const key of ['host','http_endpoint','endpoint','ldap_host'])if(typeof config[key]==='string')config[key]=config[key].replace(/127\.0\.0\.1/g,'198.51.100.1');
    }
    expect(canonicalUi(fresh)).toBe(canonicalUi(actual));expect(PRODUCTION_PLUGIN_NAMES).toHaveLength(34);expect(new Set(PRODUCTION_PLUGIN_NAMES).size).toBe(34);
    expect(PRODUCTION_UI_ACTIONS).toHaveLength(178);expect(PRODUCTION_UI_ACTIONS.filter((x:string)=>x.startsWith('entity.'))).toHaveLength(32);expect(PRODUCTION_UI_ACTIONS.filter((x:string)=>x.startsWith('plugin.'))).toHaveLength(136);expect(PRODUCTION_UI_ACTIONS.at(-1)).toBe('cleanup.carrier.archive');
    for(const path of ['tests/security/production-ui-lifecycle.mjs','tests/security/lib/production-ui-fixtures.mjs','tests/security/lib/production-ui-journal.mjs','tests/security/lib/production-ui-storage.mjs']){const code=read(path);expect(code).not.toMatch(/loadEnvFile|['"]\.env(?:[.'"]|$)|from\s+['"].*live-m2|security-M2|\.post\(/);}
  });
  it('uses actual recorded 1.5 schemas and product payload producer for all 34 recursive config forms',()=>{
    const root=JSON.parse(read('tests/fixtures/kong-1.5.1/schema-plugins.json')),pairs=productionPluginConfigurations((label:string)=>`synthetic-${label}`);
    for(const name of PRODUCTION_PLUGIN_NAMES){const form=augmentFormSchema(name,JSON.parse(read(`tests/fixtures/kong-1.5.1/plugin-schema-${name}.json`))),meta=pluginMetadata(name),initial={name,enabled:false,...(name==='kubernetes-sidecar-injector'?{}:{service:{id:id(99)}}),config:pairs[name][0],tags:['source-tag']};
      const schema=productionEditorSchema(root,form,PRODUCTION_PLUGIN_NAMES);expect(()=>assertSchemaInput(schema,initial)).not.toThrow();const body=productionExpectedBody(root,initial,undefined,form),errors=analyzeKongSchema(schema,body).issues;expect(errors,`${name} actual schema errors`).toEqual([]);expect(body.enabled).toBe(false);expect(meta.constraints.service).toBe(name!=='kubernetes-sidecar-injector');
      const changed={name,enabled:false,config:pairs[name][1],tags:['source-edited']},edited=productionExpectedBody(root,changed,{...body,id:id(90)},form);expect(edited.tags).toEqual(['source-edited']);expect(edited.enabled).toBe(false);
    }
    const statsd=augmentFormSchema('statsd',JSON.parse(read('tests/fixtures/kong-1.5.1/plugin-schema-statsd.json'))),statsTrace=schemaUiTrace(statsd,pairs.statsd[0],['config']);expect(statsTrace).toContainEqual({path:['config','metrics',0,'stat_type'],kind:'select',marker:'schema-field-config-metrics-0-stat_type'});
    const rate=augmentFormSchema('response-ratelimiting',JSON.parse(read('tests/fixtures/kong-1.5.1/plugin-schema-response-ratelimiting.json'))),rateTrace=schemaUiTrace(rate,pairs['response-ratelimiting'][0],['config']);expect(rateTrace.some((x:any)=>canonicalUi(x.path)===canonicalUi(['config','limits',0,'value','minute']))).toBe(true);
    expect(schemaDomKind({type:'array',elements:{type:'string'}})).toBe('list');expect(schemaDomKind({type:'set',elements:{type:'string'}})).toBe('select-list');expect(schemaMarker(['config','metrics',0,'name'])).toBe('schema-field-config-metrics-0-name');
    const source=read('apps/console-web/src/components/KongSchemaForm.tsx');expect(source).toContain("`schema-field-${actualPath.join('-')}`");expect(source).toContain('className="schema-map-row"');expect(source).toContain('schema-record-${[...actualPath, row.name].join');
  });
  it('preserves genuine edit defaults, original secrets and map/array record wire values using real product helpers',()=>{
    const root=JSON.parse(read('tests/fixtures/kong-1.5.1/schema-plugins.json')),form=augmentFormSchema('aws-lambda',JSON.parse(read('tests/fixtures/kong-1.5.1/plugin-schema-aws-lambda.json'))),body=productionExpectedBody(root,{name:'aws-lambda',enabled:false,config:{aws_key:'synthetic-aws-key',aws_secret:'synthetic-aws-secret',aws_region:'us-east-1',function_name:'source-disabled'}},undefined,form);
    const edited=productionExpectedBody(root,{name:'aws-lambda',enabled:false,config:{timeout:1001},tags:['source-edit']},{...body,id:id(9),config:{...body.config,aws_key:'[REDACTED:1111111111111111]',aws_secret:'[REDACTED:2222222222222222]'},tags:['source-tag','kos-ws-owned']},form);
    expect(edited.config.aws_key).toBeUndefined();expect(edited.config.aws_secret).toBeUndefined();expect(edited.config.timeout).toBe(1001);expect(edited.tags).toEqual(['source-edit']);expect(JSON.stringify(edited)).not.toContain('REDACTED');
    const s={fields:[{config:{type:'record',fields:[{metrics:{type:'array',elements:{type:'record',fields:[{name:{type:'string'}},{sample_rate:{type:'number',default:1}},{enabled:{type:'boolean',default:false}}]}}},{limits:{type:'map',values:{type:'record',fields:[{minute:{type:'integer'}},{second:{type:'integer',default:0}}]}}}]}}]};
    const payload=productionExpectedBody(s,{config:{metrics:[{name:'source'}],limits:{fixture:{minute:10}}}});expect(payload.config.metrics).toEqual([{name:'source',sample_rate:1,enabled:false}]);expect(payload.config.limits.fixture).toEqual({minute:10,second:0});
  });
  it('rejects foreign/mutable/expired/failed production handoffs before any launch or write',()=>{
    for(const change of [(f:any)=>f.ref.uiHandoff.origin='http://synthetic-console.invalid',(f:any)=>f.ref.uiHandoff.origin='https://user:password@synthetic-console.invalid',(f:any)=>f.ref.uiHandoff.origin+='?query=1',(f:any)=>f.ref.uiHandoff.securityReportPath='artifacts/M8/security-live-final.json',(f:any)=>f.ref.uiHandoff.workspaceId=id(88),(f:any)=>f.ref.uiHandoff.approvedActions.pop(),(f:any)=>f.ref.session.expiresAt=new Date(now+299000).toISOString(),(f:any)=>f.ref.session.signedAccessVerified=false,(f:any)=>f.ref.requests.push({state:'response_unknown'}),(f:any)=>f.report.allPassed=false,(f:any)=>f.report.m8ClosureComplete=false]){const f=reference();change(f);expect(()=>validateProductionHandoff(f.ref,f.report,f.bytes,now)).toThrow();}
    const source=read('tests/security/production-ui-lifecycle.mjs'),ast=ts.createSourceFile('runner.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS),guard=ast.statements.filter(ts.isIfStatement).slice(0,2).map(node=>node.getText(ast)).join('\n'),privateReader=vi.fn();
    for(const env of [{},{PRODUCTION_UI_EXCLUSIVE_READY:'true',PRODUCTION_UI_UNUSED_TAIL_READY:'true'}])expect(()=>vm.runInNewContext(guard,{process:{env},readProductionUiReference:privateReader})).toThrow();expect(privateReader).not.toHaveBeenCalled();
  });
  it('durably captures original actor/SID/scope/raw body/key before packet and stops on save failure or duplicate',()=>{
    const j=armed(journal()),p=packet(j),events:string[]=[];beforeProductionUiPacket(j,p,productionCookies(j.origin,j.session.cookie),(snapshot:any)=>{expect(snapshot.attempts[0].state).toBe('prepared');expect(snapshot.attempts[0].rawBody).toBe(p.rawBody);expect(snapshot.attempts[0].actorId).toBe(j.actorId);expect(snapshot.attempts[0].sessionId).toBe(j.sessionId);events.push('fsync');},now);events.push('transport');expect(events).toEqual(['fsync','transport']);expect(productionAttemptFor(j,p)).toBe(j.attempts[0]);expect(productionAttemptFor(j,{...p,rawBody:'{}'})).toBeUndefined();expect(()=>beforeProductionUiPacket(j,p,productionCookies(j.origin,j.session.cookie),()=>{},now)).toThrow();expect(j.phase).toBe('stopped-without-replay');
    const broken=armed(journal());expect(()=>beforeProductionUiPacket(broken,packet(broken),productionCookies(broken.origin,broken.session.cookie),()=>{throw Error('synthetic-fsync-failure');},now)).toThrow();expect(broken.phase).toBe('stopped-without-replay');expect(broken.nextIndex).toBe(0);
  });
  it('runs actual fsync writer and actual route boundary in memory: 0600 atomic durability precedes continue and save failure sends nothing',async()=>{
    const extract=(path:string,name:string)=>{const text=read(path),file=ts.createSourceFile(path,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS),node=file.statements.find((row:any)=>ts.isFunctionDeclaration(row)&&row.name?.text===name)!;return node.getText(file).replace(/^export\s+/,'');};
    for(const broken of [false,true]){
      const events:string[]=[],j=armed(journal()),p=packet(j);let handler:any,fd=0;
      const writer=vm.runInNewContext(`(${extract('tests/security/lib/production-ui-storage.mjs','durableProductionJson')})`,{dirname:()=>'/synthetic-source',mkdirSync:()=>{},Buffer,randomUUID:()=> 'source-only-tmp',constants:{O_WRONLY:1,O_CREAT:2,O_EXCL:4,O_NOFOLLOW:8,O_RDONLY:16},openSync:(_path:string,_flags:number,mode?:number)=>{if(mode!==undefined){expect(mode).toBe(0o600);events.push('open600');}return ++fd;},writeFileSync:()=>{events.push('write');if(broken)throw Error('source-fsync-failure');},fsyncSync:()=>events.push('fsync'),closeSync:()=>events.push('close'),renameSync:()=>events.push('atomic-rename')});
      const fakeContext={route:async(_glob:string,callback:any)=>{handler=callback;},on:()=>{},cookies:async()=>productionCookies(j.origin,j.session.cookie)},sandbox={context:fakeContext,journal:j,URL,retain:()=>writer('/synthetic-source/private.json',j),beforeProductionUiPacket:(a:any,b:any,c:any,persist:any)=>beforeProductionUiPacket(a,b,c,persist,now),packetForProductionUi:(request:any,headers:any)=>({method:request.method(),url:request.url(),rawBody:request.postData(),headers}),stopProductionUi:vi.fn(),productionAttemptFor:vi.fn(),observeProductionUiAck:vi.fn(),saveReport:vi.fn(),asyncError:null,chain:Promise.resolve()};
      await vm.runInNewContext(`(${extract('tests/security/production-ui-lifecycle.mjs','boundary')})()`,sandbox);
      await handler({request:()=>({method:()=>p.method,url:()=>p.url,postData:()=>p.rawBody,allHeaders:async()=>p.headers}),continue:async()=>events.push('transport'),abort:async()=>events.push('abort')});
      if(broken){expect(events).not.toContain('transport');expect(events.at(-1)).toBe('abort');expect(j.phase).toBe('stopped-without-replay');}
      else{expect(events.filter(x=>x==='fsync')).toHaveLength(2);expect(events.indexOf('atomic-rename')).toBeLessThan(events.indexOf('transport'));expect(events.lastIndexOf('fsync')).toBeLessThan(events.indexOf('transport'));expect(j.attempts[0].state).toBe('prepared');}
    }
  });
  it('rejects unstaged or wrong body/scope/cookie and any refresh/login/Native/toggle endpoint before transport',()=>{
    for(const change of [(p:any)=>p.rawBody='{}',(p:any)=>p.url=p.url.replace(id(2),id(30)),(p:any)=>p.headers['x-csrf-token']='wrong',(p:any)=>p.headers.cookie='kongos_access=wrong; kongos_csrf=source-csrf',(p:any)=>p.method='DELETE',...( ['/api/v1/auth/refresh','/api/v1/auth/login',`/api/v1/clusters/${id(1)}/plugin-center/instances/${id(20)}/toggle`,`/api/v1/clusters/${id(1)}/workflows/${id(20)}/execute`].map(path=>(p:any)=>p.url=`https://synthetic-console.invalid${path}?workspaceId=${id(2)}`))]){const j=armed(journal()),p=packet(j);change(p);expect(()=>beforeProductionUiPacket(j,p,productionCookies(j.origin,j.session.cookie),()=>{},now)).toThrow();expect(j.attempts).toHaveLength(0);expect(j.phase).toBe('stopped-without-replay');}
    const j=journal();expect(()=>beforeProductionUiPacket(j,packet(j),productionCookies(j.origin,j.session.cookie),()=>{},now)).toThrow();
  });
  it('classifies exact capability POST as read-only while retaining its full original packet independently',()=>{
    const j=journal(),p={...packet(j),url:`${j.origin}/api/v1/clusters/${j.cid}/authorization/entity-capabilities?workspaceId=${j.wid}`,rawBody:JSON.stringify({entities:[{type:'services',id:id(22)}]})},a=beforeProductionUiPacket(j,p,productionCookies(j.origin,j.session.cookie),()=>{},now);expect(a.category).toBe('readonly-authorization-review');observeProductionUiAck(j,a,{status:200,requestId:id(23),data:{items:[{type:'services',id:id(22),write:true}],permissionsVersion:'source-v1'}},()=>{});expect(j.nextIndex).toBe(0);expect(j.attempts).toHaveLength(0);expect(j.reviews).toHaveLength(1);expect(j.phase).toBe('active');
    const wrong=journal();expect(()=>beforeProductionUiPacket(wrong,{...p,rawBody:JSON.stringify({entities:[{type:'services',id:id(22)}],confirmed:true})},productionCookies(wrong.origin,wrong.session.cookie),()=>{},now)).toThrow();
  });
  it('requires an original terminal protected receipt after ACK and refuses wrong actor/scope/target/action/key or incomplete execution',()=>{
    const j=armed(journal()),a=ack(j,packet(j));expect(a.state).toBe('acknowledged');expect(j.nextIndex).toBe(0);const path=productionReceiptPath(j,a);confirmProductionUiReceipt(j,a,{method:'GET',url:j.origin+path},receipt(j),id(25),()=>{});expect(j.nextIndex).toBe(1);expect(j.inFlight).toBeNull();expect(a.state).toBe('succeeded');
    for(const change of [(r:any)=>r.actor_id=id(99),(r:any)=>r.workspace_id=id(99),(r:any)=>r.entity_id=id(99),(r:any)=>r.action='update',(r:any)=>r.remote_completed=false,(r:any)=>r.state='uncertain',(r:any)=>r.safe_result.id=id(99)]){const other=armed(journal()),attempt=ack(other,packet(other)),r=receipt(other);change(r);expect(()=>confirmProductionUiReceipt(other,attempt,{method:'GET',url:other.origin+productionReceiptPath(other,attempt)},r,id(25),()=>{})).toThrow();expect(other.nextIndex).toBe(0);expect(other.phase).toBe('stopped-without-replay');}
    const other=armed(journal()),attempt=ack(other,packet(other));expect(()=>confirmProductionUiReceipt(other,attempt,{method:'GET',url:other.origin+productionReceiptPath(other,attempt).replace(attempt.key,id(99))},receipt(other),id(25),()=>{})).toThrow();
  });
  it('blocks enabled or routed sweep plugins and retains only actual secrets for final scanning',()=>{
    const j=journal();j.nextIndex=PRODUCTION_UI_ACTIONS.indexOf('plugin.loggly.create');j.bindings.services={id:id(80)};
    const base={action:'plugin.loggly.create',method:'POST',path:`/api/v1/clusters/${j.cid}/entities/plugins`,body:{name:'loggly',enabled:false,service:{id:id(80)},config:{key:'synthetic-secret'}},entityType:'plugins',mutationAction:'create',pluginName:'loggly',pluginSweep:true};expect(()=>armProductionUi(j,base,()=>{})).not.toThrow();
    for(const changes of [{enabled:true},{route:{id:id(91)}},{service:{id:id(91)}}]){const other=journal();other.nextIndex=j.nextIndex;other.bindings.services={id:id(80)};expect(()=>armProductionUi(other,{...base,body:{...base.body,...changes}},()=>{})).toThrow();}
    const set=productionUiSecrets({key:id(10),endpoint:'https://public.invalid/hook',config:{key:'synthetic-loggly-key',secret:'synthetic-session-secret'},privateKey:'-----BEGIN PRIVATE KEY----- synthetic'});expect([...set]).toEqual(['synthetic-loggly-key','synthetic-session-secret','-----BEGIN PRIVATE KEY----- synthetic']);expect(set.has(id(10))).toBe(false);expect(set.has('https://public.invalid/hook')).toBe(false);
  });
  it('allows only the two explicit local Service toggle intents after recent genuine no-route readback',()=>{
    expect(PRODUCTION_UI_ACTIONS.filter((action:string)=>action.startsWith('bindings.'))).toEqual(['bindings.route.create','bindings.consumer.create','bindings.global.create','bindings.service.enable','bindings.service.disable','bindings.route.archive','bindings.consumer.archive','bindings.global.archive']);
    const j=journal();j.nextIndex=PRODUCTION_UI_ACTIONS.indexOf('bindings.service.enable');j.bindings.services={id:id(80)};j.bindings['plugin:rate-limiting']={id:id(81),entity:{name:'rate-limiting',service:{id:id(80)},enabled:false}};
    const p={method:'GET',url:j.origin+`/api/v1/clusters/${j.cid}/entities/services/${id(80)}?workspaceId=${j.wid}`},data={entity:{id:id(80)},relations:{routes:{items:[],nextCursor:null,availability:'available'}}};
    expect(()=>armProductionUiToggle(j,true,()=>{},now)).toThrow();proveProductionIsolation(j,p,data,id(82),()=>{},now);const baseline=structuredClone(j);armProductionUiToggle(j,true,()=>{},now);expect(j.armed.body).toEqual({enabled:true});
    const packet={method:'POST',url:j.origin+j.armed.path+`?workspaceId=${j.wid}`,rawBody:'{"enabled":true}',headers:{...packetFromHeader(j),'x-idempotency-key':id(83)}};
    const attempt=beforeProductionUiPacket(j,packet,productionCookies(j.origin,j.session.cookie),()=>{},now);observeProductionUiAck(j,attempt,{status:201,requestId:id(84),data:{entity:{id:id(81),name:'rate-limiting',enabled:true,service:{id:id(80)},route:null,consumer:null}}},()=>{});expect(attempt.state).toBe('acknowledged');
    for(const mutate of [(a:any)=>a.bindings['plugin:rate-limiting'].entity.route={id:id(90)},(a:any)=>a.bindings['plugin:rate-limiting'].entity.name='http-log',(a:any)=>a.isolation.observedAt=new Date(now-30001).toISOString()]){const foreign=structuredClone(baseline);mutate(foreign);expect(()=>armProductionUiToggle(foreign,true,()=>{},now)).toThrow();}
  });
  it('preserves actual failed HTTP status and original response metadata while globally stopping',()=>{
    const j=armed(journal()),a=beforeProductionUiPacket(j,packet(j),productionCookies(j.origin,j.session.cookie),()=>{},now);expect(()=>observeProductionUiAck(j,a,{status:409,requestId:id(77),data:{code:'SYNTHETIC_DUPLICATE'}},()=>{})).toThrow();expect(a.status).toBe(409);expect(a.requestId).toBe(id(77));expect(a.responseData.code).toBe('SYNTHETIC_DUPLICATE');expect(j.nextIndex).toBe(0);expect(j.phase).toBe('stopped-without-replay');
  });
});
function packetFromHeader(j:any){return {'x-csrf-token':j.session.csrf,cookie:'kongos_access=source-access; kongos_csrf=source-csrf'};}
function safePrefix(){
  const j=armed(journal()),a=ack(j,packet(j));confirmProductionUiReceipt(j,a,{method:'GET',url:j.origin+productionReceiptPath(j,a)},receipt(j),id(25),()=>{});
  j.bindings.carrier={id:id(12),entity:{id:id(12),name:'source-carrier'}};j.progress={checks:[],screenshots:[],reads:[],domActions:[],coverage:[]};j.history={originalRequestCount:0,originalRequestPrefixSha256:productionSha([])};j.currentReportPath='artifacts/production/ui-lifecycle.json';
  pauseProductionUiIfNeeded(j,()=>{},now+781000);return j;
}
function tailFixture(){
  const old=safePrefix(),bytes=Buffer.from(JSON.stringify(old)),oldReport={allPassed:false,failed:0,unknownUiWrites:0,journalPhase:'paused-safe-prefix',testTag:old.tag,origin:old.origin,clusterId:old.cid,workspaceId:old.wid,plannedActions:[...PRODUCTION_UI_ACTIONS]},reportBytes=Buffer.from(JSON.stringify(oldReport));
  const renewed=reference().ref.session;renewed.cookie='kongos_access=source-access-renewed; kongos_refresh=source-refresh-renewed; kongos_csrf=source-csrf-renewed';renewed.csrf='source-csrf-renewed-0123456789';renewed.expiresAt=new Date(now+1681000).toISOString();
  const renewal={allPassed:true,failed:0,unknownWrites:0,authWrites:1,businessWrites:0,loginWrites:0,nativeWrites:0,actorId:old.actorId,sessionId:old.sessionId,origin:old.origin,clusterId:old.cid,workspaceId:old.wid,originalUiJournalSha256:productionSha(bytes),sessionExpiresAt:renewed.expiresAt,currentSessionVerified:true,signedAccessVerified:true,currentUserProven:true},renewalBytes=Buffer.from(JSON.stringify(renewal));
  const ref={version:1,milestone:'M0-M8-production-ui',phase:'unused-tail-ready',requests:[],secrets:[],session:renewed,uiUnusedTailHandoff:{version:1,phase:'ready',exclusiveRuntimeOwner:'production-ui',generation:1,testTag:old.tag,origin:old.origin,clusterId:old.cid,workspaceId:old.wid,actorId:old.actorId,sessionId:old.sessionId,nextIndex:1,originalUiJournalSha256:productionSha(bytes),originalReportSha256:productionSha(reportBytes),approvedActions:PRODUCTION_UI_ACTIONS.slice(1),renewalReportPath:'artifacts/production/ui-original-session-maintenance-1.json',renewalReportSha256:productionSha(renewalBytes)}};
  return {old,bytes,oldReport,reportBytes,ref,renewal,renewalBytes};
}
describe('production UI exact known-prefix independent unused tail',()=>{
  it('pauses only a complete zero-unknown prefix before the next write using genuine expiry, with no fixed sleep',()=>{
    const j=journal();j.progress={checks:[]};expect(pauseProductionUiIfNeeded(j,()=>{},now)).toBe(false);
    const f=safePrefix();expect(f.phase).toBe('paused-safe-prefix');expect(f.stopCode).toBe(PRODUCTION_UI_PAUSE_CODE);expect(f.attempts).toHaveLength(1);expect(f.nextIndex).toBe(1);expect(()=>assertProductionKnownPrefix(f)).not.toThrow();
    for(const mutate of [(v:any)=>v.inFlight=0,(v:any)=>v.armed={action:'bad'},(v:any)=>v.attempts[0].state='response_unknown',(v:any)=>v.attempts[0].action=PRODUCTION_UI_ACTIONS[1],(v:any)=>v.reviews.push({state:'prepared'})]){const bad=structuredClone(f);mutate(bad);expect(()=>assertProductionKnownPrefix(bad)).toThrow();}
    const source=read('tests/security/production-ui-lifecycle.mjs');expect(source).not.toMatch(/waitForTimeout|setTimeout|sleep\(/);
  });
  it('seals full original attempts/headers/session/progress and binds real same-SID maintenance without resetting or replaying',()=>{
    const f=tailFixture(),before=canonicalUi(f.old);f.ref.requests.push({key:id(92),state:'response_observed'} as never);const p=prepareProductionUnusedTail(f.old,f.bytes,f.oldReport,f.reportBytes,f.ref,f.renewal,f.renewalBytes,now+781000);
    expect(canonicalUi(f.old)).toBe(before);expect(canonicalUi(p.history.originalJournal)).toBe(before);expect(p.journal.attempts).toEqual(f.old.attempts);expect(p.journal.sessionId).toBe(f.old.sessionId);expect(p.journal.session.cookie).not.toBe(f.old.session.cookie);expect(p.journal.nextIndex).toBe(1);expect(p.journal.actorProven).toBe(false);expect(p.marker.externalNormalSessionRenewalWrites).toBe(1);
    expect(p.journal.priorKeys).toContain(id(92));expect(productionActionAlreadyCompleted(p.journal,'carrier.create')).toBe(true);expect(productionActionAlreadyCompleted(p.journal,PRODUCTION_UI_ACTIONS[1])).toBe(false);expect(()=>productionActionAlreadyCompleted(p.journal,PRODUCTION_UI_ACTIONS[2])).toThrow();
    expect(()=>prepareProductionUnusedTail(p.journal,f.bytes,f.oldReport,f.reportBytes,f.ref,f.renewal,f.renewalBytes,now+781000)).toThrow();
  });
  it('rejects foreign identity/scope/hash/old report/expired session/extra intent or unproven maintenance before launch',()=>{
    for(const mutate of [(f:any)=>f.ref.session.sid=id(90),(f:any)=>f.ref.session.user.id=id(90),(f:any)=>f.ref.session.user.capabilities={platformAdmin:true,modules:{services:['delete']}},(f:any)=>f.ref.uiUnusedTailHandoff.workspaceId=id(90),(f:any)=>f.ref.uiUnusedTailHandoff.approvedActions.unshift('carrier.create'),(f:any)=>f.ref.uiUnusedTailHandoff.originalUiJournalSha256='0'.repeat(64),(f:any)=>f.oldReport.failed=1,(f:any)=>f.ref.session.expiresAt=new Date(now+782000).toISOString(),(f:any)=>f.renewal.authWrites=2,(f:any)=>f.renewal.loginWrites=1,(f:any)=>f.renewal.signedAccessVerified=false,(f:any)=>f.old.attempts[0].rawBody='{}']){
      const f=tailFixture();mutate(f);expect(()=>prepareProductionUnusedTail(f.old,f.bytes,f.oldReport,f.reportBytes,f.ref,f.renewal,f.renewalBytes,now+781000)).toThrow();
    }
  });
  it('uses actual runner runAction to skip prior DOM actions and stops before an unused callback on pause or save failure',async()=>{
    const source=read('tests/security/production-ui-lifecycle.mjs'),file=ts.createSourceFile('runner.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS),node=file.statements.find((row:any)=>ts.isFunctionDeclaration(row)&&row.name?.text==='runAction')!,code=`(${node.getText(file)})`;
    const f=tailFixture(),p=prepareProductionUnusedTail(f.old,f.bytes,f.oldReport,f.reportBytes,f.ref,f.renewal,f.renewalBytes,now+781000),perform=vi.fn(),events:string[]=[],j=p.journal;
    const run=vm.runInNewContext(code,{journal:j,productionActionAlreadyCompleted,settle:async()=>{},checks:[],screenshots:[],reads:[],domActions:[],coverage:[],pauseProductionUiIfNeeded:(a:any,persist:any)=>pauseProductionUiIfNeeded(a,persist,now+1600000),retain:()=>events.push('persist'),saveReport:()=>events.push('report'),phase:'source',runtimeStartedAt:Date.now(),Error,PRODUCTION_UI_PAUSE_CODE});
    await run('carrier.create',perform);expect(perform).not.toHaveBeenCalled();await expect(run(PRODUCTION_UI_ACTIONS[1],perform)).rejects.toThrow(PRODUCTION_UI_PAUSE_CODE);expect(perform).not.toHaveBeenCalled();expect(events).toEqual(['persist','report']);
    const broken=p.journal;broken.phase='active';expect(()=>pauseProductionUiIfNeeded(broken,()=>{throw Error('synthetic-durable-failure');},now+1600000)).toThrow('synthetic-durable-failure');expect(perform).not.toHaveBeenCalled();
  });
  it('pins original PEM and unused secret fixtures and saves complete history before session restoration or fake launch',()=>{
    const source=read('tests/security/production-ui-lifecycle.mjs');expect(source).toContain('journal.pem=structuredClone(reference.pem)');expect(source).toContain('pem:journal.pem');expect(source).toContain('journal.pluginConfigs??productionPluginConfigurations');
    expect(source.indexOf('durableProductionJson(archivePath,prepared.history,true)')).toBeLessThan(source.indexOf('chromium.launch('));expect(source.indexOf('durableProductionJson(PRODUCTION_UI_JOURNAL,{...journal,secrets:[...secrets]},!unusedTail)')).toBeLessThan(source.indexOf('context.addCookies('));
    const entry=read('tests/security/continue-production-ui-unused-tail.mjs'),reader=vi.fn(),guard=entry.slice(0,entry.indexOf('await import('));expect(()=>vm.runInNewContext(guard,{process:{env:{}},readProductionUiReference:reader})).toThrow('PRODUCTION_EXCLUSIVE_UNUSED_TAIL_HANDOFF_REQUIRED');expect(reader).not.toHaveBeenCalled();
  });
});
