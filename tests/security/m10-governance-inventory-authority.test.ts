import 'reflect-metadata';
import { beforeEach,afterEach,describe,it,expect,vi } from 'vitest';
import { ForbiddenException,HttpException,NotFoundException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { GovernanceAuthorityService } from '../../apps/console-api/src/modules/governance/governance-authority.service';
import { GovernanceInventoryService } from '../../apps/console-api/src/modules/governance/governance-inventory.service';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { EntityAnnotationsService } from '../../apps/console-api/src/modules/workspaces/entity-annotations.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { encodeTag,workspaceTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import { signCursor,readCursor } from '../../apps/console-api/src/infrastructure/kong/cursor';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { GOVERNANCE_ENTITY_TYPES } from '../../apps/console-api/src/modules/governance/governance-inventory.types';
import { workspaceTestResolver,DEFAULT_WORKSPACE_ID as wid,PAY_WORKSPACE_ID as pay } from '../unit/workspace-test-helper';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';

// Real authorization, resolver, context, native policy, entity list and inventory.
// SQL rows and native wire responses are explicit synthetic fixtures, not gateway evidence.
const cid='f1a0409f-78ec-4209-bba0-81b3b04c4d05',otherCid='a9fb68b7-42c1-4c8a-bfb8-e0a74ef2bca2';
const uid='8c5a3355-5cb1-43da-88fd-32b1681f916d',sid='d73c5772-32dd-448c-a651-6127415fa0d9';
const serviceId='b3e413d2-b903-4777-9895-32c153e3ecc6',hiddenId='a6cb75c1-0f9a-445a-9f10-d62795f5a2bc',upstreamId='c811aa61-ae5b-4c06-b101-65921d25cf6b',targetId='9f6163eb-fe39-4a51-824c-8d044643b737';
const scheduleId='2bb3b75b-ed8f-4b8a-94e0-2ee720e0ca11',runId='e6c4bf23-d237-41c7-8b31-2848db99e83d';
describe('M10 independent readonly governance authority and inventory',()=>{
  let execution:KongExecutionContextService,secrets:SecretService,authority:GovernanceAuthorityService,inventory:GovernanceInventoryService,db:any,kong:any,cluster:any,user:any,session:any,grants:any[],iam:number,wire:any[],remote:Map<string,any>,schedule:any,writeEpoch:number,pending:number;
  let beforeWire:(path:string)=>void,secondaryCluster:any,secondaryWorkspace:any;
  const actor=()=>({user:{id:uid,username:'governance-fixture',superAdmin:false},workspaceId:wid});
  const run=<T>(fn:()=>Promise<T>)=>execution.runHttp({requestId:'governance-fixture'},async()=>{
    execution.bindHttpActor(actor().user,sid);const close=execution.captureHttpCloser();try{return await fn();}finally{close();}
  });
  const globalGrants=(mods=['governance',...GOVERNANCE_ENTITY_TYPES,'annotations'])=>mods.map(module=>({module,action:'read',scope_type:'global',scope_values:[],cluster_id:cid,workspace_id:null}));
  const capture=()=>run(()=>inventory.captureActor(cid,{scope:'workspace',workspaceId:wid},actor()));
  beforeEach(()=>{
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-governance-cursor-key-at-least-thirtytwo-characters');
    secrets=new SecretService();execution=new KongExecutionContextService();iam=1;writeEpoch=1;pending=0;wire=[];beforeWire=()=>{};secondaryCluster=null;secondaryWorkspace=null;
    cluster={id:cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct',status:'healthy',revision:1,connection_secret:null,enabled_plugins:['cors']};
    user={id:uid,username:'governance-fixture',super_admin:false,status:'active',deleted_at:null,permissions_epoch:1,credential_epoch:1,force_password_change:false};
    session={id:sid,credential_epoch:1,expires_at:new Date(Date.now()+600000).toISOString()};grants=globalGrants();
    const fixture=workspaceTestResolver(cid);
    db={exec:vi.fn(async()=>1),query:vi.fn(async(sql:string)=>sql.includes('iam_effective_grants')?grants:[]),one:vi.fn(async(sql:string,params:any[])=>{
      if(sql.includes('FROM users'))return params[0]===uid&&user.status==='active'?user:null;
      if(sql.includes('FROM auth_sessions'))return params[0]===sid&&session&&!session.revoked_at?session:null;
      if(sql.includes('iam_epoch'))return{version:iam};
      if(sql.includes('governance_schedules'))return schedule;
      if(sql.includes('metrics_write_fences'))return{count:String(writeEpoch),latest_time:'synthetic',latest_id:String(writeEpoch)};
      if(sql.includes('mutation_operations'))return sql.includes('count(*)')?{count:String(pending)}:null;
      if(sql.includes('FROM clusters'))return params[0]===cid?cluster:params[0]===otherCid?secondaryCluster:null;
      if(sql.includes('workspaces'))return params[0]===otherCid?secondaryWorkspace:fixture.db.one(sql,params);return null;
    })};
    remote=new Map([['/',{version:'1.5.1',endpoints:[]}],['/plugins/enabled',{enabled_plugins:['cors']}],['/plugins/schema/cors',{fields:[{config:{type:'record',fields:[{origins:{type:'array',elements:{type:'string'}}}]}}]}]]);
    for(const type of GOVERNANCE_ENTITY_TYPES){remote.set(`/${type}`,{data:[],next:null});remote.set(`/schemas/${type}`,{fields:[{name:{type:'string',unique:true}},{tags:{type:'set'}}]});}
    remote.set('/schemas/targets',{fields:[{target:{type:'string'}},{weight:{type:'integer'}},{upstream:{type:'foreign',reference:'upstreams'}},{tags:{type:'set'}}]});
    const service={id:serviceId,name:'selected',host:'upstream',tags:[]};remote.set('/services',{data:[service],next:null});remote.set(`/services/${serviceId}`,service);
    remote.set(`/services/${serviceId}/routes`,{data:[],next:null});remote.set(`/services/${hiddenId}/routes`,{data:[],next:null});
    const upstream={id:upstreamId,name:'upstream',tags:[]};remote.set('/upstreams',{data:[upstream],next:null});remote.set(`/upstreams/${upstreamId}`,upstream);
    remote.set(`/upstreams/${upstreamId}/targets`,{data:[{id:targetId,target:'example.test:80',weight:100,tags:[workspaceTag('pay')],upstream:{id:upstreamId}}],next:null});
    kong={request:vi.fn(async(_cid:string,method:string,path:string,body?:any,query:any={})=>{
      const ticket=await execution.authorizeRequest(cluster,method,path,body,query);beforeWire(path);await execution.assertGovernanceBeforeSend(ticket);
      wire.push({method,path,query});if(!remote.has(path))throw new NotFoundException();const response=remote.get(path);const value=typeof response==='function'?response(query):response;
      return execution.authorizeResponse(ticket,structuredClone(value));
    }),list:vi.fn(async(_cid:string,path:string,query:any,cursor?:string,subject?:string)=>{
      const params={...query};if(cursor)params.offset=readCursor(cursor,cid,path,query,subject);const result=await kong.request(cid,'GET',path,undefined,params);
      const offset=result.next?new URL(result.next,'http://kong.local').searchParams.get('offset'):null;
      return{items:result.data,nextCursor:offset?signCursor({clusterId:cid,path,query,offset,subject}):null,size:query.size,...(result.console_permission_projection?{console_permission_projection:true}:{})};
    })};
    const resolver=new WorkspaceResolverService(db),authz=new AuthorizationService(db,resolver,kong,execution),policy=new NativeKongPolicyService(db,secrets,kong,execution,authz,resolver);policy.install();
    authority=new GovernanceAuthorityService(db,secrets,execution,authz,resolver,kong);authority.onModuleInit();
    const entities=new EntityService(kong,authz,{} as any,{} as any,{} as any,secrets,{} as any,{} as any,resolver,execution);
    const annotations=new EntityAnnotationsService(db,kong,authz,{} as any,{} as any,resolver,execution);
    inventory=new GovernanceInventoryService(authority,kong,entities,secrets,resolver,annotations,execution);
    const payload={kind:'inspection',scope:'workspace',intervalMinutes:5};schedule={id:scheduleId,cluster_id:cid,workspace_id:wid,owner_user_id:uid,transport_scope:transportScopeFor(cluster.admin_url),state:'active',current_version:1,revision:2,
      payload,policy_hmac:secrets.fingerprint(payload),schedule_version:1,scheduled_at:'2026-10-13T01:00:00.000Z',creator_id:uid,lease_generation:1,lease_until:new Date(Date.now()+60000).toISOString(),run_state:'running'};
  });
  afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});
  it('captures actual cursor EOF, all root schemas, old plugin schema, and inherited Target workspace without credentials',async()=>{
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',config:{origins:['*']},tags:[]}],next:null});
    const result=await capture();expect(result.inventory.reasonCodes).toEqual([]);expect(result.inventory.completeness).toBe('complete');expect(result.inventory.coverage.services).toMatchObject({state:'complete',extent:'workspace',eof:true});
    expect(result.inventory.objects.find(o=>o.entityType==='targets')).toMatchObject({parentId:upstreamId,objectWorkspaceId:wid});
    expect(wire.every(p=>p.method==='GET')).toBe(true);expect(wire.some(p=>/key-auth|basic-auth|oauth2/.test(p.path))).toBe(false);
    expect(wire.map(p=>p.path)).toContain('/plugins/schema/cors');expect(result.inventory.usage.pages).toBe(9);
    // Regression: Target objects need the Target entity schema for logical-graph normalization.
    expect(wire.map(p=>p.path)).toContain('/schemas/targets');expect(result.inventory.schemas.targets).toBeDefined();
  });
  it('captures configured plugin schemas instead of querying every enabled plugin',async()=>{
    remote.set('/plugins/enabled',{enabled_plugins:['cors',...Array.from({length:40},(_,index)=>`unused-${index}`)]});
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',config:{origins:['*']},tags:[]}],next:null});
    const result=await capture();expect(result.inventory.completeness).toBe('complete');
    expect(wire.filter(packet=>packet.path.startsWith('/plugins/schema/')).map(packet=>packet.path)).toEqual(['/plugins/schema/cors']);
    expect(result.inventory.enabledPlugins).toHaveLength(41);
  });
  it('unions explicit schema requirements with configured plugins only after selecting the service closure',async()=>{
    remote.set('/plugins/enabled',{enabled_plugins:['cors','http-log','rate-limiting']});
    remote.set('/plugins/schema/rate-limiting',{fields:[{config:{type:'record',fields:[]}}]});
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',service:{id:serviceId},config:{origins:['*']},tags:[]},{id:runId,name:'http-log',config:{http_endpoint:'http://log.test'},tags:[]}],next:null});
    const result=await run(()=>inventory.captureActor(cid,{scope:'services',serviceIds:[serviceId]},actor(),{requiredPluginSchemas:['rate-limiting','cors','rate-limiting']}));
    expect(result.inventory.completeness).toBe('complete');expect(result.inventory.objects.filter(object=>object.entityType==='plugins').map(object=>object.nativeId)).toEqual([hiddenId]);
    expect(Object.keys(result.inventory.pluginSchemas)).toEqual(['cors','rate-limiting']);expect(wire.some(packet=>packet.path==='/plugins/schema/http-log')).toBe(false);
  });
  it('deduplicates configured plugin names before applying the 200-name schema requirement budget',async()=>{
    remote.set('/plugins',{data:Array.from({length:201},(_,index)=>({id:`${index.toString(16).padStart(8,'0')}-b903-4777-9895-32c153e3ecc6`,name:'cors',config:{origins:['*']},tags:[]})),next:null});
    const result=await capture();expect(result.inventory.completeness).toBe('complete');expect(result.inventory.objects.filter(object=>object.entityType==='plugins')).toHaveLength(201);
    expect(wire.filter(packet=>packet.path==='/plugins/schema/cors')).toHaveLength(1);
  });
  it.each([['invalid/name'],Array.from({length:201},()=> 'cors')])('rejects invalid explicit schema requirements before any native read',async requiredPluginSchemas=>{
    await expect(run(()=>inventory.captureActor(cid,{scope:'workspace'},actor(),{requiredPluginSchemas}))).rejects.toMatchObject({response:{code:'GOVERNANCE_PLUGIN_SCHEMA_REQUIREMENTS_INVALID'}});expect(wire).toHaveLength(0);
  });
  it('enriches the genuine two-side schema union without repeating collections or replacing private raw fingerprints',async()=>{
    remote.set('/plugins/enabled',{enabled_plugins:['cors','http-log']});remote.set('/plugins/schema/http-log',{fields:[{config:{type:'record',fields:[]}}]});
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',config:{origins:['*']},tags:[]}],next:null});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),before=await inventory.privateFingerprints(handle,captured),usage={...captured.usage},offset=wire.length;
      expect(await inventory.enrichPluginSchemas(handle,captured,['http-log','cors','http-log'])).toBe(captured);
      expect(wire.slice(offset).map(packet=>packet.path)).toEqual(['/','/plugins/enabled','/plugins/schema/http-log']);
      expect(captured.completeness).toBe('complete');expect(Object.keys(captured.pluginSchemas)).toEqual(['cors','http-log']);expect(await inventory.privateFingerprints(handle,captured)).toEqual(before);
      expect(captured.usage.calls).toBe(usage.calls+3);expect(captured.usage.pages).toBe(usage.pages);expect(captured.usage.records).toBe(usage.records);
    });
  });
  it('reprobes actual version and enabled plugins even when enrichment is empty or all schemas already exist',async()=>{
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',config:{origins:['*']},tags:[]}],next:null});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),offset=wire.length,initial=authority.usage(handle).calls;
      await inventory.enrichPluginSchemas(handle,captured,[]);await inventory.enrichPluginSchemas(handle,captured,['cors']);
      expect(wire.slice(offset).map(packet=>packet.path)).toEqual(['/','/plugins/enabled','/','/plugins/enabled']);expect(authority.usage(handle).calls).toBe(initial+4);
      expect(captured.usage.calls).toBe(initial+4);expect(await inventory.privateFingerprints(handle,captured)).toBeDefined();
    });
  });
  it('enrichment refuses copied inventories, different genuine handles, copied handles, and altered public captures before wire',async()=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),other=await authority.acquireActor(cid,{scope:'workspace'},actor()),offset=wire.length;
      await expect(inventory.enrichPluginSchemas(handle,structuredClone(captured),['cors'])).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
      await expect(inventory.enrichPluginSchemas(other,captured,['cors'])).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
      await expect(inventory.enrichPluginSchemas({...handle},captured,['cors'])).rejects.toMatchObject({response:{code:'GOVERNANCE_AUTHORITY_REQUIRED'}});
      captured.objects[0].payload.name='altered';await expect(inventory.enrichPluginSchemas(handle,captured,['cors'])).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
      expect(wire).toHaveLength(offset);
    });
  });
  it('enrichment cannot re-sign a public object altered while the actual schema request is in flight',async()=>{
    remote.set('/plugins/enabled',{enabled_plugins:['cors','http-log']});remote.set('/plugins/schema/http-log',{fields:[{config:{type:'record',fields:[]}}]});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),originalSchemas=structuredClone(captured.pluginSchemas);
      beforeWire=path=>{if(path==='/plugins/schema/http-log')captured.objects[0].payload.name='altered-during-enrichment';};
      await expect(inventory.enrichPluginSchemas(handle,captured,['http-log'])).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
      expect(captured.pluginSchemas).toEqual(originalSchemas);await expect(inventory.privateFingerprints(handle,captured)).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
    });
  });
  it.each(['1.5.2','2.0.0'])('actual version drift to %s stops enrichment before enabled or schema reads',async version=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),before=structuredClone(captured),offset=wire.length;remote.set('/',{version,endpoints:[]});
      await expect(inventory.enrichPluginSchemas(handle,captured,['cors'])).rejects.toMatchObject({response:{code:'GOVERNANCE_VERSION_CHANGED'}});expect(wire.slice(offset).map(packet=>packet.path)).toEqual(['/']);expect(captured).toEqual(before);
    });
  });
  it('actual enabled plugin drift revokes both enrichment and a later capture using the same genuine handle',async()=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),before=structuredClone(captured),offset=wire.length;remote.set('/plugins/enabled',{enabled_plugins:['cors','http-log']});
      await expect(inventory.enrichPluginSchemas(handle,captured,['http-log'])).rejects.toMatchObject({response:{code:'GOVERNANCE_ENABLED_CHANGED'}});
      await expect(inventory.capture(handle)).rejects.toMatchObject({response:{code:'GOVERNANCE_ENABLED_CHANGED'}});
      expect(wire.slice(offset).map(packet=>packet.path)).toEqual(['/','/plugins/enabled','/','/plugins/enabled']);expect(captured).toEqual(before);
    });
  });
  it.each(['not-enabled','missing','malformed'])('a %s peer schema safely degrades completeness while preserving exact genuine native evidence',async mode=>{
    if(mode!=='not-enabled')remote.set('/plugins/enabled',{enabled_plugins:['cors','http-log']});if(mode==='malformed')remote.set('/plugins/schema/http-log',{name:'http-log'});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),before=await inventory.privateFingerprints(handle,captured);
      expect(captured.completeness).toBe('complete');await inventory.enrichPluginSchemas(handle,captured,['http-log']);expect(captured.completeness).toBe('incomplete');expect(captured.reasonCodes).toContain('PLUGIN_SCHEMA_NOT_CAPTURED');
      expect(captured.pluginSchemas['http-log']).toBeUndefined();expect(await inventory.privateFingerprints(handle,captured)).toEqual(before);expect(Object.values(captured.coverage).every(coverage=>coverage.eof)).toBe(true);
    });
  });
  it('enrichment exhausts the same aggregate budget and never renews it or claims a complete peer schema',async()=>{
    remote.set('/plugins/enabled',{enabled_plugins:['cors','http-log']});remote.set('/plugins/schema/http-log',{fields:[{config:{type:'record',fields:[]}}]});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle);
      await authority.runRead(handle,async()=>{while(execution.currentUsage().calls+authority.usage(handle).calls<498)await kong.request(cid,'GET','/');});
      await inventory.enrichPluginSchemas(handle,captured,['http-log']);expect(authority.usage(handle).calls).toBe(500);expect(captured.completeness).toBe('incomplete');expect(captured.reasonCodes).toContain('PLUGIN_SCHEMA_NOT_CAPTURED');
      expect(wire.filter(packet=>packet.path==='/plugins/schema/http-log')).toHaveLength(0);
      await expect(inventory.enrichPluginSchemas(handle,captured,[])).rejects.toMatchObject({response:{code:'GOVERNANCE_BUDGET_EXHAUSTED'}});expect(authority.usage(handle).calls).toBe(500);
    });
  });
  it('keeps projection EOF distinct and only exposes intersecting native AND governance tags',async()=>{
    const tag=encodeTag('team:pay');grants=globalGrants().map(grant=>({...grant,scope_type:'tag_group',scope_values:[tag]}));
    const selected={id:serviceId,name:'selected',host:'business.test',tags:[tag]},hidden={id:hiddenId,name:'hidden',host:'private.test',tags:[encodeTag('team:other')]};
    remote.set('/services',{data:[selected,hidden],next:null});remote.set(`/services/${serviceId}`,selected);remote.set('/upstreams',{data:[],next:null});
    const result=await capture();expect(result.inventory.projection).toBe(true);expect(result.inventory.coverage.services).toMatchObject({state:'projected',extent:'projection',eof:true});
    expect(result.inventory.objects.map(o=>o.nativeId)).toEqual([serviceId]);expect(result.inventory.objects[0].payload.tags).toEqual(['team:pay']);
  });
  it('entity whitelist cannot mint a whole-cluster completeness claim',async()=>{
    grants=globalGrants().map(grant=>({...grant,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:serviceId}]}));
    await expect(run(()=>authority.acquireActor(cid,{scope:'cluster',workspaceId:wid},actor()))).rejects.toMatchObject({response:{code:'GOVERNANCE_CLUSTER_WHOLE_SCOPE_REQUIRED'}});expect(wire).toHaveLength(0);
  });
  it('missing native permissions produce not_authorized coverage instead of silent empty complete collections',async()=>{
    grants=globalGrants(['governance','services','annotations']);const result=await capture();expect(result.inventory.completeness).toBe('incomplete');expect(result.inventory.coverage.certificates.state).toBe('not_authorized');
    expect(wire.some(p=>p.path==='/certificates')).toBe(false);
  });
  it('whole-workspace inspection can capture a broken Plugin FK without borrowing recoverable graph authority',async()=>{
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',service:{id:runId},config:{origins:['*']},tags:[]}],next:null});
    const result=await capture();expect(result.inventory.coverage.plugins).toMatchObject({state:'complete',eof:true});expect(result.inventory.objects.find(o=>o.entityType==='plugins')?.payload.service).toEqual({id:runId});
    expect(wire.filter(p=>p.path===`/services/${runId}`).length).toBeGreaterThanOrEqual(1);
  });
  it('whole workspace module rows do not expose a Plugin bound to an unauthorized foreign workspace',async()=>{
    grants=globalGrants().map(grant=>({...grant,scope_type:'workspace',scope_values:[wid],workspace_id:wid}));
    remote.set(`/services/${hiddenId}`,{id:hiddenId,name:'foreign',host:'private.test',tags:[workspaceTag('pay')]});
    remote.set('/plugins',{data:[{id:runId,name:'cors',service:{id:hiddenId},config:{origins:['foreign-sensitive-domain.test']},tags:[]}],next:null});
    const result=await capture();expect(result.inventory.objects.some(o=>o.nativeId===runId)).toBe(false);expect(result.inventory.projection).toBe(true);expect(result.inventory.coverage.plugins).toMatchObject({state:'projected',extent:'projection',eof:true});
    expect(JSON.stringify(result.inventory)).not.toContain('foreign-sensitive-domain.test');
  });
  it('logical workspace tags are encoded before membership classification in projected lists',async()=>{
    const tag=encodeTag('team:pay');grants=globalGrants().map(grant=>({...grant,scope_type:'tag_group',scope_values:[tag],workspace_id:pay}));
    remote.set('/services',{data:[{id:serviceId,name:'selected',host:'business.test',tags:[tag,workspaceTag('pay')]}],next:null});remote.set('/upstreams',{data:[],next:null});
    const result=await run(()=>inventory.captureActor(cid,{scope:'workspace',workspaceId:pay},{...actor(),workspaceId:pay}));expect(result.inventory.objects[0].objectWorkspaceId).toBe(pay);
    expect(result.inventory.objects[0].payload.tags).toEqual(['team:pay','workspace:pay']);
  });
  it.each(['POST','PATCH','DELETE'])('a true readonly handle cannot send %s even after trying to attach a native operation',async method=>{
    await expect(run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor());return authority.runRead(handle,()=>execution.runOperation({actor:actor().user,clusterId:cid,workspaceId:wid,operationId:runId,entityType:'services',action:'update'},()=>kong.request(cid,method,`/services/${serviceId}`,{name:'forbidden'})));})).rejects.toBeInstanceOf(ForbiddenException);
    expect(wire).toHaveLength(0);
  });
  it.each(['/cache','/status','/metrics',`/consumers/${serviceId}/key-auth`,'/plugins/schema/cors/extra'])('forbids arbitrary operational or credential read path %s',async path=>{
    await expect(run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor());return authority.runRead(handle,()=>kong.request(cid,'GET',path));})).rejects.toBeInstanceOf(ForbiddenException);expect(wire).toHaveLength(0);
  });
  it('a copied or serialized handle is not authority',async()=>{
    await expect(run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor());return authority.runRead({...handle},()=>Promise.resolve());})).rejects.toMatchObject({response:{code:'GOVERNANCE_AUTHORITY_REQUIRED'}});
  });
  it('caller superAdmin and permissions projections never override current SQL grants',async()=>{
    grants=[];await expect(run(()=>authority.acquireActor(cid,{scope:'workspace'},{user:{...actor().user,superAdmin:true},workspaceId:wid}))).rejects.toBeInstanceOf(ForbiddenException);expect(wire).toHaveLength(0);
  });
  it('original HTTP frame closure stops a later reused source handle',async()=>{
    const handle=await run(()=>authority.acquireActor(cid,{scope:'workspace'},actor()));await expect(authority.runRead(handle,()=>Promise.resolve())).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
  });
  it.each(['iam','credential','registry','write','pending','session'])('revocation or %s change after initial decision stops before wire',async change=>{
    beforeWire=()=>{if(change==='iam')iam++;if(change==='credential')user.credential_epoch++;if(change==='registry')cluster.revision++;if(change==='write')writeEpoch++;if(change==='pending')pending++;if(change==='session')session.revoked_at='now';};
    await expect(capture()).rejects.toBeInstanceOf(HttpException);expect(wire).toHaveLength(0);
  });
  it('does not renew the aggregate native call budget when runRead is re-entered',async()=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor());await authority.runRead(handle,async()=>{for(let call=0;call<499;call++)await kong.request(cid,'GET','/');});
      await authority.runRead(handle,()=>kong.request(cid,'GET','/'));await expect(authority.runRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_BUDGET_EXHAUSTED'}});
      expect(authority.usage(handle).calls).toBe(500);});
  });
  it('looping native offset marks coverage incomplete and never claims EOF',async()=>{
    remote.set('/services',(query:any)=>({data:query.offset?[]:[{id:serviceId,name:'selected',host:'business.test',tags:[]}],next:'/services?offset=loop'}));
    const result=await capture();expect(result.inventory.coverage.services).toMatchObject({state:'incomplete',eof:false,reasonCodes:['GOVERNANCE_CURSOR_CYCLE']});expect(result.inventory.completeness).toBe('incomplete');
  });
  it('removes private key, PEM, opaque custom config, serverless script and credential HMAC markers from public inventory',async()=>{
    const plugin={id:hiddenId,name:'custom-plugin',config:{innocent_name:'actual-fixture-secret'},tags:[]};remote.set('/plugins',{data:[plugin],next:null});
    remote.set('/certificates',{data:[{id:runId,cert:'synthetic-invalid-pem',key:'actual-fixture-private-key',tags:[]}],next:null});
    const result=await capture(),publicText=JSON.stringify(result.inventory);expect(publicText).not.toContain('actual-fixture-secret');expect(publicText).not.toContain('actual-fixture-private-key');expect(publicText).not.toContain('synthetic-invalid-pem');expect(publicText).not.toContain('[REDACTED:');
    expect(result.inventory.objects.find(o=>o.entityType==='plugins')?.sensitiveFields).toContain('/config');expect(result.inventory.objects.find(o=>o.entityType==='certificates')?.certificate?.state).toBe('invalid');
  });
  it('private raw fingerprints detect omitted plugin config and certificate key changes without granting secrets.read or exposing hashes',async()=>{
    const plugin={id:hiddenId,name:'custom-plugin',config:{innocent_name:'first-private-value'},tags:[]},certificate={id:runId,cert:'synthetic-invalid-pem',key:'first-private-key',tags:[]};
    remote.set('/plugins',{data:[plugin],next:null});remote.set('/certificates',{data:[certificate],next:null});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),first=await inventory.capture(handle),initial=await inventory.privateFingerprints(handle,first);
      plugin.config.innocent_name='second-private-value';certificate.key='second-private-key';
      const second=await inventory.capture(handle),fresh=await inventory.privateFingerprints(handle,second);
      expect(first.objects).toEqual(second.objects);expect(initial[`plugins:${hiddenId}`]).not.toBe(fresh[`plugins:${hiddenId}`]);expect(initial[`certificates:${runId}`]).not.toBe(fresh[`certificates:${runId}`]);
      expect(fresh[`services:${serviceId}`]).toBe(initial[`services:${serviceId}`]);expect(Object.isFrozen(initial)).toBe(true);
      for(const value of Object.values(initial)){expect(value).toMatch(/^[a-f\d]{64}$/);expect(JSON.stringify(first)).not.toContain(value);}
      expect(JSON.stringify(initial)).not.toMatch(/private-value|private-key|invalid-pem/);expect(grants.some(g=>g.module==='secrets')).toBe(false);
    });expect(wire.every(p=>p.method==='GET')).toBe(true);expect(wire.some(p=>/key-auth|basic-auth|oauth2/.test(p.path))).toBe(false);
  });
  it('copied public inventory and a different genuine source handle cannot retrieve a private raw receipt',async()=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),other=await authority.acquireActor(cid,{scope:'workspace'},actor());
      await expect(inventory.privateFingerprints(handle,structuredClone(captured))).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
      await expect(inventory.privateFingerprints(other,captured)).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
      await expect(inventory.privateFingerprints({...handle},captured)).rejects.toMatchObject({response:{code:'GOVERNANCE_AUTHORITY_REQUIRED'}});
      expect(Object.keys(await inventory.privateFingerprints(handle,captured))).toHaveLength(captured.objects.length);
    });
  });
  it('mutated public capture cannot borrow the unchanged native fingerprint receipt',async()=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle);captured.objects[0].payload.name='forged-public-object';
      await expect(inventory.privateFingerprints(handle,captured)).rejects.toMatchObject({response:{code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED'}});
    });
  });
  it('private raw receipt access rechecks the real current permission epoch and original HTTP frame',async()=>{
    let captured:any,handle:any;await run(async()=>{handle=await authority.acquireActor(cid,{scope:'workspace'},actor());captured=await inventory.capture(handle);iam++;
      await expect(inventory.privateFingerprints(handle,captured)).rejects.toMatchObject({response:{code:'GOVERNANCE_PERMISSIONS_CHANGED'}});iam=1;
    });await expect(inventory.privateFingerprints(handle,captured)).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
  });
  it('projected private receipts contain only objects visible through the native and governance tag intersection',async()=>{
    const tag=encodeTag('team:pay');grants=globalGrants().map(grant=>({...grant,scope_type:'tag_group',scope_values:[tag]}));
    remote.set('/services',{data:[{id:serviceId,name:'selected',host:'business.test',tags:[tag]},{id:hiddenId,name:'hidden',host:'private.test',tags:[encodeTag('team:other')]}],next:null});remote.set('/upstreams',{data:[],next:null});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor()),captured=await inventory.capture(handle),privateMap=await inventory.privateFingerprints(handle,captured);
      expect(Object.keys(privateMap)).toEqual([`services:${serviceId}`]);expect(JSON.stringify(privateMap)).not.toContain(hiddenId);
    });
  });
  it('selected service private receipt excludes unselected whole-workspace entities and binds Target parent payload',async()=>{
    remote.set('/services',{data:[remote.get(`/services/${serviceId}`),{id:hiddenId,name:'unselected',host:'other.test',tags:[]}],next:null});
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'services',serviceIds:[serviceId]},actor()),captured=await inventory.capture(handle),privateMap=await inventory.privateFingerprints(handle,captured);
      expect(Object.keys(privateMap).sort()).toEqual(captured.objects.map(o=>`${o.entityType}:${o.nativeId}`).sort());expect(privateMap[`services:${hiddenId}`]).toBeUndefined();
      expect(privateMap[`targets:${targetId}`]).toBe(secrets.fingerprint(remote.get(`/upstreams/${upstreamId}/targets`).data[0]));
    });
  });
  it.each(['key-auth','jwt','oauth2','hmac-auth','basic-auth','ldap-auth'])('selected service closure retains an already authorized %s anonymous Consumer as reference-only',async name=>{
    remote.set('/plugins/enabled',{enabled_plugins:[name]});remote.set(`/plugins/schema/${name}`,{fields:[{config:{type:'record',fields:[{anonymous:{type:'string'}}]}}]});
    remote.set('/plugins',{data:[{id:hiddenId,name,service:{id:serviceId},config:{anonymous:runId},tags:[]}],next:null});remote.set('/consumers',{data:[{id:runId,username:'anonymous-consumer',tags:[]}],next:null});
    const result=await run(()=>inventory.captureActor(cid,{scope:'services',serviceIds:[serviceId]},actor()));
    expect(result.inventory.completeness).toBe('complete');expect(result.inventory.objects.find(object=>object.entityType==='consumers')).toMatchObject({nativeId:runId,referenceOnly:true,payload:{username:'anonymous-consumer'}});
    expect(result.inventory.objects.find(object=>object.entityType==='plugins')?.payload.config).toEqual({anonymous:runId});
    expect(Object.keys(result.inventory.pluginSchemas)).toEqual([name]);expect(wire.some(packet=>/\/consumers\/.+\/(?:key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)/.test(packet.path))).toBe(false);
  });
  it.each(['missing','foreign-workspace','native-module-denied'])('selected service anonymous closure cannot retrieve a %s Consumer outside the authorized captured map',async mode=>{
    remote.set('/plugins/enabled',{enabled_plugins:['key-auth']});remote.set('/plugins/schema/key-auth',{fields:[{config:{type:'record',fields:[{anonymous:{type:'string'}}]}}]});
    remote.set('/plugins',{data:[{id:hiddenId,name:'key-auth',service:{id:serviceId},config:{anonymous:runId},tags:[]}],next:null});
    if(mode==='foreign-workspace')remote.set('/consumers',{data:[{id:runId,username:'foreign-consumer',tags:[workspaceTag('pay')]}],next:null});
    if(mode==='native-module-denied'){grants=grants.filter(grant=>grant.module!=='consumers');remote.set('/consumers',{data:[{id:runId,username:'forbidden-consumer',tags:[]}],next:null});}
    const result=await run(()=>inventory.captureActor(cid,{scope:'services',serviceIds:[serviceId]},actor()));
    expect(result.inventory.objects.some(object=>object.entityType==='consumers')).toBe(false);expect(wire.some(packet=>packet.path.startsWith(`/consumers/${runId}`))).toBe(false);
    if(mode==='native-module-denied')expect(result.inventory.completeness).toBe('incomplete');expect(JSON.stringify(result.inventory)).not.toContain('foreign-consumer');expect(JSON.stringify(result.inventory)).not.toContain('forbidden-consumer');
  });
  it('an unrelated plugin config.anonymous does not expand the selected service Consumer reference closure',async()=>{
    remote.set('/plugins',{data:[{id:hiddenId,name:'cors',service:{id:serviceId},config:{anonymous:runId},tags:[]}],next:null});remote.set('/consumers',{data:[{id:runId,username:'unrelated-consumer',tags:[]}],next:null});
    const result=await run(()=>inventory.captureActor(cid,{scope:'services',serviceIds:[serviceId]},actor()));expect(result.inventory.objects.some(object=>object.entityType==='consumers')).toBe(false);
  });
  it('failed capture discards its private recording token while a later real capture keeps the same aggregate budget',async()=>{
    await run(async()=>{const handle=await authority.acquireActor(cid,{scope:'workspace'},actor());beforeWire=path=>{if(path==='/schemas/services')iam++;};
      await expect(inventory.capture(handle)).rejects.toMatchObject({response:{code:'GOVERNANCE_PERMISSIONS_CHANGED'}});const prior=authority.usage(handle).calls;expect(prior).toBeGreaterThan(0);
      iam=1;beforeWire=()=>{};const captured=await inventory.capture(handle);expect((await inventory.privateFingerprints(handle,captured))[`services:${serviceId}`]).toMatch(/^[a-f\d]{64}$/);expect(authority.usage(handle).calls).toBeGreaterThan(prior);
    });
  });
  it('timer authority uses actual owner and claimed occurrence without a fake SID or due-nextRun dependency',async()=>{
    const locator={scheduleId,clusterId:cid,workspaceId:wid,ownerUserId:uid,version:1,revision:2,scheduledAt:schedule.scheduled_at,runId,leaseGeneration:1};
    const handle=await authority.acquireDueSchedule(locator);expect((await authority.verifyHandle(handle)).sessionId).toBeUndefined();expect((await inventory.capture(handle)).completeness).toBe('complete');
  });
  it.each(['owner','policy','version','revision','lease','occurrence','state'])('timer %s invalidation refuses the next native packet',async change=>{
    const locator={scheduleId,clusterId:cid,workspaceId:wid,ownerUserId:uid,version:1,revision:2,scheduledAt:schedule.scheduled_at,runId,leaseGeneration:1};const handle=await authority.acquireDueSchedule(locator);
    if(change==='owner')schedule.owner_user_id=serviceId;if(change==='policy')schedule.policy_hmac='0'.repeat(64);if(change==='version')schedule.current_version++;if(change==='revision')schedule.revision++;if(change==='lease')schedule.lease_until=new Date(0).toISOString();if(change==='occurrence')schedule.scheduled_at='2026-10-13T02:00:00Z';if(change==='state')schedule.run_state='succeeded';
    await expect(authority.runRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toBeInstanceOf(HttpException);expect(wire).toHaveLength(0);
  });
  it('HTTP request cannot mint timer authority using a genuine due locator',async()=>{
    await expect(run(()=>authority.acquireDueSchedule({scheduleId,clusterId:cid,workspaceId:wid,ownerUserId:uid,version:1,revision:2,scheduledAt:schedule.scheduled_at,runId,leaseGeneration:1}))).rejects.toMatchObject({response:{code:'GOVERNANCE_TIMER_ORIGIN_REQUIRED'}});
  });
  const driftFixture=()=>{
    const otherWid='f79231c9-477e-4496-b082-1b48a1ec591a';secondaryCluster={...cluster,id:otherCid,admin_url:'http://other-kong:8001'};secondaryWorkspace={id:otherWid,cluster_id:otherCid,code:'target',name:'target',revision:1,status:'active',is_default:false};
    schedule.payload={kind:'drift',scope:'workspace',intervalMinutes:5,target:{clusterId:otherCid,workspaceId:otherWid,scope:'workspace'}};schedule.policy_hmac=secrets.fingerprint(schedule.payload);
    const own=globalGrants(['drift',...GOVERNANCE_ENTITY_TYPES,'annotations']);grants=[...own,...own.map(g=>({...g,cluster_id:otherCid}))];
    return{scheduleId,clusterId:cid,workspaceId:wid,ownerUserId:uid,version:1,revision:2,scheduledAt:schedule.scheduled_at,runId,leaseGeneration:1};
  };
  it('a drift timer proves both real owner grant sets before minting any source read',async()=>{
    const locator=driftFixture();grants=grants.filter(g=>g.cluster_id!==otherCid||g.module==='drift');await expect(authority.acquireDueSchedule(locator)).rejects.toMatchObject({response:{code:'GOVERNANCE_NATIVE_READ_REQUIRED'}});expect(wire).toHaveLength(0);
  });
  it('a registered target alias of the same physical gateway cannot pose as independent drift',async()=>{
    const locator=driftFixture();secondaryCluster.admin_url=cluster.admin_url;await expect(authority.acquireDueSchedule(locator)).rejects.toMatchObject({response:{code:'GOVERNANCE_DRIFT_DISTINCT_TRANSPORT_REQUIRED'}});expect(wire).toHaveLength(0);
  });
  it('target registry changes revoke the source timer capability before its next source packet',async()=>{
    const locator=driftFixture(),handle=await authority.acquireDueSchedule(locator);secondaryCluster.revision++;await expect(authority.runRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_SCHEDULE_PEER_CHANGED'}});expect(wire).toHaveLength(0);
  });
  it('timer readonly deadline is exactly bounded and cannot be renewed by re-entry',async()=>{
    vi.useFakeTimers();const locator={scheduleId,clusterId:cid,workspaceId:wid,ownerUserId:uid,version:1,revision:2,scheduledAt:schedule.scheduled_at,runId,leaseGeneration:1};const handle=await authority.acquireDueSchedule(locator),deadline=(await authority.description(handle)).expiresAt;
    expect(deadline-Date.now()).toBe(120000);vi.setSystemTime(deadline+1);await expect(authority.runRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_AUTHORITY_EXPIRED'}});expect(wire).toHaveLength(0);
  });
  it('fresh source authority may be prepared in a real target actor frame without inheriting its CID',async()=>{
    await run(()=>execution.runActor({actor:actor().user,clusterId:otherCid,workspaceId:wid,module:'promote'},async()=>{
      const handle=await authority.acquireActor(cid,{scope:'workspace'},actor());await authority.runRead(handle,()=>kong.request(cid,'GET','/'));expect(execution.current().clusterId).toBe(otherCid);
    }));expect(wire).toHaveLength(1);
  });
});
