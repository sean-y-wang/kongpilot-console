import 'reflect-metadata';
import { describe,it,expect,vi,beforeEach,afterEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { assertKongPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalAdminService } from '../../apps/console-api/src/modules/portal/portal-admin.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { WorkflowPlansService } from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Actual admin/compiler/repository/secrets; an explicit transactional SQL fixture.
 * Gateway/IAM/execution are fakes. PostgreSQL constraints and sessions have separate gates. */
function fixture(mode:'direct'|'approval'='direct'){
  const cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),serviceId=randomUUID(),reviewerRoleId=randomUUID(),secrets=new SecretService(),workspace={id:wid,revision:1,status:'active'};
  const actor:any={user:{id:uid,superAdmin:false},workspaceId:wid,idempotencyKey:'portal-original-create-key',requestId:randomUUID(),ip:'192.0.2.17'};
  const state:any={settings:null,publications:[],pages:[],definitions:[],workflows:[],versions:[],steps:[],executions:[],operations:[],iamOperations:[],audits:[]};let inTx=false,failPlan=false,loseCommit=false;
  const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
    if(sql==="SELECT id FROM roles WHERE builtin_kind='super-admin' AND code='super-admin' AND cluster_id IS NULL AND workspace_id IS NULL AND status='active' AND deleted_at IS NULL"){
      expect(p).toEqual([]);return{id:reviewerRoleId};
    }
    if(sql.includes('FROM iam_operations'))return null;
    if(sql.includes('FROM workflow_definitions d')){const row=state.definitions.find((r:any)=>r.kind===p[2]);return row?{id:row.id,current_version:1,policy_hash:row.hash??'a'.repeat(64)}:null;}
    if(sql.includes('FROM workflow_definitions'))return state.definitions.find((r:any)=>r.kind===p[2])??null;
    if(sql.includes('FROM workflow_versions'))return state.versions.find((r:any)=>r.workflow_id===p[0])??null;
    if(sql.includes('FROM workflows'))return sql.includes('idempotency_key')?state.workflows.find((r:any)=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.requester_user_id===p[2]&&r.idempotency_key===p[3])??null:state.workflows.find((r:any)=>r.id===p[0])??null;
    if(sql.includes('FROM workflow_steps'))return state.steps.find((r:any)=>r.workflow_id===p[0]&&r.state==='succeeded')??null;
    if(sql.includes('FROM portal_settings'))return state.settings;
    if(sql.includes('FROM portal_publications')){const found=state.publications.find((r:any)=>r.id===p[0]||r.id===p[2]);return found?structuredClone(found):null;}
    if(sql.includes('FROM portal_content'))return state.pages.find((r:any)=>r.id===p[0]||r.id===p[2])??null;
    if(sql.includes('FROM clusters'))return{revision:1,execution_mode:mode,version:'1.5.1',status:'healthy'};return null;
  }),query:vi.fn(async(sql:string,p:any[]=[])=>{
    if(sql.includes('FROM workflow_executions'))return state.executions.filter((r:any)=>r.workflow_id===p[0]);
    if(sql.includes('FROM workflow_steps'))return state.steps.filter((r:any)=>r.workflow_id===p[0]);
    if(sql.includes('FROM mutation_operations'))return state.operations.filter((r:any)=>r.cluster_id===p[0]&&(r.workflow_id===p[1]||p[2].includes(r.idempotency_key)||p[3].includes(r.id)));
    if(sql.includes('FROM iam_operations'))return state.iamOperations.filter((r:any)=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.actor_id===p[2]&&p[3].includes(r.idempotency_key));
    return[];
  }),exec:vi.fn(async(sql:string,p:any[]=[])=>{
    if(sql.startsWith('INSERT INTO portal_settings'))state.settings={id:randomUUID(),cluster_id:p[0],workspace_id:p[1],slug:p[2],name:'未发布的门户',description:'',status:'active',published:false,registration_enabled:false,branding:{},revision:1};
    if(sql.startsWith('INSERT INTO portal_publications'))state.publications.push({id:p[0],cluster_id:p[1],workspace_id:p[2],transport_scope:p[3],slug:p[4],name:p[5],service_id:p[6],acl_group:p[7],revision:1,current_revision:1,state:'draft'});
    if(sql.startsWith('INSERT INTO portal_content('))state.pages.push({id:p[0],cluster_id:p[1],workspace_id:p[2],slug:p[3],title:'未发布的页面',revision:1,current_revision:1,state:'draft'});
    if(sql.startsWith('INSERT INTO workflow_definitions('))state.definitions.push({id:p[0],kind:p[3]});
    if(sql.startsWith('INSERT INTO workflow_definition_versions'))state.definitions.find((r:any)=>r.id===p[2]).hash=p[4];
    if(sql.startsWith('INSERT INTO workflows('))state.workflows.push({id:p[0],cluster_id:p[1],workspace_id:p[2],kind:p[3],subject_type:p[4],subject_id:p[5],requester_type:p[6],requester_user_id:p[7],plan_revision:p[11],plan_hash:p[12],execution_mode:p[13],approval_required:p[14],request_hash:p[15],idempotency_key:p[16],expires_at:p[17],revision:1,state:'pending',created_at:new Date().toISOString()});
    if(sql.startsWith('INSERT INTO workflow_versions')){if(failPlan)throw new ServiceUnavailableException({code:'INJECTED_PLAN_FAILURE'});state.versions.push({workflow_id:p[2],plan_hash:p[4],payload_secret:p[7],steps_hash:p[11],safe_diff:JSON.parse(p[12]),safe_impact:JSON.parse(p[13])});}
    if(sql.startsWith('INSERT INTO workflow_steps'))state.steps.push({id:p[0],cluster_id:p[1],workspace_id:p[2],workflow_id:p[3],plan_revision:p[4],plan_hash:p[5],step_key:p[8],step_order:p[9],state:'pending',kind:p[10],entity_type:p[12],entity_id:p[13],parent_id:p[14],credential_kind:p[15],mutation_action:p[17],mutation_idempotency_key:p[19],safe_result:null});
    if(sql.startsWith('UPDATE portal_publications SET state=$2,workflow_id=$3')){const publication=state.publications.find((row:any)=>row.id===p[0]);if(!publication||publication.revision!==p[4]||(publication.workflow_id??null)!==(p[5]??null))return 0;publication.state=p[1];publication.workflow_id=p[2];publication.revision++;}
    return 1;
  }),transaction:vi.fn(async(fn:any)=>{const saved=structuredClone(state);inTx=true;let result:any;try{result=await fn(db);}catch(error){Object.assign(state,saved);throw error;}finally{inTx=false;}if(loseCommit){loseCommit=false;throw new ServiceUnavailableException({code:'TEST_COMMIT_ACK_LOST'});}return result;})};
  const authz:any={assertCluster:vi.fn(),assertWholeWorkspace:vi.fn(),assertScopedResource:vi.fn(),assertEntity:vi.fn(),permissionVersion:vi.fn(async()=> 'epoch-1')},audit:any={append:vi.fn(async(event:any)=>state.audits.push(event))},resolver:any={resolve:vi.fn(async()=>workspace),prepareUpdate:vi.fn(async(_cid:any,_type:any,_before:any,patch:any)=>patch),prepareCreate:vi.fn(async(_cid:any,_type:any,payload:any)=>payload)},kong:any={transportScope:vi.fn(async()=> 'b'.repeat(64)),request:vi.fn(async()=>({id:serviceId,tags:['kos-ws-pay']}))},context:any={runActor:vi.fn(async(_scope:any,fn:any)=>fn()),runPortalMetadataRead:vi.fn(async(_cid:any,_path:any,fn:any)=>fn()),runInternalRead:vi.fn(async(_cid:any,_purpose:any,fn:any)=>fn())};
  const native=new PortalNativeService(db,secrets,kong,context,authz,resolver),plans=new WorkflowPlansService(db,secrets,audit),registry=new WorkflowRegistryService(),iam:any={execute:vi.fn(),completed:vi.fn()},approved:any={assertSubject:vi.fn()};
  const workflows:any={execute:vi.fn(async(_cid:string,id:string)=>{expect(inTx).toBe(false);const row=state.workflows.find((r:any)=>r.id===id),step=state.steps.find((r:any)=>r.workflow_id===id),plan=secrets.decrypt<any>(state.versions.find((r:any)=>r.workflow_id===id).payload_secret,planAad(cid,wid,id,1)),before=plan.steps[0].before;
    row.state='succeeded';step.state='succeeded';step.safe_result={entity:{id:before.id,name:plan.steps[0].metadata.name??plan.steps[0].metadata.title,revision:2}};return{workflowId:id,state:'succeeded',steps:[]};}),receiptByKey:vi.fn(async(_cid:string,key:string)=>{const row=state.workflows.find((r:any)=>r.idempotency_key===key);return{workflowId:row.id,state:row.state,steps:[]};})};
  const documents:any={parse:vi.fn((document:any)=>({document,hash:secrets.fingerprint(document),report:{operationCount:0}})),markdown:vi.fn((value:any)=>value)};
  const service=new PortalAdminService(db,secrets,authz,audit,iam,{}as any,resolver,approved,plans,registry,workflows,native,documents);service.onModuleInit();
  const settingsBody={slug:'test-portal',name:'正式门户',published:true,registrationEnabled:true};
  return{service,cid,wid,actor,state,db,secrets,workflows,kong,plans,registry,authz,resolver,context,settingsBody,serviceId,setFailPlan:()=>failPlan=true,setLoseCommit:()=>loseCommit=true};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','aa'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M6 initial metadata reservation and immutable workflow atomicity',()=>{
  it('rolls back hidden settings, definitions and workflow if plan persistence fails',async()=>{const f=fixture();f.setFailPlan();await expect(f.service.saveSettings(f.cid,f.settingsBody,f.actor,true)).rejects.toMatchObject({response:{code:'INJECTED_PLAN_FAILURE'}});expect(f.state.settings).toBeNull();expect(f.state.workflows).toHaveLength(0);expect(f.state.definitions).toHaveLength(0);expect(f.workflows.execute).not.toHaveBeenCalled();});
  it('keeps approved settings reservation hidden without applying requested registration or branding',async()=>{const f=fixture('approval');const result=await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);expect(result.entity.approvalRequired).toBe(true);expect(f.state.settings).toMatchObject({published:false,registration_enabled:false,name:'未发布的门户'});expect(f.state.workflows).toHaveLength(1);expect(f.state.audits.find((row:any)=>row.action==='workflow.submit')).toMatchObject({requestId:f.actor.requestId,ip:f.actor.ip});expect(f.workflows.execute).not.toHaveBeenCalled();expect(f.db.transaction).toHaveBeenCalledOnce();});
  it('direct creation executes only after durable plan commit and returns the actual settings entity',async()=>{const f=fixture();const result=await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);expect(result.entity.id).toBe(f.state.settings.id);expect(result.entity.id).not.toBe(result.workflowId);expect(result.receipt.state).toBe('succeeded');expect(f.state.workflows[0].approval_required).toBe(false);expect(f.kong.request).not.toHaveBeenCalled();});
  it('lost reservation commit acknowledgment is recoverable by original key with no automatic dispatch',async()=>{const f=fixture();f.setLoseCommit();await expect(f.service.saveSettings(f.cid,f.settingsBody,f.actor,true)).rejects.toMatchObject({response:{code:'TEST_COMMIT_ACK_LOST'}});const recovered=await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);expect(recovered.state).toBe('pending');expect(f.state.workflows).toHaveLength(1);expect(f.workflows.execute).not.toHaveBeenCalled();});
  it('successful original create replay returns same actual entity without a second execution',async()=>{const f=fixture();const a=await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true),b=await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);expect(b.entity).toEqual(a.entity);expect(f.workflows.execute).toHaveBeenCalledOnce();});
  it('rejects same-key changed create content before revision checks',async()=>{const f=fixture();await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);await expect(f.service.saveSettings(f.cid,{...f.settingsBody,name:'different'},f.actor,true)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});expect(f.workflows.execute).toHaveBeenCalledOnce();});
  it('rejects POST to PATCH semantic substitution with identical body and key',async()=>{const f=fixture();await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);await expect(f.service.saveSettings(f.cid,f.settingsBody,f.actor,false)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});});
  it.each(['publications','pages']as const)('rolls back %s hidden reservation together with its plan',async(type)=>{const f=fixture();f.setFailPlan();const call=type==='publications'?f.service.savePublication(f.cid,undefined,{slug:'api',name:'API',serviceId:f.serviceId},f.actor):f.service.savePage(f.cid,undefined,{slug:'page',title:'页面',markdown:'内容'},f.actor);await expect(call).rejects.toMatchObject({response:{code:'INJECTED_PLAN_FAILURE'}});expect(f.state[type]).toHaveLength(0);expect(f.state.workflows).toHaveLength(0);});
  it.each(['publications','pages']as const)('binds %s request to collection-create versus a specific target UUID',async(type)=>{const f=fixture('approval'),body=type==='publications'?{slug:'api',name:'API',serviceId:f.serviceId}:{slug:'page',title:'页面',markdown:'内容'};if(type==='publications')await f.service.savePublication(f.cid,undefined,body,f.actor);else await f.service.savePage(f.cid,undefined,body,f.actor);const target=randomUUID();await expect(type==='publications'?f.service.savePublication(f.cid,target,body,f.actor):f.service.savePage(f.cid,target,body,f.actor)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});});
  it('direct metadata authorization uses only its actual module and never grants approval',async()=>{const f=fixture();await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);const row=f.state.workflows[0],plan=f.secrets.decrypt<any>(f.state.versions[0].payload_secret,planAad(f.cid,f.wid,row.id,1)),handler=f.registry.get('portal.settings.update');await handler.authorize(plan,f.actor,'write');expect(f.authz.assertWholeWorkspace.mock.calls.at(-1)?.slice(3)).toEqual(['portal','write']);await expect(handler.authorize(plan,f.actor,'approve')).rejects.toMatchObject({response:{code:'DIRECT_WORKFLOW_APPROVAL_FORBIDDEN'}});});
  it('public metadata diff excludes raw Service, schemas, secrets and private publication proof while sealed payload remains exact',async()=>{const f=fixture('approval');await f.service.saveSettings(f.cid,f.settingsBody,f.actor,true);const previous=f.state.workflows[0],plan=f.secrets.decrypt<any>(f.state.versions[0].payload_secret,planAad(f.cid,f.wid,previous.id,1)),privateConfig={id:randomUUID(),host:'private.backend.internal',port:8001};plan.workflowId=randomUUID();plan.steps[0].metadata={name:'visible business change',documentHash:'d'.repeat(64),service:privateConfig,schemas:{keyAuth:{password:{default:'hidden'}}},definitions:{internal:true},publicationProof:{raw:privateConfig},requestKey:'raw-secret',key:'hidden'};plan.steps[0].metadataPayloadHmac=f.secrets.fingerprint(plan.steps[0].metadata);await f.db.transaction((tx:any)=>f.plans.persist(plan,'another-plan-key',{},tx,{requestId:randomUUID(),ip:'192.0.2.17'}));const version=f.state.versions.at(-1),diff=JSON.stringify(version.safe_diff),impact=JSON.stringify(version.safe_impact);expect(diff).toContain('visible business change');expect(diff).toContain('documentHash');for(const privateValue of ['private.backend.internal','schemas','definitions','publicationProof','raw-secret','hidden'])expect(diff).not.toContain(privateValue);expect(impact).not.toContain('private.backend.internal');expect(f.secrets.decrypt<any>(version.payload_secret,planAad(f.cid,f.wid,plan.workflowId,1)).steps[0].metadata.service).toEqual(privateConfig);});

});

describe('M6 publication preflight through strict Kong 1.5 paths',()=>{
  async function publicationFixture(){
    const f=fixture('approval');await f.plans.definitions(f.cid,f.wid,f.actor.user.id);
    const publication={id:randomUUID(),cluster_id:f.cid,workspace_id:f.wid,transport_scope:'b'.repeat(64),service_id:f.serviceId,name:'Scoped API',slug:'scoped-api',acl_group:'portal-group',revision:2,current_revision:2,state:'draft'};
    f.state.publications.push(publication);f.db.transaction.mockClear();f.kong.request.mockClear();
    const body={revision:2,confirmed:true,confirm_name:publication.name};return{...f,publication,body};
  }
  function gateway(f:Awaited<ReturnType<typeof publicationFixture>>,plugins:(query:any)=>any){
    f.kong.request.mockImplementation(async(_cid:string,method:string,path:string,_body:any,query:any)=>{
      assertKongPath(method as any,path);
      if(path==='/plugins')return plugins(query);
      if(path===`/services/${f.serviceId}`)return{id:f.serviceId,name:'real-service',tags:['kos-ws-pay']};
      if(path.startsWith('/schemas/'))return{fields:[]};
      throw new Error(`Unexpected preflight path: ${path}`);
    });
  }
  async function failedPublication(withReceipt=false){
    const f=await publicationFixture();gateway(f,()=>({data:[],next:null}));
    const initial=await f.service.publish(f.cid,f.publication.id,f.body,f.actor),row=f.state.workflows[0],plan=f.secrets.decrypt<any>(f.state.versions[0].payload_secret,planAad(f.cid,f.wid,initial.workflowId,1));row.state='failed';
    const execution={id:randomUUID(),cluster_id:f.cid,workspace_id:f.wid,workflow_id:row.id,plan_revision:row.plan_revision,plan_hash:row.plan_hash,execution_mode:plan.executionMode,approval_required:plan.approvalRequired,approved_by:randomUUID(),execution_actor_id:f.actor.user.id,idempotency_key:'failed-execution-key',state:'failed'};
    f.state.executions.push(execution);
    if(withReceipt){const expected=plan.steps[0],operationId=randomUUID(),step=f.state.steps[0],binding={workflowId:row.id,executionId:execution.id,planRevision:row.plan_revision,planHash:row.plan_hash,stepId:expected.id,beforeHmac:expected.beforeFingerprint};
      step.state='failed';step.completed_at=new Date().toISOString();step.operation_id=operationId;step.safe_result={nativeOperationId:operationId,remoteStarted:true,remoteCompleted:false};
      f.state.operations.push({id:operationId,cluster_id:f.cid,workspace_id:f.wid,actor_id:f.actor.user.id,transport_scope:plan.scope.transportScope,idempotency_key:expected.mutationIdempotencyKey,entity_type:expected.entityType,entity_id:null,parent_id:null,credential_kind:null,action:expected.mutationAction,state:'failed',remote_started:true,remote_completed:false,workflow_id:row.id,workflow_execution_id:execution.id,workflow_plan_revision:row.plan_revision,workflow_plan_hash:row.plan_hash,workflow_step_id:expected.id,payload_secret:f.secrets.encrypt(expected.mutationPayload,`mutation:${operationId}:payload`),before_secret:f.secrets.encrypt(expected.before,`mutation:${operationId}:before`),request_hash:f.secrets.fingerprint({actor:f.actor.user.id,clusterId:f.cid,workspaceId:f.wid,entityType:expected.entityType,entityId:null,action:expected.mutationAction,payload:expected.mutationPayload,parentId:null,credentialKind:null,approvedWorkflow:binding})});
    }
    f.db.transaction.mockClear();f.kong.request.mockClear();return{...f,row,plan,execution,nextActor:{...f.actor,idempotencyKey:'explicit-new-publication-key'},nextBody:{...f.body,revision:f.publication.revision}};
  }
  it('finds actual Service-only plugins on a later global cursor page without using forbidden nested paths',async()=>{
    const f=await publicationFixture(),acl={id:randomUUID(),name:'acl',service:{id:f.serviceId},route:null,consumer:null,enabled:false,config:{whitelist:['existing-group'],blacklist:null}},keyAuth={id:randomUUID(),name:'key-auth',service:{id:f.serviceId},route:null,consumer:null,enabled:true,config:{key_names:['custom-api-key'],hide_credentials:false,anonymous:null}};
    const ignored=[{id:randomUUID(),name:'acl',service:null,config:{blacklist:['global-block']}},{id:randomUUID(),name:'key-auth',service:{id:randomUUID(),name:'real-service'},config:{anonymous:randomUUID()}},{id:randomUUID(),name:'acl',service:{id:f.serviceId},route:{id:randomUUID()},config:{blacklist:['route-block']}},{id:randomUUID(),name:'key-auth',service:{id:f.serviceId},consumer:{id:randomUUID()},config:{anonymous:randomUUID()}}];
    gateway(f,query=>query.offset?{data:[acl,keyAuth],next:null}:{data:ignored,next:'/plugins?size=100&offset=page-two'});
    const result=await f.service.publish(f.cid,f.publication.id,f.body,f.actor);
    const plan=f.secrets.decrypt<any>(f.state.versions[0].payload_secret,planAad(f.cid,f.wid,result.workflowId,1));
    expect(f.kong.request.mock.calls.filter((call:any[])=>call[2]==='/plugins').map((call:any[])=>call[4])).toEqual([{size:100},{size:100,offset:'page-two'}]);
    expect(plan.steps.slice(0,2).map((step:any)=>step.mutationAction)).toEqual(['update','update']);
    expect(plan.steps[0]).toMatchObject({entityId:acl.id,mutationPayload:{enabled:true,config:{whitelist:['existing-group','portal-group'],blacklist:null}}});
    expect(plan.steps[1]).toMatchObject({entityId:keyAuth.id,mutationPayload:{enabled:true,config:keyAuth.config}});
    expect(f.authz.assertEntity.mock.calls.map((call:any[])=>call[4].id)).toEqual([acl.id,keyAuth.id]);
    expect(f.workflows.execute).not.toHaveBeenCalled();expect(f.kong.request.mock.calls.every((call:any[])=>call[1]==='GET')).toBe(true);
    expect(()=>assertKongPath('GET',`/services/${f.serviceId}/plugins`)).toThrow();
  });
  it('does not stop at an early matching plugin when the global collection exceeds the bounded scan',async()=>{
    const f=await publicationFixture(),early={id:randomUUID(),name:'acl',service:{id:f.serviceId},config:{whitelist:['existing-group'],blacklist:null}};let page=0;
    gateway(f,()=>({data:page++===0?[early]:[],next:`/plugins?offset=page-${page}`}));
    await expect(f.service.publish(f.cid,f.publication.id,f.body,f.actor)).rejects.toMatchObject({response:{code:'PORTAL_PREFLIGHT_BUDGET'}});
    expect(f.kong.request.mock.calls.filter((call:any[])=>call[2]==='/plugins')).toHaveLength(10);
    expect(f.state.workflows).toHaveLength(0);expect(f.db.transaction).not.toHaveBeenCalled();expect(f.workflows.execute).not.toHaveBeenCalled();
  });
  it('checks current write permission on the selected existing Service plugin before persisting a publication plan',async()=>{
    const f=await publicationFixture(),acl={id:randomUUID(),name:'acl',service:{id:f.serviceId},config:{whitelist:['existing-group'],blacklist:null}};
    gateway(f,()=>({data:[acl],next:null}));f.authz.assertEntity.mockRejectedValue(new ForbiddenException({code:'ENTITY_PERMISSION_DENIED'}));
    await expect(f.service.publish(f.cid,f.publication.id,f.body,f.actor)).rejects.toMatchObject({response:{code:'ENTITY_PERMISSION_DENIED'}});
    expect(f.authz.assertEntity.mock.calls[0].slice(1)).toEqual([f.cid,'plugins','write',acl,f.wid]);
    expect(f.db.transaction).not.toHaveBeenCalled();expect(f.state.workflows).toHaveLength(0);expect(f.workflows.execute).not.toHaveBeenCalled();
  });
  it.each([false,true])('permits an explicitly confirmed new plan after complete failed-parent proof (native failed receipt=%s)',async(withReceipt)=>{
    const f=await failedPublication(withReceipt),result=await f.service.publish(f.cid,f.publication.id,f.nextBody,f.nextActor);
    expect(result.workflowId).not.toBe(f.row.id);expect(f.state.workflows).toHaveLength(2);expect(f.state.workflows[0].state).toBe('failed');
    expect(f.workflows.execute).not.toHaveBeenCalled();expect(f.state.operations).toHaveLength(withReceipt?1:0);
    expect(f.db.one.mock.calls.some((call:any[])=>call[0].includes('FOR UPDATE')&&call[1][0]===f.row.id)).toBe(true);
  });
  it('old-key failed publication replay preserves its old receipt without a native read or new plan',async()=>{
    const f=await failedPublication(true),result=await f.service.publish(f.cid,f.publication.id,f.body,f.actor);
    expect(result).toMatchObject({workflowId:f.row.id,state:'failed'});expect(f.state.workflows).toHaveLength(1);expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['pending','approved','executing','partial','uncertain'])('denies a new plan while the old parent is %s',async(state)=>{
    const f=await failedPublication(true);f.row.state=state;
    await expect(f.service.publish(f.cid,f.publication.id,f.nextBody,f.nextActor)).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_RECOVERY_REQUIRED',workflowId:f.row.id,state}});
    expect(f.kong.request.mock.calls.map((call:any[])=>call[2])).toEqual([`/services/${f.serviceId}`]);expect(f.db.transaction).not.toHaveBeenCalled();expect(f.state.workflows).toHaveLength(1);
  });
  it.each(['missing-execution','extra-execution','wrong-plan','wrong-step-type','completed-native','uncertain-native','running-step','succeeded-step','missing-receipt','payload-substitution','foreign-actor','metadata-iam-uncertain'])('fails closed on %s despite a failed workflow state',async(reason)=>{
    const f=await failedPublication(true),operation=f.state.operations[0];
    if(reason==='missing-execution')f.state.executions=[];
    if(reason==='extra-execution')f.state.executions.push({...f.execution,id:randomUUID()});
    if(reason==='wrong-plan')f.execution.plan_hash='f'.repeat(64);
    if(reason==='wrong-step-type')f.state.steps[0].entity_type='consumers';
    if(reason==='completed-native')operation.remote_completed=true;
    if(reason==='uncertain-native')operation.state='uncertain';
    if(reason==='running-step')f.state.steps[0].state='running';
    if(reason==='succeeded-step')f.state.steps[0].state='succeeded';
    if(reason==='missing-receipt')f.state.operations=[];
    if(reason==='payload-substitution')operation.payload_secret=f.secrets.encrypt({id:randomUUID()},`mutation:${operation.id}:payload`);
    if(reason==='foreign-actor')operation.actor_id=randomUUID();
    if(reason==='metadata-iam-uncertain'){const step=f.plan.steps.at(-1);f.state.iamOperations.push({id:randomUUID(),cluster_id:f.cid,workspace_id:f.wid,actor_id:f.execution.execution_actor_id,state:'uncertain',idempotency_key:`metadata-${f.secrets.fingerprint({id:f.row.id,step:step.id,key:f.execution.idempotency_key}).slice(0,48)}`});}
    await expect(f.service.publish(f.cid,f.publication.id,f.nextBody,f.nextActor)).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_RECOVERY_REQUIRED',workflowId:f.row.id}});
    expect(f.kong.request.mock.calls.map((call:any[])=>call[2])).toEqual([`/services/${f.serviceId}`]);expect(f.state.workflows).toHaveLength(1);
  });
  it('rechecks the failed-parent proof in the plan transaction and rejects publication revision/association races',async()=>{
    const f=await failedPublication(true),transaction=f.db.transaction.getMockImplementation()!;
    f.db.transaction.mockImplementation(async(fn:any)=>{f.state.operations[0].state='uncertain';return transaction(fn);});
    await expect(f.service.publish(f.cid,f.publication.id,f.nextBody,f.nextActor)).rejects.toMatchObject({response:{code:'PORTAL_PUBLICATION_RECOVERY_REQUIRED'}});
    expect(f.state.workflows).toHaveLength(1);expect(f.publication.workflow_id).toBe(f.row.id);
  });
  it('publishes capability for a proven failed plan and disables it when a native result becomes unknown',async()=>{
    const f=await failedPublication(true),first=await f.service.publication(f.cid,f.publication.id,f.actor);expect(first.entity.capabilities.publish).toBe(true);
    f.state.operations[0].state='uncertain';const second=await f.service.publication(f.cid,f.publication.id,f.actor);expect(second.entity.capabilities.publish).toBe(false);
  });
  it('checks the actual publication Service permission before exposing a pending workflow recovery identifier',async()=>{
    const f=await failedPublication(true);f.authz.assertScopedResource.mockRejectedValue(new ForbiddenException({code:'SCOPED_RESOURCE_FORBIDDEN'}));f.db.query.mockClear();
    await expect(f.service.publish(f.cid,f.publication.id,f.nextBody,f.nextActor)).rejects.toMatchObject({response:{code:'SCOPED_RESOURCE_FORBIDDEN'}});
    expect(f.db.query).not.toHaveBeenCalled();expect(f.db.transaction).not.toHaveBeenCalled();expect(f.state.workflows).toHaveLength(1);
  });
});
