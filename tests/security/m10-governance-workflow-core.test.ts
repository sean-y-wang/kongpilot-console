import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {ApprovedWorkflowExecutionService} from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {GovernanceMetadataService} from '../../apps/console-api/src/modules/governance/governance-metadata.service';
import {GovernanceRepositoryService} from '../../apps/console-api/src/modules/governance/governance-repository.service';
import {validateWorkflowPlan} from '../../apps/console-api/src/modules/workflows/workflow-validation';
import {planAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {workspaceTestResolver,PAY_WORKSPACE_ID as wid} from '../unit/workspace-test-helper';

/** Real workflow, private proofs, governance intent crypto, independent reviewer
 * SQL grant checks and resource writer. Explicit SQL/lock/audit fixtures do not
 * represent real PostgreSQL acceptance or a deployed gateway. */
function fixture(){
 const cid=randomUUID(),uid=randomUUID(),reviewer=randomUUID(),sid=randomUUID(),wf=randomUUID(),intentId=randomUUID(),rid=randomUUID();
 const secrets=new SecretService(),context=new KongExecutionContextService(),ws=workspaceTestResolver(cid),copy=(x:any)=>x==null?x:structuredClone(x);
 const actor={user:{id:uid,username:'governance-owner',superAdmin:false},workspaceId:wid,requestId:randomUUID(),ip:'192.0.2.9',idempotencyKey:'original-governance-execution'};
 const cluster={id:cid,admin_url:'http://kong:8001',transport_scope:'c'.repeat(64),revision:1,execution_mode:'approval',version:'1.5.1',status:'healthy'};
 const users=new Map([uid,reviewer].map(id=>[id,{id,username:id,super_admin:false,status:'active',deleted_at:null,force_password_change:false,permissions_epoch:1,credential_epoch:1}]));
 const grant=(module:string,action:string)=>({cluster_id:cid,workspace_id:wid,module,action,scope_type:'workspace',scope_values:[wid]});
 const grants=new Map([[uid,[grant('workflows','read'),grant('workflows','write'),grant('lint','read'),grant('lint','write')]],
  [reviewer,[grant('workflows','approve'),grant('workflows','read'),grant('lint','read')]]]);
 const content={code:'require-owner',name:'负责人规范',given:{entityTypes:['services']},then:{path:'tags',op:'required'},severity:'warn',description:'负责人标签',enabled:true};
 const request={type:'governance_rules',target:null,operation:'create',input:content};
 const scope={clusterId:cid,workspaceId:wid,transportScope:cluster.transport_scope,clusterRevision:1,workspaceRevision:1,executionMode:'approval',permissionVersion:`${uid}:1:1`,originalRequest:request};
 const metadata={intentId,resourceType:'governance_rules',resourceId:rid,operation:'create',payloadHmac:secrets.fingerprint(content)};
 const plan:WorkflowPlanV1={version:1,kind:'governance-metadata',clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,executionMode:'approval',approvalRequired:true,
  subject:{type:'governance_metadata_requests',id:intentId},requester:{type:'console',id:uid},definition:{id:randomUUID(),version:1,policyHash:'a'.repeat(64)},
  issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600000).toISOString(),scope:{transportScope:cluster.transport_scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],
  steps:[{id:randomUUID(),key:'governance.metadata',order:1,kind:'metadata',handler:'governance.metadata',entityType:'governance_metadata_requests',entityId:intentId,permissionAction:'write',dependencies:[],nativeRequests:[],
   before:null,metadataRevision:0,metadataBeforeHmac:secrets.fingerprint(null),metadata,metadataPayloadHmac:secrets.fingerprint(metadata)}]};
 validateWorkflowPlan(plan);const hash=secrets.fingerprint(plan),step=plan.steps[0];
 const version={cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:hash,steps_hash:secrets.fingerprint(plan.steps),execution_mode:'approval',approval_required:true,
  expires_at:plan.expiresAt,step_count:1,native_request_count:0,policy_version:1,payload_secret:secrets.encrypt(plan,planAad(cid,wid,wf,1))};
 const state:any={epoch:1,sessionActive:true,resource:null,content:null,audits:[],failAudit:false,failLease:false,executions:new Map(),
  workflow:{id:wf,cluster_id:cid,workspace_id:wid,kind:plan.kind,subject_type:plan.subject.type,subject_id:intentId,requester_type:'console',requester_user_id:uid,
   definition_id:plan.definition.id,definition_version:1,plan_revision:1,plan_hash:hash,state:'approved',revision:1,approved_by:reviewer,execution_mode:'approval',approval_required:true,
   created_at:new Date().toISOString(),expires_at:plan.expiresAt,idempotency_key:'original-governance-submit',request_hash:secrets.fingerprint({requester:plan.requester,clusterId:cid,workspaceId:wid,request})},
  intent:{id:intentId,cluster_id:cid,workspace_id:wid,actor_id:uid,resource_type:'governance_rules',resource_id:rid,operation:'create',workflow_id:wf,idempotency_key:'original-governance-submit',request_hmac:secrets.fingerprint(request),
   payload_secret:secrets.encrypt(content,`governance:metadata-payload:${intentId}`),payload_hmac:secrets.fingerprint(content),before_secret:null,before_hmac:secrets.fingerprint(null),scope_secret:secrets.encrypt(scope,`governance:metadata-scope:${intentId}`)},
  rows:[{id:step.id,cluster_id:cid,workspace_id:wid,workflow_id:wf,plan_revision:1,plan_hash:hash,execution_mode:'approval',approval_required:true,step_key:step.key,step_order:1,kind:'metadata',handler:step.handler,
   entity_type:step.entityType,entity_id:intentId,parent_id:null,credential_kind:null,permission_action:'write',mutation_action:null,mutation_payload_hmac:null,mutation_idempotency_key:null,before_fingerprint:null,
   native_requests:[],dependencies:[],metadata_before_hmac:step.metadataBeforeHmac,metadata_revision:0,metadata_payload_hmac:step.metadataPayloadHmac,operation_id:null,state:'pending',revision:1}]};
 const approvals=[{decision:'approve',approver_id:reviewer,plan_hash:hash,level:1}],stages=[{state:'approved',required_approvals:1,level:1,plan_hash:hash}];
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('iam_epoch'))return{version:state.epoch};
  if(sql.includes('FROM users')){const r=users.get(p[0]);return r?.status==='active'&&!r.deleted_at?copy(r):null;}
  if(sql.includes('FROM auth_sessions'))return state.sessionActive&&p[0]===sid&&p[1]===uid?{id:sid}:null;
  if(sql.includes('FROM clusters'))return p[0]===cid?copy(cluster):null;
  if(sql.includes('FROM workspaces'))return ws.db.one(sql,p);
  if(sql.includes('FROM governance_metadata_requests'))return p[0]===intentId&&(!p[1]||p[1]===cid)&&(!p[2]||p[2]===wid)?copy(state.intent):null;
  if(sql.includes('FROM governance_rules'))return p[0]===rid&&p[1]===cid&&p[2]===wid&&state.resource?copy({...state.resource,content:state.content,content_hmac:secrets.fingerprint(state.content)}):null;
  if(sql.includes('FROM workflow_definition_versions'))return{mode:'single',allow_self_approval:false,policy_hash:plan.definition.policyHash};
  if(sql.includes('FROM workflow_events')||sql.includes('FROM workflow_approvals'))return null;
  if(sql.includes('FROM workflow_executions e JOIN workflows')){const e=state.executions.get(p[0]);return e?.state==='executing'&&state.workflow.state==='executing'&&state.rows[0].state==='running'&&p[1]===wf&&p[2]===cid&&p[3]===wid&&p[4]===uid&&p[5]===step.id?{id:e.id}:null;}
  if(sql.includes('FROM workflow_executions'))return copy(sql.includes('WHERE workflow_id=$1')?[...state.executions.values()].find((e:any)=>e.workflow_id===p[0]&&e.plan_revision===p[1]):state.executions.get(p[0]));
  if(sql.includes('FROM workflow_versions'))return copy(sql.includes('WHERE workflow_id=$1')?p[0]===wf&&p[1]===cid&&p[2]===wid&&p[3]===1?version:null:p[0]===cid&&p[1]===wid&&p[2]===wf&&p[3]===1?version:null);
  if(sql.includes('FROM workflows w LEFT JOIN workflow_executions'))return p[0]===cid&&p[1]===wid&&p[2]===uid&&(p[3]===state.workflow.idempotency_key||[...state.executions.values()].some((e:any)=>e.execution_actor_id===uid&&e.idempotency_key===p[3]))?copy(state.workflow):null;
  if(sql.includes('FROM workflows'))return copy(sql.includes('WHERE cluster_id=$1')?p[0]===cid&&p[1]===wid&&p[2]===wf?state.workflow:null:p[0]===wf?state.workflow:null);
  if(sql.includes('FROM workflow_steps'))return copy(state.rows.find((r:any)=>r.state==='running'));
  throw new Error(`Unexpected SQL read: ${sql}`);
 }),query:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.replace(/\s+/g,' ').trim()===`SELECT DISTINCT w.* FROM workflows w LEFT JOIN workflow_executions e ON e.workflow_id=w.id LEFT JOIN workflow_approvals a ON a.workflow_id=w.id LEFT JOIN workflow_events v ON v.workflow_id=w.id AND v.action='decision.cancel' WHERE w.cluster_id=$1 AND w.kind='control-metadata' AND ((w.requester_user_id=$2 AND w.idempotency_key=$3) OR (e.execution_actor_id=$2 AND e.idempotency_key=$3) OR (a.approver_id=$2 AND a.idempotency_key=$3) OR (v.actor_id=$2 AND v.safe_metadata->>'key'=$3)) LIMIT 2`){
    expect(p).toEqual([cid,uid,actor.idempotencyKey]);expect(state.workflow.kind).toBe('governance-metadata');return [];
  }
  if(sql.includes('FROM iam_effective_grants'))return copy(grants.get(p[0])??[]);
  if(sql.includes('FROM workflow_approvals'))return copy(approvals);
  if(sql.includes('FROM workflow_stages'))return copy(stages);
  if(sql.includes('FROM workflow_steps'))return copy(state.rows);
  throw new Error(`Unexpected SQL list: ${sql}`);
 }),exec:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.startsWith('INSERT INTO workspaces'))return 0;
  if(sql.startsWith('INSERT INTO governance_rules')){if(state.resource)throw new Error('Duplicate rule');state.resource={id:p[0],cluster_id:p[1],workspace_id:p[2],code:p[3],name:p[4],owner_user_id:p[5],state:'active',enabled:p[6],current_version:1,revision:1,created_at:new Date().toISOString(),updated_at:new Date().toISOString()};return 1;}
  if(sql.startsWith('INSERT INTO governance_rule_versions')){if(!state.resource||p[0]!==cid||p[1]!==wid||p[2]!==rid||p[3]!==1||p[5]!==secrets.fingerprint(JSON.parse(p[4])))throw new Error('Version source mismatch');state.content=JSON.parse(p[4]);return 1;}
  if(sql.startsWith('INSERT INTO workflow_executions')){const[id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,claim_token_hash,request_id,idempotency_key,expires_at]=p;
   state.executions.set(id,{id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,claim_token_hash,request_id,idempotency_key,expires_at,state:'executing',snapshot_state:'pending',revision:1});return 1;}
  if(sql.startsWith('UPDATE workflow_steps')){const r=state.rows[0];if(p[0]!==r.id)return 0;
   if(sql.includes("SET state='running'")){if(r.state!=='pending')return 0;r.state='running';}
   else if(sql.includes("SET state='succeeded'")){if(r.state!=='running'||p[2]!==wf||p[3]!==1||p[4]!==hash)return 0;r.state='succeeded';r.safe_result=JSON.parse(p[1]);}
   else if(sql.includes('SET state=$2')){if(r.state!=='running')return 0;r.state=p[1];r.error_code=p[2];r.safe_result=JSON.parse(p[3]);}
   else throw new Error(`Unexpected step write: ${sql}`);r.revision++;return 1;}
  if(sql.startsWith('UPDATE workflow_executions')){const e=state.executions.get(p[0]);if(!e)return 0;
   if(sql.includes("snapshot_state='ready'")){if(e.state!=='executing'||e.snapshot_state!=='pending'||p[4]!==wf||p[5]!==hash)return 0;Object.assign(e,{snapshot_state:'ready',snapshot_secret:p[1],snapshot_hash:p[2],snapshot_id:p[3]});}
   else if(sql.includes("SET state='succeeded'")){if(e.state!=='executing'||p[1]!==wf||p[2]!==1||p[3]!==hash||p[4]!==uid)return 0;e.state='succeeded';}
   else if(sql.includes('SET state=$2')){if(e.state!=='executing')return 0;e.state=p[1];}
   else throw new Error(`Unexpected execution write: ${sql}`);e.revision++;return 1;}
  if(sql.startsWith('UPDATE workflows')){const r=state.workflow;if(p[0]!==wf)return 0;
   if(sql.includes("SET state='executing'")){if(r.revision!==p[1]||r.state!==p[2])return 0;r.state='executing';}
   else if(sql.includes("SET state='succeeded'")){if(r.state!=='executing'||p[1]!==1||p[2]!==hash||p[3]!==r.revision)return 0;r.state='succeeded';}
   else if(sql.includes('SET state=$2')){if(r.state!=='executing')return 0;r.state=p[1];}
   else throw new Error(`Unexpected workflow write: ${sql}`);r.revision++;return 1;}
  throw new Error(`Unexpected SQL write: ${sql}`);
 }),transaction:vi.fn(async(fn:any)=>{const snapshot=copy(state);try{return await fn(db);}catch(e){Object.assign(state,snapshot);throw e;}})};
 const kong:any={request:vi.fn(async()=>{throw new Error('Metadata workflow must not send a native request');}),transportScope:vi.fn(async()=>cluster.transport_scope)};
 const authz=new AuthorizationService(db,ws.resolver,kong,context),redis:any={withLock:vi.fn(async(_k:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>{if(state.failLease)throw new Error('Lease lost');})};
 const audit:any={append:vi.fn(async(event:any,tx:any)=>{if(state.failAudit&&event.action==='governance.metadata.create')throw new Error('Audit write failed');state.audits.push({event:copy(event),transaction:tx===db});return{id:randomUUID()};})};
 const approved=new ApprovedWorkflowExecutionService(db,secrets,authz,ws.resolver,kong,redis,context);approved.onModuleInit();
 const plans=new WorkflowPlansService(db,secrets,audit),registry=new WorkflowRegistryService(),repo=new GovernanceRepositoryService(db,secrets);
 const metadataService=new GovernanceMetadataService(db,redis,secrets,authz,ws.resolver,{}as any,{}as any,audit,repo,plans,registry,approved,context);metadataService.onModuleInit();
 const workflow=new WorkflowService(db,redis,secrets,kong,context,authz,audit,{}as any,{}as any,{}as any,ws.resolver,plans,registry,approved,{}as any);
 const http=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,sid);const close=context.captureHttpCloser();try{return await fn();}finally{close();}});
 const execute=()=>http(()=>workflow.execute(cid,wf,{revision:state.workflow.revision,planHash:hash,confirmed:true,confirm_name:'governance-metadata'},actor));
 return{cid,uid,reviewer,sid,wf,intentId,rid,plan,version,scope,request,state,users,grants,db,kong,context,authz,secrets,approved,plans,registry,metadataService,workflow,actor,http,execute};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','bd'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());

describe('M10 fixed governance metadata workflow core',()=>{
 it('executes the original sealed intent with a separate live reviewer and transaction audit, without Kong requests',async()=>{
  const f=fixture(),receipt=await f.execute();expect(receipt).toMatchObject({workflowId:f.wf,state:'succeeded',steps:[{state:'succeeded',operationId:null}]});
  expect(f.state.resource.id).toBe(f.rid);expect(f.state.content.name).toBe('负责人规范');expect(f.kong.request).not.toHaveBeenCalled();
  expect(f.state.audits.filter((r:any)=>r.event.action==='governance.metadata.create')).toMatchObject([{transaction:true,event:{entityType:'governance_rules',entityId:f.rid,actorId:f.uid,workflowId:f.wf}}]);
  expect(f.context.peek()).toBeNull();
  await expect(f.http(()=>f.workflow.receiptByKey(f.cid,'original-governance-execution',f.actor))).resolves.toMatchObject({state:'succeeded'});
 });
 it.each(['lint-read','workflow-approve','foreign-workspace','restricted-scope','inactive','password-reset'])('stops execution when the reviewer current eligibility changes: %s',async(kind)=>{
  const f=fixture();if(kind==='inactive')f.users.get(f.reviewer)!.status='disabled';else if(kind==='password-reset')f.users.get(f.reviewer)!.force_password_change=true;
  else {const g=f.grants.get(f.reviewer)!;if(kind==='lint-read')f.grants.set(f.reviewer,g.filter(x=>x.module!=='lint'));if(kind==='workflow-approve')f.grants.set(f.reviewer,g.filter(x=>x.action!=='approve'));
   if(kind==='foreign-workspace')g.forEach(x=>{x.workspace_id=randomUUID();x.scope_values=[x.workspace_id];});if(kind==='restricted-scope')g.forEach(x=>{x.scope_type='tag_group';x.scope_values=['team:pay'];});}
  await expect(f.execute()).rejects.toMatchObject({status:403});expect(f.state.resource).toBeNull();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('rolls back the target, version and step acknowledgment when the business audit fails',async()=>{
  const f=fixture();f.state.failAudit=true;await expect(f.execute()).rejects.toMatchObject({status:503,response:{state:'uncertain'}});
  expect(f.state.resource).toBeNull();expect(f.state.content).toBeNull();expect(f.state.rows[0].state).toBe('uncertain');expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['actor','workflow','payload-hmac','before','scope','request-hmac','request-key','requester-hash','missing-original-request','session'])('rejects immutable intent or current session changes: %s',async(kind)=>{
  const f=fixture();if(kind==='actor')f.state.intent.actor_id=randomUUID();if(kind==='workflow')f.state.intent.workflow_id=randomUUID();if(kind==='payload-hmac')f.state.intent.payload_hmac='d'.repeat(64);
  if(kind==='before')f.state.intent.before_hmac='d'.repeat(64);if(kind==='scope')f.state.intent.scope_secret=f.secrets.encrypt({...f.scope,workspaceRevision:2},`governance:metadata-scope:${f.intentId}`);if(kind==='session')f.state.sessionActive=false;
  if(kind==='request-hmac')f.state.intent.request_hmac='e'.repeat(64);if(kind==='request-key')f.state.intent.idempotency_key='foreign-submit-key';if(kind==='requester-hash')f.state.workflow.request_hash='e'.repeat(64);
  if(kind==='missing-original-request'){const scope={...f.scope};delete(scope as any).originalRequest;f.state.intent.scope_secret=f.secrets.encrypt(scope,`governance:metadata-scope:${f.intentId}`);}
  await expect(f.execute()).rejects.toBeDefined();expect(f.state.resource).toBeNull();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('uses no foreign reviewer identity under the real executor SID',async()=>{
  const f=fixture(),snap=vi.spyOn(f.authz,'snapshot');await f.execute();expect(snap.mock.calls.every(([user])=>user.id===f.uid)).toBe(true);
  expect(f.db.one.mock.calls.some(([sql,p]:any)=>sql.includes('FROM auth_sessions')&&p[1]===f.reviewer)).toBe(false);
 });
 it('cannot turn an original metadata step into a native mutation permit',async()=>{
  const f=fixture();const altered=structuredClone(f.plan);altered.steps[0].nativeRequests=[{method:'PATCH',canonicalPath:`/services/${f.rid}`,nativeType:'services',nativeId:f.rid,body:{tags:[]},bodyHmac:f.secrets.fingerprint({tags:[]})}];
  expect(()=>validateWorkflowPlan(altered)).toThrow();await expect(f.approved.mutationBinding({execution:{executionId:randomUUID()},stepId:f.plan.steps[0].id,kind:'native'}as any,{}as any)).rejects.toMatchObject({status:403});
 });
 it.each(['wrong-kind','wrong-subject','wrong-handler','foreign-step-subject','native-type','native-payload','native-before','parent','dependencies','prerequisites','generated','wrong-resource','delete-op','extra-payload','wrong-revision','create-before','false-approval','direct-mode'])('rejects a forged fixed metadata shape: %s',kind=>{
  const f=fixture(),p=structuredClone(f.plan),s=p.steps[0],m=s.metadata as any;
  if(kind==='wrong-kind')p.kind='portal-metadata';if(kind==='wrong-subject')p.subject.type='portal_content';if(kind==='wrong-handler')s.handler='portal.settings.update';if(kind==='foreign-step-subject')s.entityId=randomUUID();
  if(kind==='native-type')s.kind='native';if(kind==='native-payload')s.mutationPayload={tags:[]};if(kind==='native-before')s.beforeFingerprint='e'.repeat(64);if(kind==='parent')s.parentId=randomUUID();
  if(kind==='dependencies')s.dependencies=[randomUUID()];if(kind==='prerequisites')p.prerequisites=[{type:'services',id:randomUUID(),path:'/services',fingerprint:'e'.repeat(64),before:{}}];if(kind==='generated')p.generated={consumerId:randomUUID(),aclId:randomUUID(),credentialId:randomUUID(),key:'synthetic-key'};
  if(kind==='wrong-resource')m.resourceType='clusters';if(kind==='delete-op')m.operation='delete';if(kind==='extra-payload')m.approved=true;if(kind==='wrong-revision')s.metadataRevision=-1;if(kind==='create-before')s.before={id:f.rid};if(kind==='false-approval')p.approvalRequired=false;if(kind==='direct-mode')p.executionMode='direct';
  expect(()=>validateWorkflowPlan(p)).toThrow();
 });
 it.each(['key','request'])('persistence rejects an exact sealed intent registered under a changed %s before inserting a workflow',async(kind)=>{
  const f=fixture(),key=kind==='key'?'foreign-submit-key':'original-governance-submit',request=kind==='request'?{...f.request,input:{...f.request.input,name:'altered'}}:f.request;
  await expect(f.plans.persist(f.plan,key,request,f.db,{requestId:f.actor.requestId,ip:f.actor.ip})).rejects.toMatchObject({response:{code:'GOVERNANCE_WORKFLOW_REQUEST_BINDING_INVALID'}});
  expect(f.db.exec.mock.calls.some(([sql]:any)=>sql.startsWith('INSERT INTO workflows'))).toBe(false);
 });
 it('rejects a missing installed governance authority before persistence or proof creation',async()=>{
  const f=fixture(),plans=new WorkflowPlansService(f.db,f.secrets,{}as any);
  await expect(plans.persist(f.plan,'original-governance-submit',f.request,f.db,{requestId:f.actor.requestId,ip:f.actor.ip})).rejects.toMatchObject({response:{code:'GOVERNANCE_WORKFLOW_POLICY_UNAVAILABLE'}});
  const verifier=new ApprovedWorkflowExecutionService(f.db,f.secrets,f.authz,{}as any,f.kong,{}as any,f.context);
  await expect(verifier.assertSubject(f.plan,f.actor.user,'read')).rejects.toMatchObject({response:{code:'GOVERNANCE_WORKFLOW_POLICY_UNAVAILABLE'}});
 });
});
