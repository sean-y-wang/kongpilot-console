import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ForbiddenException} from '@nestjs/common';
import {ControlMetadataService} from '../../apps/console-api/src/modules/control-plane/control-metadata.service';
import {ControlMetadataBusinessService} from '../../apps/console-api/src/modules/control-plane/control-metadata-business.service';
import {ClustersService} from '../../apps/console-api/src/modules/clusters/clusters.service';
import {DataSourcesService} from '../../apps/console-api/src/modules/data-sources/data-sources.service';
import {WorkspaceService} from '../../apps/console-api/src/modules/workspaces/workspace.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {validateWorkflowPlan} from '../../apps/console-api/src/modules/workflows/workflow-validation';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {validGrant,coarseGrantMatches} from '../../apps/console-api/src/modules/authorization/grant-policy';
import {CONTROL_WORKSPACE_SEED_MODULES,CONTROL_WORKSPACE_SEED_ROLES,CONTROL_WORKSPACE_SEED_PERMISSIONS,CONTROL_WORKSPACE_SEED_EPOCH_DELTA} from '../../apps/console-api/src/modules/control-plane/control-workspace-seed';

/** Independently derive fixture bootstrap tuples from the frozen SQL005
 * function rather than the production TS constants under test. This models
 * statements and their AFTER STATEMENT epoch bumps; it is not a SQL trial. */
function sql005WorkspaceSeedModel(){
 const sql=readFileSync(resolve(process.cwd(),'apps/console-api/src/infrastructure/migrations/005_m4_iam.sql'),'utf8'),start=sql.indexOf('CREATE FUNCTION iam_seed_roles('),open=sql.indexOf('AS $$',start),end=sql.indexOf('$$;',open+5),body=sql.slice(open+5,end),strings=(raw:string)=>[...raw.matchAll(/'([^']+)'/g)].map(m=>m[1]);
 const capture=(pattern:RegExp)=>{const match=pattern.exec(body);if(!match)throw new Error(`SQL005 workspace seed model lost original rule ${pattern}`);return strings(match[1]);};
 const modules=capture(/mods text\[\]:=ARRAY\[([^\]]+)\]/),roles=capture(/ELSE ARRAY\[([^\]]+)\] END LOOP/),actions=capture(/FOREACH act IN ARRAY ARRAY\[([^\]]+)\]/),
  blockedModules=capture(/IF wid IS NOT NULL AND mod IN \(([^)]+)\) THEN CONTINUE/),readOnlyRoles=capture(/IF item IN \(([^)]+)\) AND act<>'read' THEN CONTINUE/),
  noApproveRoles=capture(/IF item IN \(([^)]+)\) AND act='approve' THEN CONTINUE/),noSecretRoles=[...body.matchAll(/IF item IN \(([^)]+)\) AND mod='secrets' THEN CONTINUE/g)].flatMap(m=>strings(m[1]));
 if(!body.includes("IF mod='secrets' AND act<>'read' THEN CONTINUE;END IF;")||!body.includes("CASE WHEN wid IS NULL THEN 'global' ELSE 'workspace' END"))throw new Error('SQL005 seed transport requires its exact workspace-only secret/read and scope rules');
 const permissions=roles.flatMap(role=>modules.flatMap(module=>blockedModules.includes(module)||module==='secrets'&&noSecretRoles.includes(role)?[]:actions
  .filter(action=>(!readOnlyRoles.includes(role)||action==='read')&&(!noApproveRoles.includes(role)||action!=='approve')&&(module!=='secrets'||action==='read')).map(action=>({role,module,action}))));
 const epochTrigger=sql.slice(sql.indexOf('CREATE FUNCTION iam_bump_epoch()'),sql.indexOf('CREATE VIEW iam_effective_grants'));
 if(!epochTrigger.includes("'roles','role_permissions'")||!epochTrigger.includes('FOR EACH STATEMENT EXECUTE FUNCTION iam_bump_epoch()'))throw new Error('SQL005 seed transport requires its real statement epoch trigger');
 return {modules,roles,permissions,epochDelta:roles.length+permissions.length};
}
const sql005Seed=sql005WorkspaceSeedModel();

/** Real main service, original Clusters/DataSources/Workspace validators and
 * callbacks, private Business/Completion WeakMaps, shared plan validator and
 * genuine Context ALS. SQL/Redis, Root persist/private Approved provider and
 * Kong read transport are fixtures. These tests are not live DDL/HTTP evidence. */
function fixture(){
 const cid=randomUUID(),wid=randomUUID(),targetWid=randomUUID(),sourceId=randomUUID(),userId=randomUUID(),reviewerId=randomUUID(),sid=randomUUID(),otherSid=randomUUID(),reviewerSid=randomUUID();
 const secrets=new SecretService(),context=new KongExecutionContextService(),copy=<T>(v:T):T=>structuredClone(v);
 const author:any={user:{id:userId,username:'control-owner',superAdmin:false},workspaceId:wid,idempotencyKey:'control-original-key',requestId:randomUUID(),ip:'192.0.2.81'},
  reviewer:any={user:{id:reviewerId,username:'control-reviewer',superAdmin:false},workspaceId:wid,idempotencyKey:'control-reviewer-key',requestId:randomUUID(),ip:'192.0.2.82'};
 const globalGrant=(module:string,action:string)=>({module,action,scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null});
 let state:any={epoch:10,users:new Map([userId,reviewerId].map(id=>[id,{id,status:'active',deleted_at:null,force_password_change:false,super_admin:false,credential_epoch:3,permissions_epoch:7}])),
  grants:new Map([userId,reviewerId].map(id=>[id,['clusters','data-sources','workspaces','workflows'].flatMap(module=>['read','write','delete','approve'].map(action=>globalGrant(module,action)))])),
  sessions:new Map([[sid,{id:sid,user_id:userId,credential_epoch:3,expires_at:new Date(Date.now()+1800000).toISOString(),revoked_at:null}],
   [otherSid,{id:otherSid,user_id:userId,credential_epoch:3,expires_at:new Date(Date.now()+1800000).toISOString(),revoked_at:null}],
   [reviewerSid,{id:reviewerSid,user_id:reviewerId,credential_epoch:3,expires_at:new Date(Date.now()+1800000).toISOString(),revoked_at:null}]]),
  cluster:{id:cid,name:'Production',environment:'prod',admin_url:'http://192.0.2.11:8001',proxy_origin:null,transport_scope:null,labels:['owner:gateway'],execution_mode:'approval',connection_secret:null,
   revision:2,status:'healthy',version:'1.5.1',capabilities:{services:true},enabled_plugins:['key-auth'],last_probed_at:null,deleted_at:null},
  sources:new Map([[sourceId,{id:sourceId,cluster_id:cid,name:'Metrics',type:'prometheus',base_url:'http://192.0.2.12:9090',auth_secret:null,enabled:true,revision:3,deleted_at:null,last_status:'unknown',last_probed_at:null}]]),
  workspaces:new Map([[wid,{id:wid,cluster_id:cid,code:'default',name:'默认工作区',is_default:true,status:'active',revision:3,deleted_at:null,retention_until:null,description:'',owner_user_id:null}],
   [targetWid,{id:targetWid,cluster_id:cid,code:'pay',name:'Payments',is_default:false,status:'active',revision:5,deleted_at:null,retention_until:null,description:'Original workspace',owner_user_id:null}]]),
  intents:new Map(),requests:new Map(),plans:new Map(),workflows:new Map(),facts:new Map(),audit:new Map(),running:null,duplicateCluster:false,duplicateSource:false,
  seedRoles:new Map(),seedPermissions:new Map(),seedUserBindings:[],seedTeamBindings:[],seedTagValues:[],seedEntityValues:[],
  definition:{id:randomUUID(),version:1},policyFormat:2,policy:{version:2,kind:'control-metadata',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,
   stages:[{level:1,name:'Control reviewer',mode:'any',threshold:1,selector:{users:[reviewerId]}}]}};
 const writes:string[]=[],calls:any[]=[],metadataChecks:any[]=[];
 let onWorkspaceSeed:((facts:{state:any;workspaceId:string;roleIds:string[];permissionIds:string[]})=>void)|undefined;
 const seedWorkspace=(workspaceId:string)=>{
  const roleIds:string[]=[],permissionIds:string[]=[];
  for(const kind of sql005Seed.roles){const id=randomUUID();roleIds.push(id);state.seedRoles.set(id,{id,code:kind,name:kind,builtin_kind:kind,cluster_id:cid,workspace_id:workspaceId,protected:true,status:'active',revision:1,deleted_at:null});state.epoch++;
   for(const p of sql005Seed.permissions.filter(p=>p.role===kind)){const permissionId=randomUUID();permissionIds.push(permissionId);state.seedPermissions.set(permissionId,{id:permissionId,role_id:id,module:p.module,action:p.action,scope_type:'workspace',cluster_id:cid,workspace_id:workspaceId,status:'active',revision:1,deleted_at:null});state.epoch++;}
  }
  onWorkspaceSeed?.({state,workspaceId,roleIds,permissionIds});
 };
 const project=(sql:string,row:any)=>{
  if(!row)return null;if(/^SELECT \*/.test(sql))return copy(row);
  const select=/^SELECT ([\s\S]+?) FROM /.exec(sql)?.[1];if(!select)return copy(row);
  const result:any={};for(const field of select.split(',')){const alias=/\((\w+) IS NOT NULL\) AS (\w+)/i.exec(field.trim());
   if(alias)result[alias[2]]=row[alias[1]]!==null;else if(/^\w+$/.test(field.trim()))result[field.trim()]=copy(row[field.trim()]);}return result;
 };
 const assign=(row:any,sql:string,p:any[])=>{for(const m of sql.matchAll(/(?:SET\s+|,)\s*([a-z_]+)=\$(\d+)/g))row[m[1]]=copy(p[Number(m[2])-1]);if(sql.includes('revision=revision+1'))row.revision++;};
 const one=(sql:string,p:any[]=[]):any=>{
  if(sql.includes('FROM iam_epoch'))return {version:state.epoch};
  if(sql.includes('FROM auth_sessions')){const s=state.sessions.get(p[0]),u=s&&state.users.get(s.user_id);return s&&(!p[1]||s.user_id===p[1])&&!s.revoked_at&&Date.parse(s.expires_at)>Date.now()
   &&(p[2]===undefined||String(s.credential_epoch)===String(p[2]))&&(!sql.includes('JOIN users')||u?.status==='active'&&!u.deleted_at&&!u.force_password_change&&u.credential_epoch===s.credential_epoch)?copy(s):null;}
  if(sql.includes('FROM users WHERE id=')){const u=state.users.get(p[0]);return u&&(!sql.includes("status='active'")||u.status==='active'&&!u.deleted_at&&!u.force_password_change)?copy(u):null;}
  if(sql.includes('FROM control_change_intents')){const row=sql.includes('actor_id=$1')?[...state.intents.values()].find((r:any)=>r.actor_id===p[0]&&(sql.includes('cluster_id=$2')?r.cluster_id===p[1]&&r.idempotency_key===p[2]:r.idempotency_key===p[1])):state.intents.get(p[0]);return copy(row??null);}
  if(sql.includes('FROM control_metadata_requests')){const r=state.requests.get(p[0]);return r&&(!p[1]||r.workflow_id===p[1])&&(!p[2]||r.cluster_id===p[2])&&(!p[3]||r.workspace_id===p[3])?copy(r):null;}
  if(sql.includes('FROM control_workflow_mutation_facts')){
   if(sql.includes('AS execution_key')){const fact=[...state.facts.values()].find((f:any)=>f.intent_id===p[0]&&f.workflow_id===p[1]&&f.actor_id===p[2]&&f.session_id===p[3]&&f.plan_hash===p[4]&&f.cluster_id===p[5]&&f.workspace_id===p[6]),w=fact&&state.workflows.get(fact.workflow_id),r=state.running,a=fact&&state.audit.get(fact.audit_id);
    return fact&&w?.state==='succeeded'&&r?.executionState==='succeeded'&&r.stepState==='succeeded'&&r.executionId===fact.execution_id&&r.workflowId===fact.workflow_id&&r.stepId===fact.step_id&&r.planHash===fact.plan_hash&&r.planRevision===fact.plan_revision&&r.actorId===fact.actor_id
     &&r.approvalFormat===2&&r.approvalSetId===w.approval_set_id&&r.approvalSetHmac===w.approval_set_hmac&&r.handler==='control.metadata'&&r.nativeCount===0&&a?.actorId===fact.actor_id&&(a.actorType??'user')==='user'
     &&a.clusterId===fact.cluster_id&&a.workspaceId===fact.workspace_id&&a.entityType===fact.resource&&a.entityId===fact.resource_id&&a?.action==='control.metadata'&&a?.workflowId===w.id&&(!a.result||a.result==='success')
     &&fact.resource===p[7]&&fact.resource_id===p[8]&&fact.operation===p[9]&&fact.before_config_hmac===p[10]&&fact.before_revision===p[11]
     ?{...copy(fact),execution_key:r.executionKey,revision:w.revision}:null;}
   const f=state.facts.get(p[0]),a=f&&state.audit.get(f.audit_id);if(!f||f.intent_id!==p[1]||f.workflow_id!==p[2]||f.execution_id!==p[3]||f.step_id!==p[4]||!a)return null;
   return {...copy(f),audit_actor:a.actorId,audit_cluster:a.clusterId,audit_workspace:a.workspaceId,audit_type:a.entityType,audit_entity:a.entityId,audit_action:a.action,audit_workflow:a.workflowId,audit_result:a.result??'success'};
  }
  if(sql.includes('FROM workflow_definition_versions'))return {approval_format:state.policyFormat,policy:copy(state.policy)};
  if(sql.includes('FROM workflow_executions e JOIN workflows')){const r=state.running,w=r&&state.workflows.get(r.workflowId);return r&&r.executionId===p[0]&&r.workflowId===p[1]&&r.clusterId===p[2]&&r.workspaceId===p[3]&&r.actorId===p[4]&&r.stepId===p[5]&&r.planHash===p[6]&&r.planRevision===p[7]
   &&r.executionState==='executing'&&r.workflowState==='executing'&&r.stepState==='running'&&r.approvalFormat===2&&r.approvalSetId===w.approval_set_id&&r.approvalSetHmac===w.approval_set_hmac&&r.handler==='control.metadata'&&r.kind==='metadata'&&r.nativeCount===0?{id:r.executionId}:null;}
  if(sql.includes('FROM workflows WHERE id='))return copy(state.workflows.get(p[0])??null);
  if(sql.includes('FROM iam_operations'))return null;
  if(sql.startsWith('SELECT EXISTS(SELECT 1 FROM user_role_bindings'))return {present:state.seedUserBindings.some((v:any)=>p[0].includes(v.role_id))||state.seedTeamBindings.some((v:any)=>p[0].includes(v.role_id))||state.seedTagValues.some((v:any)=>p[1].includes(v.permission_id))||state.seedEntityValues.some((v:any)=>p[1].includes(v.permission_id))};
  if(sql.startsWith('INSERT INTO workspaces')){const cols=/workspaces\(([^)]+)\)/.exec(sql)![1].split(','),row:any={revision:1,is_default:false,status:'active',deleted_at:null,retention_until:null};cols.forEach((c,i)=>row[c.trim()]=copy(p[i]));if([...state.workspaces.values()].some((w:any)=>w.cluster_id===row.cluster_id&&w.code===row.code))return null;writes.push(sql);state.workspaces.set(row.id,row);seedWorkspace(row.id);return copy(row);}
  if(sql.startsWith('UPDATE workspaces')){const w=state.workspaces.get(p[1]),revision=sql.includes('SET name=')?p[6]:p[2];if(!w||w.cluster_id!==p[0]||w.revision!==revision)return null;writes.push(sql);assign(w,sql,p);
   if(sql.includes("SET status='deleted'"))Object.assign(w,{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+86400000).toISOString()});
   if(sql.includes("SET status='active'"))Object.assign(w,{status:'active',deleted_at:null,retention_until:null});return copy(w);}
  if(sql.includes('FROM clusters')){if(sql.includes('environment=$1'))return state.duplicateCluster?{id:randomUUID()}:null;const c=state.cluster;return p[0]===c.id&&(!sql.includes('deleted_at IS NULL')||!c.deleted_at)?project(sql,c):null;}
  if(sql.includes('FROM data_sources')){if(sql.includes('lower(name)'))return state.duplicateSource?{id:randomUUID()}:null;const s=state.sources.get(p[1]);return s&&s.cluster_id===p[0]&&(!sql.includes('deleted_at IS NULL')||!s.deleted_at)?project(sql,s):null;}
  if(sql.includes('FROM workspaces')){const w=sql.includes('is_default=true')||sql.includes("code='default'")?[...state.workspaces.values()].find((w:any)=>w.cluster_id===p[0]&&w.is_default):state.workspaces.get(p[1]);return w&&w.cluster_id===p[0]&&(!sql.includes("status='active'")||w.status==='active'&&!w.deleted_at)?project(sql,w):null;}
  throw new Error(`Unimplemented control fixture query: ${sql}`);
 };
 const query=(sql:string,p:any[]=[]):any[]=>{
  if(sql.includes('FROM iam_effective_grants'))return copy(state.grants.get(p[0])??[]);
  if(sql.includes('FROM roles WHERE cluster_id='))return copy([...state.seedRoles.values()].filter((r:any)=>r.cluster_id===p[0]&&r.workspace_id===p[1]));
  if(sql.includes('FROM role_permissions WHERE role_id=ANY'))return copy([...state.seedPermissions.values()].filter((r:any)=>p[0].includes(r.role_id)));
  if(sql.includes('FROM clusters'))return state.cluster.deleted_at?[]:[{id:cid,admin_url:state.cluster.admin_url}];
  throw new Error(`Unimplemented control fixture list: ${sql}`);
 };
 const exec=(sql:string,p:any[]=[]):number=>{
  writes.push(sql);const inserted=/^INSERT INTO (control_\w+)\(([\s\S]*?)\)\s*VALUES/.exec(sql);
  if(inserted){const row:any={};inserted[2].split(',').forEach((c,i)=>row[c.trim()]=copy(p[i]));const map=inserted[1]==='control_change_intents'?state.intents:inserted[1]==='control_metadata_requests'?state.requests:state.facts;map.set(row.id,row);return 1;}
  if(sql.startsWith('INSERT INTO data_sources')){const row:any={revision:1,deleted_at:null,last_status:'unknown',last_probed_at:null};/data_sources\(([^)]+)\)/.exec(sql)![1].split(',').forEach((c,i)=>row[c.trim()]=copy(p[i]));state.sources.set(row.id,row);return 1;}
  if(sql.startsWith('UPDATE clusters')){const c=state.cluster;if(c.id!==p[0]||c.revision!==p[1]||c.deleted_at)return 0;assign(c,sql,p);if(sql.includes('deleted_at=now()'))Object.assign(c,{deleted_at:new Date().toISOString(),status:'disabled'});return 1;}
  if(sql.startsWith('UPDATE data_sources')){const s=state.sources.get(p[1]);if(!s||s.cluster_id!==p[0]||s.revision!==p[2]||s.deleted_at)return 0;assign(s,sql,p);if(sql.includes('deleted_at=now()'))Object.assign(s,{deleted_at:new Date().toISOString(),enabled:false,last_status:'disabled'});return 1;}
  throw new Error(`Unexpected control fixture write: ${sql}`);
 };
 const transport=(name:string):any=>({one:vi.fn(async(sql:string,p?:any[])=>{calls.push({name,sql,p});return one(sql,p);}),query:vi.fn(async(sql:string,p?:any[])=>{calls.push({name,sql,p});return query(sql,p);}),exec:vi.fn(async(sql:string,p?:any[])=>{calls.push({name,sql,p});return exec(sql,p);})});
 const tx=transport('tx'),db=transport('outer');db.transaction=vi.fn(async(fn:any)=>{const before=copy(state);try{return await fn(tx);}catch(error){state=before;throw error;}});
 const allowed=(id:string,module:string,action:string,clusterId?:string,workspaceId?:string)=>{const u=state.users.get(id);return u?.status==='active'&&!u.deleted_at&&!u.force_password_change&&(u.super_admin||state.grants.get(id)?.some((g:any)=>coarseGrantMatches(g,module,action as any,{clusterId,workspaceId})));};
 const authz:any={assertConsole:vi.fn(async(u:any,m:string,a:string)=>{if(!allowed(u.id,m,a)||!state.users.get(u.id).super_admin&&!state.grants.get(u.id).some((g:any)=>validGrant(g)&&g.module===m&&g.action===a&&g.scope_type==='global'&&g.cluster_id===null&&g.workspace_id===null))throw new ForbiddenException({code:'FIXTURE_CONSOLE_DENIED'});}),
  assertCluster:vi.fn(async(u:any,c:string,m:string,a:string,w?:string)=>{if(!allowed(u.id,m,a,c,w))throw new ForbiddenException({code:'FIXTURE_CLUSTER_DENIED'});}),assertEntity:vi.fn(async(u:any,c:string,m:string,a:string,_r:any,w:string)=>{if(!allowed(u.id,m,a,c,w))throw new ForbiddenException({code:'FIXTURE_ENTITY_DENIED'});}),
  snapshot:vi.fn(async(u:any)=>({user:{...u,superAdmin:state.users.get(u.id)?.super_admin===true},grants:copy(state.grants.get(u.id)??[])})),isPlatformAdmin:vi.fn(async(u:any)=>state.users.get(u.id)?.super_admin===true),permissionVersion:vi.fn(async(u:any)=>`${u.id}:${state.users.get(u.id).permissions_epoch}:${state.epoch}`)};
 const redis:any={withLock:vi.fn(async(_k:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn()},audit:any={append:vi.fn(async(event:any,transaction:any)=>{expect(transaction).toBe(tx);const id=randomUUID();state.audit.set(id,{id,...secrets.redact(event) as any});return {id};})};
 const operations:any={completed:vi.fn(async()=>null),execute:vi.fn(async()=>{throw new Error('Control approval cannot enter ordinary Direct ledger');})},mutations:any={execute:vi.fn(async()=>{throw new Error('Control approval cannot mint generic Native authority');})};
 const kong:any={invalidate:vi.fn(),list:vi.fn(async()=>({items:[],nextCursor:null,size:1}))},clusters=new ClustersService(db,secrets,kong,audit,authz,operations,context),
  sources=new DataSourcesService(db,secrets,clusters,audit,authz,operations),resolver=new WorkspaceResolverService(db),workspaces=new WorkspaceService(db,resolver,authz,mutations,audit,kong,context),
  business=new ControlMetadataBusinessService(db,secrets,clusters,sources,workspaces,operations);business.onModuleInit();
 const registry=new WorkflowRegistryService(),plans:any={definitions:vi.fn(),definition:vi.fn(async()=>({...state.definition,policyHash:secrets.fingerprint(state.policy)})),
  persist:vi.fn(async(plan:any,key:string,_request:any,transaction:any)=>{expect(transaction).toBe(tx);validateWorkflowPlan(plan);state.plans.set(plan.workflowId,immutableJson(plan));state.workflows.set(plan.workflowId,{id:plan.workflowId,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,state:'pending',revision:1,plan_revision:plan.planRevision,plan_hash:secrets.fingerprint(plan),idempotency_key:key,approval_set_id:randomUUID(),approval_set_hmac:secrets.fingerprint({syntheticApproval:true})});})};
 const workflow=new ControlMetadataService(db,redis,secrets,audit,authz,context,business,plans,registry);workflow.onModuleInit();
 const originals=new WeakMap<object,any>(),steps=new WeakMap<object,any>(),approved:any={
  verifyExecution:vi.fn(async(h:object)=>{const proof=originals.get(h);if(!proof)throw new Error('Fixture original Approved handle required');return proof;}),
  verifyStep:vi.fn(async(p:any,id:string)=>{if(!state.running||state.running.executionId!==p.executionId||state.running.stepId!==id)throw new Error('Fixture original Approved step required');const step=Object.freeze({execution:p,stepId:id,kind:'metadata'});steps.set(step,p);return step;}),
  assertMetadata:vi.fn(async(step:any,input:any,transaction:any)=>{const plan=state.plans.get(step.execution.workflowId),sealed=plan.steps[0];if(steps.get(step)!==step.execution||transaction!==tx||input.handler!=='control.metadata'||input.actor.id!==userId||input.clusterId!==plan.clusterId||input.workspaceId!==plan.workspaceId||input.entityType!==plan.subject.type||input.entityId!==plan.subject.id||input.revision!==sealed.metadataRevision||secrets.fingerprint(input.before)!==sealed.metadataBeforeHmac||secrets.fingerprint(input.payload)!==sealed.metadataPayloadHmac)throw new Error('Fixture original exact metadata step required');metadataChecks.push({step,input,transaction});}),
  mutationBinding:vi.fn(()=>{throw new Error('Control metadata cannot mint Native binding');}),bindOperation:vi.fn(),assertNative:vi.fn(()=>{throw new Error('Control metadata cannot send Native');})};context.installApprovedPolicy(approved);
 const http=<T>(fn:()=>Promise<T>,actor:any=author,sessionId:string|undefined=actor.user.id===userId?sid:reviewerSid)=>context.runHttp({requestId:actor.requestId,ip:actor.ip},async()=>{context.bindHttpActor(actor.user,sessionId);const close=context.captureHttpCloser();try{return await fn();}finally{close();}});
 const request=()=>({resource:'clusters',operation:'update',resourceId:cid,input:{revision:2,name:'Approved production',execution_mode:'direct'}});
 const prepare=(body:any=request())=>http(()=>workflow.prepare(cid,body,author));
 const submit=(r:any,key=author.idempotencyKey)=>http(()=>workflow.submit(cid,r.intentId,{confirmed:true,materialHmac:r.materialHmac},{...author,idempotencyKey:key}));
 const intent=(id?:string):any=>{const row:any=id?state.intents.get(id):[...state.intents.values()][0];return secrets.decrypt(row.material_secret,`control-workflow:${row.id}:intent`);};
 const plan=():any=>[...state.plans.values()][0];
 const terminal=()=>{state.running.executionState='succeeded';state.running.workflowState='succeeded';state.running.stepState='succeeded';const w=state.workflows.get(state.running.workflowId);w.state='succeeded';w.revision++;};
 const execute=(value:any=plan(),mutateRunning?:(r:any)=>void,after?:(input:any,result:any,pv:string)=>Promise<void>)=>http(()=>db.transaction(async(transaction:any)=>{
  const sealed=state.plans.get(value.workflowId),executionId=randomUUID(),handle=Object.freeze({}),pv=`${userId}:${state.users.get(userId).permissions_epoch}:${state.epoch}`,
   proof=Object.freeze({executionId,workflowId:sealed.workflowId,actorId:userId,sessionId:sid,clusterId:sealed.clusterId,workspaceId:sealed.workspaceId,permissionVersion:pv,expiresAt:Date.now()+60000});originals.set(handle,proof);
  const w=state.workflows.get(sealed.workflowId);w.state='executing';state.running={executionId,executionKey:`workflow-${executionId}`,workflowId:sealed.workflowId,clusterId:sealed.clusterId,workspaceId:sealed.workspaceId,actorId:userId,stepId:sealed.steps[0].id,planHash:secrets.fingerprint(sealed),planRevision:sealed.planRevision,
   executionState:'executing',workflowState:'executing',stepState:'running',handler:'control.metadata',kind:'metadata',nativeCount:0,approvalFormat:2,approvalSetId:w.approval_set_id,approvalSetHmac:w.approval_set_hmac};if(mutateRunning)mutateRunning(state.running);
  return context.runApprovedWorkflow(handle as any,()=>context.runApprovedStep(value.steps[0].id,async()=>{const input={plan:value,step:value.steps[0],actor:{...author,workspaceId:value.workspaceId},executionId,transaction},result=await registry.get('control.metadata').apply(input);if(after)await after(input,result,pv);return result;}));
 }));
 return {cid,wid,targetWid,sourceId,userId,reviewerId,sid,otherSid,author,reviewer,secrets,context,db,tx,authz,redis,audit,operations,mutations,kong,clusters,sources,workspaces,business,plans,registry,approved,workflow,writes,calls,metadataChecks,state:()=>state,http,request,prepare,submit,intent,plan,execute,terminal,
  mutateSeedOnInsert:(fn:(facts:{state:any;workspaceId:string;roleIds:string[];permissionIds:string[]})=>void)=>{onWorkspaceSeed=fn;}};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6d'.repeat(32));vi.stubEnv('APP_SECRET','control-metadata-test-signing-key-more-than-32-bytes');vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','192.0.2.11,192.0.2.12,192.0.2.13');});
afterEach(()=>vi.unstubAllEnvs());

describe('M11 real control metadata prepare and submit',()=>{
 it('captures the real original cluster validators and encrypted intention without configuration writes',async()=>{
  const f=fixture(),before=structuredClone(f.state().cluster),receipt=await f.prepare(),intent=f.intent();
  expect(receipt).toMatchObject({state:'prepared',nativeRequestsSent:0,workflowId:null,clusterId:f.cid,workspaceId:f.wid});
  expect(intent).toMatchObject({actorId:f.userId,authoringSessionId:f.sid,credentialEpoch:'3',permissionVersion:`${f.userId}:7:10`});
  expect(intent.capture.mutation).toMatchObject({resource:'clusters',operation:'update',clusterId:f.cid,resourceId:f.cid,action:'write',payload:f.request().input});
  expect(f.state().cluster).toEqual(before);expect(f.writes).toHaveLength(1);expect(f.writes[0]).toContain('INSERT INTO control_change_intents');
  expect(JSON.stringify([...f.state().intents.values()])).not.toContain('Approved production');expect(receipt).not.toHaveProperty('material_secret');
  expect(f.operations.execute).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
 it('uses the genuine HTTP SID even if a caller supplies a sessionId field',async()=>{const f=fixture();await f.http(()=>f.workflow.prepare(f.cid,f.request(),{...f.author,sessionId:randomUUID()}));expect(f.intent().authoringSessionId).toBe(f.sid);});
 it.each(['no-context','no-sid','wrong-actor','fake-sid','revoked-sid'])('rejects %s before storing an intention',async variant=>{
  const f=fixture();if(variant==='revoked-sid')f.state().sessions.get(f.sid).revoked_at=new Date().toISOString();
  const op=variant==='no-context'?f.workflow.prepare(f.cid,f.request(),f.author):variant==='no-sid'?f.context.runHttp({},async()=>{f.context.bindHttpActor(f.author.user);return f.workflow.prepare(f.cid,f.request(),f.author);}):f.http(()=>f.workflow.prepare(f.cid,f.request(),f.author),variant==='wrong-actor'?f.reviewer:f.author,variant==='fake-sid'?randomUUID():variant==='wrong-actor'?undefined:f.sid);
  await expect(op).rejects.toThrow();expect(f.state().intents.size).toBe(0);expect(f.writes).toEqual([]);
 });
 it('does not let caller super-admin claims replace actual SQL grants',async()=>{const f=fixture();f.author.user.superAdmin=true;f.state().grants.set(f.userId,[]);await expect(f.prepare()).rejects.toThrow();expect(f.state().intents.size).toBe(0);});
 it('requires actual module READ to expose a prepared review',async()=>{const f=fixture();f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>!(g.module==='clusters'&&g.action==='read')));await expect(f.prepare()).rejects.toMatchObject({response:{code:'CONTROL_PREVIEW_READ_DENIED'}});expect(f.state().intents.size).toBe(0);});
 it.each(['tag_group','entity'])('does not widen restricted %s workflow authority to a registry change',async type=>{
  const f=fixture(),g=f.state().grants.get(f.userId).filter((g:any)=>!(g.module==='workflows'&&g.action==='write'));g.push({module:'workflows',action:'write',scope_type:type,cluster_id:f.cid,workspace_id:null,scope_values:type==='tag_group'?['team-payments']:[{entity_type:'services',entity_id:randomUUID()}]});f.state().grants.set(f.userId,g);
  await expect(f.prepare()).rejects.toMatchObject({response:{code:'CONTROL_WORKFLOW_SCOPE_DENIED'}});expect(f.state().intents.size).toBe(0);
 });
 it('preserves idempotent preparation and rejects a changed body or other cluster for that key',async()=>{
  const f=fixture(),one=await f.prepare();expect(await f.prepare()).toEqual(one);expect(f.state().intents.size).toBe(1);
  await expect(f.prepare({...f.request(),input:{revision:2,name:'Different'}})).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});
  await expect(f.http(()=>f.workflow.prepare(randomUUID(),f.request(),f.author))).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});
 });
 it('submits a real shared-validated Native0 plan once and returns a durable retry receipt',async()=>{
  const f=fixture(),prepared=await f.prepare(),receipt=await f.submit(prepared);expect(await f.submit(prepared)).toEqual(receipt);
  const plan=f.plan();expect(()=>validateWorkflowPlan(plan)).not.toThrow();expect(plan).toMatchObject({kind:'control-metadata',executionMode:'approval',approvalRequired:true,prerequisites:[]});
  expect(plan.steps).toHaveLength(1);expect(plan.steps[0]).toMatchObject({kind:'metadata',handler:'control.metadata',nativeRequests:[],metadataRevision:2});expect(f.plans.persist).toHaveBeenCalledOnce();
 });
 it.each(['different-owner','different-sid','different-key','wrong-material','unconfirmed'])('refuses %s submission',async variant=>{
  const f=fixture(),p=await f.prepare();if(variant==='different-key'){await f.submit(p);await expect(f.submit(p,'different-submit-key')).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});return;}
  const body={confirmed:variant==='unconfirmed'?false:true,materialHmac:variant==='wrong-material'?'f'.repeat(64):p.materialHmac},a=variant==='different-owner'?f.reviewer:f.author;
  await expect(f.http(()=>f.workflow.submit(f.cid,p.intentId as string,body,a),a,variant==='different-sid'?f.otherSid:undefined)).rejects.toThrow();expect(f.plans.persist).not.toHaveBeenCalled();expect(f.state().requests.size).toBe(0);
 });
 it.each(['cluster-revision','registry-url','transport-scope','workspace-revision','mode','credential-epoch','permission-version','module-grant','workflow-grant','row-body','revoked-session'])('fences a prepared change on current %s drift',async variant=>{
  const f=fixture(),p=await f.prepare();
  if(variant==='cluster-revision')f.state().cluster.revision++;if(variant==='registry-url')f.state().cluster.admin_url='http://192.0.2.13:8001';if(variant==='transport-scope')f.state().cluster.transport_scope='f'.repeat(64);
  if(variant==='workspace-revision')f.state().workspaces.get(f.wid).revision++;if(variant==='mode')f.state().cluster.execution_mode='direct';
  if(variant==='credential-epoch')f.state().users.get(f.userId).credential_epoch++;if(variant==='permission-version')f.state().epoch++;
  if(['module-grant','workflow-grant'].includes(variant))f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>!(g.module===(variant==='module-grant'?'clusters':'workflows')&&g.action==='write')));
  if(variant==='row-body')f.state().cluster.labels.push('unexpected');if(variant==='revoked-session')f.state().sessions.get(f.sid).revoked_at=new Date().toISOString();
  await expect(f.submit(p)).rejects.toThrow();expect(f.plans.persist).not.toHaveBeenCalled();expect(f.state().requests.size).toBe(0);
 });
 it('allows observation status and timestamps to change without inventing configuration revision drift',async()=>{
  const f=fixture(),p=await f.prepare();Object.assign(f.state().cluster,{status:'unhealthy',version:'1.5.1',last_probed_at:new Date().toISOString(),enabled_plugins:['key-auth','prometheus']});await expect(f.submit(p)).resolves.toMatchObject({state:'pending'});
 });
 it.each(['actor_id','authoring_session_id','credential_epoch','permission_version','material_hmac','material_secret','resource','resource_id','operation','before_revision','before_config_hmac','issued_at','expires_at'])('refuses altered intention field %s',async field=>{
  const f=fixture(),p=await f.prepare(),r=f.state().intents.get(p.intentId);r[field]=field==='credential_epoch'||field==='before_revision'?999:field==='material_hmac'||field==='before_config_hmac'?'f'.repeat(64):field==='material_secret'?`${r.material_secret}corrupt`:randomUUID();
  await expect(f.submit(p)).rejects.toThrow();expect(f.plans.persist).not.toHaveBeenCalled();
 });
 it.each(['kind','subject','handler','entity-id','resource','operation','material-hmac','extra-payload','before','before-hmac','payload-hmac','metadata-revision','scope','native-request','dependency','prerequisite','permission-action'])('rejects changed sealed plan %s material through the real typed binding',async variant=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const plan=structuredClone(f.plan()),s=plan.steps[0];
  if(variant==='kind')plan.kind='iam-metadata';if(variant==='subject')plan.subject.id=randomUUID();if(variant==='handler')s.handler='iam.metadata';if(variant==='entity-id')s.entityId=randomUUID();
  if(variant==='resource')s.metadata.resource='workspaces';if(variant==='operation')s.metadata.operation='deactivate';if(variant==='material-hmac')s.metadata.materialHmac='f'.repeat(64);if(variant==='extra-payload')s.metadata.approvalBypass=true;
  if(variant==='before')s.before.name='Forged baseline';if(variant==='before-hmac')s.metadataBeforeHmac='f'.repeat(64);if(variant==='payload-hmac')s.metadataPayloadHmac='f'.repeat(64);if(variant==='metadata-revision')s.metadataRevision++;
  if(variant==='scope')plan.scope.clusterRevision++;if(variant==='native-request')s.nativeRequests.push({method:'POST',canonicalPath:'/services',bodyHmac:'f'.repeat(64)});if(variant==='dependency')s.dependencies.push(randomUUID());if(variant==='prerequisite')plan.prerequisites.push({});if(variant==='permission-action')s.permissionAction='delete';
  await expect(f.http(()=>f.workflow.verifyIntent(plan,f.tx))).rejects.toThrow();expect(f.state().cluster.revision).toBe(2);expect(f.state().facts.size).toBe(0);
 });
 it('reviewers require current workflow approval and module read, without authoring a new operation',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);await expect(f.http(()=>f.workflow.verifyReviewer(f.reviewerId,f.plan(),f.tx),f.reviewer)).resolves.toBeUndefined();
  f.state().grants.set(f.reviewerId,f.state().grants.get(f.reviewerId).filter((g:any)=>!(g.module==='clusters'&&g.action==='read')));
  await expect(f.http(()=>f.workflow.verifyReviewer(f.reviewerId,f.plan(),f.tx),f.reviewer)).rejects.toMatchObject({response:{code:'CONTROL_SUBJECT_DENIED'}});expect(f.state().facts.size).toBe(0);
 });
 it('a reviewer with module read alone cannot approve or execute the original author intention',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);f.state().grants.set(f.reviewerId,f.state().grants.get(f.reviewerId).filter((g:any)=>!(g.module==='workflows'&&g.action==='approve')));
  await expect(f.http(()=>f.workflow.verifyReviewer(f.reviewerId,f.plan(),f.tx),f.reviewer)).rejects.toMatchObject({response:{code:'CONTROL_WORKFLOW_SCOPE_DENIED'}});
  await expect(f.http(()=>f.registry.get('control.metadata').authorize(f.plan(),f.reviewer,'write'),f.reviewer)).rejects.toMatchObject({response:{code:'CONTROL_EXECUTOR_DENIED'}});
 });
 it('review previews hide private auth and registry URLs for non-platform reviewers',async()=>{
  const f=fixture(),token='synthetic-control-header-token';const p=await f.prepare({...f.request(),input:{revision:2,name:'Approved production',connection_auth:{type:'header',header_name:'X-Private-Token',header_value:token}}});await f.submit(p);
  const preview=await f.http(()=>f.workflow.reviewPreview(f.plan(),f.reviewer),f.reviewer);expect(JSON.stringify(preview)).not.toContain(token);expect(JSON.stringify(preview)).not.toContain('192.0.2.11');expect(JSON.stringify(preview)).not.toContain('connection_auth');expect(JSON.stringify(preview)).not.toContain('connection_secret');
  await f.execute(f.plan(),undefined,async(i,r,pv)=>f.workflow.verifyMetadataCompletion(i,r,pv));
  expect(f.secrets.decrypt(f.state().cluster.connection_secret,`cluster:${f.cid}`)).toMatchObject({type:'header',header_value:token});
  expect(JSON.stringify([...f.state().audit.values()])).not.toContain(token);expect([...f.state().audit.values()].find((a:any)=>a.action==='control.metadata').after.protectedFields.connection_secret).toMatch(/^\[REDACTED:/);
 });
});

describe('M11 real control metadata original execution and completion',()=>{
 it('executes the original SQL callback and closes only its genuine same-transaction result after a mode switch',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const result=await f.execute(f.plan(),undefined,async(input,r,pv)=>f.workflow.verifyMetadataCompletion(input,r,pv));
  expect(result).toMatchObject({intentId:p.intentId,resource:'clusters',resourceId:f.cid,operation:'update',nativeRequestsSent:0});expect(Object.keys(result).sort()).toEqual(['intentId','nativeRequestsSent','operation','resource','resourceId']);
  expect(f.state().cluster).toMatchObject({name:'Approved production',execution_mode:'direct',revision:3});expect(f.state().facts.size).toBe(1);
  expect(f.metadataChecks).toHaveLength(2);expect(f.metadataChecks.every(c=>c.transaction===f.tx)).toBe(true);expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'control.metadata',workflowId:f.plan().workflowId}),f.tx);
  expect(f.operations.execute).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.approved.assertNative).not.toHaveBeenCalled();expect(f.approved.mutationBinding).not.toHaveBeenCalled();
 });
 it.each(['execution-state','workflow-state','step-state','wrong-handler','native-packet','legacy-approval','different-approval-set'])('rejects current %s before business SQL',async variant=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const before=structuredClone(f.state().cluster);
  await expect(f.execute(f.plan(),r=>{if(variant==='execution-state')r.executionState='failed';if(variant==='workflow-state')r.workflowState='failed';if(variant==='step-state')r.stepState='pending';if(variant==='wrong-handler')r.handler='iam.metadata';if(variant==='native-packet')r.nativeCount=1;if(variant==='legacy-approval')r.approvalFormat=1;if(variant==='different-approval-set')r.approvalSetId=randomUUID();})).rejects.toThrow();
  expect(f.state().cluster).toEqual(before);expect(f.state().facts.size).toBe(0);
 });
 it('does not accept a copied Business execution handle',async()=>{const f=fixture(),p=await f.prepare();await f.submit(p);await expect(f.http(()=>f.business.apply(Object.freeze({}),f.intent().capture,f.author,f.tx))).rejects.toMatchObject({response:{code:'CONTROL_ORIGINAL_EXECUTION_REQUIRED'}});expect(f.state().cluster.revision).toBe(2);});
 it('cannot execute outside genuine Context Approved metadata proof',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const plan=f.plan();await expect(f.http(()=>f.registry.get('control.metadata').apply({plan,step:plan.steps[0],actor:f.author,executionId:randomUUID(),transaction:f.tx}))).rejects.toThrow();expect(f.state().facts.size).toBe(0);
 });
 it.each(['cloned-result','cloned-input','different-transaction','mutated-input-transaction','wrong-before-pv','current-config-mismatch','credential-epoch','session-revoked','permissions-epoch'])('rejects %s completion and rolls back the original configuration transaction',async variant=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const before=structuredClone(f.state().cluster);
  await expect(f.execute(f.plan(),undefined,async(input,result,pv)=>{
   let candidate=input,out=result,beforePV=pv;if(variant==='cloned-result')out=structuredClone(result);if(variant==='cloned-input')candidate={...input};if(variant==='different-transaction')candidate={...input,transaction:f.db};if(variant==='mutated-input-transaction')input.transaction=f.db;
   if(variant==='wrong-before-pv')beforePV='different';if(variant==='current-config-mismatch')f.state().cluster.labels.push('outside');if(variant==='credential-epoch')f.state().users.get(f.userId).credential_epoch++;
   if(variant==='session-revoked')f.state().sessions.get(f.sid).revoked_at=new Date().toISOString();if(variant==='permissions-epoch')f.state().epoch++;
   await f.workflow.verifyMetadataCompletion(candidate,out,beforePV);
  })).rejects.toThrow();expect(f.state().cluster).toEqual(before);expect(f.state().facts.size).toBe(0);
 });
 it('consumes private completion proof once and grants no ordinary post-mode-flip business handle',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);await f.execute(f.plan(),undefined,async(input,result,pv)=>{await f.workflow.verifyMetadataCompletion(input,result,pv);await expect(f.workflow.verifyMetadataCompletion(input,result,pv)).rejects.toMatchObject({response:{code:'CONTROL_ORIGINAL_COMPLETION_REQUIRED'}});});
  expect(f.state().cluster.execution_mode).toBe('direct');
 });
 it.each(['actor_id','session_id','cluster_id','workspace_id','plan_hash','plan_revision','before_revision','after_revision','before_permission_version','after_permission_version','resource','resource_id','operation','before_config_hmac','after_config_hmac','result_hmac','result_secret'])('rejects altered committed mutation fact %s before acknowledging the exact result',async field=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const before=structuredClone(f.state().cluster);
  await expect(f.execute(f.plan(),undefined,async(i,r,pv)=>{const fact:any=[...f.state().facts.values()][0];fact[field]=field==='plan_revision'?999:field==='result_secret'?`${fact.result_secret}corrupt`:randomUUID();await f.workflow.verifyMetadataCompletion(i,r,pv);})).rejects.toThrow();
  expect(f.state().cluster).toEqual(before);expect(f.state().facts.size).toBe(0);
 });
 it.each(['actorId','clusterId','workspaceId','entityType','entityId','action','workflowId','result'])('requires the actual correlated audit %s on completion',async field=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);const before=structuredClone(f.state().cluster);
  await expect(f.execute(f.plan(),undefined,async(i,r,pv)=>{const fact:any=[...f.state().facts.values()][0],audit=f.state().audit.get(fact.audit_id);audit[field]=randomUUID();await f.workflow.verifyMetadataCompletion(i,r,pv);})).rejects.toThrow();
  expect(f.state().cluster).toEqual(before);expect(f.state().facts.size).toBe(0);
 });
 it('returns a minimal original-owner receipt after the actual cluster is soft-deactivated',async()=>{
  const f=fixture(),p=await f.prepare({resource:'clusters',operation:'deactivate',resourceId:f.cid,input:{revision:2,confirm:true,confirm_name:'Production'}});await f.submit(p);const plan=f.plan();
  await f.execute(plan,undefined,async(input,result,pv)=>{await f.workflow.verifyMetadataCompletion(input,result,pv);f.terminal();});
  expect(f.state().cluster).toMatchObject({status:'disabled',revision:3});expect(f.state().cluster.deleted_at).toBeTruthy();
  const receipt=await f.http(()=>f.workflow.receipt(f.cid,p.intentId as string,f.author)),terminal=await f.http(()=>f.workflow.terminalReceipt(plan,f.author));
  expect(receipt).toMatchObject({state:'succeeded',preview:null,nativeRequestsSent:0});expect(terminal).toMatchObject({state:'succeeded',propagation:'acknowledged',steps:[{operationId:null,remoteStarted:false}]});
  expect(JSON.stringify([receipt,terminal])).not.toContain('192.0.2.11');expect(JSON.stringify([receipt,terminal])).not.toContain('connection_secret');
  await expect(f.http(()=>f.workflow.receipt(f.cid,p.intentId as string,f.reviewer),f.reviewer)).rejects.toMatchObject({response:{code:'CONTROL_INTENT_OWNER_REQUIRED'}});
 });
 it.each(['different-sid','revoked-sid','missing-fact','wrong-execution','failed-step','missing-audit'])('refuses %s terminal receipt after a mode switch',async variant=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);await f.execute(f.plan(),undefined,async(input,r,pv)=>{await f.workflow.verifyMetadataCompletion(input,r,pv);f.terminal();});
  if(variant==='revoked-sid')f.state().sessions.get(f.sid).revoked_at=new Date().toISOString();if(variant==='missing-fact')f.state().facts.clear();if(variant==='wrong-execution')f.state().running.executionId=randomUUID();if(variant==='failed-step')f.state().running.stepState='failed';if(variant==='missing-audit')f.state().audit.clear();
  await expect(f.http(()=>f.workflow.terminalReceipt(f.plan(),f.author),f.author,variant==='different-sid'?f.otherSid:f.sid)).rejects.toThrow();
 });
 it.each(['actorType','clusterId','workspaceId','entityType','entityId'])('does not derive an owned terminal receipt from another audit %s tuple',async field=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);await f.execute(f.plan(),undefined,async(i,r,pv)=>{await f.workflow.verifyMetadataCompletion(i,r,pv);f.terminal();});
  const fact:any=[...f.state().facts.values()][0];f.state().audit.get(fact.audit_id)[field]=field==='actorType'?'system':randomUUID();
  await expect(f.http(()=>f.workflow.terminalReceipt(f.plan(),f.author))).rejects.toMatchObject({response:{code:'CONTROL_TERMINAL_RECEIPT_UNAVAILABLE'}});
 });
});

describe('M11 original data-source and workspace configuration approval',()=>{
 it.each(['create','update','deactivate'])('uses original DataSources %s validations and exact SQL write with no generic Direct operation',async operation=>{
  const f=fixture(),input=operation==='create'?{name:'Approved Loki',type:'loki',base_url:'http://192.0.2.13:3100',enabled:true}:operation==='update'?{revision:3,name:'Approved metrics'}:{revision:3,confirm:true,confirm_name:'Metrics'},
   p=await f.prepare({resource:'data-sources',operation,...(operation==='create'?{}:{resourceId:f.sourceId}),input});await f.submit(p);await f.execute(f.plan(),undefined,async(i,r,pv)=>f.workflow.verifyMetadataCompletion(i,r,pv));
  const source=f.state().sources.get(f.intent().capture.mutation.resourceId);expect(source.revision).toBe(operation==='create'?1:4);if(operation==='deactivate'){expect(source.deleted_at).toBeTruthy();expect(source.enabled).toBe(false);}else expect(source.name).toBe(operation==='create'?'Approved Loki':'Approved metrics');
  expect(f.state().facts.size).toBe(1);expect(f.operations.execute).not.toHaveBeenCalled();expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
 it.each(['create','update','archive','restore'])('uses original Workspace %s validators and preserves a genuine same-transaction completion',async operation=>{
  const f=fixture();if(operation==='restore')Object.assign(f.state().workspaces.get(f.targetWid),{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+86400000).toISOString()});
  const input=operation==='create'?{code:'new_team',name:'Approved workspace'}:operation==='update'?{revision:5,name:'Approved workspace',status:'disabled'}:{revision:5,confirmed:true,confirm_name:'Payments'},p=await f.prepare({resource:'workspaces',operation,...(operation==='create'?{}:{resourceId:f.targetWid}),input});
  await f.submit(p);await f.execute(f.plan(),undefined,async(i,r,pv)=>{await f.workflow.verifyMetadataCompletion(i,r,pv);f.terminal();});const w=f.state().workspaces.get(f.intent().capture.mutation.resourceId);
  expect(w.revision).toBe(operation==='create'?1:6);expect(w.status).toBe(operation==='archive'?'deleted':operation==='update'?'disabled':'active');
  if(operation==='archive')expect(f.kong.list).toHaveBeenCalledTimes(8);else expect(f.kong.list).not.toHaveBeenCalled();
  const receipt=await f.http(()=>f.workflow.receipt(f.cid,p.intentId as string,f.author));expect(receipt).toMatchObject({state:'succeeded',preview:null,nativeRequestsSent:0});expect(f.mutations.execute).not.toHaveBeenCalled();expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
 it('enforces actual private raw workspace emptiness only during original approved archive, never during capture',async()=>{
  const f=fixture(),p=await f.prepare({resource:'workspaces',operation:'archive',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});expect(f.kong.list).not.toHaveBeenCalled();await f.submit(p);
  f.kong.list.mockResolvedValue({items:[{id:randomUUID()}],nextCursor:null,size:1});await expect(f.execute()).rejects.toMatchObject({response:{code:'WORKSPACE_NOT_EMPTY'}});expect(f.state().workspaces.get(f.targetWid)).toMatchObject({status:'active',revision:5,deleted_at:null});expect(f.state().facts.size).toBe(0);
 });
 it('rejects bootstrap replacement, unknown handler registration and a control handler smuggled into another kind',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);expect(()=>f.workflow.onModuleInit()).toThrow();expect(()=>f.business.onModuleInit()).toThrow();expect(()=>f.registry.register('control.injected',f.registry.get('control.metadata'))).toThrow();
  const plan=structuredClone(f.plan());plan.kind='portal-metadata';plan.subject.type='portal_content';expect(()=>validateWorkflowPlan(plan)).toThrow();
 });
});

describe('M11 control workflow admission retains the actual HTTP selector',()=>{
 const workspaceGrant=(cid:string,wid:string,module:string,action:string)=>({module,action,scope_type:'workspace',cluster_id:cid,workspace_id:wid,scope_values:[wid]});
 async function restoreFixture(){
  const f=fixture();Object.assign(f.state().workspaces.get(f.targetWid),{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+86400000).toISOString()});
  // Actual SQL grants contain no default-workspace or console-global grant.
  f.state().grants.set(f.userId,['workspaces','workflows'].flatMap(module=>['read','write'].map(action=>workspaceGrant(f.cid,f.targetWid,module,action))));
  f.state().grants.set(f.reviewerId,['workspaces','workflows'].flatMap(module=>(module==='workflows'?['read','approve']:['read']).map(action=>workspaceGrant(f.cid,f.targetWid,module,action))));
  const receipt=await f.prepare({resource:'workspaces',operation:'restore',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});await f.submit(receipt);
  expect(f.plan().workspaceId).toBe(f.wid);expect(f.intent().scope.targetWorkspaceId).toBe(f.targetWid);return f;
 }
 it.each(['anchor','target','undefined'])('admits original %s selector for a genuinely deleted target using target-only current permissions',async selector=>{
  const f=await restoreFixture(),selected=selector==='target'?f.targetWid:selector==='anchor'?f.wid:undefined,
   actor={...f.author,workspaceId:selected},before=structuredClone(f.state().workspaces),writeCount=f.writes.length;
  await f.http(()=>f.context.runActor({actor:actor.user,clusterId:f.cid,workspaceId:selected,module:'workflows',action:'write'},async()=>{
   const frame=f.context.current();await f.workflow.approvedDelegate().assertWorkflowAdmission(f.plan(),actor,'write',f.tx);
   expect(f.context.current()).toBe(frame);expect(frame.workspaceId).toBe(selected);expect(frame.clusterId).toBe(f.cid);
  }),actor);
  expect(f.state().workspaces).toEqual(before);expect(f.writes).toHaveLength(writeCount);expect(f.state().facts.size).toBe(0);
  expect(f.approved.mutationBinding).not.toHaveBeenCalled();expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
 it('admits a target-only reviewer without rewriting the original target frame or granting anchor reads',async()=>{
  const f=await restoreFixture(),actor={...f.reviewer,workspaceId:f.targetWid};
  await f.http(()=>f.context.runActor({actor:actor.user,clusterId:f.cid,workspaceId:f.targetWid,module:'workflows',action:'approve'},async()=>{
   const frame=f.context.current();await f.workflow.approvedDelegate().assertWorkflowAdmission(f.plan(),actor,'approve',f.tx);
   await f.workflow.approvedDelegate().assertSubject(f.plan(),f.reviewerId,'read',f.tx);expect(f.context.current()).toBe(frame);expect(frame.workspaceId).toBe(f.targetWid);
  }),actor);
  expect(f.state().grants.get(f.reviewerId).every((g:any)=>g.workspace_id===f.targetWid)).toBe(true);expect(f.state().facts.size).toBe(0);
 });
 it.each(['foreign-actor-wid','foreign-frame-wid','foreign-cluster-frame'])('refuses %s despite otherwise valid target permissions and a genuine same-actor SID',async variant=>{
  const f=await restoreFixture(),foreign=randomUUID(),actor={...f.author,workspaceId:variant==='foreign-actor-wid'?foreign:f.targetWid},
   frameWid=variant==='foreign-frame-wid'?foreign:f.targetWid,frameCid=variant==='foreign-cluster-frame'?foreign:f.cid,writeCount=f.writes.length;
  await expect(f.http(()=>f.context.runActor({actor:actor.user,clusterId:frameCid,workspaceId:frameWid,module:'workflows',action:'write'},async()=>{
   const frame=f.context.current();try{await f.workflow.approvedDelegate().assertWorkflowAdmission(f.plan(),actor,'write',f.tx);}finally{expect(f.context.current()).toBe(frame);expect(frame.workspaceId).toBe(frameWid);expect(frame.clusterId).toBe(frameCid);}
  }),actor)).rejects.toMatchObject({response:{code:'CONTROL_WORKFLOW_SELECTOR_DENIED'}});
  expect(f.writes).toHaveLength(writeCount);expect(f.state().facts.size).toBe(0);expect(f.state().workspaces.get(f.targetWid).status).toBe('deleted');expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
 it('assertSubject uses the actual current foreign frame selector and does not substitute the sealed default anchor',async()=>{
  const f=await restoreFixture(),foreign=randomUUID();await expect(f.http(()=>f.context.runActor({actor:f.author.user,clusterId:f.cid,workspaceId:foreign,module:'workflows',action:'read'},
   ()=>f.workflow.approvedDelegate().assertSubject(f.plan(),f.userId,'read',f.tx)))).rejects.toMatchObject({response:{code:'CONTROL_WORKFLOW_SELECTOR_DENIED'}});
  expect(f.state().facts.size).toBe(0);
 });
 it('continues to admit a normal active plan using its genuine anchor selector',async()=>{
  const f=fixture(),p=await f.prepare();await f.submit(p);await f.http(()=>f.context.runActor({actor:f.author.user,clusterId:f.cid,workspaceId:f.wid,module:'workflows',action:'write'},async()=>{
   const frame=f.context.current();await f.workflow.approvedDelegate().assertWorkflowAdmission(f.plan(),f.author,'write',f.tx);await f.workflow.approvedDelegate().assertSubject(f.plan(),f.userId,'read',f.tx);expect(f.context.current()).toBe(frame);
  }));expect(f.state().cluster.revision).toBe(2);expect(f.state().facts.size).toBe(0);
 });
 it('does not treat an allowed original target selector as a waiver for revoked current target permissions',async()=>{
  const f=await restoreFixture();f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>!(g.module==='workspaces'&&g.action==='write')));
  const actor={...f.author,workspaceId:f.targetWid};await expect(f.http(()=>f.context.runActor({actor:actor.user,clusterId:f.cid,workspaceId:f.targetWid,module:'workflows',action:'write'},
   ()=>f.workflow.approvedDelegate().assertWorkflowAdmission(f.plan(),actor,'write',f.tx)),actor)).rejects.toMatchObject({response:{code:'CONTROL_SUBJECT_DENIED'}});
  expect(f.state().facts.size).toBe(0);
 });
});

describe('M11 original SQL005 workspace role seed closure',()=>{
 const createRequest=()=>({resource:'workspaces',operation:'create',input:{code:'seeded_team',name:'Seeded workspace'}});
 function alterSeed(state:any,variant:string,userId:string){
  const role:any=[...state.seedRoles.values()][0],permission:any=[...state.seedPermissions.values()][0];
  if(variant==='missing-role')state.seedRoles.delete(role.id);
  if(variant==='extra-role'){const id=randomUUID();state.seedRoles.set(id,{...role,id});}
  if(variant==='unprotected-role')role.protected=false;if(variant==='wrong-role-kind')role.builtin_kind='admin';if(variant==='wrong-role-name')role.name='Adopted role';
  if(variant==='wrong-role-scope')role.workspace_id=randomUUID();if(variant==='revoked-role')role.status='deleted';if(variant==='role-revision')role.revision++;
  if(variant==='missing-permission')state.seedPermissions.delete(permission.id);
  if(variant==='extra-permission'){const id=randomUUID();state.seedPermissions.set(id,{...permission,id});}
  if(variant==='duplicate-permission-tuple'){const p:any=[...state.seedPermissions.values()][1];Object.assign(p,{module:permission.module,action:permission.action});}
  if(variant==='foreign-permission-role')permission.role_id=randomUUID();if(variant==='nonworkspace-permission')permission.scope_type='global';if(variant==='wrong-permission-scope')permission.workspace_id=randomUUID();
  if(variant==='revoked-permission')permission.status='revoked';if(variant==='permission-revision')permission.revision++;if(variant==='unsupported-permission')permission.module='users';
  if(variant==='new-user-binding')state.seedUserBindings.push({role_id:role.id,user_id:userId});if(variant==='new-team-binding')state.seedTeamBindings.push({role_id:role.id,team_id:randomUUID()});
  if(variant==='tag-value')state.seedTagValues.push({permission_id:permission.id,physical_tag:'team-pay'});if(variant==='entity-value')state.seedEntityValues.push({permission_id:permission.id,entity_id:randomUUID()});
  if(variant==='author-grant-addition')state.grants.get(userId).push({module:'workspaces',action:'read',scope_type:'workspace',cluster_id:role.cluster_id,workspace_id:role.workspace_id,scope_values:[role.workspace_id]});
  if(variant==='author-grant-revocation')state.grants.get(userId).pop();if(variant==='author-permission-epoch')state.users.get(userId).permissions_epoch++;
  if(variant==='author-credential-epoch')state.users.get(userId).credential_epoch++;if(variant==='author-superadmin')state.users.get(userId).super_admin=true;
  if(variant==='epoch-low')state.epoch--;if(variant==='epoch-high')state.epoch++;if(variant==='epoch-unchanged')state.epoch=10;
 }
 const badSeeds=['missing-role','extra-role','unprotected-role','wrong-role-kind','wrong-role-name','wrong-role-scope','revoked-role','role-revision',
  'missing-permission','extra-permission','duplicate-permission-tuple','foreign-permission-role','nonworkspace-permission','wrong-permission-scope','revoked-permission','permission-revision','unsupported-permission',
  'new-user-binding','new-team-binding','tag-value','entity-value','author-grant-addition','author-grant-revocation','author-permission-epoch','author-credential-epoch','author-superadmin','epoch-low','epoch-high','epoch-unchanged'];
 it('matches every module, role and permission tuple independently derived from immutable SQL005',()=>{
  const tuple=(p:{role:string;module:string;action:string})=>`${p.role}:${p.module}:${p.action}`;
  expect([...CONTROL_WORKSPACE_SEED_MODULES]).toEqual(sql005Seed.modules);expect([...CONTROL_WORKSPACE_SEED_ROLES]).toEqual(sql005Seed.roles);
  expect(CONTROL_WORKSPACE_SEED_PERMISSIONS.map(tuple).sort()).toEqual(sql005Seed.permissions.map(tuple).sort());expect(CONTROL_WORKSPACE_SEED_EPOCH_DELTA).toBe(sql005Seed.epochDelta);
  expect(sql005Seed.roles).toHaveLength(3);expect(sql005Seed.permissions.length).toBe(265);expect(sql005Seed.epochDelta).toBe(268);
 });
 it('acknowledges only the original three protected unassigned seed roles and 265 exact workspace permission inserts',async()=>{
  const f=fixture(),beforeUsers=structuredClone(f.state().users),beforeGrants=structuredClone(f.state().grants),p=await f.prepare(createRequest());await f.submit(p);
  expect(f.state().epoch).toBe(10);expect(f.state().seedRoles.size).toBe(0);expect(f.state().seedPermissions.size).toBe(0);
  await f.execute(f.plan(),undefined,async(input,result,pv)=>{expect(pv).toBe(`${f.userId}:7:10`);await f.workflow.verifyMetadataCompletion(input,result,pv);f.terminal();});
  const fact:any=[...f.state().facts.values()][0];expect(fact.before_permission_version).toBe(`${f.userId}:7:10`);expect(fact.after_permission_version).toBe(`${f.userId}:7:278`);
  expect(f.state().seedRoles.size).toBe(3);expect(f.state().seedPermissions.size).toBe(265);expect(f.state().epoch).toBe(278);
  expect(f.state().users).toEqual(beforeUsers);expect(f.state().grants).toEqual(beforeGrants);expect(f.state().seedUserBindings).toEqual([]);expect(f.state().seedTeamBindings).toEqual([]);
  expect(f.calls.filter(c=>c.sql.includes('FROM roles WHERE cluster_id=')).length).toBe(2);expect(f.calls.filter(c=>c.sql.includes('FROM role_permissions WHERE role_id=ANY')).length).toBe(2);
  expect(f.approved.assertNative).not.toHaveBeenCalled();expect(f.approved.mutationBinding).not.toHaveBeenCalled();expect(f.operations.execute).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();
  const receipt=await f.http(()=>f.workflow.terminalReceipt(f.plan(),f.author));expect(receipt).toMatchObject({state:'succeeded',steps:[{operationId:null,remoteStarted:false}]});expect(JSON.stringify(receipt)).not.toContain('permissions');
 });
 it.each(badSeeds)('rejects %s immediately after original workspace SQL and rolls back the entire seed transaction',async variant=>{
  const f=fixture(),p=await f.prepare(createRequest());await f.submit(p);const before=structuredClone(f.state().workspaces),seedBefore=f.state().epoch;
  f.mutateSeedOnInsert(({state})=>alterSeed(state,variant,f.userId));await expect(f.execute()).rejects.toThrow();
  expect(f.state().workspaces).toEqual(before);expect(f.state().seedRoles.size).toBe(0);expect(f.state().seedPermissions.size).toBe(0);expect(f.state().epoch).toBe(seedBefore);expect(f.state().facts.size).toBe(0);expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
 it.each(badSeeds)('rechecks %s on the original same-transaction completion rather than trusting the earlier seed result',async variant=>{
  const f=fixture(),p=await f.prepare(createRequest());await f.submit(p);const before=structuredClone(f.state().workspaces);
  await expect(f.execute(f.plan(),undefined,async(input,result,pv)=>{alterSeed(f.state(),variant,f.userId);await f.workflow.verifyMetadataCompletion(input,result,pv);})).rejects.toThrow();
  expect(f.state().workspaces).toEqual(before);expect(f.state().seedRoles.size).toBe(0);expect(f.state().seedPermissions.size).toBe(0);expect(f.state().epoch).toBe(10);expect(f.state().facts.size).toBe(0);
 });
 it('does not reject unchanged grants solely because SQL returns them in another order',async()=>{
  const f=fixture(),p=await f.prepare(createRequest());await f.submit(p);f.mutateSeedOnInsert(({state})=>state.grants.get(f.userId).reverse());
  await expect(f.execute(f.plan(),undefined,async(i,r,pv)=>f.workflow.verifyMetadataCompletion(i,r,pv))).resolves.toMatchObject({nativeRequestsSent:0});expect(f.state().epoch).toBe(278);
 });
 it.each(['old-before-pv','old-after-pv','forged-after-pv'])('refuses %s even after a structurally valid original workspace seed',async variant=>{
  const f=fixture(),p=await f.prepare(createRequest());await f.submit(p);
  await expect(f.execute(f.plan(),undefined,async(i,r,pv)=>{const fact:any=[...f.state().facts.values()][0];if(variant==='old-before-pv')pv=`${f.userId}:7:278`;else fact.after_permission_version=variant==='old-after-pv'?`${f.userId}:7:10`:`${f.userId}:7:999`;await f.workflow.verifyMetadataCompletion(i,r,pv);})).rejects.toThrow();
  expect(f.state().epoch).toBe(10);expect(f.state().facts.size).toBe(0);expect(f.state().seedRoles.size).toBe(0);
 });
 it.each(['clusters','data-sources','workspaces'])('does not waive an IAM epoch change for a non-create %s operation',async resource=>{
  const f=fixture(),request=resource==='clusters'?f.request():resource==='data-sources'?{resource,operation:'update',resourceId:f.sourceId,input:{revision:3,name:'Approved metrics'}}:{resource,operation:'update',resourceId:f.targetWid,input:{revision:5,name:'Approved workspace'}},p=await f.prepare(request);await f.submit(p);
  await expect(f.execute(f.plan(),undefined,async(i,r,pv)=>{f.state().epoch+=sql005Seed.epochDelta;await f.workflow.verifyMetadataCompletion(i,r,pv);})).rejects.toThrow();expect(f.state().facts.size).toBe(0);expect(f.state().epoch).toBe(10);
 });
 it.each(['anchor','target'])('returns only the minimal terminal restore receipt to the genuine %s selector',async selector=>{
  const f=fixture();Object.assign(f.state().workspaces.get(f.targetWid),{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+86400000).toISOString()});
  const p=await f.prepare({resource:'workspaces',operation:'restore',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});await f.submit(p);await f.execute(f.plan(),undefined,async(i,r,pv)=>{await f.workflow.verifyMetadataCompletion(i,r,pv);f.terminal();});
  const selected=selector==='target'?f.targetWid:f.wid,actor={...f.author,workspaceId:selected},receipt=await f.http(()=>f.context.runActor({actor:actor.user,clusterId:f.cid,workspaceId:selected,module:'workflows',action:'read'},async()=>{const frame=f.context.current(),r=await f.workflow.terminalReceipt(f.plan(),actor);expect(f.context.current()).toBe(frame);return r;}),actor);
  expect(receipt).toMatchObject({state:'succeeded',steps:[{remoteStarted:false,operationId:null}]});expect(receipt).not.toHaveProperty('preview');expect(receipt).not.toHaveProperty('entity');
 });
 it.each(['foreign-actor-wid','foreign-frame-wid','foreign-cid'])('rejects %s terminal receipt after the exact original metadata action has completed',async variant=>{
  const f=fixture(),p=await f.prepare(createRequest());await f.submit(p);await f.execute(f.plan(),undefined,async(i,r,pv)=>{await f.workflow.verifyMetadataCompletion(i,r,pv);f.terminal();});
  const foreign=randomUUID(),actor={...f.author,workspaceId:variant==='foreign-actor-wid'?foreign:f.wid},frameWid=variant==='foreign-frame-wid'?foreign:f.wid,frameCid=variant==='foreign-cid'?foreign:f.cid;
  await expect(f.http(()=>f.context.runActor({actor:actor.user,clusterId:frameCid,workspaceId:frameWid,module:'workflows',action:'read'},()=>f.workflow.terminalReceipt(f.plan(),actor)),actor)).rejects.toMatchObject({response:{code:'CONTROL_INTENT_OWNER_REQUIRED'}});
  expect(f.approved.assertNative).not.toHaveBeenCalled();
 });
});
