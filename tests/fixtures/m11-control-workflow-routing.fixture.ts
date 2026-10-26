import {RecycleService} from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import 'reflect-metadata';
import {expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ForbiddenException,ConflictException,NotFoundException} from '@nestjs/common';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {ApprovedWorkflowExecutionService} from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
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
export const CONTROL_ROUTING_SQL005_SEED=sql005WorkspaceSeedModel();
const sql005Seed=CONTROL_ROUTING_SQL005_SEED;

/** Real main service, original Clusters/DataSources/Workspace validators and
 * callbacks, private Business/Completion WeakMaps, shared plan validator and
 * genuine Context ALS. SQL/Redis, Root persist/private Approved provider and
 * Kong read transport are fixtures. These tests are not live DDL/HTTP evidence. */
function createControlBaseFixture(){
 const cid=randomUUID(),wid=randomUUID(),targetWid=randomUUID(),sourceId=randomUUID(),userId=randomUUID(),reviewerId=randomUUID(),sid=randomUUID(),otherSid=randomUUID(),reviewerSid=randomUUID();
 const secrets=new SecretService(),context=new KongExecutionContextService(),copy=<T>(v:T):T=>structuredClone(v);
 const author:any={user:{id:userId,username:'control-owner',superAdmin:false},workspaceId:wid,idempotencyKey:'control-original-key',requestId:randomUUID(),ip:'192.0.2.81'},
  reviewer:any={user:{id:reviewerId,username:'control-reviewer',superAdmin:false},workspaceId:wid,idempotencyKey:'control-reviewer-key',requestId:randomUUID(),ip:'192.0.2.82'};
 const globalGrant=(module:string,action:string)=>({module,action,scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null});
 let state:any={epoch:10,users:new Map([userId,reviewerId].map(id=>[id,{id,status:'active',deleted_at:null,force_password_change:false,super_admin:false,credential_epoch:3,permissions_epoch:7}])),
  grants:new Map([userId,reviewerId].map(id=>[id,['clusters','data-sources','workspaces','workflows','recycle-bin','services'].flatMap(module=>['read','write','delete','approve'].map(action=>globalGrant(module,action)))])),
  sessions:new Map([[sid,{id:sid,user_id:userId,credential_epoch:3,expires_at:new Date(Date.now()+1800000).toISOString(),revoked_at:null}],
   [otherSid,{id:otherSid,user_id:userId,credential_epoch:3,expires_at:new Date(Date.now()+1800000).toISOString(),revoked_at:null}],
   [reviewerSid,{id:reviewerSid,user_id:reviewerId,credential_epoch:3,expires_at:new Date(Date.now()+1800000).toISOString(),revoked_at:null}]]),
  cluster:{id:cid,name:'Production',environment:'prod',admin_url:'http://192.0.2.11:8001',proxy_origin:null,transport_scope:null,labels:['owner:gateway'],execution_mode:'approval',connection_secret:null,
   revision:2,status:'healthy',version:'1.5.1',capabilities:{services:true},enabled_plugins:['key-auth'],last_probed_at:null,deleted_at:null},
  sources:new Map([[sourceId,{id:sourceId,cluster_id:cid,name:'Metrics',type:'prometheus',base_url:'http://192.0.2.12:9090',auth_secret:null,enabled:true,revision:3,deleted_at:null,last_status:'unknown',last_probed_at:null}]]),
  workspaces:new Map([[wid,{id:wid,cluster_id:cid,code:'default',name:'默认工作区',is_default:true,status:'active',revision:3,deleted_at:null,retention_until:null,description:'',owner_user_id:null}],
   [targetWid,{id:targetWid,cluster_id:cid,code:'pay',name:'Payments',is_default:false,status:'active',revision:5,deleted_at:null,retention_until:null,description:'Original workspace',owner_user_id:null}]]),
  recycles:new Map(),recycleEligible:true,intents:new Map(),requests:new Map(),plans:new Map(),workflows:new Map(),facts:new Map(),audit:new Map(),running:null,duplicateCluster:false,duplicateSource:false,
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
  if(sql.includes('m11_self_approval_permitted'))return {ok:false};
  if(sql.includes('m11_recycle_purge_available'))return {eligible:state.recycleEligible};
  if(sql.includes('FROM recycle_entries')){const r=state.recycles.get(p[1]);return r&&r.cluster_id===p[0]?project(sql,r):null;}
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
  if(sql.startsWith("UPDATE recycle_entries SET state='purged'")){const r=state.recycles.get(p[1]);if(!r||r.cluster_id!==p[0]||r.workspace_id!==p[2]||r.revision!==p[3]||r.payload_secret!==p[4]||r.state!==p[5])return 0;Object.assign(r,{state:'purged',payload_secret:null,purged_at:new Date().toISOString(),revision:r.revision+1});return 1;}
  throw new Error(`Unexpected control fixture write: ${sql}`);
 };
 const transport=(name:string):any=>({one:vi.fn(async(sql:string,p?:any[])=>{calls.push({name,sql,p});return one(sql,p);}),query:vi.fn(async(sql:string,p?:any[])=>{calls.push({name,sql,p});return query(sql,p);}),exec:vi.fn(async(sql:string,p?:any[])=>{calls.push({name,sql,p});return exec(sql,p);})});
 const tx=transport('tx'),db=transport('outer');db.transaction=vi.fn(async(fn:any)=>{const before=copy(state);try{return await fn(tx);}catch(error){state=before;throw error;}});
 const allowed=(id:string,module:string,action:string,clusterId?:string,workspaceId?:string)=>{const u=state.users.get(id);return u?.status==='active'&&!u.deleted_at&&!u.force_password_change&&(u.super_admin||state.grants.get(id)?.some((g:any)=>coarseGrantMatches(g,module,action as any,{clusterId,workspaceId})));};
 const identityAuthority=new AuthorizationService(db,undefined as any,undefined as any,context);
 const authz:any={assertConsole:vi.fn(async(u:any,m:string,a:string)=>{if(!allowed(u.id,m,a)||!state.users.get(u.id).super_admin&&!state.grants.get(u.id).some((g:any)=>validGrant(g)&&g.module===m&&g.action===a&&g.scope_type==='global'&&g.cluster_id===null&&g.workspace_id===null))throw new ForbiddenException({code:'FIXTURE_CONSOLE_DENIED'});}),
  assertCluster:vi.fn(async(u:any,c:string,m:string,a:string,w?:string)=>{if(!allowed(u.id,m,a,c,w))throw new ForbiddenException({code:'FIXTURE_CLUSTER_DENIED'});}),assertEntity:vi.fn(async(u:any,c:string,m:string,a:string,_r:any,w:string)=>{if(!allowed(u.id,m,a,c,w))throw new ForbiddenException({code:'FIXTURE_ENTITY_DENIED'});}),
  snapshot:vi.fn(async(u:any)=>({user:{...u,superAdmin:state.users.get(u.id)?.super_admin===true},grants:copy(state.grants.get(u.id)??[])})),isPlatformAdmin:vi.fn(async(u:any)=>state.users.get(u.id)?.super_admin===true),permissionVersion:vi.fn(identityAuthority.permissionVersion.bind(identityAuthority))};
 authz.assertArchivedEntity=authz.assertEntity;
 const redis:any={withLock:vi.fn(async(_k:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn()},audit:any={append:vi.fn(async(event:any,transaction:any)=>{expect(transaction).toBe(tx);const id=randomUUID();state.audit.set(id,{id,...secrets.redact(event) as any});return {id};})};
 const operations:any={completed:vi.fn(async()=>null),execute:vi.fn(async()=>{throw new Error('Control approval cannot enter ordinary Direct ledger');})},mutations:any={execute:vi.fn(async()=>{throw new Error('Control approval cannot mint generic Native authority');})};
 const kong:any={invalidate:vi.fn(),list:vi.fn(async()=>({items:[],nextCursor:null,size:1}))},clusters=new ClustersService(db,secrets,kong,audit,authz,operations,context),
  sources=new DataSourcesService(db,secrets,clusters,audit,authz,operations),resolver=new WorkspaceResolverService(db),workspaces=new WorkspaceService(db,resolver,authz,mutations,audit,kong,context),
  recycle=new RecycleService(db,secrets,kong,mutations,{} as any,authz,audit,{} as any,{} as any,resolver,context),
  business=new ControlMetadataBusinessService(db,secrets,clusters,sources,workspaces,operations,recycle);business.onModuleInit();
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
 const runFixtureApproved=async<T>(executionId:string,fn:()=>Promise<T>):Promise<T>=>{
  const execution=state.rootExecutions.get(executionId),sealed=execution&&state.plans.get(execution.workflow_id),frame=context.current(),user=frame.actor&&state.users.get(frame.actor.id),session=frame.sessionId&&state.sessions.get(frame.sessionId);
  if(!execution||execution.state!=='executing'||!sealed||frame.actor?.id!==execution.execution_actor_id||!session||session.user_id!==frame.actor.id||session.revoked_at||Date.parse(session.expires_at)<=Date.now()||session.credential_epoch!==user?.credential_epoch)throw new ForbiddenException({code:'FIXTURE_ORIGINAL_APPROVED_EXECUTION_REQUIRED'});
  state.running={executionId,executionKey:execution.idempotency_key,workflowId:sealed.workflowId,clusterId:sealed.clusterId,workspaceId:sealed.workspaceId,actorId:frame.actor.id,stepId:sealed.steps[0].id,planHash:secrets.fingerprint(sealed),planRevision:sealed.planRevision,
   executionState:execution.state,workflowState:state.workflows.get(sealed.workflowId).state,stepState:state.rootSteps.get(sealed.steps[0].id).state,handler:'control.metadata',kind:'metadata',nativeCount:0,approvalFormat:execution.approval_format,approvalSetId:execution.approval_set_id,approvalSetHmac:execution.approval_set_hmac};
  const handle=Object.freeze({}),proof=Object.freeze({executionId,workflowId:sealed.workflowId,actorId:frame.actor.id,sessionId:frame.sessionId,clusterId:sealed.clusterId,workspaceId:sealed.workspaceId,permissionVersion:`${frame.actor.id}:${user.permissions_epoch}:${state.epoch}`,expiresAt:Date.now()+60000});originals.set(handle,proof);
  try{return await context.runApprovedWorkflow(handle as any,fn);}finally{originals.delete(handle);}
 };
 return {cid,wid,targetWid,sourceId,userId,reviewerId,sid,otherSid,author,reviewer,secrets,context,db,tx,authz,redis,audit,operations,mutations,kong,clusters,sources,workspaces,recycle,business,plans,registry,approved,workflow,writes,calls,metadataChecks,state:()=>state,http,request,prepare,submit,intent,plan,execute,terminal,
  runFixtureApproved, resolver, mutateSeedOnInsert:(fn:(facts:{state:any;workspaceId:string;roleIds:string[];permissionIds:string[]})=>void)=>{onWorkspaceSeed=fn;}};
}

/** Adds Root's real routing/dispatch around the same genuine Main and Business
 * pipeline. SQL, policy vote records and the Approved issuer are named fixture
 * transports. No HTTP call, native permit or production migration executes. */
export function createControlWorkflowRoutingFixture(){
 const f=createControlBaseFixture(),copy=<T>(v:T):T=>structuredClone(v),initial=f.state();
 Object.assign(initial,{rootExecutions:new Map(),rootSteps:new Map(),rootApprovals:[],rootEvents:[],rootStages:new Map()});
 const sync=()=>{const s=f.state(),r=s.running;if(!r)return;const e=s.rootExecutions.get(r.executionId),w=s.workflows.get(r.workflowId),step=s.rootSteps.get(r.stepId);if(e)r.executionState=e.state;if(w)r.workflowState=w.state;if(step)r.stepState=step.state;};
 const handleOne=(sql:string,p:any[]):{handled:boolean;value:any}=>{
  const s=f.state(),result=(value:any)=>({handled:true,value:copy(value)});
  if(sql.includes('FROM workflow_executions WHERE workflow_id=')){const row=[...s.rootExecutions.values()].find((e:any)=>e.workflow_id===p[0]&&e.plan_revision===p[1]&&(!p[2]||e.execution_actor_id===p[2]));return result(row??null);}
  if(sql.includes('FROM workflow_executions WHERE id='))return result(s.rootExecutions.get(p[0])??null);
  if(sql.includes('FROM workflow_steps WHERE workflow_id=')&&sql.includes("state='running'"))return result([...s.rootSteps.values()].find((step:any)=>step.workflow_id===p[0]&&step.state==='running')??null);
  if(sql.includes('FROM workflow_stages')){const stage=s.rootStages.get(p[0]);return result(stage&&(!p[1]||stage.plan_revision===p[1])&&(!p[2]||stage.level===p[2])&&(!sql.includes("state='active'")||stage.state==='active')&&(!sql.includes("state='pending'")||stage.state==='pending')?stage:null);}
  if(sql.includes('FROM workflow_approvals')){
   if(sql.startsWith('SELECT count('))return result({votes:s.rootApprovals.filter((a:any)=>a.workflow_id===p[0]&&a.plan_revision===p[1]&&a.level===p[2]&&a.decision==='approve').length});
   const row=sql.includes('cluster_id=$1')?s.rootApprovals.find((a:any)=>a.cluster_id===p[0]&&a.workspace_id===p[1]&&a.approver_id===p[2]&&a.idempotency_key===p[3])
    :s.rootApprovals.find((a:any)=>a.workflow_id===p[0]&&a.approver_id===p[1]&&a.idempotency_key===p[2]);return result(row??null);
  }
  if(sql.includes('FROM workflow_events')){const row=s.rootEvents.find((e:any)=>sql.includes('cluster_id=$1')?e.cluster_id===p[0]&&e.workspace_id===p[1]&&e.actor_id===p[2]&&e.safe_metadata.key===p[3]
   :e.workflow_id===p[0]&&e.actor_id===p[1]&&e.action===(sql.includes("action='decision.cancel'")?'decision.cancel':p[2])&&e.safe_metadata.key===(sql.includes("action='decision.cancel'")?p[2]:p[3]));return result(row??null);}
  if(sql.includes('FROM workflows WHERE id=')){const w=s.workflows.get(p[0]);if(!w||p[1]&&w.cluster_id!==p[1]||p[2]&&sql.includes('workspace_id=$3')&&w.workspace_id!==p[2])return result(null);
   if(sql.includes("state='succeeded'")&&(w.state!=='succeeded'||w.requester_user_id!==p[2]))return result(null);return result(w);}
  if(sql.startsWith('SELECT w.* FROM workflows'))return result([...s.workflows.values()].find((w:any)=>w.cluster_id===p[0]&&w.workspace_id===p[1]&&(w.requester_user_id===p[2]&&w.idempotency_key===p[3]||[...s.rootExecutions.values()].some((e:any)=>e.workflow_id===w.id&&e.execution_actor_id===p[2]&&e.idempotency_key===p[3])))??null);
  return {handled:false,value:null};
 };
 const handleQuery=(sql:string,p:any[]):{handled:boolean;value:any[]}=>{
  const s=f.state(),result=(v:any[])=>({handled:true,value:copy(v)});
  if(sql.includes('SELECT DISTINCT w.* FROM workflows'))return result([...s.workflows.values()].filter((w:any)=>w.cluster_id===p[0]&&w.kind==='control-metadata'&&(w.requester_user_id===p[1]&&w.idempotency_key===p[2]
   ||[...s.rootExecutions.values()].some((e:any)=>e.workflow_id===w.id&&e.execution_actor_id===p[1]&&e.idempotency_key===p[2])||s.rootApprovals.some((a:any)=>a.workflow_id===w.id&&a.approver_id===p[1]&&a.idempotency_key===p[2])||s.rootEvents.some((e:any)=>e.workflow_id===w.id&&e.actor_id===p[1]&&e.safe_metadata.key===p[2]))).slice(0,2));
  if(sql.includes('FROM workflow_steps WHERE workflow_id='))return result([...s.rootSteps.values()].filter((step:any)=>step.workflow_id===p[0]&&(!p[1]||step.plan_revision===p[1])).sort((a:any,b:any)=>a.step_order-b.step_order));
  if(sql.includes('FROM workflow_approvals WHERE workflow_id='))return result(s.rootApprovals.filter((a:any)=>a.workflow_id===p[0]&&(!p[1]||a.plan_revision===p[1])));
  if(sql.startsWith('SELECT * FROM workflows w WHERE'))return result([...s.workflows.values()].filter((w:any)=>{const i=s.intents.get(w.subject_id);return w.cluster_id===p[0]&&(w.workspace_id===p[1]||w.kind==='control-metadata'&&i?.resource==='workspaces'&&i.resource_id===p[1])&&(!p[2]||w.state===p[2])&&(p[3]!=='submitted'||w.requester_user_id===p[4])&&(!p[7]||w.kind==='control-metadata');}).slice(p[6],p[6]+p[5]));
  return {handled:false,value:[]};
 };
 const handleExec=(sql:string,p:any[]):{handled:boolean;value:number}=>{
  const s=f.state(),done=(v=1)=>{f.writes.push(sql);sync();return {handled:true,value:v};};
  if(sql.startsWith('INSERT INTO workspaces')&&sql.includes('SELECT id'))return done(); // Existing default: genuine ON CONFLICT no-op, no row trigger.
  if(sql.startsWith('INSERT INTO workflow_executions')){const e={id:p[0],cluster_id:p[1],workspace_id:p[2],workflow_id:p[3],plan_revision:p[4],plan_hash:p[5],execution_mode:p[6],approval_required:p[7],approved_by:p[8],execution_actor_id:p[9],state:'executing',claim_token_hash:p[10],request_id:p[11],idempotency_key:p[12],expires_at:p[13],approval_format:p[14],approval_set_id:p[15],approval_set_hmac:p[16],revision:1,snapshot_state:'pending',started_at:new Date().toISOString()};s.rootExecutions.set(e.id,e);return done();}
  if(sql.startsWith('UPDATE workflow_executions')){const e=s.rootExecutions.get(p[0]);if(!e||e.state!=='executing')return done(0);
   if(sql.includes("snapshot_state='ready'")){if(e.snapshot_state!=='pending'||e.workflow_id!==p[4]||e.plan_hash!==p[5])return done(0);Object.assign(e,{snapshot_state:'ready',snapshot_secret:p[1],snapshot_hash:p[2],snapshot_id:p[3]});}
   else if(sql.includes("SET state='succeeded'")){if(e.workflow_id!==p[1]||e.plan_revision!==p[2]||e.plan_hash!==p[3]||e.execution_actor_id!==p[4])return done(0);Object.assign(e,{state:'succeeded',completed_at:new Date().toISOString()});}
   else Object.assign(e,{state:p[1],completed_at:new Date().toISOString()});e.revision++;return done();}
  if(sql.startsWith('UPDATE workflow_steps')){const step=s.rootSteps.get(p[0]);if(!step)return done(0);
   if(sql.includes("SET state='running'")){if(step.state!=='pending')return done(0);Object.assign(step,{state:'running',started_at:new Date().toISOString()});}
   else if(sql.includes("SET state='succeeded'")){if(step.state!=='running'||step.workflow_id!==p[2]||step.plan_revision!==p[3]||step.plan_hash!==p[4])return done(0);Object.assign(step,{state:'succeeded',safe_result:JSON.parse(p[1]),completed_at:new Date().toISOString()});}
   else {if(step.state!=='running')return done(0);Object.assign(step,{state:p[1],error_code:p[2],safe_result:JSON.parse(p[3]),completed_at:new Date().toISOString()});}step.revision++;return done();}
  if(sql.startsWith('UPDATE workflows')){const w=s.workflows.get(p[0]);if(!w)return done(0);
   if(sql.includes("SET state='executing'")){if(w.revision!==p[1]||w.state!==p[2])return done(0);w.state='executing';}
   else if(sql.includes("SET state='succeeded'")){if(w.state!=='executing'||w.plan_revision!==p[1]||w.plan_hash!==p[2]||w.revision!==p[3])return done(0);w.state='succeeded';}
   else if(sql.includes('approved_by=')){if(w.revision!==p[4])return done(0);Object.assign(w,{state:p[1],approved_by:p[2],approved_at:p[3]});}
   else {if(w.state!=='executing')return done(0);w.state=p[1];}w.revision++;return done();}
  if(sql.startsWith('INSERT INTO workflow_approvals')){const row={id:randomUUID(),cluster_id:p[0],workspace_id:p[1],workflow_id:p[2],plan_revision:p[3],plan_hash:p[4],level:p[5],approver_id:p[6],decision:p[7],reason:p[8],request_id:p[9],idempotency_key:p[10],candidate_version:p[11],candidate_manifest_hmac:p[12],stage_revision:p[13],decided_at:new Date().toISOString()};s.rootApprovals.push(row);return done();}
  if(sql.startsWith('UPDATE workflow_stages')){const stage=s.rootStages.get(p[0]);if(!stage)return done(0);if(sql.includes("state='pending'")){if(stage.state==='pending')stage.state='skipped';return done();}
   if(stage.state!=='active'||stage.plan_revision!==p[2]||stage.level!==p[3]||stage.revision!==p[4])return done(0);stage.state=p[1];stage.revision++;return done();}
  if(sql.startsWith('INSERT INTO workflow_events')){s.rootEvents.push({cluster_id:p[0],workspace_id:p[1],workflow_id:p[2],plan_revision:p[3],plan_hash:p[4],actor_type:'user',actor_id:p[5],action:p[6],result:'success',safe_metadata:JSON.parse(p[7]),request_id:p[8]});return done();}
  return {handled:false,value:0};
 };
 for(const [name,transport] of [['outer',f.db],['tx',f.tx]] as const){
  const originalOne=transport.one.bind(transport),originalQuery=transport.query.bind(transport),originalExec=transport.exec.bind(transport);
  transport.one=vi.fn(async(sql:string,p:any[]=[])=>{const handled=handleOne(sql,p);if(!handled.handled)return originalOne(sql,p);f.calls.push({name,sql,p});return handled.value;});
  transport.query=vi.fn(async(sql:string,p:any[]=[])=>{const handled=handleQuery(sql,p);if(!handled.handled)return originalQuery(sql,p);f.calls.push({name,sql,p});return handled.value;});
  transport.exec=vi.fn(async(sql:string,p:any[]=[])=>{const handled=handleExec(sql,p);if(!handled.handled)return originalExec(sql,p);f.calls.push({name,sql,p});return handled.value;});
 }
 const originalPersist=f.plans.persist.bind(f.plans);f.plans.persist=vi.fn(async(plan:any,...rest:any[])=>{await originalPersist(plan,...rest);const s=f.state(),w=s.workflows.get(plan.workflowId);
  Object.assign(w,{kind:plan.kind,subject_type:plan.subject.type,subject_id:plan.subject.id,requester_user_id:plan.requester.id,approval_format:2,execution_mode:plan.executionMode,approval_required:plan.approvalRequired,
   expires_at:plan.expiresAt,created_at:plan.issuedAt,approved_by:null,candidate_version:1,candidate_manifest_hmac:f.secrets.fingerprint({syntheticCandidate:true})});
  for(const step of plan.steps)s.rootSteps.set(step.id,{id:step.id,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,workflow_id:plan.workflowId,plan_revision:plan.planRevision,plan_hash:w.plan_hash,step_key:step.key,step_order:step.order,kind:step.kind,handler:step.handler,entity_type:step.entityType,entity_id:step.entityId,metadata_revision:step.metadataRevision,metadata_before_hmac:step.metadataBeforeHmac,metadata_payload_hmac:step.metadataPayloadHmac,native_requests:[],state:'pending',revision:1,operation_id:null,recycle_entry_id:null,safe_result:{},error_code:null});
  s.rootStages.set(plan.workflowId,{workflow_id:plan.workflowId,cluster_id:plan.clusterId,workspace_id:plan.workspaceId,plan_revision:plan.planRevision,plan_hash:w.plan_hash,level:1,revision:1,state:'active',required_approvals:1});
 });
 f.plans.load=vi.fn(async(cid:string,wid:string,id:string)=>{const w=f.state().workflows.get(id),plan=f.state().plans.get(id);if(!w||!plan||w.cluster_id!==cid||w.workspace_id!==wid)throw new NotFoundException({code:'FIXTURE_WORKFLOW_NOT_FOUND'});validateWorkflowPlan(plan);if(w.plan_hash!==f.secrets.fingerprint(plan))throw new ConflictException({code:'FIXTURE_PLAN_HASH_CHANGED'});
  return {row:copy(w),plan,version:{safe_diff:[],safe_impact:{nativeRequests:0},plan_hash:w.plan_hash},rows:copy([...f.state().rootSteps.values()].filter((s:any)=>s.workflow_id===id))};});
 const approval:any={
  verifyApprovalSet:vi.fn(async(plan:any,_input:any,tx:any)=>{await f.workflow.verifyIntent(plan,tx);const w=f.state().workflows.get(plan.workflowId),votes=f.state().rootApprovals.filter((v:any)=>v.workflow_id===w.id&&v.decision==='approve');
   if(!w||w.approval_format!==2||!['approved','executing'].includes(w.state)||!w.approval_set_id||!w.approval_set_hmac||votes.length!==1||votes[0].approver_id===plan.requester.id)throw new ForbiddenException({code:'FIXTURE_APPROVAL_SET_INVALID'});
   await f.workflow.verifyReviewer(votes[0].approver_id,plan,tx);return {format:2,setId:w.approval_set_id,setHmac:w.approval_set_hmac,reviewers:votes.map((v:any)=>({approvalId:v.id,userId:v.approver_id,level:v.level,candidateVersion:v.candidate_version}))};}),
  assertCanVote:vi.fn(async(plan:any,vote:any,tx:any)=>{const stage=f.state().rootStages.get(plan.workflowId),row=f.state().workflows.get(plan.workflowId);if(vote.reviewerId===plan.requester.id||row.state!=='pending'||vote.level!==stage.level||vote.stageRevision!==stage.revision||stage.state!=='active'||vote.candidateVersion!==row.candidate_version)throw new ForbiddenException({code:'FIXTURE_VOTE_NOT_ELIGIBLE'});await f.workflow.verifyReviewer(vote.reviewerId,plan,tx);}),
  assertVoteFeasible:vi.fn(async(plan:any,reviewerId:string,_level:number,tx:any)=>f.workflow.verifyReviewer(reviewerId,plan,tx)),
  sealApprovalSet:vi.fn(async(plan:any,_tx:any)=>{const w=f.state().workflows.get(plan.workflowId);w.approval_set_id=randomUUID();w.approval_set_hmac=f.secrets.fingerprint({workflowId:w.id,votes:f.state().rootApprovals});return {format:2,setId:w.approval_set_id,setHmac:w.approval_set_hmac};}),
  projection:vi.fn(async(plan:any)=>({format:2,candidateVersion:1,activeStage:copy(f.state().rootStages.get(plan.workflowId)),stages:[copy(f.state().rootStages.get(plan.workflowId))]}))};
 const rootApproved=new ApprovedWorkflowExecutionService(f.db,f.secrets,f.authz,f.resolver,f.kong,f.redis,f.context,approval);rootApproved.installControlMetadataDelegate(f.workflow.approvedDelegate());
 // Only issuance/load transport is replaced. Admission, metadata assertion,
 // Root's dispatch and Main's private completion delegates are actual Source.
 vi.spyOn(rootApproved,'runApprovedExecution').mockImplementation((id,fn)=>f.runFixtureApproved(id,fn));
 const root=new WorkflowService(f.db,f.redis,f.secrets,f.kong,f.context,f.authz,f.audit,{} as any,f.mutations,f.operations,f.resolver,f.plans,f.registry,rootApproved,{} as any,undefined,undefined,approval);
 root.installControlMetadataCompletionDelegate(f.workflow.completionDelegate());
 const approveFixture=(plan:any=f.plan())=>{const s=f.state(),w=s.workflows.get(plan.workflowId);if(!w||w.state!=='pending')throw new Error('Fixture approval needs original pending workflow');w.state='approved';w.approved_by=f.reviewerId;w.revision++;s.rootStages.get(w.id).state='approved';
  s.rootApprovals.push({id:randomUUID(),cluster_id:w.cluster_id,workspace_id:w.workspace_id,workflow_id:w.id,plan_revision:w.plan_revision,plan_hash:w.plan_hash,level:1,approver_id:f.reviewerId,decision:'approve',idempotency_key:'fixture-vote-key',candidate_version:1});return copy(w);};
 const executeRoot=(actor:any={...f.author,idempotencyKey:'control-root-execute-key'},body?:any)=>f.http(()=>{const w=f.state().workflows.get(f.plan().workflowId);return root.execute(f.cid,w.id,body??{revision:w.revision,planHash:w.plan_hash,confirmed:true,confirm_name:'control-metadata'},actor);},actor);
 const receiptRoot=(key='control-root-execute-key',actor:any=f.author)=>f.http(()=>root.receiptByKey(f.cid,key,actor),actor);
 return {...f,root,rootApproved,approval,approveFixture,executeRoot,receiptRoot};
}
export type ControlWorkflowRoutingFixture=ReturnType<typeof createControlWorkflowRoutingFixture>;
