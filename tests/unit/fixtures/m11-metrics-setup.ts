import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {vi} from 'vitest';
import {SecretService} from '../../../apps/console-api/src/infrastructure/secret.service';
import {VitalsSetupService} from '../../../apps/console-api/src/modules/vitals/vitals-setup.service';
import {workspaceTag} from '../../../apps/console-api/src/infrastructure/kong/tags';

/** SOURCE fixture with real AEAD/HMAC. These rows and HTTP frames model
 * contracts; they do not constitute an actual SQL/Redis/Approved permit. */
export function metricsSetupFixture(mode:'native_prometheus'|'collector'='collector'){
 process.env.CONSOLE_ENCRYPTION_KEY='52'.repeat(32);const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),sid=randomUUID(),sourceId=randomUUID();
 const actor:any={user:{id:uid,username:'owner',superAdmin:true},workspaceId:wid,requestId:randomUUID(),idempotencyKey:'prepare-key-unique-1'},token='source-fixture-ingest-token';
 const policy:any={version:2,kind:'metrics-setup',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:1,stages:[{level:1,name:'review',mode:'any',threshold:1,selector:{users:[randomUUID()]}}]};
 const definition={id:randomUUID(),version:1,policyHash:secrets.fingerprint(policy)},user:any={id:uid,username:'owner',status:'active',deleted_at:null,force_password_change:false,super_admin:true,permissions_epoch:1,credential_epoch:1};
 const cluster:any={id:cid,name:'生产',version:'1.5.1',status:'online',execution_mode:'approval',revision:1,admin_url:'http://kong:8001',transport_scope:null,enabled_plugins:['prometheus','http-log']};
 const workspace:any={id:wid,cluster_id:cid,name:'默认工作区',code:'default',revision:1,status:'active',is_default:true,deleted_at:null};
 const source:any={id:sourceId,name:'指标源',type:'prometheus',revision:1,baseUrl:'http://prometheus:9090',auth:{type:'basic',username:'reader',password:'source-fixture-private-password'},status:'healthy',availability:'available'};
 const control:any={cluster_id:cid,revision:3,active_source_id:null,enabled:false,collector_enabled:false,credential_generation:1,max_age_ms:15000,safe_capabilities:{}};
 const frame:any={actor:actor.user,clusterId:cid,workspaceId:wid,sessionId:sid,requestId:actor.requestId};
 const intents=new Map<string,any>(),materials:any[]=[],requests=new Map<string,any>(),workflowRows=new Map<string,any>(),savedPlans=new Map<string,any>(),mutations:any[]=[],steps:any[]=[],facts:any[]=[];
 let legacy=false,namespace=false,activeCredential=true,epoch=1;const globalRows:any[]=[];
 const trace:string[]=[],users=new Map<string,any>([[uid,user]]);
 const db:any={one:vi.fn(async(sql:string,params:any[]=[])=>{trace.push(sql);
  if(sql.includes('SELECT version FROM iam_epoch'))return{version:epoch};
  if(sql.includes('FROM auth_sessions s JOIN users'))return frame.sessionId===sid&&user.status==='active'&&!user.force_password_change&&params[0]===sid?{id:sid,credential_epoch:user.credential_epoch,expires_at:new Date(Date.now()+7200000).toISOString()}:null;
  if(sql.includes('FROM auth_sessions WHERE'))return params[0]===sid&&params[1]===uid?{id:sid}:null;
  if(sql.includes('FROM users WHERE')){const u=users.get(params[0]);return u?.status==='active'&&!u.force_password_change?u:null;}
  if(sql.includes('FROM clusters WHERE'))return params[0]===cid?cluster:null;
  if(sql.includes('FROM workspaces WHERE'))return params[0]===cid&&params[1]===wid?workspace:null;
  if(sql.includes('FROM metrics_settings WHERE'))return control;
  if(sql.includes('FROM metrics_setup_intents WHERE actor_id'))return [...intents.values()].find(i=>i.actor_id===params[0]&&i.idempotency_key===params[1])??null;
  if(sql.includes('SELECT id FROM metrics_setup_intents'))return [...intents.values()].find(i=>i.actor_id===params[0]&&i.cluster_id===params[1]&&i.workspace_id===params[2]&&i.idempotency_key===params[3])??null;
  if(sql.includes('FROM metrics_setup_intents WHERE id='))return [...intents.values()].find(i=>i.id===params[0]&&i.cluster_id===params[1]&&i.workspace_id===params[2])??null;
  if(sql.includes('FROM metrics_setup_requests')){const r=requests.get(params[0]);if(!r)return null;if(params.length===4&&(r.workflow_id!==params[1]||r.cluster_id!==params[2]||r.workspace_id!==params[3]))return null;return r;}
  if(sql.includes('FROM workflows WHERE'))return workflowRows.get(params[0])??null;
  if(sql.includes('FROM iam_operations'))return legacy?{id:randomUUID()}:null;
  if(sql.includes('FROM workflow_definition_versions'))return{approval_format:2,policy};
  if(sql.includes('FROM data_sources'))return{id:source.id,revision:source.revision};
  if(sql.includes('SELECT e.id FROM workflow_executions'))return{id:params[0]};
  if(sql.includes('SELECT m.*,s.state'))return mutations.find(m=>m.workflow_step_id===params[0])??null;
  throw Error('Unmodeled SQL SOURCE query: '+sql);
 }),query:vi.fn(async(sql:string,params:any[]=[])=>{trace.push(sql);
  if(sql.includes('iam_effective_grants'))return[];
  if(sql.includes('metrics_setup_plugin_material'))return materials.filter(m=>m.intent_id===params[0]).sort((a,b)=>a.step_order-b.step_order);
  if(sql.includes('SELECT s.id,s.step_key'))return steps;throw Error('Unmodeled SOURCE query: '+sql);
 }),exec:vi.fn(async(sql:string,p:any[])=>{trace.push(sql);
  if(sql.startsWith('INSERT INTO metrics_setup_intents')){const names=['id','cluster_id','workspace_id','actor_id','authoring_session_id','workflow_id','idempotency_key','request_hmac','material_hmac','material_secret','credential_epoch','permission_version','mode','source_id','source_revision','settings_revision','credential_generation','issued_at','expires_at'];const row=Object.fromEntries(names.map((n,i)=>[n,p[i]]));intents.set(row.id,row);return 1;}
  if(sql.startsWith('INSERT INTO metrics_setup_plugin_material')){const names=['intent_id','cluster_id','workspace_id','name','step_order','action','native_id','material_hmac','before_hmac','payload_hmac','schema_hmac','path_hmac'];materials.push(Object.fromEntries(names.map((n,i)=>[n,p[i]])));return 1;}
  if(sql.startsWith('INSERT INTO metrics_setup_requests')){const names=['id','cluster_id','workspace_id','actor_id','workflow_id','idempotency_key','submit_key','request_hmac','material_hmac'];requests.set(p[0],Object.fromEntries(names.map((n,i)=>[n,p[i]])));return 1;}
  if(sql.startsWith('INSERT INTO metrics_setup_completion_facts')){facts.push(p);return 1;}
  throw Error('Unmodeled SOURCE write: '+sql);
 }),transaction:vi.fn(async(fn:any)=>fn(db))};
 const execution:any={current:()=>frame,hasWorkflowScheduledNamespace:()=>namespace,runActor:vi.fn(async(_bind:any,fn:any)=>fn()),runInternalRead:vi.fn(async(_cid:any,_purpose:any,fn:any)=>fn()),
  runManagedMetricsProvision:vi.fn(async(_cid:any,fn:any)=>fn()),assertApprovedMetadataStep:vi.fn(async()=>undefined)};
 const redis:any={withLock:vi.fn(async(_name:any,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>undefined)},audit:any={append:vi.fn(async()=>undefined)};
 const kong:any={list:vi.fn(async()=>({items:globalRows,nextCursor:null})),schema:vi.fn(async()=>({fields:[{name:{type:'string'}}]})),pluginSchema:vi.fn(async(_cid:any,name:any)=>({name,fields:[{config:{type:'record',fields:[]}}]})),request:vi.fn(async()=>{throw Error('Unexpected SOURCE native/GET callback');})};
 const entities:any={prepareCore:vi.fn(async(_cid:any,_type:any,action:any,id:any,body:any)=>{const before=action==='update'?globalRows.find(r=>r.id===id):null;return{before,payload:before?{...body,config:{...before.config,...body.config}}:{...body,tags:[workspaceTag('default')]},references:[]};})};
 const workspaces:any={classify:vi.fn(async(_cid:any,tags:any)=>({state:'resolved',workspace:tags?.includes('other')?{...workspace,id:randomUUID()}:workspace}))};
 const sources:any={read:vi.fn(async(_cid:any,id:any)=>{if(_cid!==cid||id!==sourceId)throw Error('source missing');return structuredClone(source);}),assertCurrent:vi.fn(async(_cid:any,previous:any)=>{if(source.revision!==previous.revision||source.baseUrl!==previous.baseUrl||secrets.fingerprint(source.auth)!==secrets.fingerprint(previous.auth))throw Error('source drift');})};
 const credentials:any={getActiveIngestCredential:vi.fn(async()=>{if(!activeCredential)throw Error('credential missing');return{generation:control.credential_generation,token,fingerprint:secrets.fingerprint(token)};}),
  verifyManagedIngestUrl:vi.fn(async(_cid:any,url:any)=>({valid:activeCredential&&url===`http://kongos:${token}@telemetry-collector:9093/ingest/${cid}`,generation:control.credential_generation,fingerprint:secrets.fingerprint(token)}))};
 const plans:any={definitions:vi.fn(async()=>undefined),definition:vi.fn(async()=>definition),persist:vi.fn(async(plan:any)=>{savedPlans.set(plan.workflowId,plan);workflowRows.set(plan.workflowId,{id:plan.workflowId,state:'pending',revision:1,plan_hash:secrets.fingerprint(plan)});})};
 const settings:any={configure:vi.fn(async(_cid:any,input:any)=>{control.revision=control.revision===0?2:control.revision+1;control.active_source_id=input.activeSourceId;control.enabled=input.enabled;control.collector_enabled=input.collectorEnabled;return{revision:control.revision};})},authz:any={permissionVersion:vi.fn(async()=>`${uid}:${user.permissions_epoch}:${epoch}`)},registry:any={register:vi.fn()};
 const service=new VitalsSetupService(db,redis,secrets,audit,authz,execution,kong,entities,workspaces,sources,settings,credentials,plans,registry);
 const body={sourceId,mode,confirmed:true,confirm_name:cluster.name},query={workspaceId:wid};
 return{service,secrets,cid,wid,uid,sid,actor,body,query,cluster,workspace,user,control,frame,source,token,definition,policy,db,execution,redis,audit,kong,entities,sources,credentials,plans,settings,registry,
  intents,materials,requests,workflowRows,savedPlans,mutations,steps,facts,globalRows,trace,users,setLegacy:(v:boolean)=>legacy=v,setNamespace:(v:boolean)=>namespace=v,setCredential:(v:boolean)=>activeCredential=v,setEpoch:(v:number)=>epoch=v};
}
