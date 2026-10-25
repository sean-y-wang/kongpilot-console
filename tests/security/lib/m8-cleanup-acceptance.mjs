import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { entity, scope, sha256 } from './m8-harness.mjs';
import { configurationWrite, completeConfigurationWorkflow } from './m8-configuration-acceptance.mjs';
import { M8_TERMINAL_CAPTURE_ARCHIVE, assertM8KnownTerminalCaptureCleanup } from './m8-terminal-snapshot-cleanup.mjs';

const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const kinds=['services','consumers','upstreams','certificates','ca_certificates','routes','plugins','snis'];
const credentials=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
const areaKey=a=>`${a.cid}:${a.wid}`, typedKey=(a,type,id)=>`${areaKey(a)}:${type}:${id}`;
function actorsFor(h,a){return [a.admin,a.owner,a.other,a.approver,h.state.sessions['read-only']].filter(Boolean);}
function bound(h,j){h.check(h.state.requests.length>=j.originalRequestCount&&sha256(JSON.stringify(h.state.requests.slice(0,j.originalRequestCount)))===j.originalRequestsSha256
  &&(h.state.privateHistoryRefs??[]).length>=j.originalHistoryRefCount&&sha256(JSON.stringify((h.state.privateHistoryRefs??[]).slice(0,j.originalHistoryRefCount)))===j.originalHistoryRefsSha256,'cleanup retains every complete original packet and exact private history reference unchanged');}
function context(h,actors){
 const s=h.state,areas=Object.values(s.scopes??{}),accounts=s.accounts??[];
 h.check(s.version===1&&s.milestone==='M8'&&typeof s.testTag==='string'&&areas.length===3&&areas.every(a=>uuid(a.cid)&&uuid(a.wid))&&new Set(areas.map(areaKey)).size===3
  &&s.nativeFixture?.area?.cid===s.scopes.direct.cid&&s.nativeFixture.area.wid===s.scopes.direct.wid,'cleanup selects only the original three fresh M8 scopes');
 h.check(['admin','owner','other-owner','read-only','approver'].every(label=>accounts.some(a=>a.label===label&&uuid(a.userId)&&uuid(a.role?.id)))
  &&actors.admin?.label==='admin'&&actors.owner?.label==='owner'&&actors.other?.label==='other-owner'&&actors.bootstrap?.label==='bootstrap-provisioner'
  &&[actors.admin,actors.owner,actors.other,actors.bootstrap,actors.approver,s.sessions['read-only']].every(a=>uuid(a?.user?.id)&&uuid(a?.sid)&&a.cookie
   &&s.sessions[a.label]?.user.id===a.user.id&&s.sessions[a.label].sid===a.sid),
 'cleanup uses original named active actors; no account, grant or synthetic SID is created');
 for(const account of accounts){const actor=actorsFor(h,actors).find(a=>a.user.id===account.userId);h.check(actor&&actor.user.username===account.username,'every original M8 account has its actual same-user session');}
 return{areas,accounts};
}
function activeJournal(h,phase){const j=h.state.cleanupJournal;h.assertWritable();h.check(j?.version===1&&j.testTag===h.state.testTag&&j.phase===phase&&j.inFlight===null,'cleanup stage continues only its exact known previous completion once');bound(h,j);return j;}
function prepare(h,j,actor,name,path,method,body){h.assertWritable();bound(h,j);h.check(j.inFlight===null&&!j.phase.startsWith('stopped'),'unresolved original cleanup operation blocks all subsequent transport');
 const op={index:j.operations.length,name,path,method,actorId:actor.user.id,sessionId:actor.sid,idempotencyKey:['GET','HEAD'].includes(method)?null:randomUUID(),bodySha256:sha256(body===undefined?'null':JSON.stringify(body)),state:'prepared'};
 j.operations.push(op);j.inFlight=op.index;h.save();return op;}
function observed(h,j,op,result){Object.assign(op,{state:'response_observed',status:result.status,requestId:result.requestId});j.inFlight=null;bound(h,j);h.save();}
function stopped(h,j){if(j.inFlight!==null)j.operations[j.inFlight].state='response_unknown';j.phase='stopped-original-retained';h.save({phase:'stopped-cleanup-original-retained'});const e=Error('M8_CLEANUP_ORIGINAL_STOP_NO_REPLAY');e.safeEvidenceMessage=true;return e;}
async function request(h,j,actor,name,path,method='GET',body,expected=[200,201]){
 const op=prepare(h,j,actor,name,path,method,body),result=await h.request(actor,path,method,body,{expected,...(op.idempotencyKey?{key:op.idempotencyKey}:{})});
 h.check(expected.includes(result.status)&&uuid(result.requestId),'cleanup response has its exact original server request identity and known status');observed(h,j,op,result);
 return result.status>=400?result:h.data(result);
}
async function hook(h,j,actors,name,fn){if(!fn)return;h.check(typeof fn==='function'&&!j.hooks[name],'cleanup source hook is an explicit one-time caller operation');
 j.hooks[name]='prepared';h.save();await fn(h,actors);bound(h,j);h.assertWritable();j.hooks[name]='complete';h.save();}
async function manualActors(h,j,actors){const manual=h.state.manualUiJournal;
 h.check(manual?.phase==='complete'&&manual.attempts?.length===12&&manual.attempts.every(p=>p.state==='succeeded'),'all twelve original manual UI operations are known before cleanup');
 for(const[label,actor]of[['admin',actors.admin],['owner',actors.owner],['readonly',h.state.sessions['read-only']]]){
  const original=manual.sessions?.[label];h.check(original?.user.id===actor.user.id&&original.sid===actor.sid,'cleanup preserves each original manual actor and its actual SID');
  const me=await request(h,j,actor,`${label}-manual-actor-current`,'/auth/me');h.check(me.user?.id===original.user.id&&me.user.username===original.user.username,'public current user proves the original manual actor remains active');
  const page=await request(h,j,actor,`${label}-manual-sid-current`,'/auth/me/sessions?size=100');
  h.check(Array.isArray(page.items)&&page.items.length<=100&&page.nextCursor===null&&page.total===null&&page.items.filter(r=>r.current===true).length===1&&page.items.some(r=>r.id===original.sid&&r.current===true),'public active-session page proves each original manual SID before account removal');
 }j.manualActorsProven=true;h.save();
}
async function pages(h,j,actor,name,path,{size=j.pageSize,...query}={}){
 let cursor;const seen=new Set(),ids=new Set(),items=[];let count=0;
 do{h.check(count++<100,'cleanup pagination keeps its explicit 100-page bound');const url=new URL(path,'http://source.invalid');for(const[k,v]of Object.entries({...query,size,...(cursor?{cursor}:{})}))url.searchParams.set(k,String(v));
  const page=await request(h,j,actor,name,url.pathname+url.search);h.check(Array.isArray(page.items)&&page.items.length<=size&&page.total===null,'cleanup list remains server paginated');
  for(const row of page.items){h.check(uuid(row.id)&&!ids.has(row.id)&&items.length<10000,'cleanup page yields each exact typed identity once within 10000 records');ids.add(row.id);items.push(row);}
  cursor=page.nextCursor;h.check(cursor===null||typeof cursor==='string'&&cursor.length>0&&cursor.length<=4096&&!seen.has(cursor),'cleanup cursor advances to explicit EOF without cycles');if(cursor)seen.add(cursor);
 }while(cursor);j.eofPages.push({name,actorId:actor.user.id,path,pages:count,items:items.length,terminal:true});h.save();return items;
}
function selections(h,areas){const map=new Map(areas.map(area=>[`${areaKey(area)}:workspace:[]`,{area,kind:'workspace',roots:[]}]))
 for(const packet of h.state.requests){const area=areas.find(a=>a.cid===packet.clusterId&&a.wid===packet.workspaceId),body=packet.body;
  if(!area||!body||body.scope===undefined)continue;const kind=body.scope,roots=body.serviceIds??[];
  h.check(['workspace','services','cluster'].includes(kind)&&Array.isArray(roots)&&roots.length<=100&&roots.every(uuid)&&(kind==='services')===(roots.length>0)&&new Set(roots).size===roots.length,'configuration cleanup selection follows the exact original body scope and roots');
  map.set(`${areaKey(area)}:${kind}:${JSON.stringify(roots)}`,{area,kind,roots});
 }h.check(map.size<=100,'cleanup scope selection stays explicitly bounded');return[...map.values()];}
async function inventory(h,j,actors,selection,type){const {area,kind,roots}=selection,query={scope:kind,...(roots.length?{serviceIds:roots.join(',')}:{ }),includeDeleted:'true'};
 const rows=await pages(h,j,actors.admin,`${type}-all-current`,scope(area.cid,area.wid,type),query),owners=new Map();
 for(const row of rows){h.check(row.clusterId===area.cid&&row.workspaceId===area.wid&&row.scopeKind===kind&&JSON.stringify(row.rootIds)===JSON.stringify(roots)&&Number.isInteger(row.revision)&&row.revision>0&&typeof row.name==='string','configuration inventory has exact fresh scope, root selection and current revision');
  if(row.state!=='deleted'&&row.capabilities?.delete===true)owners.set(row.id,actors.admin);
 }
 if(rows.some(r=>r.state!=='deleted'&&!owners.has(r.id)))for(const actor of actorsFor(h,actors).filter(a=>a.user.id!==actors.admin.user.id&&a.label!=='read-only')){
  const account=h.state.accounts.find(a=>a.userId===actor.user.id);if(account?.cid!==area.cid||account?.wid!==area.wid)continue;
  const owned=await pages(h,j,actor,`${type}-exact-current-owner`,scope(area.cid,area.wid,type),query);
  for(const row of owned)if(row.capabilities?.delete===true){h.check(!owners.has(row.id)||owners.get(row.id).user.id===actor.user.id,'configuration resource has only one actual current owner');owners.set(row.id,actor);}
 }
 for(const row of rows)if(row.state!=='deleted'){const actor=owners.get(row.id);h.check(actor&&(type!=='snapshots/schedules'||row.ownerUserId===actor.user.id),'metadata archive requires the actual resource owner, never admin fallback');}
 return{rows,owners,query};
}
async function configurationMutation(h,j,actors,actor,selection,type,row,operation){const {area}=selection,path=type==='snapshots'?`snapshots/${row.id}/archive`:`snapshots/schedules/${row.id}`;
 const pause=operation==='pause',method=pause?'PATCH':type==='snapshots'?'POST':'DELETE',body={revision:row.revision,confirmed:true,confirm_name:row.name,
  ...(pause?{scope:row.scopeKind,serviceIds:row.rootIds,name:row.name,intervalMinutes:row.intervalMinutes,timezone:row.timezone,retentionDays:row.retentionDays,paused:true}:{})};
 const op=prepare(h,j,actor,`${type}-${operation}`,scope(area.cid,area.wid,path),method,body),first=h.state.requests.length;
 let receipt=await configurationWrite(h,actor,area,path,body,{kind:'compare',key:op.idempotencyKey,method,allowApproval:true});
 if(receipt.state==='waiting_approval'){const approver=actor.user.id===actors.admin.user.id?actors.approver:actors.admin;h.check(approver&&approver.user.id!==actor.user.id,'metadata approval uses only the existing different authorized M8 actor');receipt=await completeConfigurationWorkflow(h,{admin:actor,approver},area,receipt,'configuration-metadata','configuration.metadata');}
 h.check(receipt.state==='succeeded'&&receipt.executionCompleted===true&&receipt.resourceId===row.id&&receipt.resourceType===(type==='snapshots'?'config_snapshots':'config_snapshot_schedules')&&receipt.operation===(pause?'update':'archive'),'archive is an actual successful original metadata receipt');
 const packets=h.state.requests.slice(first).filter(p=>p.key===op.idempotencyKey);h.check(packets.length===1&&packets[0].actorId===actor.user.id&&packets[0].sessionId===op.sessionId&&packets[0].bodySha256===op.bodySha256&&packets[0].state==='response_observed','configuration cleanup retains one unchanged original owner packet');
 observed(h,j,op,packets[0]);const {rows}=await inventory(h,j,actors,selection,type),current=rows.find(r=>r.id===row.id);
 h.check(current&&current.name===row.name&&current.revision===row.revision+1&&current.state===(pause?'paused':'deleted'),'actual current list proves metadata soft archive or deactivation with the next revision');
 j.metadata.push({cid:area.cid,wid:area.wid,type,id:row.id,operation,state:current.state,jobId:receipt.jobId});h.save();return current;
}
async function modes(h,j,actors){const list=await request(h,j,actors.admin,'current-cluster-modes','/clusters');h.check(Array.isArray(list)||Array.isArray(list.items),'cluster mode response is the actual current cluster list');
 const rows=Array.isArray(list)?list:list.items;for(const area of[j.areas.find(a=>a.cid===h.state.scopes.direct.cid),h.state.scopes.approval]){const original=h.state.originalClusterModes?.[area.cid],row=rows.find(r=>r.id===area.cid);
  h.check(original&&['direct','approval'].includes(original.mode)&&row&&Number.isInteger(row.revision),'cleanup mode is bound to the exact original cluster and current revision');
  if(row.execution_mode!==original.mode){h.check(area.cid===h.state.scopes.approval.cid&&h.state.c2ModeChanged===true&&row.execution_mode==='approval','only the previously changed exact C2 original mode may be restored');
   const current=await request(h,j,actors.admin,'restore-exact-original-C2-mode',`/clusters/${area.cid}`,'PATCH',{revision:row.revision,execution_mode:original.mode});
   h.check(current.id===area.cid&&current.execution_mode===original.mode&&current.revision===row.revision+1,'original C2 mode restoration uses the exact durable CAS packet');h.state.c2ModeRestored=true;h.save();
  }
 }j.originalModesRestored=true;h.save();
}
/** Explicit entrypoint before any business cleanup; no whole-stage replay. */
export async function beginM8Cleanup(h,actors,{pageSize=100,beforeCleanup}={}){
 const c=context(h,actors);h.assertWritable();h.check(!h.state.cleanupJournal&&Number.isInteger(pageSize)&&pageSize>=1&&pageSize<=100,'M8 cleanup begins only once with an explicit bounded page size');
 h.check(h.state.httpAcceptanceComplete===true&&h.state.deckAcceptance&&h.state.rbacAcceptance?.complete===true,'original HTTP/CLI/RBAC acceptance completes before cleanup');
 const j={version:1,testTag:h.state.testTag,phase:'starting',inFlight:null,pageSize,areas:c.areas.map(a=>({...a})),originalRequestCount:h.state.requests.length,
  originalRequestsSha256:sha256(JSON.stringify(h.state.requests)),originalHistoryRefCount:(h.state.privateHistoryRefs??[]).length,originalHistoryRefsSha256:sha256(JSON.stringify(h.state.privateHistoryRefs??[])),operations:[],hooks:{},eofPages:[],metadata:[],archives:[],affected:[],identity:[]};
 h.state.cleanupJournal=j;h.save();try{await manualActors(h,j,actors);await hook(h,j,actors,'beforeCleanup',beforeCleanup);j.phase='prepared';h.save();return{prepared:true,originalManualActorsActive:true};}catch{throw stopped(h,j);}
}
export async function m8CleanupConfiguration(h,actors){const j=activeJournal(h,'prepared');try{
 j.phase='configuration-running';h.save();
 await modes(h,j,actors);j.selections=selections(h,j.areas);h.save();
 // Every timer source is stopped before the final full snapshot inventory and
 // before any native deletion. Internal preview snapshots need no fixture name.
 for(const selection of j.selections){const {rows,owners}=await inventory(h,j,actors,selection,'snapshots/schedules');for(const row of rows){if(row.state==='deleted')continue;
  h.check(['active','paused'].includes(row.state),'only known nondeleted schedule states may be deactivated');let current=row;
  if(row.state==='active')current=await configurationMutation(h,j,actors,owners.get(row.id),selection,'snapshots/schedules',row,'pause');
  await configurationMutation(h,j,actors,owners.get(row.id),selection,'snapshots/schedules',current,'archive');}}
 for(const selection of j.selections){const {rows,owners}=await inventory(h,j,actors,selection,'snapshots');for(const row of rows){if(row.state==='deleted')continue;
  if(row.state==='capturing'){
   const proof=assertM8KnownTerminalCaptureCleanup(row,selection,owners.get(row.id),h.state,readFileSync(M8_TERMINAL_CAPTURE_ARCHIVE.proofPath));
   j.originalFailedUnsealedCaptureProof=proof;h.save();
  }else h.check(['ready','failed','incomplete','expired'].includes(row.state),'running or unknown captures are never silently archived');
  await configurationMutation(h,j,actors,owners.get(row.id),selection,'snapshots',row,'archive');}}
 for(const selection of j.selections)for(const type of['snapshots/schedules','snapshots']){const {rows}=await inventory(h,j,actors,selection,type);h.check(rows.every(r=>r.state==='deleted'),'full final metadata EOF inventory proves every timer source and snapshot is soft archived');}
 j.sourcesDeactivated=true;j.phase='configuration-complete';h.save();return{configurationArchived:true,timerSourcesDeactivated:true,archivedMetadata:j.metadata.filter(r=>r.operation==='archive').length};
 }catch{throw stopped(h,j);}}
function nativePlan(h,j){const map=new Map();for(const f of h.state.fixtures){if(![...kinds,'targets','credentials'].includes(f.type))continue;const area=j.areas.find(a=>a.cid===f.cid&&a.wid===f.wid);
  h.check(area&&uuid(f.id)&&(!['targets','credentials'].includes(f.type)||uuid(f.parentId))&&(f.type!=='credentials'||credentials.includes(f.credentialKind)),'native cleanup selects only original typed fixtures in fresh exact scopes');
  const type=f.type==='credentials'?f.credentialKind:f.type,typedIdentity=typedKey(area,type,f.id),prior=map.get(typedIdentity);h.check(!prior||prior.parentId===f.parentId,'duplicate native fixture identities keep their exact original parent');map.set(typedIdentity,{...f,type,typedIdentity,area});}
 h.check(map.size>0&&map.size<=10000,'native cleanup has a bounded nonempty exact original fixture plan');return map;}
async function archiveProof(h,j,actors,area,id,plan){const view=await request(h,j,actors.admin,'current-recycle-affected-proof',scope(area.cid,area.wid,`recycle-bin/${id}`)),entry=view.entry;
 h.check(entry?.id===id&&entry.cluster_id===area.cid&&entry.workspace_id===area.wid&&entry.state==='deleted'&&view.graph?.complete===true&&view.graph.purpose==='recycle'
  &&Array.isArray(view.nodes)&&view.nodes.length===view.graph.nodes?.length,'actual scoped archive is complete, fully deleted and retains every node');
 const affected=[];for(const node of view.nodes){if(node.affected!==true)continue;const f=plan.get(typedKey(area,node.entity_type,node.original_id)),matches=view.graph.nodes.filter(g=>g.type===node.entity_type&&g.id===node.original_id),graph=matches[0];
  h.check(f&&node.delete_state==='deleted'&&matches.length===1&&graph?.affected===true&&graph.data?.id===f.id
   &&node.node_key===(f.parentId?`${f.type}:${f.parentId}:${f.id}`:`${f.type}:${f.id}`),'only exact planned affected and durably deleted nodes prove native absence');
  // preview.graph.key is deliberately redacted. The public SQL node_key and
  // typed graph identity bind the canonical parent without relying on a secret.
  if(f.parentId){const parentType=f.type==='targets'?'upstreams':'consumers',parents=view.nodes.filter(n=>n.entity_type===parentType&&n.original_id===f.parentId),parent=parents[0],raw=f.type==='targets'?graph.data?.upstream:graph.data?.consumer;
   h.check(parents.length===1&&parent.node_key===`${parentType}:${f.parentId}`&&graph.dependencies?.includes(parent.node_key)&&graph.path===`/${parentType}/${f.parentId}/${f.type==='targets'?'targets':f.type}/${f.id}`
    &&(raw==null||(typeof raw==='string'?raw:raw.id)===f.parentId),'archived child retains its exact original canonical parent path and captured dependency');}
  affected.push({typedIdentity:f.typedIdentity,entryId:id,type:f.type,id:f.id,cid:area.cid,wid:area.wid});}
 h.check(affected.some(f=>f.type===(entry.root_type==='credentials'?entry.credential_kind:entry.root_type)&&f.id===entry.original_id),'the archive affected-node proof includes its actual root');
 for(const proof of affected)if(!j.affected.some(p=>p.typedIdentity===proof.typedIdentity))j.affected.push(proof);h.save();return{entry,affected};
}
export async function m8CleanupNative(h,actors,{beforeNative}={}){const j=activeJournal(h,'configuration-complete');try{
 j.phase='native-running';h.save();
 h.check(j.sourcesDeactivated===true&&j.originalModesRestored===true,'native cleanup starts only after original modes and timer deactivation are proven');await hook(h,j,actors,'beforeNative',beforeNative);
 const plan=nativePlan(h,j);j.nativePlan=[...plan.values()].map(({typedIdentity,type,id,cid,wid,parentId})=>({typedIdentity,type,id,cid,wid,parentId}));h.save();
 for(const area of j.areas){for(const type of kinds){const rows=await pages(h,j,actors.admin,'current-native-scope-inventory',scope(area.cid,area.wid,`entities/${type}`));
   for(const row of rows)h.check(plan.has(typedKey(area,type,row.id)),'fresh workspace current native object must have its original typed fixture identity before any delete');}
  const entries=await pages(h,j,actors.admin,'current-deleted-archive-inventory',scope(area.cid,area.wid,'recycle-bin'),{state:'deleted'});
  for(const entry of entries)if(plan.has(typedKey(area,entry.root_type==='credentials'?entry.credential_kind:entry.root_type,entry.original_id)))await archiveProof(h,j,actors,area,entry.id,plan);
 }
 for(const type of kinds)for(const f of [...plan.values()].filter(f=>f.type===type)){
  const response=await request(h,j,actors.admin,'current-original-native-root',scope(f.cid,f.wid,`entities/${type}/${f.id}`),'GET',undefined,[200,404]);
  if(response.status===404){h.check(j.affected.some(p=>p.typedIdentity===f.typedIdentity),'a current 404 is successful cleanup only with actual exact affected/delete-state archive proof');continue;}
  const current=entity(response);h.check(current.id===f.id&&Array.isArray(current.tags)&&current.tags.includes(h.state.testTag),'native delete is bound to the current original tagged fixture');
  const name=current.name??current.username??current.target??current.id,deleted=await request(h,j,actors.admin,'soft-recycle-original-native-root',scope(f.cid,f.wid,`entities/${type}/${f.id}`),'DELETE',{confirmed:true,confirm_name:name});
  h.check(uuid(deleted.entryId)&&deleted.state==='deleted'&&Array.isArray(deleted.deleted),'native delete succeeds only after durable graph soft archive');
  const proof=await archiveProof(h,j,actors,f.area,deleted.entryId,plan);h.check(proof.entry.root_type===type&&proof.entry.original_id===f.id&&deleted.deleted.length===proof.affected.length
   &&deleted.deleted.every(d=>proof.affected.some(p=>p.type===d.type&&p.id===d.id)),'native root acknowledgement agrees with its exact complete affected node graph');
  j.archives.push({cid:f.cid,wid:f.wid,type,id:f.id,entryId:deleted.entryId,affected:proof.affected.length});h.save();
  const absent=await request(h,j,actors.admin,'soft-recycled-root-now-absent',scope(f.cid,f.wid,`entities/${type}/${f.id}`),'GET',undefined,[404]);h.check(absent.status===404,'native root is absent after its actual durable archive');
 }
 for(const f of plan.values())h.check(j.affected.some(p=>p.typedIdentity===f.typedIdentity),'all exact native roots and their typed children have actual affected archive proofs');
 for(const area of j.areas)for(const type of kinds)h.check((await pages(h,j,actors.admin,'final-native-empty-EOF',scope(area.cid,area.wid,`entities/${type}`))).length===0,'full final native EOF proves exact fresh workspace is empty');
 j.phase='native-complete';h.save();return{nativeRecycled:true,nativeRootsRecycled:j.archives.length,nativeAffectedObjects:j.affected.length};
 }catch{throw stopped(h,j);}}
async function iamDelete(h,j,actor,type,fixture){const current=await request(h,j,actor,`current-${type}-CAS`, `/iam/${type}/${fixture.id}`),name=type==='users'?current.username:current.name;
 h.check(current.id===fixture.id&&name===fixture.name&&['active','disabled'].includes(current.status)&&Number.isInteger(current.revision)&&current.revision>0,'IAM cleanup uses only exact original current identity/name and revision');
 const removed=await request(h,j,actor,`soft-delete-${type}`,`/iam/${type}/${fixture.id}`,'DELETE',{revision:current.revision,confirmed:true,confirm_name:name});
 h.check(removed.id===current.id&&removed.status==='deleted'&&removed.revision===current.revision+1&&(type==='users'?removed.username:removed.name)===name,'IAM soft delete acknowledges its exact current CAS and preserved name');
 j.identity.push({type,id:fixture.id,revision:removed.revision,state:'deleted',actorId:actor.user.id});h.save();}
export async function m8CleanupIdentity(h,actors,{beforeIdentity,beforeFinalIdentity,afterIdentity}={}){const j=activeJournal(h,'native-complete');try{
 j.phase='identity-running';h.save();
 await manualActors(h,j,actors);await hook(h,j,actors,'beforeIdentity',beforeIdentity);
 const unique=new Map(h.state.fixtures.filter(f=>['users','roles','workspaces'].includes(f.type)).map(f=>[`${f.type}:${f.id}`,f])),adminAccount=h.state.accounts.find(a=>a.label==='admin');
 for(const account of h.state.accounts){const fixture=unique.get(`users:${account.userId}`);h.check(fixture?.name===account.username,'every original named account has its exact soft-delete fixture');if(account.label!=='admin')await iamDelete(h,j,actors.admin,'users',fixture);}
 for(const f of unique.values())if(f.type==='roles'&&f.id!==adminAccount.role.id){h.check(h.state.accounts.some(a=>a.role.id===f.id)&&f.name.startsWith(h.state.testTag),'only original custom acceptance roles are archived');await iamDelete(h,j,actors.admin,'roles',f);}
 for(const area of j.areas){const f=unique.get(`workspaces:${area.wid}`);h.check(f?.cid===area.cid&&f.name.startsWith(h.state.testTag),'workspace removal is bound to its original fresh registered fixture');
  const row=await request(h,j,actors.admin,'current-workspace-CAS',`/clusters/${area.cid}/workspaces/${area.wid}`);h.check(row.id===area.wid&&row.cluster_id===area.cid&&row.name===f.name&&row.is_default===false&&row.status==='active'&&Number.isInteger(row.revision),'only exact current nondefault emptied workspaces are soft deleted');
  const deleted=await request(h,j,actors.admin,'soft-delete-original-workspace',`/clusters/${area.cid}/workspaces/${area.wid}`,'DELETE',{revision:row.revision,confirmed:true,confirm_name:row.name});
  h.check(deleted.state==='deleted'&&deleted.workspace?.id===row.id&&deleted.workspace.cluster_id===area.cid&&deleted.workspace.status==='deleted'&&deleted.workspace.revision===row.revision+1,'workspace soft delete proves its exact current empty-scope CAS');j.identity.push({type:'workspaces',id:row.id,state:'deleted'});h.save();}
 await hook(h,j,actors,'beforeFinalIdentity',beforeFinalIdentity);h.check(adminAccount.userId===actors.admin.user.id&&adminAccount.role.id===unique.get(`roles:${adminAccount.role.id}`)?.id,'bootstrap final cleanup targets only the original named admin account and custom role');
 await iamDelete(h,j,actors.bootstrap,'users',unique.get(`users:${adminAccount.userId}`));await iamDelete(h,j,actors.bootstrap,'roles',unique.get(`roles:${adminAccount.role.id}`));
 j.phase='business-complete';h.state.cleanup={...(h.state.cleanup??{}),businessCompleted:true,configurationArchived:true,nativeRecycled:true,identitySoftDeleted:true,
  immutableJobsAuditsWorkflowsPlansImportsExportsRetained:true,privateMaterialsRetained:true};h.save();await hook(h,j,actors,'afterIdentity',afterIdentity);j.phase='complete';h.save();
 return{...h.state.cleanup,archivedMetadata:j.metadata.filter(r=>r.operation==='archive').length,nativeRootsRecycled:j.archives.length,nativeAffectedObjects:j.affected.length,softDeletedIdentityResources:j.identity.length};
 }catch{throw stopped(h,j);}}
export async function m8CleanupAcceptance(h,actors,options={}){await beginM8Cleanup(h,actors,options);await m8CleanupConfiguration(h,actors);await m8CleanupNative(h,actors,options);return m8CleanupIdentity(h,actors,options);}
