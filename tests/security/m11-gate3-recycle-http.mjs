import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {existsSync,readFileSync} from 'node:fs';
import {ReleaseHarness,releaseScope} from './lib/release-harness.mjs';

// Real HTTP only. Root explicitly selects one stage; the original ledger and
// original idempotency keys survive every failure. No failed native send is
// replayed, and no mock response can establish this acceptance.
assert.equal(process.env.RELEASE_LAB_M11_RECYCLE_READY,'true');
const stage=process.argv[2];assert(['service-delete','service-delete-after-observer-fix','service-restore','service-restore-after-revalidation-fix','consumer-delete','consumer-restore'].includes(stage));
const semanticStage=stage==='service-delete-after-observer-fix'?'service-delete':stage==='service-restore-after-revalidation-fix'?'service-restore':stage;
const report=resolve(`artifacts/M11/gate3-recycle-${stage}-http-attempt1.json`);assert(!existsSync(report),'ORIGINAL_REPORT_EXISTS');
const h=new ReleaseHarness('M11',{resume:true});h.reportPath=report;
const cid=h.state.cid,wid=h.state.wid,admin=h.state.sessions.admin,fixtures=h.state.gate2.fixtures;
const g=h.state.gate3Recycle??={intents:{}};h.save();
const path=(suffix,extra={})=>releaseScope(cid,wid,suffix,extra);
async function approve(record,label){
 record.submitBody??={revision:record.receipt.revision,materialHmac:record.receipt.materialHmac,confirmed:true,confirm_name:'native-change'};h.save();
 record.workflowId=(await h.once(`m11-recycle-${label}-submit`,admin,path(`entity-changes/${record.id}/submit`),'POST',record.submitBody)).data.workflowId;h.save();
 for(const [index,reviewer]of ['a','b','c'].entries()){
  const view=(await h.request(admin,path(`workflows/${record.workflowId}`))).data.entity;assert.equal(view.state,'pending');
  const active=view.approval.stages.find(s=>s.state==='active');assert(active);
  record.votes??={};record.votes[reviewer]??={revision:view.revision,planHash:view.planHash,confirmed:true,confirm_name:'native-change',execute:false,
   level:active.level,stageRevision:active.revision,candidateVersion:view.approval.candidateVersion};h.save();
  await h.once(`m11-recycle-${label}-vote-${reviewer}`,h.state.sessions[reviewer],path(`workflows/${record.workflowId}/approve`),'POST',record.votes[reviewer]);
  assert.equal((await h.request(admin,path(`workflows/${record.workflowId}`))).data.entity.state,index===2?'approved':'pending');
 }
 const view=(await h.request(admin,path(`workflows/${record.workflowId}`))).data.entity;assert.equal(view.state,'approved');assert.equal(view.capabilities.execute,true);return view;
}
async function execute(record,label){
 const view=await approve(record,label);record.executeBody??={revision:view.revision,planHash:view.planHash,confirmed:true,confirm_name:'native-change'};h.save();
 const result=(await h.once(`m11-recycle-${label}-execute`,admin,path(`workflows/${record.workflowId}/execute`),'POST',record.executeBody)).data;
 record.executionId=result.executionId;record.executionReceipt=result;h.save();assert.equal(result.state,'succeeded');assert(result.baselineId);
 const detail=(await h.request(admin,path(`workflows/${record.workflowId}`))).data;
 assert.equal(detail.entity.state,'succeeded');assert(detail.nativeChange.packets.length>=2);
 for(const packet of detail.nativeChange.packets){assert.equal(packet.state,'succeeded');assert(semanticStage.endsWith('-delete')?packet.nativeStatus===204:packet.nativeStatus>=200&&packet.nativeStatus<300);}
 assert.equal(detail.nativeChange.baseline.nativeAuthority,false);return detail;
}
async function proxy(label,expected){
 const route=fixtures.route,body={routeId:route.id,input:{method:'GET',url:`http://${route.hosts[0]}${route.paths[0]}/recycle/live`,headers:{apikey:fixtures.key}},confirmed:true,confirm_name:route.name};
 for(let index=0;index<60;index++){
  const result=(await h.once(`m11-recycle-${label}-proxy-${index}`,admin,path('toolbox/probes'),'POST',body)).data;
  if(result.status===expected)return;assert([200,401,403,404,502,503,504].includes(result.status));await new Promise(r=>setTimeout(r,200));
 }throw Error('ACTUAL_PROXY_PROPAGATION_TIMEOUT');
}
try{
 const service=stage.startsWith('service'),name=service?'service':'consumer',entity=fixtures[name],entityType=service?'services':'consumers';
 if(semanticStage.endsWith('-delete')){
  if(stage==='service-delete-after-observer-fix'){
   const proof=JSON.parse(readFileSync(resolve('artifacts/M11/gate3-recycle-first-execution-readonly.json'),'utf8'));
   const original=g.intents['service-delete'];assert.equal(proof.readOnly,true);assert.equal(proof.rows.length,1);
   const fact=proof.rows[0];assert.equal(fact.workflow_id,original.workflowId);assert.equal(fact.state,'failed');assert.equal(fact.execution_state,'failed');
   assert.equal(fact.send_intents,0);assert.equal(fact.mutations,0);assert.equal(fact.events,1);
   const previous=(await h.request(admin,path(`workflows/${original.workflowId}`))).data;
   assert.equal(previous.entity.state,'failed');assert.equal(previous.nativeChange.packets[0].state,'failed-known-not-sent');
   assert(h.state.requests.some(r=>r.path.split('?')[0].endsWith(`/workflows/${original.workflowId}/execute`)&&r.status===403));
  }
  await proxy(stage+'-before',200);
  const record=g.intents[stage]??={body:{change:{kind:'recycle',action:'delete',entityType,entityId:entity.id,confirmed:true,confirm_name:String(entity.name??entity.username)}}};h.save();
  record.receipt=(await h.once(`m11-recycle-${stage}-prepare`,admin,path('entity-changes/prepare'),'POST',record.body)).data;record.id=record.receipt.id;h.save();
  const detail=await execute(record,stage);
  await h.request(admin,path(`entities/${entityType}/${entity.id}`),'GET',undefined,{expected:[404]});
  const listing=(await h.request(admin,path('recycle-bin',{type:entityType,search:entity.id,size:'20'}))).data;
  const entry=listing.items.find(e=>e.original_id===entity.id&&e.state==='deleted'&&e.mutation_id===null);assert(entry,'ACTUAL_SOURCE23_ENTRY_REQUIRED');
  record.entryId=entry.id;record.nodeCount=entry.node_count;record.nativePacketCount=detail.nativeChange.packets.length;h.save();
  assert(entry.node_count>=record.nativePacketCount);assert(record.nativePacketCount>=2);
  if(service){for(const [type,id]of [['routes',fixtures.route.id],['plugins',h.state.gate3Core.fixturePlugin.id]])await h.request(admin,path(`entities/${type}/${id}`),'GET',undefined,{expected:[404]});}
  else await proxy(stage+'-credential-rejected',401);
  h.check(true,`${name}: complete graph was archived before real approved DELETE packets; all exact nodes have native204 and verified point404`,{workflowId:record.workflowId,executionId:record.executionId,entryId:entry.id,nativePackets:record.nativePacketCount});
 }else{
  if(stage==='service-restore-after-revalidation-fix'){
   const proof=JSON.parse(readFileSync(resolve('artifacts/M11/gate3-recycle-first-restore-execution-readonly.json'),'utf8'));
   const original=g.intents['service-restore'];assert.equal(proof.readOnly,true);assert.equal(proof.rows.length,1);
   const fact=proof.rows[0];assert.equal(fact.workflow_id,original.workflowId);assert.equal(fact.state,'failed');assert.equal(fact.execution_state,'failed');
   assert.equal(fact.send_intents,0);assert.equal(fact.mutations,0);assert.equal(fact.events,1);
   const view=(await h.request(admin,path(`workflows/${original.workflowId}`))).data;
   assert.equal(view.entity.state,'failed');assert.equal(view.nativeChange.packets[0].state,'failed-known-not-sent');
   assert(h.state.requests.some(r=>r.path.split('?')[0].endsWith(`/workflows/${original.workflowId}/execute`)&&r.status===409));
  }
  const original=service?g.intents['service-delete-after-observer-fix']??g.intents['service-delete']:g.intents[`${name}-delete`];assert(original?.entryId,'ORIGINAL_ARCHIVE_REQUIRED');
  const record=g.intents[stage]??={body:{change:{kind:'recycle',action:'restore',entryId:original.entryId,confirmed:true,confirm_name:String(entity.name??entity.username)}}};h.save();
  record.receipt=(await h.once(`m11-recycle-${stage}-prepare`,admin,path('entity-changes/prepare'),'POST',record.body)).data;record.id=record.receipt.id;h.save();
  const detail=await execute(record,stage);assert.equal(detail.nativeChange.packets.length,original.nativePacketCount);
  assert.equal((await h.request(admin,path(`entities/${entityType}/${entity.id}`))).data.entity.id,entity.id);
  if(service){assert.equal((await h.request(admin,path(`entities/routes/${fixtures.route.id}`))).data.entity.id,fixtures.route.id);assert.equal((await h.request(admin,path(`entities/plugins/${h.state.gate3Core.fixturePlugin.id}`))).data.entity.id,h.state.gate3Core.fixturePlugin.id);}
  else assert.equal((await h.request(admin,path(`consumers/${fixtures.consumer.id}/credentials/key-auth`))).data.items.find(c=>c.id===fixtures.credential.id)?.id,fixtures.credential.id);
  const entry=(await h.request(admin,path('recycle-bin',{type:entityType,search:entity.id,size:'20'}))).data.items.find(e=>e.id===original.entryId);assert.equal(entry?.state,'restored');
  await proxy(stage+'-original-key',200);
  h.check(true,`${name}: new three-vote restore uses a distinct real baseline/source and restores every original native ID; actual original API Key authenticates`,{workflowId:record.workflowId,executionId:record.executionId,entryId:original.entryId,nativePackets:detail.nativeChange.packets.length});
 }
 h.state.phase=`m11-gate3-recycle-${stage}-complete`;h.save();h.report(true);console.log(JSON.stringify({passed:true,stage,wholeGate3Accepted:false,overallM11Accepted:false}));
}catch(error){h.state.phase=`m11-gate3-recycle-${stage}-stopped`;h.save();h.report(false,'M11_RECYCLE_HTTP_STOPPED');console.error(JSON.stringify({passed:false,stage,kind:error?.name==='AssertionError'?'assertion':'runtime',message:String(error?.message??'').slice(0,300)}));process.exitCode=1;}
