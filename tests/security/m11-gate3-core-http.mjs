import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {ReleaseHarness,releaseScope} from './lib/release-harness.mjs';
assert.equal(process.env.RELEASE_LAB_M11_GATE3_CORE_READY,'true');
const h=new ReleaseHarness('M11',{resume:true});h.reportPath=resolve('artifacts/M11/gate3-core-http-verification.json');
const cid=h.state.cid,wid=h.state.wid,admin=h.state.sessions.admin,g=h.state.gate3Core??={intents:{}};
const path=suffix=>releaseScope(cid,wid,suffix);
async function approve(record,label,user){
  record.submitBody??={revision:record.receipt.revision,materialHmac:record.receipt.materialHmac,confirmed:true,confirm_name:'native-change'};h.save();
  const result=(await h.once(`m11-g3-${label}-submit`,user,path(`entity-changes/${record.id}/submit`),'POST',record.submitBody)).data;
  record.workflowId=result.workflowId;h.save();
  for(const [index,reviewer]of ['a','b','c'].entries()){
    const view=(await h.request(user,path(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(view.state,'pending');const active=view.approval.stages.find(stage=>stage.state==='active');assert(active);
    record.approveBodies??={};record.approveBodies[reviewer]??={revision:view.revision,planHash:view.planHash,confirmed:true,confirm_name:'native-change',execute:false,
      level:active.level,stageRevision:active.revision,candidateVersion:view.approval.candidateVersion};h.save();
    await h.once(`m11-g3-${label}-approve-${reviewer}`,h.state.sessions[reviewer],path(`workflows/${record.workflowId}/approve`),'POST',record.approveBodies[reviewer]);
    const after=(await h.request(user,path(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(after.state,index===2?'approved':'pending');
  }
  const approved=(await h.request(user,path(`workflows/${record.workflowId}`))).data.entity;
  assert.equal(approved.state,'approved');assert.equal(approved.capabilities.execute,true);return approved;
}
async function execute(record,label,user,view){
  record.executeBody??={revision:view.revision,planHash:view.planHash,confirmed:true,confirm_name:'native-change'};h.save();
  const result=(await h.once(`m11-g3-${label}-execute`,user,path(`workflows/${record.workflowId}/execute`),'POST',record.executeBody)).data;
  record.executionId=result.executionId;record.executionReceipt=result;h.save();assert.equal(result.state,'succeeded');assert(result.baselineId);
  const detail=(await h.request(user,path(`workflows/${record.workflowId}`))).data;
  assert.equal(detail.entity.state,'succeeded');assert.equal(detail.nativeChange.packets.length,1);
  assert.equal(detail.nativeChange.packets[0].state,'succeeded');assert(detail.nativeChange.packets[0].nativeStatus>=200&&detail.nativeChange.packets[0].nativeStatus<=299);
  assert.equal(detail.nativeChange.baseline.nativeAuthority,false);assert.equal(detail.nativeChange.baseline.baseline.baselineId,result.baselineId);
  return result;
}
async function probe(label,key,expected){
  const route=h.state.gate2.fixtures.route;
  const body={routeId:route.id,input:{method:'GET',url:`http://${route.hosts[0]}${route.paths[0]}/credential/live`,headers:{apikey:key}},confirmed:true,confirm_name:route.name};
  for(let n=0;n<60;n++){
    const result=(await h.once(`m11-g3-${label}-proxy-${n}`,admin,path('toolbox/probes'),'POST',body)).data;
    if(result.status===expected)return result;
    assert([200,401,403,404,502,503,504].includes(result.status));await new Promise(resolve=>setTimeout(resolve,200));
  }throw Error('ACTUAL_PROXY_PROPAGATION_TIMEOUT');
}
try{
  const stage=process.argv[2]??'setup';h.save();
  if(stage==='setup'){
    const cluster=(await h.request(admin,`/clusters/${cid}`)).data;assert.equal(cluster.execution_mode,'direct');
    const defs=(await h.request(admin,path('workflow-definitions'))).data.items,definition=defs.find(d=>d.kind==='native-change');assert(definition);
    g.policyBody??={revision:definition.revision,confirmed:true,confirm_name:definition.name,policy:{version:2,kind:'native-change',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,
      stages:[{level:1,name:'独立初审',mode:'any',threshold:1,selector:{users:[h.state.sessions.a.user.id]}},
        {level:2,name:'双人会签',mode:'all',threshold:null,selector:{users:[h.state.sessions.b.user.id,h.state.sessions.c.user.id]}}]}};h.save();
    await h.once('m11-g3-native-v2-policy',admin,path(`workflow-definitions/${definition.id}/versions`),'POST',g.policyBody);
    const current=(await h.request(admin,path('workflow-definitions'))).data.items.find(d=>d.id===definition.id);assert.equal(current.format,2);assert.equal(current.policy.stages.length,2);
    g.fixturePlugin=(await h.once('m11-g3-keyauth-fixture-plugin',admin,path('entities/plugins'),'POST',{name:'key-auth',service:{id:h.state.gate2.fixtures.service.id},
      config:{key_names:['apikey'],hide_credentials:true},tags:['team:m11-acceptance','owner:m11-acceptance']})).data.entity;h.save();
    await probe('fixture-original-key',h.state.gate2.fixtures.key,200);
    const mode=(await h.request(admin,`/clusters/${cid}`)).data;g.modeBody??={revision:mode.revision,execution_mode:'approval'};h.save();
    await h.once('m11-g3-enable-approval',admin,`/clusters/${cid}`,'PATCH',g.modeBody);
    h.check(true,'real native-change V2 policy requires one independent vote and two-person countersign; actual proxy accepts the isolated original credential');
  }else if(['service-update','service-update-after-no-send-closed','service-update-after-alias-fix','service-update-after-append-only-fix'].includes(stage)){
    const user=h.state.sessions['tag-writer'],service=h.state.gate2.fixtures.service;
    const before=(await h.request(user,path(`entities/services/${service.id}`))).data.entity;
    g.originalReadTimeout??=before.read_timeout;h.save();
    if(stage!=='service-update'){
      const original=g.intents.serviceUpdate,closed=(await h.request(user,path(`workflows/${original.workflowId}`))).data;
      assert.equal(closed.entity.state,'failed');assert.equal(closed.nativeChange.packets.length,0);
      assert(h.state.requests.some(p=>p.path.split('?')[0].endsWith(`/workflows/${original.workflowId}/execute`)&&p.status===500&&p.resolution?.knownNoNativeSend===true));
    }
    if(stage==='service-update-after-append-only-fix'){
      const previous=g.intents.serviceUpdateAfterAliasFix,closed=(await h.request(user,path(`workflows/${previous.workflowId}`))).data;
      assert.equal(closed.entity.state,'failed');assert.equal(closed.nativeChange.packets.length,1);assert.equal(closed.nativeChange.packets[0].state,'rejected-before-send');
    }
    const slot=stage==='service-update'?'serviceUpdate':stage==='service-update-after-append-only-fix'?'serviceUpdateAfterAppendOnlyFix':stage==='service-update-after-alias-fix'?'serviceUpdateAfterAliasFix':'serviceUpdateAfterNoSendClosed',label=stage;
    const record=g.intents[slot]??={body:{change:{kind:'entity',action:'update',entityType:'services',entityId:service.id,body:{read_timeout:3210}}}};h.save();
    const prepared=(await h.once(`m11-g3-${label}-prepare`,user,path('entity-changes/prepare'),'POST',record.body)).data;record.id=prepared.id;record.receipt=prepared;h.save();
    assert.equal((await h.request(user,path(`entities/services/${service.id}`))).data.entity.read_timeout,before.read_timeout);
    const view=await approve(record,label,user);await execute(record,label,user,view);
    assert.equal((await h.request(user,path(`entities/services/${service.id}`))).data.entity.read_timeout,3210);
    h.check(true,'tag-scoped real Service change executes only after all three actual V2 votes, with a complete recovery baseline and genuine native 2xx receipt',{workflowId:record.workflowId,executionId:record.executionId});
  }else if(stage==='credential-update'){
    const user=h.state.sessions['credential-writer'],f=h.state.gate2.fixtures;
    g.newKey??=randomBytes(24).toString('hex');h.save();
    const record=g.intents.credentialUpdate??={body:{change:{kind:'credential',action:'update',consumerId:f.consumer.id,credentialKind:'key-auth',credentialId:f.credential.id,body:{key:g.newKey}}}};h.save();
    const prepared=(await h.once('m11-g3-credential-update-prepare',user,path('entity-changes/prepare'),'POST',record.body)).data;record.id=prepared.id;record.receipt=prepared;h.save();
    await probe('key-before-approval',f.key,200);const view=await approve(record,'credential-update',user);await execute(record,'credential-update',user,view);
    await probe('rotated-key',g.newKey,200);await probe('old-key-rejected',f.key,401);
    await h.request(user,path(`entities/consumers/${f.consumer.id}`),'GET',undefined,{expected:[403]});
    h.check(true,'credential-ID-only user rotates the real API Key after independent V2 approval; new key authenticates and old key is rejected without public Consumer access',{workflowId:record.workflowId,executionId:record.executionId});
  }else if(stage==='rollback-updates'){
    for(const [label,original,user]of [['service',g.intents.serviceUpdateAfterAppendOnlyFix??g.intents.serviceUpdateAfterAliasFix??g.intents.serviceUpdateAfterNoSendClosed??g.intents.serviceUpdate,h.state.sessions['tag-writer']],['credential',g.intents.credentialUpdate,h.state.sessions['credential-writer']]]){
      const view=(await h.request(user,path(`workflows/${original.workflowId}`))).data.entity;
      original.rollbackBody??={revision:view.revision,planHash:view.planHash,executionId:original.executionId,confirmed:true,confirm_name:'native-change'};h.save();
      const planned=(await h.once(`m11-g3-${label}-rollback-prepare`,user,path(`workflows/${original.workflowId}/rollback-prepare`),'POST',original.rollbackBody)).data;
      assert(planned.submissionRequired);assert.notEqual(planned.intent.id,original.id);
      const record=g.intents[`${label}Rollback`]??={id:planned.intent.id,receipt:planned.intent,linkId:planned.linkId};h.save();
      const approved=await approve(record,`${label}-rollback`,user);await execute(record,`${label}-rollback`,user,approved);
      h.check(true,`${label}: rollback produces a distinct current-before intent and immutable baseline link, then repeats the real three-vote approval and obtains its own execution baseline`,{originalWorkflowId:original.workflowId,workflowId:record.workflowId,linkId:record.linkId});
    }
    assert.equal((await h.request(admin,path(`entities/services/${h.state.gate2.fixtures.service.id}`))).data.entity.read_timeout,g.originalReadTimeout);
    await probe('rollback-original-key',h.state.gate2.fixtures.key,200);await probe('rollback-rotated-key-rejected',g.newKey,401);
    h.check(true,'real Service configuration and original API Key are restored; the rotated key is rejected by the actual proxy');
  }else throw Error('UNKNOWN_GATE3_STAGE');
  h.state.phase=`m11-gate3-core-${stage}-complete`;h.save();h.report(true);console.log(JSON.stringify({passed:true,phase:h.state.phase,checks:h.state.checks.length,overallM11Accepted:false}));
}catch(error){h.state.phase='m11-gate3-core-stopped';h.save();h.report(false,'M11_GATE3_CORE_HTTP_STOPPED');console.error(JSON.stringify({passed:false,message:String(error.message).slice(0,450)}));process.exitCode=1;}
