import assert from 'node:assert/strict';
import { ReleaseHarness, releasePassword, releaseScope } from './lib/release-harness.mjs';

const h=new ReleaseHarness('M9',{resume:true});
try{
  assert(h.state.phase==='native-core-passed'||h.state.extendedStarted,'Native core handoff required');h.state.extendedStarted=true;h.save();
  const admin=h.state.sessions.admin,cid=h.state.cid,wid=h.state.wid,path=suffix=>releaseScope(cid,wid,suffix);
  const {service,route,plugin}=h.state.fixtures;
  const roles=(await h.request(admin,'/iam/roles?size=100')).data.items;
  async function account(label,roleCode){
    h.state.accounts??={};let a=h.state.accounts[label];
    if(!a){a={username:`${h.state.tag}-${label}`,initialPassword:releasePassword(),password:releasePassword()};h.state.accounts[label]=a;h.save();}
    const created=(await h.once(`${label}-create`,admin,'/iam/users','POST',{username:a.username,password:a.initialPassword,display_name:`M9 ${label}`,email:`${a.username}@example.invalid`})).data,user=created.entity??created;
    if(!h.state.sessions[label]){
      const initial=h.state.sessions[`${label}-initial`]??await h.login(`${label}-initial`,a.username,a.initialPassword);
      await h.once(`${label}-password`,initial,'/auth/me/password','POST',{revision:initial.user.revision,current_password:a.initialPassword,new_password:a.password,confirmed:true});
      await h.login(label,a.username,a.password);
    }
    const role=roles.find(role=>role.code===roleCode&&!role.cluster_id&&!role.workspace_id);assert(role);
    await h.once(`${label}-grant`,admin,`/iam/users/${user.id}/role-bindings`,'POST',{role_id:role.id,cluster_id:null,workspace_id:null});
    return h.state.sessions[label];
  }
  const approver=await account('approver','super-admin'),reader=await account('reader','read-only');
  const draft=h.state.requests.find(packet=>packet.label==='draft').responseData.entity;
  await h.request(approver,path(`drafts/${draft.id}`),'GET',undefined,{expected:[404]});
  await h.request(reader,path('toolbox/cache/invalidate'),'POST',{key:`${h.state.tag}.reader`,confirmed:true,confirm_name:`${h.state.tag}.reader`},{expected:[403]});
  await h.request(reader,path('batches/plan'),'POST',{action:'plugin-enabled',roots:[{type:'plugins',id:plugin.id}],enabled:false},{expected:[403]});
  h.check(true,'another super-admin cannot read personal draft; read-only cannot invalidate cache or plan native batches');
  async function batch(label,body){
    const result=(await h.once(`${label}-plan`,admin,path('batches/plan'),'POST',body)).data;
    const planId=result.planId??result.entity?.safeProgress?.planId??result.safeProgress?.planId??result.job?.safeProgress?.planId;
    assert(planId,`Expected actual immutable batch plan; returned ${Object.keys(result).join(',')}`);
    const p=(await h.request(admin,path(`configuration/plans/${planId}`))).data.entity;
    const execution=(await h.once(`${label}-apply`,admin,path(`configuration/plans/${planId}/apply`),'POST',{planRevision:p.planRevision,planHash:p.planHash,confirmed:true,confirm_name:p.name,...(p.deleteCount?{confirm_deletes:true}:{})})).data;
    assert(['succeeded','pending-approval'].includes(execution.state??execution.entity?.state??execution.job?.state),`Expected actual batch execution; returned ${Object.keys(execution).join(',')}`);
    return{plan:p,execution};
  }
  await batch('tags',{action:'tags',roots:[{type:'services',id:service.id}],tags:['team:m9-verification']});
  const tagged=(await h.request(admin,path(`entities/services/${service.id}`))).data.entity;
  h.check(tagged.tags.includes('team:m9-verification')&&tagged.tags.includes('workspace:default'),'batch tagging updates the selected native object and preserves workspace membership');
  await batch('disable-plugin',{action:'plugin-enabled',roots:[{type:'plugins',id:plugin.id}],enabled:false});
  const disabled=(await h.request(admin,path(`entities/plugins/${plugin.id}`))).data.entity;
  h.check(disabled.enabled===false,'native bulk plugin disable preserves boolean false');
  await batch('enable-plugin',{action:'plugin-enabled',roots:[{type:'plugins',id:plugin.id}],enabled:true});
  h.check((await h.request(admin,path(`entities/plugins/${plugin.id}`))).data.entity.enabled===true,'native bulk plugin enable completes through the existing configuration executor');
  const cluster=(await h.request(admin,`/clusters/${cid}`)).data;
  if(cluster.execution_mode!=='approval')await h.request(admin,`/clusters/${cid}`,'PATCH',{revision:cluster.revision,execution_mode:'approval'});
  const key=`kongpilot.${h.state.tag}.approval`;
  const pending=(await h.once('approval-cache',admin,path('toolbox/cache/invalidate'),'POST',{key,confirmed:true,confirm_name:key})).data;
  h.check(pending.state==='pending-approval'&&!pending.remoteStarted&&pending.workflowId,'approval-mode cache invalidation creates a real workflow without sending a native DELETE');
  let workflow=(await h.request(admin,path(`workflows/${pending.workflowId}`))).data.entity;
  await h.request(admin,path(`workflows/${workflow.id}/execute`),'POST',{revision:workflow.revision,planHash:workflow.plan_hash??workflow.planHash,confirmed:true,confirm_name:workflow.kind},{expected:[409]});
  await h.request(admin,path(`workflows/${workflow.id}/approve`),'POST',{revision:workflow.revision,planHash:workflow.plan_hash??workflow.planHash,confirmed:true,confirm_name:workflow.kind},{expected:[403]});
  await h.once('approval-cache-approve',approver,path(`workflows/${workflow.id}/approve`),'POST',{revision:workflow.revision,planHash:workflow.plan_hash??workflow.planHash,confirmed:true,confirm_name:workflow.kind});
  workflow=(await h.request(admin,path(`workflows/${pending.workflowId}`))).data.entity;
  await h.once('approval-cache-execute',admin,path(`workflows/${workflow.id}/execute`),'POST',{revision:workflow.revision,planHash:workflow.plan_hash??workflow.planHash,confirmed:true,confirm_name:workflow.kind});
  const completed=(await h.request(admin,path(`toolbox/operations/${pending.id}`))).data;
  h.check(completed.state==='succeeded'&&completed.remoteStarted&&completed.remoteCompleted,'independent approval and requester execution complete the exact native cache operation');
  h.state.phase='native-extended-passed';h.save();h.report(true);console.log(JSON.stringify({passed:true,checks:h.state.checks.length,phase:h.state.phase}));
}catch(error){h.state.phase='native-extended-stopped';h.save();h.report(false,'NATIVE_EXTENDED_ACCEPTANCE_FAILED');console.error(JSON.stringify({passed:false,message:String(error.message).slice(0,500),checks:h.state.checks.length}));process.exitCode=1;}
