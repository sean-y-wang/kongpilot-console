import assert from 'node:assert/strict';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';
const h=new ReleaseHarness('M9',{resume:true});
try{
  const admin=h.state.sessions.admin,cid=h.state.cid,defaultWid=h.state.wid;
  async function workspace(suffix){const value=(await h.once(`workspace-${suffix}`,admin,`/clusters/${cid}/workspaces`,'POST',{code:`${h.state.tag}-${suffix}`,name:`M9 ${suffix}`,owner_user_id:admin.user.id,description:'Isolated KongPilot native validation'})).data;return value.entity??value;}
  const target=await workspace('move'),other=await workspace('other');h.state.workspaceFixtures={target,other};h.save();
  const consumer=h.state.requests.find(p=>p.label==='recycle-v2-consumer').responseData.entity;
  const credential=h.state.requests.find(p=>p.label==='recycle-v2-key').responseData.entity;
  const scoped=(wid,suffix)=>releaseScope(cid,wid,suffix);
  const migration=(await h.once('workspace-move-plan',admin,scoped(defaultWid,'batches/plan'),'POST',{action:'workspace-move',roots:[{type:'consumers',id:consumer.id}],targetWorkspaceId:target.id})).data.entity;
  assert.equal(migration.conflicts.length,0);assert(migration.affected.some(n=>n.id===credential.id),'Original nested credential must be part of the migration');
  const applied=(await h.once('workspace-move-apply',admin,scoped(defaultWid,`workspace-migrations/${migration.id}/apply`),'POST',{plan_hash:migration.plan_hash,confirmed:true,confirm_name:target.name})).data;
  assert.equal(applied.state,'succeeded');
  await h.request(admin,scoped(defaultWid,`entities/consumers/${consumer.id}`),'GET',undefined,{expected:[403]});
  const moved=(await h.request(admin,scoped(target.id,`entities/consumers/${consumer.id}`))).data.entity;
  h.check(moved.id===consumer.id&&moved.tags.includes(`workspace:${target.code}`),'batch workspace migration preserves the original Consumer ID and removes source visibility');
  const credentials=(await h.request(admin,scoped(target.id,`consumers/${consumer.id}/credentials/key-auth`))).data.items;
  h.check(credentials.some(k=>k.id===credential.id),'nested key-auth credential remains reachable under the target workspace');
  await h.request(admin,scoped(other.id,`consumers/${consumer.id}/credentials/key-auth`),'GET',undefined,{expected:[403]});
  h.check(true,'credential parent scope rejects a third-workspace IDOR');
  const route=h.state.requests.find(p=>p.label==='recycle-v2-auth-route').responseData.entity;
  const input={method:'GET',url:`http://pilot.example.com/${h.state.tag}-v2-auth/native`,headers:{apikey:h.state.recycleFixture_v2.key}};
  await h.poll(async()=>(await h.request(admin,scoped(defaultWid,'toolbox/probes'),'POST',{routeId:route.id,input,confirmed:true,confirm_name:route.name})).data,r=>r.status===200,'MIGRATED_CREDENTIAL_MUST_REMAIN_USABLE');
  h.check(true,'workspace tagging does not rotate or invalidate the actual API Key');
  h.state.phase='native-workspaces-passed';h.save();h.report(true);console.log(JSON.stringify({passed:true,checks:h.state.checks.length,phase:h.state.phase}));
}catch(error){h.state.phase='native-workspaces-stopped';h.save();h.report(false,'NATIVE_WORKSPACES_ACCEPTANCE_FAILED');console.error(JSON.stringify({passed:false,message:String(error.message).slice(0,500),checks:h.state.checks.length}));process.exitCode=1;}
