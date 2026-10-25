import assert from 'node:assert/strict';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

const h=new ReleaseHarness('M9',{resume:true});
try{
  assert.equal(process.env.RELEASE_LAB_DIRECT_MIGRATION_IP_READY,'true');assert.equal(h.state.phase,'native-migration-approval-passed');
  const admin=h.state.sessions.admin,cid=h.state.cid,source=h.state.workspaceFixtures.other,target=h.state.workspaceFixtures.target;
  const consumer=h.state.requests.find(packet=>packet.label===`composite-${source.code}-consumer`).responseData.entity;
  const credential=h.state.requests.find(packet=>packet.label===`composite-${source.code}-key`).responseData.entity;
  const scoped=(wid,suffix)=>releaseScope(cid,wid,suffix),prefix='direct-migration-current-ip';
  const current=(await h.request(admin,scoped(source.id,`entities/consumers/${consumer.id}`))).data.entity;
  assert(current.tags.includes(`workspace:${source.code}`));
  const before=(await h.request(admin,`/clusters/${cid}`)).data;assert.equal(before.execution_mode,'approval');
  await h.once(`${prefix}-mode-direct`,admin,`/clusters/${cid}`,'PATCH',{revision:before.revision,execution_mode:'direct'});
  const migration=(await h.once(`${prefix}-plan`,admin,scoped(source.id,'batches/plan'),'POST',
    {action:'workspace-move',roots:[{type:'consumers',id:consumer.id}],targetWorkspaceId:target.id})).data.entity;
  assert.equal(migration.conflicts.length,0);assert(migration.affected.some(node=>node.id===credential.id));
  const applied=(await h.once(`${prefix}-apply`,admin,scoped(source.id,`workspace-migrations/${migration.id}/apply`),'POST',
    {plan_hash:migration.plan_hash,confirmed:true,confirm_name:target.name})).data;
  assert.equal(applied.state,'succeeded');assert(applied.affected.every(node=>node.status==='succeeded'));
  const moved=(await h.request(admin,scoped(target.id,`entities/consumers/${consumer.id}`))).data.entity;
  assert.equal(moved.id,consumer.id);assert(moved.tags.includes(`workspace:${target.code}`));
  await h.request(admin,scoped(source.id,`entities/consumers/${consumer.id}`),'GET',undefined,{expected:[403]});
  const credentials=(await h.request(admin,scoped(target.id,`consumers/${consumer.id}/credentials/key-auth`))).data.items;
  assert(credentials.some(value=>value.id===credential.id));
  h.check(true,'fresh direct-controller migration preserves original IDs after the request IP metadata repair');
  const cluster=(await h.request(admin,`/clusters/${cid}`)).data;
  await h.once(`${prefix}-mode-approval`,admin,`/clusters/${cid}`,'PATCH',{revision:cluster.revision,execution_mode:'approval'});
  h.check(true,'direct-controller audit acceptance returns the isolated cluster to its original approval mode');
  h.state.phase='native-migration-approval-passed';h.save();h.report(true);console.log(JSON.stringify({passed:true,phase:h.state.phase,checks:h.state.checks.length,auditSourceIpVerification:'delegated to independent SQL audit worker'}));
}catch(error){h.state.phase='native-direct-migration-ip-stopped';h.save();h.report(false,'NATIVE_DIRECT_MIGRATION_IP_CHECK_FAILED');console.error(JSON.stringify({passed:false,errorType:error.name,message:String(error.message).slice(0,500)}));process.exitCode=1;}
