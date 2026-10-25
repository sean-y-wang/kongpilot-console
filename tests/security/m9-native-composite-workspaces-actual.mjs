import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { parse, stringify } from 'yaml';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';
const h=new ReleaseHarness('M9',{resume:true});
try{
  const admin=h.state.sessions.admin,cid=h.state.cid,anchor=h.state.wid,path=suffix=>releaseScope(cid,anchor,suffix);
  const workspaces=[h.state.workspaceFixtures.target,h.state.workspaceFixtures.other],fixtures=[];
  h.state.compositeWorkspaceFixtures??={};h.save();
  for(const ws of workspaces){
    const scope=suffix=>releaseScope(cid,ws.id,suffix);h.state.compositeWorkspaceFixtures[ws.id]??={key:'SyntheticComposite-'+randomBytes(20).toString('hex')};h.save();
    const consumer=(await h.once(`composite-${ws.code}-consumer`,admin,scope('entities/consumers'),'POST',{username:`${ws.code}-composite-consumer`,tags:[h.state.tag]})).data.entity;
    const credential=(await h.once(`composite-${ws.code}-key`,admin,scope(`consumers/${consumer.id}/credentials/key-auth`),'POST',{key:h.state.compositeWorkspaceFixtures[ws.id].key,tags:[h.state.tag]})).data.entity;
    fixtures.push({ws,consumer,credential});
  }
  const workspace=(await h.request(admin,`/clusters/${cid}/workspaces/${anchor}`)).data;
  const exported=(await h.once('composite-cluster-export',admin,path('configuration/exports'),'POST',{scope:'cluster',mode:'deployment',confirmed:true,confirm_name:workspace.name})).data;
  assert.equal(exported.state,'succeeded');assert(exported.exportId&&exported.exportRevision);
  const downloaded=await h.once('composite-cluster-download',admin,path(`configuration/exports/${exported.exportId}/download`),'POST',{revision:exported.exportRevision,confirmed:true,confirm_name:exported.confirmationName},{raw:true});
  const document=parse(downloaded.bytes.toString());assert.equal(document._format_version,'1.1');assert(Array.isArray(document.consumers));
  document.consumers=document.consumers.filter(consumer=>!fixtures.some(f=>f.consumer.id===consumer.id));
  const diff=(await h.once('composite-cluster-import',admin,path('configuration/imports'),'POST',{scope:'cluster',mode:'sync',yaml:stringify(document),confirm_deletes:true})).data;
  assert.equal(diff.state,'succeeded');const plan=(await h.request(admin,path(`configuration/plans/${diff.planId}`))).data.entity;
  assert.equal(plan.deleteCount,4,'Only the two consumers and their two original keys may be removed');
  const applied=(await h.once('composite-cluster-apply',admin,path(`configuration/plans/${plan.id}/apply`),'POST',{planRevision:plan.planRevision,planHash:plan.planHash,confirmed:true,confirm_name:plan.name,confirm_deletes:true})).data;
  assert.equal(applied.state,'succeeded');
  for(const f of fixtures){
    const scoped=suffix=>releaseScope(cid,f.ws.id,suffix);
    await h.request(admin,scoped(`entities/consumers/${f.consumer.id}`),'GET',undefined,{expected:[404]});
    const page=(await h.request(admin,releaseScope(cid,f.ws.id,'recycle-bin',{size:'100',search:f.consumer.username}))).data;
    const entries=page.items.filter(e=>e.original_id===f.consumer.id&&!['restored','purged'].includes(e.state));assert.equal(entries.length,1,'One complete visible archive per workspace');assert.equal(entries[0].workspace_id,f.ws.id);
    const restored=(await h.once(`composite-${f.ws.code}-restore`,admin,scoped(`recycle-bin/${entries[0].id}/restore`),'POST',{confirmed:true,confirm_name:entries[0].root_name})).data;
    assert.equal(restored.state,'restored');const keys=(await h.request(admin,scoped(`consumers/${f.consumer.id}/credentials/key-auth`))).data.items;
    assert(keys.some(k=>k.id===f.credential.id),'Original nested credential must be restored in the correct workspace');
    h.check(true,'cluster-wide deletion preserves independent complete recovery graphs and original credential IDs',{workspaceId:f.ws.id});
  }
  h.state.phase='native-composite-workspaces-passed';h.save();h.report(true);console.log(JSON.stringify({passed:true,checks:h.state.checks.length,phase:h.state.phase}));
}catch(error){h.state.phase='native-composite-workspaces-stopped';h.save();h.report(false,'NATIVE_COMPOSITE_WORKSPACES_FAILED');console.error(JSON.stringify({passed:false,message:String(error.message).slice(0,500),checks:h.state.checks.length}));process.exitCode=1;}
