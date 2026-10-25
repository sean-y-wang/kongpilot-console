import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';
const h=new ReleaseHarness('M9',{resume:true});
const variant=process.argv.includes('--new-fixture')?'v2':'v1',label=name=>`recycle-${variant}-${name}`,fixtureKey=`recycleFixture_${variant}`,testTag=variant==='v1'?h.state.tag:`${h.state.tag}-${variant}`;
const planLabel=name=>label(process.argv.includes('--replan')?`${name}-after-graph-fix`:name);
try{
  const admin=h.state.sessions.admin,cid=h.state.cid,wid=h.state.wid,path=suffix=>releaseScope(cid,wid,suffix);
  const cluster=(await h.request(admin,`/clusters/${cid}`)).data;
  if(cluster.execution_mode!=='direct')await h.request(admin,`/clusters/${cid}`,'PATCH',{revision:cluster.revision,execution_mode:'direct'});
  h.state[fixtureKey]??={key:'SyntheticM9-'+randomBytes(20).toString('hex')};h.save();
  const consumer=(await h.once(label('consumer'),admin,path('entities/consumers'),'POST',{username:`${testTag}-batch-consumer`,tags:[h.state.tag]})).data.entity;
  const credential=(await h.once(label('key'),admin,path(`consumers/${consumer.id}/credentials/key-auth`),'POST',{key:h.state[fixtureKey].key,tags:[h.state.tag]})).data.entity;
  const authRoute=(await h.once(label('auth-route'),admin,path('entities/routes'),'POST',{name:`${testTag}-auth-route`,service:{id:h.state.fixtures.service.id},protocols:['http'],hosts:['pilot.example.com'],paths:[`/${testTag}-auth`],tags:[h.state.tag]})).data.entity;
  await h.once(label('auth-plugin'),admin,path('entities/plugins'),'POST',{name:'key-auth',route:{id:authRoute.id},config:{hide_credentials:true},tags:[h.state.tag]});
  const input={method:'GET',url:`http://pilot.example.com/${testTag}-auth/native`,headers:{apikey:h.state[fixtureKey].key}};
  async function probe(expected){return h.poll(async()=>(await h.request(admin,path('toolbox/probes'),'POST',{routeId:authRoute.id,input,confirmed:true,confirm_name:authRoute.name})).data,r=>r.status===expected,`ACTUAL_CREDENTIAL_PROXY_STATUS_${expected}_REQUIRED`);}
  await probe(200);h.check(true,'fresh native key-auth credential authenticates a BFF-routed proxy request');
  const job=(await h.once(planLabel('delete-plan'),admin,path('batches/plan'),'POST',{action:'delete',roots:[{type:'consumers',id:consumer.id}]})).data;
  const planId=job.planId??job.safeProgress?.planId??job.entity?.safeProgress?.planId;assert(planId);
  const plan=(await h.request(admin,path(`configuration/plans/${planId}`))).data.entity;assert(plan.deleteCount>=2,'Consumer and its original credential must be included');
  await h.once(planLabel('delete-apply'),admin,path(`configuration/plans/${plan.id}/apply`),'POST',{planRevision:plan.planRevision,planHash:plan.planHash,confirmed:true,confirm_name:plan.name,confirm_deletes:true});
  await h.request(admin,path(`entities/consumers/${consumer.id}`),'GET',undefined,{expected:[404]});await probe(401);
  h.check(true,'approved selected deletion removes the native Consumer and makes its credential unusable');
  const page=(await h.request(admin,releaseScope(cid,wid,'recycle-bin',{size:'100',search:consumer.username}))).data;
  const entry=page.items.find(e=>e.original_id===consumer.id&&!['restored','purged'].includes(e.state));assert(entry,'Actual Consumer recycle graph required');
  const restored=(await h.once(label('consumer-restore'),admin,path(`recycle-bin/${entry.id}/restore`),'POST',{confirmed:true,confirm_name:entry.root_name})).data;
  assert.equal(restored.state,'restored');
  const keys=(await h.request(admin,path(`consumers/${consumer.id}/credentials/key-auth`))).data.items;
  h.check(keys.some(k=>k.id===credential.id),'Consumer recycle restore preserves the original nested credential UUID');
  await probe(200);h.check(true,'original key-auth credential is usable after the Consumer graph is restored');
  h.state.phase='native-recycle-passed';h.save();h.report(true);console.log(JSON.stringify({passed:true,checks:h.state.checks.length,phase:h.state.phase}));
}catch(error){h.state.phase='native-recycle-stopped';h.save();h.report(false,'NATIVE_RECYCLE_ACCEPTANCE_FAILED');console.error(JSON.stringify({passed:false,message:String(error.message).slice(0,500),checks:h.state.checks.length}));process.exitCode=1;}
