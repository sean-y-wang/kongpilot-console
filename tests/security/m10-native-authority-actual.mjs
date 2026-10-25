import assert from 'node:assert/strict';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ReleaseHarness,releasePassword,releaseScope} from './lib/release-harness.mjs';
import {AUTHORITY_PHASES,authorityPhase,authorityLedger,authorityPermissions,assertAuthorityBinding,assertAuthorityBlockedTimer,assertAuthorityInitialLogin} from './lib/m10-native-authority-helper.mjs';
import {buildM10TimerScheduleFixture} from './lib/m10-native-timer-worker.mjs';
import {observeOptinConsole,optinDistFingerprint} from './lib/m10-native-optin-observer.mjs';
import {observeAuthorityTimerConsole} from './lib/m10-native-authority-observer.mjs';

// Root-only isolated lab operator. IAM changes are separate audited direct
// operations, not approval workflows. No old plan/occurrence is rewritten or
// applied after restoration. Unknown outcomes keep their original intent key.
const phase=authorityPhase(process.argv.slice(2)),h=new ReleaseHarness('M10',{resume:true}),ledger=authorityLedger(h),s=ledger.state;
let attemptPath;
try{
 assert.equal(process.env.RELEASE_LAB_M10_DEPLOYED,'true');assert.equal(process.env.RELEASE_LAB_M10_AUTHORITY_READY,'true');
 assert.equal(h.state.phase,'native-m10-core-passed','ACTUAL_M10_CORE_HANDOFF_REQUIRED');
 const runtime=JSON.parse(readFileSync('artifacts/M10/runtime-deployment.json','utf8'));
 for(const field of ['apiBuildExit','copyExit','apiRestartExit'])assert.equal(runtime[field],0);assert.equal(runtime.readinessStatus,200);
 assert.equal(process.env.RELEASE_LAB_M10_RUNTIME_SOURCE_SHA,runtime.apiSourceSha256,'ROOT_MUST_BIND_CURRENT_DEPLOYED_CANDIDATE');
 const runtimeDistSha256=optinDistFingerprint('/dev/shm/kongos-production-ram-m08-20261012-a3/public/output/kongpilot-release-lab/context/apps/console-api/dist');
 const migrations=Object.fromEntries(runtime.migrations.filter(r=>['017_m10_governance.sql','018_m10_configuration_origins.sql'].includes(r.name)).map(r=>[r.name,r.checksum]));assert.equal(Object.keys(migrations).length,2);
 const cid=h.state.cid,wid=h.state.wid,targetCid=h.state.targetCid,targetWid=h.state.targetWid,admin=h.state.sessions.admin;
 assert.equal(cid,'e269f167-53e9-4895-af89-5b1b8835c6ec');assert.equal(wid,'833340e1-61b8-4bf1-9b0a-52e90b369b29');
 assert.equal(targetCid,'095b11dd-a414-4f76-b591-9fdfa4a29d83');assert.equal(targetWid,'c0e1eb07-602b-421a-9929-a28c6d971ba7');assert(admin?.user?.id);
 const index=AUTHORITY_PHASES.indexOf(phase);if(index)assert.equal(s.phases[AUTHORITY_PHASES[index-1]]?.passed,true,'PREVIOUS_ACTUAL_AUTHORITY_PHASE_REQUIRED');
 const p=s.phases[phase]??={attempts:[]};assert.notEqual(p.passed,true,'COMPLETED_AUTHORITY_PHASE_MUST_NOT_BE_REEXECUTED');
 mkdirSync(resolve('artifacts/M10'),{recursive:true});attemptPath=resolve(`artifacts/M10/native-authority-${phase}-attempt-${p.attempts.length+1}.json`);assert(!existsSync(attemptPath));
 p.attempts.push({startedAt:new Date().toISOString(),reportPath:attemptPath});p.state='running';h.save();h.assertWritable();
 const src=(suffix,extra={})=>releaseScope(cid,wid,suffix,extra),dst=(suffix,extra={})=>releaseScope(targetCid,targetWid,suffix,extra);
 const read=async(session,path,expected=[200])=>(await h.request(session,path,'GET',undefined,{expected}));
 const entity=response=>response.data.entity??response.data;
 const publicReport=(passed,errorCode)=>({passed,milestone:'M10',phase,productionDeployment:false,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:targetCid,targetWorkspaceId:targetWid,
  ownerId:s.ownerId??null,sourceBindingId:s.sourceBinding?.id??null,targetBindingId:s.targetBinding?.id??null,sourceServiceId:s.sourceService?.id??null,targetServiceId:s.targetService?.id??null,
  planId:s.planId??null,promotionId:s.promotionId??null,timerId:s.timer?.id??null,timerVersion:s.timer?.currentVersion??null,checks:s.checks,
  runtimeSourceSha256:runtime.apiSourceSha256,sqlMutationRequested:false,kongDatabaseAccess:false,futureClockUsed:false,fakeSidUsed:false,approvalWorkflowClaim:false,
  ...((s.zeroNative&&phase==='verify')?{actualZeroNative:s.zeroNative}:{}),...((s.timerProof&&['timer-observe','restore'].includes(phase))?{actualTimer:s.timerProof}:{}),...(errorCode?{errorCode}:{})});
 s.reportBuilderFacts={runtimeSourceSha256:runtime.apiSourceSha256};h.save();
 for(const cluster of [cid,targetCid])assert.equal(entity(await read(admin,`/clusters/${cluster}`)).execution_mode,'direct','ACTUAL_IAM_DIRECT_MODE_REQUIRED');
 if(phase==='bootstrap'){
  s.account??={username:`${h.state.tag}-authority`,initialPassword:releasePassword(),password:releasePassword()};h.save();
  const user=entity(await ledger.once('m10-authority-user-create',admin,'/iam/users','POST',{username:s.account.username,password:s.account.initialPassword,display_name:'M10 authority verification owner',email:`${s.account.username}@example.invalid`}));
  assert.equal(user.super_admin,false);assert.equal(user.auth_source,'local');s.ownerId=user.id;h.save();
  for(const [side,clusterId,workspaceId]of [['source',cid,wid],['target',targetCid,targetWid]]){
   const role=entity(await ledger.once(`m10-authority-${side}-role-create`,admin,'/iam/roles','POST',{code:`${h.state.tag}-authority-${side}`,name:`${h.state.tag} authority ${side}`,description:'Isolated M10 source authority acceptance',cluster_id:clusterId,workspace_id:workspaceId}));
   await ledger.once(`m10-authority-${side}-permissions`,admin,`/iam/roles/${role.id}/permissions`,'PUT',ledger.freeze(`${side}-permissions`,()=>({revision:role.revision,permissions:authorityPermissions(clusterId,workspaceId)})));
   s[`${side}Role`]=role;
   const binding=entity(await ledger.once(`m10-authority-${side}-binding-create`,admin,`/iam/users/${user.id}/role-bindings`,'POST',{role_id:role.id,cluster_id:clusterId,workspace_id:workspaceId}));
   assertAuthorityBinding(binding,{userId:user.id,roleId:role.id,roleName:role.name,clusterId,workspaceId,status:'active'});s[`${side}Binding`]=binding;h.save();
  }
  async function login(label,password){
   const result=await ledger.once(label,null,'/auth/login','POST',{username:s.account.username,password},[201]),jar=new Map();
   for(const raw of result.packet.responseCookies??[]){const pair=raw.split(';')[0],at=pair.indexOf('=');jar.set(pair.slice(0,at),pair.slice(at+1));}
   const cookie=[...jar].map(([key,value])=>`${key}=${value}`).join('; '),access=jar.get('kongos_access');assert(access);
   const claims=JSON.parse(Buffer.from(access.split('.')[1],'base64url'));assert.equal(claims.sub,s.ownerId);
   return{user:result.data.user,csrf:result.data.csrfToken,cookie,username:s.account.username,password,sid:claims.sid};
  }
  const initial=h.state.sessions['authority-initial']??await login('m10-authority-login-initial',s.account.initialPassword);h.state.sessions['authority-initial']=initial;h.save();
  s.initialForcePasswordChange=assertAuthorityInitialLogin(initial.user,s.ownerId);h.save();
  const changed=(await ledger.once('m10-authority-password-change',initial,'/auth/me/password','POST',ledger.freeze('password-change',()=>({revision:initial.user.revision,current_password:s.account.initialPassword,new_password:s.account.password,confirmed:true})))).data;
  assert.equal(changed.id,s.ownerId);assert.equal(changed.sessionsRevoked,true);assert.equal(changed.forcePasswordChange,false);
  const owner=h.state.sessions['authority-owner']??await login('m10-authority-login-current',s.account.password);h.state.sessions['authority-owner']=owner;h.save();
  const current=(await read(owner,'/auth/me')).data.user;assert.equal(current.id,user.id);assert.equal(current.superAdmin,false);assert.equal(current.forcePasswordChange,false);
  assert.notEqual(owner.sid,initial.sid,'ACTUAL_NEW_POST_PASSWORD_CHANGE_SESSION_REQUIRED');
  ledger.check(true,'Dedicated actual non-super owner uses two disjoint workspace role bindings, a real password change with old-session revocation and a separate post-password-change login',{ownerId:user.id,initialForcePasswordChange:s.initialForcePasswordChange});
 }else{
  const owner=h.state.sessions['authority-owner'];assert(owner?.user?.id===s.ownerId&&owner.sid);const me=(await read(owner,'/auth/me')).data.user;assert.equal(me.superAdmin,false);
  const binding=async(side,status)=>{
   const clusterId=side==='source'?cid:targetCid,workspaceId=side==='source'?wid:targetWid,role=s[`${side}Role`],original=s[`${side}Binding`];
   const page=(await read(admin,`/iam/users/${s.ownerId}/role-bindings?${new URLSearchParams({clusterId,workspaceId,status,size:'100'})}`)).data;
   assert(Array.isArray(page.items)&&page.nextCursor===null&&page.total===null);const found=page.items.filter(row=>row.id===original.id);assert.equal(found.length,1);
   return assertAuthorityBinding(found[0],{userId:s.ownerId,roleId:role.id,roleName:role.name,clusterId,workspaceId,status});
  };
  if(phase==='prepare'){
   for(const [side,path]of [['source',src],['target',dst]]){
    const service=entity(await ledger.once(`m10-authority-${side}-service-create`,admin,path('entities/services'),'POST',{
     name:`${h.state.tag}-authority-service`,protocol:'http',host:'echo',port:8080,connect_timeout:side==='source'?5000:7000,write_timeout:5000,read_timeout:5000,retries:1,
     tags:['owner:pilot-authority-verification','purpose:m10-authority-verification']}));s[`${side}Service`]=service;h.save();
    assert.equal(entity(await read(owner,path(`entities/services/${service.id}`))).id,service.id);
   }
   const comparison=entity(await ledger.once('m10-authority-comparison',owner,src('governance/comparisons'),'POST',{
    scope:'services',serviceIds:[s.sourceService.id],target:{clusterId:targetCid,workspaceId:targetWid,scope:'services',serviceIds:[s.targetService.id]},threshold:0,includeEnvironmentFields:true}));
   const cmp=(await read(owner,src(`governance/comparisons/${comparison.id}`))).data;assert.equal(cmp.entity.quality,'complete');
   const roots=(await read(owner,src(`governance/comparisons/${comparison.id}/source-objects`,{entityType:'services',size:'100'}))).data;
   assert(Array.isArray(roots.items)&&roots.nextCursor===null);const root=roots.items.find(row=>row.nativeId===s.sourceService.id);assert(root?.objectKey);
   const promoted=(await ledger.once('m10-authority-promote-plan',owner,src(`governance/comparisons/${comparison.id}/promote-plan`),'POST',{
    selectedObjectKeys:[root.objectKey],includeEnvironmentFields:true,includeSecrets:false,includeCredentials:false,confirmed:true,confirm_name:cmp.entity.confirmationName})).data;
   assert(promoted.planId&&promoted.jobId);s.planId=promoted.planId;s.sourceJobId=promoted.jobId;
   const receipt=(await read(owner,src(`governance/operations/by-key/${ledger.packet('m10-authority-promote-plan').key}`))).data;assert.equal(receipt.state,'ready');assert.equal(receipt.actorId,s.ownerId);s.promotionId=receipt.id;
   const plan=(await read(owner,dst(`configuration/plans/${s.planId}`,{size:'100'}))).data;assert.equal(plan.entity.deleteCount,0);assert(plan.entity.stepCount>0,'ACTUAL_NONEMPTY_AUTHORITY_PLAN_REQUIRED');assert.equal(plan.entity.capabilities.apply,true,'TARGET_NATIVE_PLAN_WRITE_ELIGIBILITY_REQUIRED');
   assert(Array.isArray(plan.items)&&plan.items.some(step=>step.entityType==='services'&&step.action==='update'),'ACTUAL_ISOLATED_SERVICE_UPDATE_PLAN_REQUIRED');
   s.plan=ledger.freeze('observed-original-plan',()=>plan);s.applyBody=ledger.freeze('original-apply-body',()=>({planRevision:plan.entity.planRevision,planHash:plan.entity.planHash,confirmed:true,confirm_name:plan.entity.name}));h.save();
   const created=(await ledger.once('m10-authority-timer-register',owner,src('governance/schedules'),'POST',{
    name:`${h.state.tag} authority timer`,kind:'inspection',scope:'services',serviceIds:[s.sourceService.id],intervalMinutes:5,timezone:'Asia/Shanghai',paused:false})).data;
   const id=created.resourceId??created.entity?.id;assert(id);const observed=await read(owner,src(`governance/schedules/${id}`));
   s.timer=buildM10TimerScheduleFixture(observed,{observedAt:new Date().toISOString(),actorId:s.ownerId,id,kind:'inspection'});h.save();
   ledger.check(true,'Fresh current private-origin Promote plan has a real isolated Service update; an independent 5-minute schedule is registered by the actual owner',{planId:s.planId,timerId:id,dueAt:s.timer.nextRunAt});
  }else if(phase==='revoke'){
   assert(Date.now()<Date.parse(s.timer.nextRunAt)-30000,'SOURCE_REVOKE_MUST_PRECEDE_NATURAL_TIMER_DUE');
   const current=await binding('source','active');assert.equal((await binding('target','active')).revision,s.targetBinding.revision);
   const result=entity(await ledger.once('m10-authority-source-binding-revoke',admin,`/iam/users/${s.ownerId}/role-bindings/${current.id}`,'DELETE',
    ledger.freeze('revoke-body',()=>({revision:current.revision,confirmed:true,confirm_name:current.role_name}))));
   assertAuthorityBinding(result,{userId:s.ownerId,roleId:s.sourceRole.id,roleName:s.sourceRole.name,clusterId:cid,workspaceId:wid,status:'revoked',previousRevision:current.revision});s.revokedBinding=result;
   s.revokedAt=ledger.packet('m10-authority-source-binding-revoke').startedAt;h.save();ledger.check(true,'Only the source binding was revoked by an independent audited administrator IAM operation; target binding remains active');
  }else if(phase==='verify'){
   await binding('source','revoked');const target=await binding('target','active');assert.equal(target.revision,s.targetBinding.revision);
   await read(owner,src(`entities/services/${s.sourceService.id}`),[403]);assert.equal(entity(await read(owner,dst(`entities/services/${s.targetService.id}`))).id,s.targetService.id);
   await read(owner,dst(`configuration/plans/${s.planId}`),[403]);
   const denied=await ledger.once('m10-authority-original-plan-apply-denied',owner,dst(`configuration/plans/${s.planId}/apply`),'POST',s.applyBody,[403]);assert.equal(denied.packet.errorCode,'GOVERNANCE_PROMOTE_SCOPE_DENIED');
   s.zeroNative=observeOptinConsole({mode:'no-native',actorId:s.ownerId,clusterId:targetCid,workspaceId:targetWid,key:denied.packet.key,requestId:denied.requestId,
    runtimeSourceSha256:runtime.apiSourceSha256,runtimeDistSha256,migrations});h.save();
   const safePromotion=(await read(owner,src(`governance/operations/by-key/${ledger.packet('m10-authority-promote-plan').key}`))).data;
   assert.equal(safePromotion.id,s.promotionId);assert.equal(safePromotion.planId,s.planId);assert.equal(safePromotion.state,'ready');assert.equal(safePromotion.nativeExecutionRequested,false);
   const safeJob=(await read(owner,dst(`configuration/jobs/${s.sourceJobId}`))).data.entity;assert.equal(safeJob.id,s.sourceJobId);assert.equal(safeJob.state,'succeeded');
   ledger.check(true,'Source revocation blocks old plan read/apply before target job or native mutation, while target access and original safe promotion/job receipts remain readable',{requestId:denied.requestId,originalPlanId:s.planId});
  }else if(phase==='timer-observe'){
   const deadline=Date.parse(s.timer.nextRunAt)+180000;assert(deadline>Date.now()&&deadline-Date.now()<=600000,'ORIGINAL_NATURAL_TIMER_OBSERVATION_WINDOW_REQUIRED');
   let blocked;
   while(Date.now()<deadline){const response=await read(admin,src(`governance/schedules/${s.timer.id}`));s.timerObservations??=[];s.timerObservations.push({observedAt:new Date().toISOString(),requestId:response.requestId,entity:response.data.entity});h.save();
    if(Date.now()>=Date.parse(s.timer.nextRunAt)&&response.data.entity.executionBlocked){blocked=assertAuthorityBlockedTimer(response.data.entity,s.timer);break;}
    process.stdout.write(JSON.stringify({event:'m10.authority.await-natural-due',secondsUntilDue:Math.max(0,Math.ceil((Date.parse(s.timer.nextRunAt)-Date.now())/1000))})+'\n');await new Promise(resolve=>setTimeout(resolve,10000));
   }assert(blocked,'ACTUAL_NATURAL_AUTHORITY_TIMER_BLOCK_NOT_OBSERVED');s.blockedTimer=blocked;
   s.timerProof=observeAuthorityTimerConsole({mode:'revoked',actorId:s.ownerId,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:targetCid,targetWorkspaceId:targetWid,
    sourceBindingId:s.sourceBinding.id,targetBindingId:s.targetBinding.id,sourceRoleId:s.sourceRole.id,targetRoleId:s.targetRole.id,timer:s.timer,blockedTimer:blocked,
    runtimeSourceSha256:runtime.apiSourceSha256,runtimeDistSha256,migrations});h.save();
   ledger.check(true,'The original naturally due occurrence stops as paused_authority for the exact immutable owner/version; no fake session, forced tick, clock or native mutation',{timerId:s.timer.id,occurrenceId:blocked.blockingOccurrenceId});
  }else if(phase==='restore'){
   const current=await binding('source','revoked');
   const result=entity(await ledger.once('m10-authority-source-binding-restore',admin,`/iam/users/${s.ownerId}/role-bindings/${current.id}/restore`,'POST',
    ledger.freeze('restore-body',()=>({revision:current.revision,confirmed:true,confirm_name:current.role_name}))));
   assertAuthorityBinding(result,{userId:s.ownerId,roleId:s.sourceRole.id,roleName:s.sourceRole.name,clusterId:cid,workspaceId:wid,status:'active',previousRevision:current.revision});
   assert.equal(entity(await read(owner,src(`entities/services/${s.sourceService.id}`))).id,s.sourceService.id);assert.equal((await binding('target','active')).revision,s.targetBinding.revision);
   const blocked=assertAuthorityBlockedTimer((await read(admin,src(`governance/schedules/${s.timer.id}`))).data.entity,s.timer);assert.equal(blocked.blockingOccurrenceId,s.blockedTimer.blockingOccurrenceId);
   s.timerProof=observeAuthorityTimerConsole({mode:'restored',actorId:s.ownerId,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:targetCid,targetWorkspaceId:targetWid,
    sourceBindingId:s.sourceBinding.id,targetBindingId:s.targetBinding.id,sourceRoleId:s.sourceRole.id,targetRoleId:s.targetRole.id,timer:s.timer,blockedTimer:blocked,
    runtimeSourceSha256:runtime.apiSourceSha256,runtimeDistSha256,migrations});
   s.restoredBinding=result;ledger.check(true,'A separate current-revision IAM restore recovers source access without rewriting or executing the old plan, unblocking/rearming the old timer or changing its original occurrence');h.save();
  }
 }
 p.passed=true;p.state='passed';p.completedAt=new Date().toISOString();h.save();writeFileSync(attemptPath,JSON.stringify(publicReport(true),null,2)+'\n',{flag:'wx'});
 process.stdout.write(JSON.stringify({passed:true,phase,checks:s.checks.length,nextPhase:AUTHORITY_PHASES[index+1]??null,mainPhaseChanged:false})+'\n');
}catch(error){const p=s.phases[phase];if(p){p.state='stopped';p.passed=false;}h.save();
 const code=/^[A-Z0-9_]+$/.test(error.message??'')?error.message:'M10_AUTHORITY_ACTUAL_ACCEPTANCE_FAILED';
 if(attemptPath&&!existsSync(attemptPath))writeFileSync(attemptPath,JSON.stringify({passed:false,milestone:'M10',phase,productionDeployment:false,code,checks:s.checks,mainPhaseChanged:false,originalResponseRewritten:false},null,2)+'\n',{flag:'wx'});
 process.stderr.write(JSON.stringify({passed:false,phase,code})+'\n');process.exitCode=1;
}
