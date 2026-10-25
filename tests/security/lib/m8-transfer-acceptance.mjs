import { parse, stringify } from 'yaml';
import { entity, scope } from './m8-harness.mjs';
import { configurationRead, configurationWrite, completeConfigurationWorkflow } from './m8-configuration-acceptance.mjs';
import { recycleAndRestore, nativeRead, sixCredentialProxyAcceptance } from './m8-native-acceptance.mjs';
import { setApprovalMode, restoreClusterMode } from './m8-fixtures.mjs';

export async function fiveClassRecoveryAcceptance(h, actors) {
  const f = h.state.nativeFixture, results = [];
  for (const [type, original] of [['plugins',f.plugins['key-auth']],['consumers',f.consumer],['services',f.service],['upstreams',f.upstream],['certificates',f.certificate]]) {
    const restored = await recycleAndRestore(h, actors.admin, f.area, type, original); results.push({type,id:original.id,entryId:restored.entry.id,fullyRestored:restored.restored.state==='restored'});
    if (type==='consumers') {
      for(const [kind,credential]of Object.entries(f.credentials)) {
        const current=entity(h.data(await h.request(actors.admin,scope(f.area.cid,f.area.wid,`consumers/${f.consumer.id}/credentials/${kind}/${credential.id}`))));
        h.check(current.id===credential.id&&current.consumer?.id===f.consumer.id,'Consumer graph restores each original credential parent and ID',{kind});
      }
      await sixCredentialProxyAcceptance(h,f,'consumer-graph-restored');
    }
    if(type==='upstreams') {
      const current=h.data(await h.request(actors.admin,scope(f.area.cid,f.area.wid,`upstreams/${f.upstream.id}/targets`,{size:100})));
      h.check(current.items.some(t=>t.id===f.target.id&&t.target===f.target.target&&t.weight===f.target.weight),'Upstream restore verifies original target UUID, effective address and weight');
    }
    if(type==='certificates') {
      const current=await nativeRead(h,actors.admin,f.area,'snis',f.sni.id);h.check(current.certificate?.id===f.certificate.id,'certificate graph restores original SNI relation');
    }
  }
  await sixCredentialProxyAcceptance(h,f,'five-classes-restored');
  h.state.fiveClassRecovery=results;h.public??={};h.public.fiveClassRecovery=results;h.save();return results;
}
/** The first actual pass already restored the Plugin and deleted the Consumer.
 * This tail is callable only after its caller proves and resumes the exact
 * original, side-effect-free Consumer restore. It never repeats either delete
 * or the successful Plugin restoration. */
export async function finishM8FiveClassRecovery(h, actors, consumerReceipt) {
  const f=h.state.nativeFixture,area=f.area,entries=h.state.recycleEntries;
  h.check(!h.state.fiveClassRecovery&&consumerReceipt?.state==='restored'
    &&consumerReceipt.entryId==='57e3ac7b-cc7a-4ed1-aff8-802339029411', 'unused five-class tail starts only after original Consumer archive fully restores');
  const plugins=entries.filter(e=>e.type==='plugins'&&e.originalId===f.plugins['key-auth'].id),consumers=entries.filter(e=>e.id===consumerReceipt.entryId),plugin=plugins[0],consumer=consumers[0];
  h.check(entries.length===2&&plugins.length===1&&consumers.length===1&&plugin.cid===area.cid&&plugin.wid===area.wid&&consumer?.cid===area.cid&&consumer.wid===area.wid&&consumer.type==='consumers'&&consumer.originalId===f.consumer.id,'two unique exact-scope typed original archive identities anchor the completed prefix and no remaining class has started');
  h.check(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].every(kind=>typeof f.credentials[kind]?.id==='string')&&Object.keys(f.credentials).length===6,'all six original credential UUIDs are present before any recovery-tail write');
  const pluginCurrent=await nativeRead(h,actors.admin,area,'plugins',f.plugins['key-auth'].id);
  h.check(pluginCurrent.id===f.plugins['key-auth'].id,'current Plugin read proves already successful restoration without repeating its writes');
  const results=[{type:'plugins',id:plugin.originalId,entryId:plugin.id,fullyRestored:true,inheritedOriginalSuccess:true},{type:'consumers',id:f.consumer.id,entryId:consumer.id,fullyRestored:true}];
  for(const [kind,credential]of Object.entries(f.credentials)){
    const current=entity(h.data(await h.request(actors.admin,scope(area.cid,area.wid,`consumers/${f.consumer.id}/credentials/${kind}/${credential.id}`))));
    h.check(current.id===credential.id&&current.consumer?.id===f.consumer.id,'Consumer graph restores each original credential parent and ID',{kind});
  }
  await sixCredentialProxyAcceptance(h,f,'consumer-graph-restored');
  for(const [type,original]of [['services',f.service],['upstreams',f.upstream],['certificates',f.certificate]]){
    const restored=await recycleAndRestore(h,actors.admin,area,type,original);results.push({type,id:original.id,entryId:restored.entry.id,fullyRestored:restored.restored.state==='restored'});
    if(type==='upstreams'){
      const current=h.data(await h.request(actors.admin,scope(area.cid,area.wid,`upstreams/${f.upstream.id}/targets`,{size:100})));
      h.check(current.items.some(t=>t.id===f.target.id&&t.target===f.target.target&&t.weight===f.target.weight),'Upstream restore verifies original target UUID, effective address and weight');
    }
    if(type==='certificates')h.check((await nativeRead(h,actors.admin,area,'snis',f.sni.id)).certificate?.id===f.certificate.id,'certificate graph restores original SNI relation');
  }
  await sixCredentialProxyAcceptance(h,f,'five-classes-restored');
  h.state.fiveClassRecovery=results;h.public??={};h.public.fiveClassRecovery=results;h.save();return results;
}
export async function applyImportedJob(h, actors, area, imported, {approval=false,driver='bff'}={}) {
  const detail=await configurationRead(h,actors.admin,area,`configuration/plans/${imported.planId}`),plan=entity(detail);
  h.check(plan.id===imported.planId&&plan.planHash===imported.planHash&&plan.planRevision===imported.planRevision&&plan.capabilities?.apply===true,'apply reads current sealed plan identity and current capabilities');
  const applied=await configurationWrite(h,actors.admin,area,`configuration/plans/${plan.id}/apply`,{planRevision:plan.planRevision,planHash:plan.planHash,revision:plan.revision,driver,confirmed:true,confirm_name:plan.name,...(plan.deleteCount?{confirm_deletes:true}:{})},{kind:plan.mode==='rollback'?'rollback':'apply',allowApproval:approval});
  if(approval)return completeConfigurationWorkflow(h,actors,area,applied,'configuration_v2','configuration_v2');
  return applied;
}
export async function directImportRollbackAcceptance(h,actors) {
  const f=h.state.nativeFixture,b=h.state.baseline,document=parse(b.yaml),service=document.services.find(s=>s.id===f.service.id);
  h.check(service&&Array.isArray(document.consumers),'deployment YAML contains original Service and nested Consumers');
  service.retries=1;const basicPasswordIntents={};
  for(const c of document.consumers)for(const credential of c.basicauth_credentials??[]){delete credential.password;basicPasswordIntents[`credentials:basic-auth:${c.id}:${credential.id}`]='keep';}
  const imported=await configurationWrite(h,actors.admin,f.area,'configuration/imports',{scope:'workspace',mode:'merge',yaml:stringify(document),basicPasswordIntents},{kind:'import'});
  h.check(imported.counts?.update>=1&&typeof imported.planId==='string','actual import computes a non-empty current-before diff');
  const applied=await applyImportedJob(h,actors,f.area,imported);const current=await nativeRead(h,actors.admin,f.area,'services',f.service.id);
  h.check(current.retries===1&&applied.state==='succeeded','direct BFF import changes real Kong Service exactly');
  await sixCredentialProxyAcceptance(h,f,'direct-import-applied');
  const snapshot=entity(await configurationRead(h,actors.admin,f.area,`snapshots/${b.snapshotId}`));
  const rollback=await configurationWrite(h,actors.admin,f.area,`snapshots/${b.snapshotId}/rollback-plan`,{revision:snapshot.revision,confirmed:true,confirm_name:b.name,confirm_deletes:true},{kind:'compare'});
  const restored=await applyImportedJob(h,actors,f.area,rollback),after=await nativeRead(h,actors.admin,f.area,'services',f.service.id);
  h.check(after.retries===f.service.retries&&restored.state==='succeeded','actual baseline rollback restores real Service before value');
  await sixCredentialProxyAcceptance(h,f,'snapshot-rollback-applied');
  h.state.directTransfer={importJobId:imported.jobId,applyJobId:applied.jobId,rollbackPlanJobId:rollback.jobId,rollbackJobId:restored.jobId};h.public??={};h.public.directTransfer={...h.state.directTransfer,proxyCredentialRecoveryProven:true};h.save();
}
/** Resume after the first genuine import succeeded but its first apply failed
 * before any execution or Native operation. The caller independently proves
 * that historical failure and supplies the current, possibly re-diffed plan. */
export async function finishM8DirectImportRollback(h,actors,imported){
  const f=h.state.nativeFixture,b=h.state.baseline;
  h.check(!h.state.directTransfer&&h.state.fiveClassRecovery?.length===5&&imported?.state==='succeeded'
    &&imported.kind==='import'&&imported.actorId===actors.admin.user.id&&imported.clusterId===f.area.cid&&imported.workspaceId===f.area.wid
    &&typeof imported.planId==='string'&&imported.counts?.update>=1,'unused direct apply starts from a genuinely successful current scoped import and inherits completed five-class recovery');
  const applied=await applyImportedJob(h,actors,f.area,imported),current=await nativeRead(h,actors.admin,f.area,'services',f.service.id);
  h.check(current.retries===1&&applied.state==='succeeded','new direct apply intent actually changes real Kong Service without reusing the failed request key');
  await sixCredentialProxyAcceptance(h,f,'direct-import-applied');
  const snapshot=entity(await configurationRead(h,actors.admin,f.area,`snapshots/${b.snapshotId}`));
  const rollback=await configurationWrite(h,actors.admin,f.area,`snapshots/${b.snapshotId}/rollback-plan`,{revision:snapshot.revision,confirmed:true,confirm_name:b.name,confirm_deletes:true},{kind:'compare'});
  const restored=await applyImportedJob(h,actors,f.area,rollback),after=await nativeRead(h,actors.admin,f.area,'services',f.service.id);
  h.check(after.retries===f.service.retries&&restored.state==='succeeded','actual baseline rollback restores original Service value after the new direct apply');
  await sixCredentialProxyAcceptance(h,f,'snapshot-rollback-applied');
  h.state.directTransfer={importJobId:imported.jobId,applyJobId:applied.jobId,rollbackPlanJobId:rollback.jobId,rollbackJobId:restored.jobId};
  h.public??={};h.public.directTransfer={...h.state.directTransfer,proxyCredentialRecoveryProven:true,originalFailedApplyReplayed:false};h.save();
}
/** Continue only after the original independently keyed import/apply really
 * succeeded. A failed rollback preview must never repeat that Native apply. */
export async function finishM8ObservedDirectApplyRollback(h,actors,{imported,applied}){
  const f=h.state.nativeFixture,b=h.state.baseline;
  h.check(!h.state.directTransfer&&h.state.fiveClassRecovery?.length===5
    &&[imported,applied].every(v=>v?.state==='succeeded'&&v.actorId===actors.admin.user.id&&v.clusterId===f.area.cid&&v.workspaceId===f.area.wid)
    &&imported.kind==='import'&&applied.kind==='apply'&&typeof imported.jobId==='string'&&typeof applied.jobId==='string'
    &&applied.executionCompleted===true,'unused rollback inherits exact current successful import/apply receipts without repeating their writes');
  const current=await nativeRead(h,actors.admin,f.area,'services',f.service.id);
  h.check(current.id===f.service.id&&current.retries===1,'real Service still carries the already successful direct apply value before unused rollback');
  const snapshot=entity(await configurationRead(h,actors.admin,f.area,`snapshots/${b.snapshotId}`));
  h.check(snapshot.id===b.snapshotId&&snapshot.clusterId===f.area.cid&&snapshot.workspaceId===f.area.wid&&Number.isInteger(snapshot.revision),'unused rollback reads the current exact original snapshot revision');
  const rollback=await configurationWrite(h,actors.admin,f.area,`snapshots/${b.snapshotId}/rollback-plan`,{revision:snapshot.revision,confirmed:true,confirm_name:b.name,confirm_deletes:true},{kind:'compare'});
  const restored=await applyImportedJob(h,actors,f.area,rollback),after=await nativeRead(h,actors.admin,f.area,'services',f.service.id);
  h.check(after.id===f.service.id&&after.retries===f.service.retries&&restored.state==='succeeded','unused actual baseline rollback restores original Service value');
  await sixCredentialProxyAcceptance(h,f,'snapshot-rollback-applied');
  h.state.directTransfer={importJobId:imported.jobId,applyJobId:applied.jobId,rollbackPlanJobId:rollback.jobId,rollbackJobId:restored.jobId};
  h.public??={};h.public.directTransfer={...h.state.directTransfer,proxyCredentialRecoveryProven:true,successfulDirectApplyReplayed:false};h.save();
}
export async function approvalV2AndMetadataAcceptance(h,actors) {
  const area=actors.approval;await setApprovalMode(h,actors.admin,area);
  const services=Array.from({length:17},(_,i)=>({name:`${h.state.testTag}-v2-${i}`,host:'echo-upstream',port:8081,protocol:'http',retries:0,tags:[h.state.testTag]}));
  const imported=await configurationWrite(h,actors.admin,area,'configuration/imports',{scope:'workspace',mode:'merge',yaml:stringify({_format_version:'1.1',services})},{kind:'import'});
  h.check(imported.counts?.create===17,'configuration V2 plan exceeds unchanged V1 sixteen-step budget with seventeen real steps');
  return finishM8ObservedApprovalImport(h,actors,imported);
}
/** A failed wrapper submission cannot repeat its already successful import or
 * the canonical mode change. Its caller proves the original failure and may
 * supply a separately re-diffed import only when the original plan expired. */
export async function finishM8ObservedApprovalImport(h,actors,imported) {
  const area=actors.approval;
  h.check(h.state.directTransfer&&h.state.fiveClassRecovery?.length===5&&!h.state.approvalTransfer
    &&imported?.state==='succeeded'&&imported.kind==='import'&&imported.actorId===actors.admin.user.id
    &&imported.clusterId===area.cid&&imported.workspaceId===area.wid&&imported.counts?.create===17
    &&typeof imported.planId==='string','unused V2 approval starts only from an exact successful seventeen-step scoped import and completed direct rollback');
  const cluster=entity(h.data(await h.request(actors.admin,`/clusters/${area.cid}`)));
  h.check(cluster.id===area.cid&&cluster.execution_mode==='approval','unused V2 approval preserves the canonical current approval mode without another mode write');
  const services=Array.from({length:17},(_,i)=>({name:`${h.state.testTag}-v2-${i}`}));
  const applied=await applyImportedJob(h,actors,area,imported,{approval:true});
  return finishM8ApprovedConfigurationMetadata(h,actors,applied,services);
}
/** The original new apply already durably submitted its pending wrapper. Only
 * approve/execute and subsequent untouched metadata remain; no apply/import. */
export async function finishM8SubmittedApproval(h,actors,pending){
  const area=actors.approval;
  h.check(h.state.directTransfer&&!h.state.approvalTransfer&&pending?.state==='waiting_approval'&&pending.kind==='apply'
    &&pending.actorId===actors.admin.user.id&&pending.clusterId===area.cid&&pending.workspaceId===area.wid
    &&pending.stepCount===17&&pending.executionCompleted===false&&typeof pending.workflowId==='string',
    'unused approval decisions start from the exact genuinely submitted seventeen-step wrapper');
  const applied=await completeConfigurationWorkflow(h,actors,area,pending,'configuration_v2','configuration_v2');
  return finishM8ApprovedConfigurationMetadata(h,actors,applied,Array.from({length:17},(_,i)=>({name:`${h.state.testTag}-v2-${i}`})));
}
async function finishM8ApprovedConfigurationMetadata(h,actors,applied,services){
  const area=actors.approval;
  const current=h.data(await h.request(actors.admin,scope(area.cid,area.wid,'entities/services',{size:100})));
  h.check(current.items.length===17&&services.every(s=>current.items.some(v=>v.name===s.name)),'all seventeen V2 native creates are actually visible in correct fresh workspace');
  for(const object of current.items)h.state.fixtures.push({...area,type:'services',id:object.id,name:object.name});h.save();
  const metadata=await configurationWrite(h,actors.admin,area,'snapshots/schedules',{scope:'workspace',name:`${h.state.testTag} approval schedule`,intervalMinutes:60,timezone:'UTC',retentionDays:7},{kind:'compare',allowApproval:true});
  const complete=await completeConfigurationWorkflow(h,actors,area,metadata,'configuration-metadata','configuration.metadata');
  const schedules=await configurationRead(h,actors.admin,area,'snapshots/schedules',{scope:'workspace',size:100});
  h.check(schedules.items.some(s=>s.name===`${h.state.testTag} approval schedule`&&s.ownerUserId===actors.admin.user.id),'approved configuration metadata has real current scoped resource');
  const schedule=schedules.items.find(s=>s.name===`${h.state.testTag} approval schedule`);h.state.fixtures.push({...area,type:'config_snapshot_schedules',id:schedule.id,name:schedule.name});h.save();
  await restoreClusterMode(h,actors.admin,area);
  h.state.approvalTransfer={jobId:applied.jobId,workflowId:applied.workflowId,nativeSteps:17,metadataJobId:complete.jobId,metadataWorkflowId:complete.workflowId};h.public??={};h.public.approvalTransfer={...h.state.approvalTransfer,V1BudgetExpanded:false,originalC2ModeRestored:true};h.save();
}
