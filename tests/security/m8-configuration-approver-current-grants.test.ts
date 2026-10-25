import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {configurationApprovedFixture as fixture,id} from './m8-configuration-approved-fixture';

describe('M8 current approver authority under the original executor frame',()=>{
  beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-secret-with-at-least-thirty-two-characters');});
  afterEach(()=>vi.unstubAllEnvs());

  it('retains real AuthorizationService anti-IDOR for cross-actor snapshots and whole-workspace checks',async()=>{
    const f=await fixture({actualAuthorization:true});expect(f.authz).toBeInstanceOf(AuthorizationService);
    await f.run(async()=>{
      const approver={id:f.approval.approver_id,username:'approver',superAdmin:true};
      await expect(f.authz.snapshot(approver)).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
      await expect(f.authz.assertWholeWorkspace(approver,f.cid,f.wid,'workflows','approve')).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
      expect(f.context.current().actor?.id).toBe(f.actor.id);expect(f.context.current().sessionId).toBe(f.sid);
      expect(f.db.one.mock.calls.filter(([sql,p]:any)=>sql.includes('FROM users')&&p[0]===approver.id)).toHaveLength(0);
    });
  });

  it('mints V2 with real executor authorization and a current exact approver grant without switching identity',async()=>{
    const f=await fixture({actualAuthorization:true}),snapshot=vi.spyOn(f.authz,'snapshot');
    let callbacks=0;await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>{
      callbacks++;expect(f.context.current().actor?.id).toBe(f.actor.id);expect(f.context.current().sessionId).toBe(f.sid);
      await f.context.runApprovedStep(f.jobStepId,async()=>{
        const binding=await f.context.approvedMutationBinding(f.mutation);expect(binding).toMatchObject({version:2,configurationExecutionId:f.executionId});
        expect(f.context.current().actor?.id).toBe(f.actor.id);expect(f.context.current().sessionId).toBe(f.sid);
      });
    }));
    expect(callbacks).toBe(1);expect(snapshot.mock.calls.every(([user]:any)=>user.id===f.actor.id)).toBe(true);
    expect(f.db.query.mock.calls.some(([sql,p]:any)=>sql==='SELECT * FROM iam_effective_grants WHERE user_id=$1'&&p[0]===f.approval.approver_id)).toBe(true);
    expect(f.db.query.mock.calls.some(([sql,p]:any)=>sql.includes('workflow_approvals')&&sql.includes('u.super_admin')&&p[0]===f.cid&&p[1]===f.wid&&p[2]===f.workflow.id&&p[3]===f.execution.approved_version&&p[4]===f.execution.workflow_plan_hash)).toBe(true);
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['unscoped','clusterCeiling','workspaceCeiling'])('accepts a complete current global grant (%s) inside the exact scope',async(which)=>{
    const f=await fixture({actualAuthorization:true});Object.assign(f.approvalGrants[0],{scope_type:'global',scope_values:[],cluster_id:which==='unscoped'?null:f.cid,workspace_id:which==='workspaceCeiling'?f.wid:null});
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).resolves.toBeUndefined();
  });

  it('accepts only current DB super-admin status, with no approver grant or actor adoption',async()=>{
    const f=await fixture({actualAuthorization:true});f.approval.super_admin=true;f.approvalGrants.length=0;
    await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>{
      expect(f.context.current().actor?.id).toBe(f.actor.id);expect(f.context.current().sessionId).toBe(f.sid);
    }));expect(f.actor.superAdmin).toBe(false);expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['revoked','wrongModule','wrongAction','wrongCID','wrongWID','tagGroup','entity','duplicateWorkspaceValue','emptyWorkspaceValue','wrongWorkspaceValue','globalForeignCID','globalForeignWID','globalNonemptyValue','missingCluster','malformedGrant','fakeSuperAdmin'])('denies %s before the callback or any mutation/native packet',async(which)=>{
    const f=await fixture({actualAuthorization:true}),grant=f.approvalGrants[0],callback=vi.fn();
    if(which==='revoked')f.approvalGrants.length=0;
    if(which==='wrongModule')grant.module='snapshots';if(which==='wrongAction')grant.action='read';if(which==='wrongCID')grant.cluster_id=id(90);if(which==='wrongWID')grant.workspace_id=id(91);
    if(which==='tagGroup')Object.assign(grant,{scope_type:'tag_group',scope_values:['team:approval']});
    if(which==='entity')Object.assign(grant,{scope_type:'entity',scope_values:[{entity_type:'workflows',entity_id:f.workflow.id}]});
    if(which==='duplicateWorkspaceValue')grant.scope_values=[f.wid,f.wid];if(which==='emptyWorkspaceValue')grant.scope_values=[];if(which==='wrongWorkspaceValue')grant.scope_values=[id(91)];
    if(which==='globalForeignCID')Object.assign(grant,{scope_type:'global',scope_values:[],cluster_id:id(90),workspace_id:null});
    if(which==='globalForeignWID')Object.assign(grant,{scope_type:'global',scope_values:[],workspace_id:id(91)});
    if(which==='globalNonemptyValue')Object.assign(grant,{scope_type:'global',scope_values:[f.wid]});if(which==='missingCluster')grant.cluster_id=null;
    if(which==='malformedGrant')grant.scope_values=null;if(which==='fakeSuperAdmin'){f.approval.super_admin='true';f.approvalGrants.length=0;}
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,callback))).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVER_REVOKED'}});
    expect(callback).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['disabled','deleted','forcePassword','selfApproval'])('keeps %s rejection even for a current DB super-admin approver',async(which)=>{
    const f=await fixture({actualAuthorization:true}),callback=vi.fn();f.approval.super_admin=true;
    if(which==='disabled')f.approval.status='disabled';if(which==='deleted')f.approval.deleted_at=new Date().toISOString();if(which==='forcePassword')f.approval.force_password_change=true;
    if(which==='selfApproval'){f.approval.approver_id=f.actor.id;f.workflow.approved_by=f.actor.id;f.wrapperExecution.approved_by=f.actor.id;}
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,callback))).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVER_REVOKED'}});
    expect(callback).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rechecks current approver grant withdrawal before the next private step capability',async()=>{
    const f=await fixture({actualAuthorization:true});await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>{
      f.approvalGrants.length=0;
      await expect(f.context.runApprovedStep(f.jobStepId,async()=>undefined)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVER_REVOKED'}});
      expect(f.context.current().actor?.id).toBe(f.actor.id);expect(f.context.current().sessionId).toBe(f.sid);
    }));expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('rejects an IAM epoch change after reading approver grants before capability mint',async()=>{
    const f=await fixture({actualAuthorization:true}),original=f.db.query.getMockImplementation()!,callback=vi.fn();
    f.db.query.mockImplementation(async(sql:string,p:any[])=>{
      const rows=await original(sql,p);if(sql.includes('iam_effective_grants')&&p[0]===f.approval.approver_id)f.iamEpoch.version++;
      return rows;
    });
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,callback))).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_GRANTS_CHANGED'}});
    expect(callback).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });
});
