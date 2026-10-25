import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {WorkflowScheduledConfigurationOriginService} from '../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import {WorkflowApprovalAuthorityService} from '../../apps/console-api/src/modules/workflows/workflow-approval-authority.service';
import {WorkflowCandidatesService} from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';
import {normalizeWorkflowApprovalPolicy} from '../../apps/console-api/src/modules/workflows/workflow-approval-policy';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','f4'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());
const id=(n:number)=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
type Stage={mode:'any'|'quorum'|'all';candidates:number[];votes?:number[];threshold?:number};
const sql=(value:string)=>value.replace(/\s+/g,' ').trim();

/** Real Origin approval gate, shared ApprovalAuthority, Candidates, policy
 * normalization and HMACs. SQL and the private Namespace transport are explicit
 * fixtures: the latter invokes the genuine shared complete-set verifier, never
 * a count-only approval mock. No PostgreSQL, live timer, Native permit or full
 * configuration-material/Context acceptance is claimed by this focused test. */
function fixture(specs:Stage[]=[{mode:'any',candidates:[1]}],distinctAcrossStages=true,selector:'users'|'teams'='users'){
  const secrets=new SecretService(),cid=id(100),wid=id(101),workflowId=id(102),definitionId=id(103),executionId=id(104),setId=id(105);
  const policy=normalizeWorkflowApprovalPolicy({version:2,kind:'configuration_v2',allowSelfApproval:false,distinctAcrossStages,
    stages:specs.map((s,i)=>({level:i+1,name:`阶段${i+1}`,mode:s.mode,threshold:s.mode==='all'?null:s.threshold??1,
      selector:selector==='users'?{users:s.candidates.map(id)}:{teams:[id(200+i)]}}))});
  const plan:any={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:2,kind:'configuration_v2',executionMode:'approval',approvalRequired:true,
    subject:{type:'configuration_jobs',id:id(106)},requester:{type:'console',id:id(107)},definition:{id:definitionId,version:2,policyHash:secrets.fingerprint(policy)},
    issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60_000).toISOString(),scope:{transportScope:'a'.repeat(64),clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[]};
  const hash=secrets.fingerprint(plan),manifest:any={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:2,planHash:hash,definitionId,definitionVersion:2,
    policyHash:plan.definition.policyHash,candidateVersion:1,stages:specs.map((s,i)=>({level:i+1,mode:s.mode,threshold:s.mode==='all'?s.candidates.length:s.threshold??1,
      candidates:[...s.candidates].sort((a,b)=>a-b).map(n=>({userId:id(n),credentialEpoch:'1',provenance:[{kind:selector==='users'?'user':'team',selectorId:selector==='users'?id(n):id(200+i)}]}))}))};
  const manifestHmac=secrets.fingerprint(manifest),decisions:any[]=specs.flatMap((s,i)=>(s.votes??s.candidates.slice(0,s.mode==='all'?s.candidates.length:s.threshold??1))
    .map((n,j)=>({id:id(300+i*100+j),approver_id:id(n),decision:'approve',level:i+1,plan_hash:hash,candidate_version:1,candidate_manifest_hmac:manifestHmac})))
    .sort((a,b)=>a.level-b.level||a.approver_id.localeCompare(b.approver_id)||a.id.localeCompare(b.id));
  const reviewers=decisions.map(v=>({approvalId:v.id,userId:v.approver_id,level:v.level,candidateVersion:v.candidate_version}));
  const setMaterial={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:2,planHash:hash,policyHash:plan.definition.policyHash,
    candidateVersion:1,candidateManifestHmac:manifestHmac,reviewers};
  const set:any={id:setId,set_hmac:secrets.fingerprint(setMaterial),manifest:setMaterial};
  const row:any={id:workflowId,plan_revision:2,plan_hash:hash,definition_id:definitionId,definition_version:2,approval_format:2,approval_required:true,state:'executing',
    approved_by:decisions.at(-1)?.approver_id,candidate_version:1,candidate_manifest_hmac:manifestHmac,approval_set_id:setId,approval_set_hmac:set.set_hmac};
  const definition:any={approval_format:2,mode:'multi',allow_self_approval:false,policy_hash:plan.definition.policyHash,policy};
  const stages:any[]=specs.map((s,i)=>({level:i+1,plan_hash:hash,approval_format:2,candidate_version:1,candidate_manifest_hmac:manifestHmac,
    stage_mode:s.mode,required_approvals:manifest.stages[i].threshold,state:'approved'}));
  const candidates:any[]=manifest.stages.flatMap((s:any)=>s.candidates.map((c:any)=>({plan_hash:hash,manifest_hmac:manifestHmac,level:s.level,
    user_id:c.userId,credential_epoch:c.credentialEpoch,provenance:c.provenance})));
  const members:any[]=decisions.map(v=>({cluster_id:cid,workspace_id:wid,workflow_id:workflowId,plan_revision:2,plan_hash:hash,set_hmac:set.set_hmac,
    approval_id:v.id,user_id:v.approver_id,level:v.level,candidate_version:1,candidate_manifest_hmac:manifestHmac}));
  const users=new Map(Array.from({length:16},(_,i)=>[id(i+1),{status:'active',deleted_at:null,force_password_change:false,credential_epoch:1}]));
  const state:any={epoch:1,invalidated:false,teamMember:true,namespaceFailure:null,copyNamespace:false};
  const one=new Map<string,[unknown[],()=>unknown]>(),many=new Map<string,[unknown[],()=>unknown]>();
  const register=(map:Map<string,[unknown[],()=>unknown]>,query:string,params:unknown[],read:()=>unknown)=>map.set(sql(query),[params,read]);
  register(one,'SELECT version FROM iam_epoch WHERE singleton=true',[],()=>({version:state.epoch}));
  register(one,'SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[workflowId,cid,wid],()=>row);
  register(one,'SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4',[workflowId,cid,wid,2],()=>({plan_hash:hash,approval_required:true,approval_format:2}));
  register(one,'SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[cid,wid,definitionId,2],()=>definition);
  register(one,'SELECT * FROM workflow_candidate_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5',[workflowId,cid,wid,2,1],()=>({manifest,manifest_hmac:manifestHmac}));
  register(one,'SELECT * FROM workflow_approval_sets WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6',[setId,cid,wid,workflowId,2,hash],()=>set);
  register(one,'SELECT * FROM workflow_executions WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6',[executionId,cid,wid,workflowId,2,hash],()=>({approval_format:2,approval_set_id:row.approval_set_id,approval_set_hmac:row.approval_set_hmac}));
  register(one,'SELECT id FROM workflow_approval_invalidations WHERE set_id=$1 LIMIT 1',[setId],()=>state.invalidated?{id:id(600)}:null);
  register(many,'SELECT * FROM workflow_stages WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level',[workflowId,cid,wid,2],()=>stages);
  register(many,'SELECT * FROM workflow_approvals WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level,approver_id,id',[workflowId,cid,wid,2],()=>decisions);
  register(many,'SELECT * FROM workflow_candidates WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5 ORDER BY level,user_id',[workflowId,cid,wid,2,1],()=>candidates);
  register(many,'SELECT * FROM workflow_approval_set_members WHERE set_id=$1 ORDER BY level,user_id,approval_id',[setId],()=>members);
  const dispatch=async(map:Map<string,[unknown[],()=>unknown]>,query:string,params:unknown[]=[])=>{
    const entry=map.get(sql(query));if(!entry)throw Error('UNIMPLEMENTED_EXACT_APPROVAL_FIXTURE_SQL');expect(params).toEqual(entry[0]);return entry[1]();
  };
  const currentUser='SELECT status,deleted_at,force_password_change,credential_epoch FROM users WHERE id=$1';
  const currentTeam=sql(`SELECT 1 FROM team_members m JOIN teams t ON t.id=m.team_id WHERE t.id=$1 AND m.user_id=$2 AND t.status='active' AND t.deleted_at IS NULL AND m.status='active' AND(t.cluster_id IS NULL OR t.cluster_id=$3) AND(t.workspace_id IS NULL OR t.workspace_id=$4)`);
  const db:any={one:vi.fn(async(query:string,params:unknown[]=[])=>{
    if(sql(query)===currentUser){expect(params).toHaveLength(1);return users.get(params[0] as string)??null;}
    if(sql(query)===currentTeam){expect(params).toHaveLength(4);expect(params.slice(2)).toEqual([cid,wid]);expect(specs.map((_,i)=>id(200+i))).toContain(params[0]);expect(users.has(params[1] as string)).toBe(true);return state.teamMember?{'?column?':1}:null;}
    return dispatch(one,query,params);
  }),query:vi.fn((query:string,params:unknown[]=[])=>dispatch(many,query,params)),exec:vi.fn(()=>{throw Error('APPROVAL_GATE_MUST_BE_READ_ONLY');})};
  const authority=new WorkflowApprovalAuthorityService(db,secrets,new WorkflowCandidatesService(db)),reviewer=vi.fn(async():Promise<void>=>undefined);
  authority.installReviewerPolicy('configuration_v2',{verifyCurrent:reviewer});
  const namespaceHandle=Object.freeze({}),namespace:any=Object.freeze({approvalSet:{format:2,policyHash:plan.definition.policyHash,setId,setHmac:set.set_hmac,reviewers}});
  const namespaces:any={verifyHandle:vi.fn(async(handle:object,phase:string)=>{
    if(handle!==namespaceHandle)throw new ForbiddenException({code:'WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED'});
    if(state.namespaceFailure)throw new ForbiddenException({code:state.namespaceFailure});
    const verified=await authority.verifyApprovalSet(plan,{executionId,checkpoint:phase==='capture'?'snapshot':phase==='before-send'?'packet':phase as any},db);
    if(secrets.fingerprint(verified)!==secrets.fingerprint(namespace.approvalSet))throw new ForbiddenException({code:'WORKFLOW_SCHEDULE_NAMESPACE_FACTS_CHANGED'});
    return state.copyNamespace?{...namespace}:namespace;
  })};
  const origin=new WorkflowScheduledConfigurationOriginService(db,secrets,{}as any,{}as any,namespaces);
  const gate=(phase='claim',ns=namespace,handle=namespaceHandle)=>(origin as any).fullApproval({namespace:ns,namespaceHandle:handle},phase,db);
  return{gate,origin,plan,definition,row,stages,decisions,candidates,members,manifest,set,namespace,namespaceHandle,namespaces,authority,reviewer,users,state,db};
}

describe('scheduled configuration full approval follows the actual sealed V2 policy',()=>{
  it.each([1,2,3])('accepts all %i genuinely completed single-vote stages without a minimum headcount',async count=>{
    const f=fixture(Array.from({length:count},(_,i)=>({mode:'any',candidates:[i+1]})));await f.gate();
    expect(f.reviewer).toHaveBeenCalledTimes(count);expect(f.namespaces.verifyHandle).toHaveBeenCalledWith(f.namespaceHandle,'claim');expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('accepts quorum only after its declared threshold, without requiring every candidate vote',async()=>{
    const f=fixture([{mode:'quorum',threshold:2,candidates:[1,2,3],votes:[1,2]}]);await f.gate();expect(f.reviewer).toHaveBeenCalledTimes(2);
  });
  it('accepts all only with every genuinely frozen candidate vote',async()=>{
    const f=fixture([{mode:'all',candidates:[1,2,3]}]);await f.gate();expect(f.reviewer).toHaveBeenCalledTimes(3);
  });
  it('supports the maximum eight-stage complete policy',async()=>{const f=fixture(Array.from({length:8},(_,i)=>({mode:'any',candidates:[i+1]})));await f.gate();expect(f.reviewer).toHaveBeenCalledTimes(8);});
  it('allows the same reviewer in different stages only when the frozen policy permits it',async()=>{
    const f=fixture([{mode:'any',candidates:[1]},{mode:'any',candidates:[1]}],false);await f.gate();expect(f.reviewer).toHaveBeenCalledTimes(2);
  });
  it('rejects cross-stage reuse when distinctAcrossStages is true',async()=>{
    const f=fixture([{mode:'any',candidates:[1,2],votes:[1]},{mode:'any',candidates:[1,2],votes:[1]}]);await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_FACT_INVALID'}});
  });
  it('rejects duplicate votes within one stage even when cross-stage reuse is allowed',async()=>{
    const f=fixture([{mode:'quorum',threshold:2,candidates:[1,2],votes:[1,1]}],false);await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED'}});expect(f.namespaces.verifyHandle).not.toHaveBeenCalled();
  });
  it.each<Stage>([{mode:'quorum',threshold:2,candidates:[1,2,3],votes:[1]},{mode:'all',candidates:[1,2,3],votes:[1,2]}])('rejects a policy-incomplete set: %j',async spec=>{
    const f=fixture([spec]);await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_SET_INCOMPLETE'}});
  });
  it.each(['pending','rejected'])('rejects a %s stage despite a full vote-shaped set',async stage=>{const f=fixture();f.stages[0].state=stage;await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_SET_INCOMPLETE'}});});
  it.each(['policy_hash','approval_format','allow_self_approval'])('retains the exact immutable policy %s fence',async field=>{
    const f=fixture();f.definition[field]=field==='policy_hash'?'f'.repeat(64):field==='approval_format'?1:true;await expect(f.gate()).rejects.toBeDefined();
  });
  it.each(['set_hmac','manifest'])('rejects an altered sealed set %s',async field=>{const f=fixture();f.set[field]=field==='set_hmac'?'e'.repeat(64):{...f.set.manifest,candidateVersion:99};await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_SET_INVALID'}});});
  it.each(['user_id','candidate_version','set_hmac','plan_revision'])('rejects substituted set member %s',async field=>{const f=fixture();f.members[0][field]=field==='user_id'?id(15):field==='set_hmac'?'e'.repeat(64):99;await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_SET_INVALID'}});});
  it('rejects an invalidated final set',async()=>{const f=fixture();f.state.invalidated=true;await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_SET_INVALIDATED'}});});
  it('rejects a changed frozen candidate manifest',async()=>{const f=fixture();f.manifest.stages[0].candidates[0].credentialEpoch='2';await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_CANDIDATE_MANIFEST_INVALID'}});});
  it.each(['credential_epoch','status','force_password_change'])('rechecks the current reviewer %s',async field=>{const f=fixture(),user:any=f.users.get(id(1));user[field]=field==='credential_epoch'?2:field==='status'?'disabled':true;await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVER_NO_LONGER_ELIGIBLE'}});});
  it('rechecks actual current team selector membership',async()=>{const f=fixture(undefined,true,'teams');f.state.teamMember=false;await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVER_SELECTOR_REVOKED'}});});
  it('retains the current subject/PV reviewer policy rather than trusting frozen identity alone',async()=>{const f=fixture();f.reviewer.mockRejectedValue(new ForbiddenException({code:'CURRENT_REVIEWER_SCOPE_REVOKED'}));await expect(f.gate()).rejects.toMatchObject({response:{code:'CURRENT_REVIEWER_SCOPE_REVOKED'}});});
  it('rejects IAM epoch drift across complete approval verification',async()=>{const f=fixture();f.reviewer.mockImplementation(async()=>{f.state.epoch++;});await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_PERMISSIONS_CHANGED'}});});
  it.each(['WORKFLOW_SCHEDULE_CLAIM_EXPIRED','WORKFLOW_SCHEDULE_POLICY_CHANGED','WORKFLOW_SCHEDULE_SCOPE_CHANGED'])('propagates the original Namespace %s fence',async code=>{const f=fixture();f.state.namespaceFailure=code;await expect(f.gate()).rejects.toMatchObject({response:{code}});});
  it('requires the genuine original Namespace proof object after verification',async()=>{const f=fixture();f.state.copyNamespace=true;await expect(f.gate()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED'}});});
  it('rejects a copied Namespace handle',async()=>{const f=fixture();await expect(f.gate('claim',f.namespace,{})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED'}});});
  it.each(['claim','capture','step','packet','before-send'])('keeps full policy verification at %s',async phase=>{const f=fixture();await f.gate(phase);expect(f.namespaces.verifyHandle).toHaveBeenCalledWith(f.namespaceHandle,phase);});
  it.each(['legacy','missingSet','empty','duplicateApproval'])('does not admit a %s envelope to the full-set verifier',async kind=>{
    const f=fixture(),set={...f.namespace.approvalSet,reviewers:[...f.namespace.approvalSet.reviewers]};
    if(kind==='legacy')set.format=1;else if(kind==='missingSet')set.setId=null;else if(kind==='empty')set.reviewers=[];else set.reviewers.push({...set.reviewers[0],userId:id(2)});
    await expect(f.gate('claim',{...f.namespace,approvalSet:set})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED'}});expect(f.namespaces.verifyHandle).not.toHaveBeenCalled();
  });
});
