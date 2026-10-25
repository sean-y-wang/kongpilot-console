import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {preNamespaceApprovalFixture} from './helpers/workflow-pre-namespace-approval-fixture';
import {WorkflowApprovalAuthorityService} from '../../apps/console-api/src/modules/workflows/workflow-approval-authority.service';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cb'.repeat(32)));
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
async function fixture(selector:'user'|'role'|'team'='user'){
 const f=await preNamespaceApprovalFixture('portal-credential-issue',2,selector),approval=new WorkflowApprovalAuthorityService(f.db,f.secrets,f.canonicalCandidates),reviewer=vi.fn(async()=>{throw Error('SQL_CLOSING_MUST_NOT_ENTER_NATIVE_REVIEWER');});
 approval.installReviewerPolicy('portal-credential-issue',{verifyCurrent:reviewer});
 const original=Object.freeze({}),gate={active:false,phase:'new'};
 const verify=(token:object,plan:any,checkpoint:string,tx:any,phase:string)=>{
  if(!gate.active||token!==original||plan!==f.plan||checkpoint!=='packet'||tx!==f.db||gate.phase!==(phase==='enter'?'new':'reading'))throw Error('SOURCE_ORIGINAL_SQL_GATE_REQUIRED');
  gate.phase=phase==='enter'?'reading':'closed';
 };
 const reader=approval.installScheduledPortalInspectionSqlReader({enter:async(...args)=>verify(...args,'enter'),leave:async(...args)=>verify(...args,'leave')});
 const read=async()=>{gate.active=true;try{return await reader(original,f.plan,{checkpoint:'packet'},f.db);}finally{gate.active=false;}};
 return{...f,approval,reviewer,gate,reader,original,read};
}
describe('Portal inspection uses the real canonical SQL approval/candidate checker',()=>{
 it('returns the exact current format-2 set without invoking subject GETs or reviewer Native policy',async()=>{
  const f=await fixture(),before=f.state.native.length;
  expect(await f.read()).toEqual({format:2,policyHash:f.plan.definition.policyHash,setId:f.set.id,setHmac:f.set.set_hmac,
   reviewers:f.votes.map((v:any)=>({approvalId:v.id,userId:v.approver_id,level:v.level,candidateVersion:v.candidate_version}))});
  expect(f.reviewer).not.toHaveBeenCalled();expect(f.state.native).toHaveLength(before);expect(f.db.exec).not.toHaveBeenCalled();expect(f.gate.phase).toBe('closed');
 });
 it.each(['status','credential','manifest','candidate-row','vote','stage','member','set','invalidation']as const)('retains canonical %s rejection',async reason=>{
  const f=await fixture();
  if(reason==='status')f.tables.users[1].status='disabled';
  else if(reason==='credential')f.tables.users[1].credential_epoch='2';
  else if(reason==='manifest')f.manifest.stages[0].candidates[0].credentialEpoch='2';
  else if(reason==='candidate-row')f.candidateRows[0].credential_epoch='2';
  else if(reason==='vote')f.votes[0].decision='reject';
  else if(reason==='stage')f.stages[0].required_approvals=2;
  else if(reason==='member')f.setMembers[0].user_id=f.actor;
  else if(reason==='set')f.set.set_hmac='0'.repeat(64);
  else f.state.invalidated=true;
  await expect(f.read()).rejects.toBeDefined();expect(f.reviewer).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['role','team']as const)('rechecks current %s candidate provenance',async selector=>{
  const f=await fixture(selector);f.state[selector==='role'?'roleLive':'teamLive']=false;
  await expect(f.read()).rejects.toBeDefined();expect(f.reviewer).not.toHaveBeenCalled();
 });
 it('retains the epoch check spanning the full SQL observation',async()=>{
  const f=await fixture();f.state.afterSql=async(sql:string)=>{if(sql.includes('FROM workflow_approval_invalidations'))f.tables.iam_epoch[0].version='2';};
  await expect(f.read()).rejects.toBeDefined();expect(f.reviewer).not.toHaveBeenCalled();
 });
 it('cannot reuse an already consumed gate or lend the reader to a different workflow kind',async()=>{
  const f=await fixture();await f.read();await expect(f.read()).rejects.toBeDefined();
  await expect(f.reader(f.original,{...f.plan,kind:'configuration_v2'},{checkpoint:'packet'},f.db)).rejects.toBeDefined();
 });
 it('keeps the public full-verification path mandatory and independent of the new SQL reader',async()=>{
  const f=await fixture();await expect(f.approval.verifyApprovalSet(f.plan,{checkpoint:'packet'},f.db)).rejects.toThrow('SQL_CLOSING_MUST_NOT_ENTER_NATIVE_REVIEWER');
  expect(f.reviewer).toHaveBeenCalledTimes(1);
 });
});
