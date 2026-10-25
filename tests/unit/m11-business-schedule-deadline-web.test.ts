import {afterEach,describe,expect,it,vi} from 'vitest';
import {businessAuthorBody,businessCanCommand,businessDeadlineLocalMax} from '../../apps/console-web/src/api/workflow-business-schedules.model';
const id=(n:number)=>`7d000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const identity={actor:id(1),cid:id(2),wid:id(3),version:'deadline-PV'};
const now=Date.parse('2026-10-15T12:00:00.000Z');
const spec={notBefore:'2026-10-15T12:05:00.000Z',windowStart:'2026-10-15T12:04:00.000Z',windowEnd:'2026-10-15T12:10:00.000Z'};
function fixture(){
 const row:any={id:id(4),workflowId:id(5),workflowPlanRevision:2,workflowPlanHash:'b'.repeat(64),state:'pending-approval',claimId:null,executorId:identity.actor,...spec};
 const workflow:any={id:row.workflowId,clusterId:identity.cid,workspaceId:identity.wid,revision:2,planRevision:row.workflowPlanRevision,planHash:row.workflowPlanHash,state:'approved',expiresAt:spec.windowEnd,approval:{format:2,approvalSetId:id(6),stages:[{state:'approved'}]}};
 const user:any={id:identity.actor,permissionsVersion:identity.version,forcePasswordChange:false,capabilities:{platformAdmin:false,grants:[{module:'workflows',action:'write',cluster_id:identity.cid,workspace_id:identity.wid,scope_type:'workspace',scope_values:[identity.wid]}]}};
 return{row,workflow,user};
}
afterEach(()=>{vi.unstubAllEnvs();vi.useRealTimers();});
describe('business scheduling honors the real server deadline',()=>{
 it.each([
  ['UTC','2026-10-15T12:10:00'],
  ['Asia/Shanghai','2026-10-15T20:10:00'],
  ['America/Los_Angeles','2026-10-15T05:10:00'],
 ])('renders the same deadline in browser timezone %s without moving it', (zone,expected)=>{vi.stubEnv('TZ',zone);expect(businessDeadlineLocalMax('2026-10-15T12:10:00.999Z')).toBe(expected);});
 it('uses the local day across UTC day boundaries',()=>{vi.stubEnv('TZ','Asia/Shanghai');expect(businessDeadlineLocalMax('2026-10-15T23:59:59.999Z')).toBe('2026-10-16T07:59:59');});
 it('does not synthesize a deadline when the server field is invalid',()=>{expect(businessDeadlineLocalMax('')).toBeUndefined();expect(businessDeadlineLocalMax('not-a-deadline')).toBeUndefined();});
 it('accepts a window ending exactly at the original deadline without extending it',()=>{vi.useFakeTimers();vi.setSystemTime(now);const f=fixture();expect(businessAuthorBody(f.workflow,spec).spec.windowEnd).toBe(f.workflow.expiresAt);expect(businessCanCommand(f.row,f.workflow,f.user,identity,'activate',now)).toBe(true);});
 it('rechecks the latest server deadline before author submission',()=>{vi.useFakeTimers();vi.setSystemTime(now);const f=fixture();expect(businessAuthorBody(f.workflow,spec).spec).toEqual(spec);f.workflow.expiresAt='2026-10-15T12:09:59.999Z';expect(()=>businessAuthorBody(f.workflow,spec)).toThrow('窗口结束不能超过工单有效期');});
 it.each(['2026-10-15T12:00:00.000Z','2026-10-15T12:09:59.999Z','invalid'])('refuses activation after the real deadline becomes %s',expiresAt=>{const f=fixture();f.workflow.expiresAt=expiresAt;expect(businessCanCommand(f.row,f.workflow,f.user,identity,'activate',now)).toBe(false);});
 it('does not confuse safe cancellation with rollback or renew an expired workflow',()=>{const f=fixture();f.workflow.expiresAt='2026-10-15T12:00:00.000Z';expect(businessCanCommand(f.row,f.workflow,f.user,identity,'cancel',now)).toBe(true);for(const state of ['claimed','running','partial','uncertain','succeeded'])expect(businessCanCommand({...f.row,state},f.workflow,f.user,identity,'cancel',now)).toBe(false);expect(f.workflow.expiresAt).toBe('2026-10-15T12:00:00.000Z');});
});
