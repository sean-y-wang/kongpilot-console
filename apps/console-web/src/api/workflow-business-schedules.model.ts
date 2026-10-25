import { canonicalId } from './workspace-scope';
import type { User, PermissionAction } from './types';
import type { Workflow } from '../features/portal.types';

export const businessScheduleLabels: Record<string,string> = { 'pending-approval':'待审批',active:'已激活',claimed:'已领取',running:'执行中',succeeded:'已完成',partial:'部分完成',failed:'执行失败',uncertain:'待核验',blocked:'已阻止',cancelled:'已撤销',expired:'已过期' };
export const businessScheduleKinds = { configuration_v2:'配置变更', 'portal-credential-issue':'凭证发放' } as const;
export interface BusinessScheduleIdentity { actor:string; cid:string; wid:string; version:string; }
export interface BusinessSchedule { id:string;revision:number;state:string;kind:keyof typeof businessScheduleKinds;workflowId:string;workflowPlanRevision:number;workflowPlanHash:string;requesterType:'console'|'developer';requesterId:string;executorId:string;notBefore:string;windowStart:string;windowEnd:string;claimId:string|null;reasonCode:string|null;nativeAuthority:false; }
export interface BusinessScheduleSpec { notBefore:string;windowStart:string;windowEnd:string; }
export interface BusinessScheduleAttempt extends BusinessScheduleIdentity { key:string;action:'author'|'activate'|'cancel';workflowId:string;planRevision:number;planHash:string;revision:number;kind:BusinessSchedule['kind'];spec?:BusinessScheduleSpec;schedule?:BusinessSchedule;state:'pending'|'unknown'; }
const hex=/^[a-f\d]{64}$/,positive=(n:unknown):n is number=>typeof n==='number'&&Number.isSafeInteger(n)&&n>0;
const fail=()=>{throw new Error('业务排程记录或操作范围无效。');};
const iso=(value:unknown):string=>{if(typeof value!=='string'||!Number.isFinite(Date.parse(value))||new Date(value).toISOString()!==value)fail();return value as string;};
export function validBusinessIdentity(value:BusinessScheduleIdentity):boolean {return ['actor','cid','wid'].every(k=>canonicalId(value[k as keyof BusinessScheduleIdentity])===value[k as keyof BusinessScheduleIdentity])&&typeof value.version==='string'&&!!value.version&&value.version.length<=256;}
export function sameBusinessIdentity(a:BusinessScheduleIdentity,b:BusinessScheduleIdentity):boolean{return validBusinessIdentity(a)&&validBusinessIdentity(b)&&['actor','cid','wid','version'].every(k=>a[k as keyof BusinessScheduleIdentity]===b[k as keyof BusinessScheduleIdentity]);}
export function businessWholeWorkspace(user:User,identity:BusinessScheduleIdentity,action:PermissionAction):boolean {
 if(!validBusinessIdentity(identity)||user.id!==identity.actor||user.permissionsVersion!==identity.version||user.forcePasswordChange||!user.capabilities||!Array.isArray(user.capabilities.grants))return false;
 return user.capabilities.platformAdmin===true||user.capabilities.grants.some(g=>g.module==='workflows'&&g.action===action&&(g.cluster_id===null||g.cluster_id===identity.cid)&&(g.workspace_id===null||g.workspace_id===identity.wid)
  &&Array.isArray(g.scope_values)&&(g.scope_type==='global'&&g.scope_values.length===0||g.scope_type==='workspace'&&g.cluster_id===identity.cid&&g.workspace_id===identity.wid&&g.scope_values.length===1&&g.scope_values[0]===identity.wid));
}
export function normalizeBusinessSchedule(raw:any):BusinessSchedule {
 if(!raw||!['id','workflowId','requesterId','executorId'].every(k=>canonicalId(raw[k])===raw[k])||!positive(raw.revision)||!positive(raw.workflowPlanRevision)||!hex.test(raw.workflowPlanHash??'')
  ||!Object.hasOwn(businessScheduleLabels,raw.state)||!Object.hasOwn(businessScheduleKinds,raw.kind)||!['console','developer'].includes(raw.requesterType)||raw.nativeAuthority!==false
  ||raw.claimId!==null&&canonicalId(raw.claimId)!==raw.claimId||raw.reasonCode!==null&&(typeof raw.reasonCode!=='string'||!/^[A-Z0-9_]{1,100}$/.test(raw.reasonCode)))fail();
 const spec={notBefore:iso(raw.notBefore),windowStart:iso(raw.windowStart),windowEnd:iso(raw.windowEnd)};
 if(Date.parse(spec.windowStart)>Date.parse(spec.notBefore)||Date.parse(spec.notBefore)>=Date.parse(spec.windowEnd))fail();
 return {id:raw.id,revision:raw.revision,state:raw.state,kind:raw.kind,workflowId:raw.workflowId,workflowPlanRevision:raw.workflowPlanRevision,workflowPlanHash:raw.workflowPlanHash,requesterType:raw.requesterType,requesterId:raw.requesterId,executorId:raw.executorId,...spec,claimId:raw.claimId,reasonCode:raw.reasonCode,nativeAuthority:false};
}
/** datetime-local uses the browser timezone; its ceiling is the real server deadline. */
export function businessDeadlineLocalMax(expiresAt:string):string|undefined {
 const date=new Date(expiresAt),year=date.getFullYear();
 if(!Number.isFinite(date.getTime())||year<1||year>9999)return;
 const pad=(value:number)=>String(value).padStart(2,'0');
 return `${String(year).padStart(4,'0')}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
export function validateBusinessSpec(value:BusinessScheduleSpec,expiresAt:string,now=Date.now()):BusinessScheduleSpec {
 const spec={notBefore:iso(value.notBefore),windowStart:iso(value.windowStart),windowEnd:iso(value.windowEnd)},start=Date.parse(spec.windowStart),due=Date.parse(spec.notBefore),end=Date.parse(spec.windowEnd),expiry=Date.parse(expiresAt);
 if(!Number.isFinite(expiry)||due<=now||start>due||due>=end||end>expiry)throw new Error('执行时间需在有效变更窗口内，窗口结束不能超过工单有效期。');return spec;
}
export function businessCanAuthor(row:Workflow|undefined,user:User,identity:BusinessScheduleIdentity,now=Date.now()):boolean {
 return !!row&&row.clusterId===identity.cid&&row.workspaceId===identity.wid&&canonicalId(row.id)===row.id&&positive(row.revision)&&positive(row.planRevision)&&hex.test(row.planHash)&&Object.hasOwn(businessScheduleKinds,row.kind)
  &&row.state==='pending'&&row.scheduled!==true&&row.approvalRequired===true&&(row.kind==='configuration_v2'?row.executionMode==='approval':['direct','approval'].includes(row.executionMode))&&row.approval?.format===2&&Array.isArray(row.approval.stages)&&row.approval.stages.length>0&&row.approval.stages.every(s=>s.votes===0&&['active','pending'].includes(s.state))
  &&Array.isArray(row.decisions)&&row.decisions.length===0&&Array.isArray(row.steps)&&row.steps.length>0&&row.steps.every(s=>s.state==='pending')&&Date.parse(row.expiresAt)>now&&businessWholeWorkspace(user,identity,'write');
}
export function businessCanCommand(row:BusinessSchedule,workflow:Workflow|undefined,user:User,identity:BusinessScheduleIdentity,action:'activate'|'cancel',now=Date.now()):boolean {
 if(!workflow||workflow.id!==row.workflowId||workflow.clusterId!==identity.cid||workflow.workspaceId!==identity.wid||workflow.planRevision!==row.workflowPlanRevision||workflow.planHash!==row.workflowPlanHash||row.claimId!==null||Date.parse(row.windowEnd)<=now)return false;
 if(action==='cancel')return row.executorId===identity.actor&&['pending-approval','active'].includes(row.state)&&businessWholeWorkspace(user,identity,'write');
 return Date.parse(workflow.expiresAt)>now&&Date.parse(row.windowEnd)<=Date.parse(workflow.expiresAt)&&row.state==='pending-approval'&&workflow.state==='approved'&&workflow.approval?.format===2&&!!canonicalId(workflow.approval.approvalSetId)&&Array.isArray(workflow.approval.stages)&&workflow.approval.stages.length>0&&workflow.approval.stages.every(s=>s.state==='approved')&&businessWholeWorkspace(user,identity,row.executorId===identity.actor?'write':'approve');
}
export function businessAuthorBody(row:Workflow,spec:BusinessScheduleSpec){return{workflowId:row.id,revision:row.revision,planRevision:row.planRevision,planHash:row.planHash,spec:validateBusinessSpec(spec,row.expiresAt),confirmed:true as const,confirm_name:'schedule-workflow'};}
export function businessCommandBody(row:BusinessSchedule,action:'activate'|'cancel'){return{revision:row.revision,confirmed:true as const,confirm_name:`${action}-schedule`};}
export function businessReceiptMatches(raw:any,attempt:BusinessScheduleAttempt,current:BusinessSchedule,workflow:Workflow):boolean {
 if(raw?.commandCompleted!==true)return false;
 let received:BusinessSchedule;try{received=normalizeBusinessSchedule(raw.entity);}catch{return false;}
 if(received.workflowId!==attempt.workflowId||received.kind!==attempt.kind||workflow.id!==received.workflowId||workflow.clusterId!==attempt.cid||workflow.workspaceId!==attempt.wid
  ||workflow.planRevision!==received.workflowPlanRevision||workflow.planHash!==received.workflowPlanHash||current.id!==received.id||current.revision<received.revision)return false;
 const fixed=['id','kind','workflowId','workflowPlanRevision','workflowPlanHash','requesterType','requesterId','executorId','notBefore','windowStart','windowEnd'] as const;
 if(fixed.some(k=>received[k]!==current[k]))return false;
 if(attempt.action==='author')return received.state==='pending-approval'&&received.workflowPlanRevision===attempt.planRevision+1&&received.workflowPlanHash!==attempt.planHash&&received.executorId===attempt.actor&&!!attempt.spec
  &&Object.entries(attempt.spec).every(([k,v])=>received[k as keyof BusinessSchedule]===v);
 return !!attempt.schedule&&received.id===attempt.schedule.id&&received.workflowPlanRevision===attempt.planRevision&&received.workflowPlanHash===attempt.planHash&&received.revision>attempt.revision
  &&received.state===(attempt.action==='activate'?'active':'cancelled')&&fixed.every(k=>received[k]===attempt.schedule![k]);
}
function keyFor(identity:BusinessScheduleIdentity):string {if(!validBusinessIdentity(identity))fail();return`kongpilot.businessScheduleAttempt:${identity.actor}:${identity.cid}:${identity.wid}`;}
function cleanAttempt(value:any):BusinessScheduleAttempt {
 if(!value||!validBusinessIdentity(value)||canonicalId(value.key)!==value.key||canonicalId(value.workflowId)!==value.workflowId||!positive(value.revision)||!positive(value.planRevision)||!hex.test(value.planHash??'')
  ||!['author','activate','cancel'].includes(value.action)||!['pending','unknown'].includes(value.state)||!Object.hasOwn(businessScheduleKinds,value.kind))fail();
 const result:BusinessScheduleAttempt={actor:value.actor,cid:value.cid,wid:value.wid,version:value.version,key:value.key,workflowId:value.workflowId,revision:value.revision,planRevision:value.planRevision,planHash:value.planHash,action:value.action,kind:value.kind,state:value.state};
 if(result.action==='author'){if(!value.spec)fail();result.spec={notBefore:iso(value.spec.notBefore),windowStart:iso(value.spec.windowStart),windowEnd:iso(value.spec.windowEnd)};}
 else{result.schedule=normalizeBusinessSchedule(value.schedule);if(result.schedule.workflowId!==result.workflowId||result.schedule.workflowPlanRevision!==result.planRevision||result.schedule.workflowPlanHash!==result.planHash||result.schedule.revision!==result.revision)fail();}
 return result;
}
export function readBusinessAttempt(identity:BusinessScheduleIdentity):BusinessScheduleAttempt|undefined {
 const raw=sessionStorage.getItem(keyFor(identity));if(raw===null)return;
 let attempt:BusinessScheduleAttempt;try{attempt=cleanAttempt(JSON.parse(raw));}catch{throw new Error('原排程请求记录损坏，请先核验审计记录。');}
 if(attempt.actor!==identity.actor||attempt.cid!==identity.cid||attempt.wid!==identity.wid)fail();return attempt;
}
export function storeBusinessAttempt(value:BusinessScheduleAttempt):void {const safe=cleanAttempt(value),previous=readBusinessAttempt(value);if(previous&&(JSON.stringify({...previous,state:'pending'})!==JSON.stringify({...safe,state:'pending'})))throw new Error('原请求尚未核验，不能创建新的请求键。');sessionStorage.setItem(keyFor(safe),JSON.stringify(safe));}
export function clearBusinessAttempt(identity:BusinessScheduleIdentity,key:string):void {const old=readBusinessAttempt(identity);if(!old||old.key!==key)fail();sessionStorage.removeItem(keyFor(identity));}
