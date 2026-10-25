import { api, ApiError, getApiActorId } from './client';
import { canonicalId, scopeQuery } from './workspace-scope';
import type { Session } from './types';
import { normalizeWorkflowDetail, type Workflow } from '../features/portal.types';
import { normalizeBusinessSchedule, validBusinessIdentity, type BusinessSchedule, type BusinessScheduleIdentity } from './workflow-business-schedules.model';
export function businessSchedulePath(identity:BusinessScheduleIdentity,resource='',query?:URLSearchParams):string {
 if(!validBusinessIdentity(identity)||resource&&!/^(?:[a-f\d-]{36}(?:\/(?:activate|cancel))?|receipts\/by-key\/[a-f\d-]{36})$/.test(resource)||resource&&(resource.startsWith('receipts/by-key/')?canonicalId(resource.slice(16))!==resource.slice(16):canonicalId(resource.split('/')[0])!==resource.split('/')[0]))throw new Error('业务排程请求范围无效。');
 return scopeQuery(`/clusters/${identity.cid}/workflow-schedules${resource?`/${resource}`:''}${query?.size?`?${query}`:''}`,identity.cid,identity.wid);
}
export async function freshBusinessSession(identity:BusinessScheduleIdentity,signal?:AbortSignal):Promise<Session>{
 const current=await api<Session>('/auth/me',{signal},true);
 if(signal?.aborted||getApiActorId()!==identity.actor||current?.user?.id!==identity.actor||current.user.permissionsVersion!==identity.version||current.user.forcePasswordChange
  ||typeof current.csrfToken!=='string'||current.csrfToken.length<16||current.csrfToken.length>128)throw new ApiError('账号或权限已变化，请重新审阅。',409,'BUSINESS_SCHEDULE_SCOPE_CHANGED');return current;
}
export async function fetchBusinessWorkflow(identity:BusinessScheduleIdentity,id:string,signal?:AbortSignal):Promise<Workflow>{
 if(canonicalId(id)!==id)throw new Error('工单标识无效。');
 const row=normalizeWorkflowDetail(await api(scopeQuery(`/clusters/${identity.cid}/workflows/${id}`,identity.cid,identity.wid),{signal},true));
 if(signal?.aborted||getApiActorId()!==identity.actor||row.id!==id||row.clusterId!==identity.cid||row.workspaceId!==identity.wid)throw new ApiError('工单范围已变化。',409,'BUSINESS_SCHEDULE_SCOPE_CHANGED');return row;
}
export async function fetchBusinessSchedule(identity:BusinessScheduleIdentity,id:string,signal?:AbortSignal):Promise<BusinessSchedule>{
 const raw=await api<{entity:unknown}>(businessSchedulePath(identity,id),{signal},true),row=normalizeBusinessSchedule(raw?.entity);
 if(signal?.aborted||getApiActorId()!==identity.actor||row.id!==id)throw new ApiError('排程范围已变化。',409,'BUSINESS_SCHEDULE_SCOPE_CHANGED');return row;
}
export async function fetchBusinessSchedulePage(identity:BusinessScheduleIdentity,cursor?:string,signal?:AbortSignal){
 if(cursor!==undefined&&(typeof cursor!=='string'||!cursor||cursor.length>4096))throw new Error('分页游标无效。');
 const q=new URLSearchParams({size:'20'});if(cursor)q.set('cursor',cursor);
 const raw=await api<any>(businessSchedulePath(identity,'',q),{signal},true);
 if(signal?.aborted||getApiActorId()!==identity.actor||!raw||!Array.isArray(raw.items)||raw.items.length>20||raw.size!==20||raw.total!==null||raw.nextCursor!==null&&(typeof raw.nextCursor!=='string'||!raw.nextCursor||raw.nextCursor.length>4096))throw new Error('排程分页响应无效。');
 return {items:raw.items.map(normalizeBusinessSchedule)as BusinessSchedule[],size:20,total:null,nextCursor:raw.nextCursor as string|null};
}
export async function fetchBusinessScheduleReceipt(identity:BusinessScheduleIdentity,key:string):Promise<unknown>{
 if(canonicalId(key)!==key)throw new Error('原请求键无效。');
 const receipt=await api(businessSchedulePath(identity,`receipts/by-key/${key}`),{},true);
 if(getApiActorId()!==identity.actor)throw new ApiError('登录账号已切换。',409,'BUSINESS_SCHEDULE_SCOPE_CHANGED');return receipt;
}
/** Feature-owned one-shot metadata transport. A 401 never refreshes or repeats
 * this POST. A lost response leaves the original-key journal fenced. */
export async function postBusinessScheduleOnce(identity:BusinessScheduleIdentity,action:'author'|'activate'|'cancel',body:unknown,key:string,csrf:string,scheduleId?:string):Promise<unknown>{
 const value=body as any,fields=action==='author'?['workflowId','revision','planRevision','planHash','spec','confirmed','confirm_name']:['revision','confirmed','confirm_name'];
 if(!validBusinessIdentity(identity)||getApiActorId()!==identity.actor||canonicalId(key)!==key||typeof csrf!=='string'||csrf.length<16||csrf.length>128
  ||!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==fields.length||fields.some(k=>!Object.hasOwn(value,k))||value.confirmed!==true
  ||value.confirm_name!==(action==='author'?'schedule-workflow':`${action}-schedule`)||!Number.isSafeInteger(value.revision)||value.revision<1
  ||action!=='author'&&canonicalId(scheduleId)!==scheduleId)throw new Error('排程命令、确认信息或真实会话无效。');
 if(action==='author'&&(canonicalId(value.workflowId)!==value.workflowId||!Number.isSafeInteger(value.planRevision)||value.planRevision<1||!/^[a-f\d]{64}$/.test(value.planHash??'')
  ||!value.spec||Object.keys(value.spec).sort().join(',')!=='notBefore,windowEnd,windowStart'||Object.values(value.spec).some(v=>typeof v!=='string'||!Number.isFinite(Date.parse(v)))))throw new Error('排程计划或窗口无效。');
 const path=businessSchedulePath(identity,action==='author'?'':`${scheduleId}/${action}`);let response:Response;
 try{response=await fetch(`/api/v1${path}`,{method:'POST',credentials:'include',headers:{Accept:'application/json','Content-Type':'application/json','X-CSRF-Token':csrf,'X-Idempotency-Key':key},body:JSON.stringify(value)});}
 catch{throw new ApiError('排程请求结果尚未确认，请核验原回执。',0,'BUSINESS_SCHEDULE_REQUEST_UNKNOWN');}
 let payload:any;try{payload=await response.json();}catch{throw new ApiError('排程响应无法读取，请核验原回执。',response.status,'BUSINESS_SCHEDULE_REQUEST_UNKNOWN');}
 if(!payload||typeof payload!=='object'||Array.isArray(payload))throw new ApiError('排程响应无法读取，请核验原回执。',response.status,'BUSINESS_SCHEDULE_REQUEST_UNKNOWN');
 if(!response.ok){const code=typeof payload.error?.code==='string'&&/^[A-Z0-9_]{1,100}$/.test(payload.error.code)?payload.error.code:undefined;
  throw new ApiError(`排程操作未完成（HTTP ${response.status}${code?` · ${code}`:''}）。请核验原请求。`,response.status,response.status>=500?'BUSINESS_SCHEDULE_REQUEST_UNKNOWN':code,undefined,canonicalId(payload.meta?.requestId));}
 if(getApiActorId()!==identity.actor)throw new ApiError('账号已切换，原请求需由原账号核验。',409,'BUSINESS_SCHEDULE_REQUEST_UNKNOWN');
 return Object.hasOwn(payload,'data')?payload.data:payload;
}
