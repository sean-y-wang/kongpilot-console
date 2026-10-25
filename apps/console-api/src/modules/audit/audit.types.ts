import { BadRequestException } from '@nestjs/common';
import type { HistoricalScope } from '../authorization/historical-scope-policy';
import { HISTORY_UUID } from '../authorization/historical-scope-policy';

export interface AuditScope {clusterId:string|null;workspaceId:string|null;mode:'global'|'cluster'|'workspace'}
export interface AuditFilter {
  actorId:string|null;entityType:string|null;entityId:string|null;action:string|null;result:string|null;
  workflowId:string|null;requestId:string|null;from:string|null;to:string|null;
}
export interface AuditQuery extends AuditScope {filter:AuditFilter;size:number;cursor?:string}
export interface AuditRow {
  id:string;chain_scope:string;sequence:string;actor_id:string|null;actor_type:string;source_ip:string|null;
  cluster_id:string|null;workspace_id:string|null;entity_type:string;entity_id:string|null;action:string;
  before:unknown;after:unknown;json_patch:unknown;workflow_id:string|null;result:string;request_id:string|null;
  prev_hash:string;event_hash:string;occurred_at:Date|string;
  millisecond_precision?:boolean;record_bytes?:number;
  history_scope:HistoricalScope|null;history_scope_hmac:string|null;history_audit_hash:string|null;
}
export interface AuditSafeView {
  id:string;actorId:string|null;actorType:string;sourceIp:string|null;clusterId:string|null;workspaceId:string|null;
  entityType:string;entityId:string|null;action:string;before:unknown;after:unknown;jsonPatch:unknown;
  workflowId:string|null;result:string;requestId:string|null;occurredAt:string;scopeQuality:'verified'|'legacy_unknown';
}
export interface AuditPage {items:AuditSafeView[];nextCursor:string|null;size:number;total:null;scanLimitReached:boolean}
export const AUDIT_SELECT = `a.*,a.sequence::text AS sequence,
  (a.occurred_at=date_trunc('milliseconds',a.occurred_at)) AS millisecond_precision,
  octet_length(row_to_json(a)::text) AS record_bytes,
  s.scope AS history_scope,s.scope_hmac AS history_scope_hmac,s.audit_event_hash AS history_audit_hash`;
export const AUDIT_SCOPE_JOIN = 'LEFT JOIN audit_event_scopes s ON s.audit_event_id=a.id';
export const AUDIT_READ_MAX_ROWS=1000;
export const AUDIT_READ_MAX_BYTES=2*1024*1024;
export const AUDIT_EXPORT_MAX_ROWS=100000;
export const AUDIT_EXPORT_MAX_BYTES=32*1024*1024;

export function auditInvalid(message='审计查询参数无效'):BadRequestException {
  return new BadRequestException({code:'INVALID_AUDIT_QUERY',message});
}
export function auditUuid(value:unknown):string {
  if(typeof value!=='string'||!HISTORY_UUID.test(value))throw auditInvalid('审计范围或对象 ID 无效');return value;
}
function text(value:unknown,max=256):string|null {
  if(value===undefined||value===null||value==='')return null;
  if(typeof value!=='string'||value.length>max||/[\u0000-\u001f\u007f]/.test(value))throw auditInvalid();return value;
}
function date(value:unknown):string|null {
  const raw=text(value,40);if(raw===null)return null;
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(raw)||!Number.isFinite(Date.parse(raw)))throw auditInvalid('时间必须为有效 UTC ISO 格式');
  const normalized=new Date(raw).toISOString();if(normalized.slice(0,19)!==raw.slice(0,19))throw auditInvalid('时间日期无效');return normalized;
}
export function auditScope(clusterId:string|null,query:Record<string,unknown>,strict=true):AuditScope {
  if(strict&&Object.keys(query).some(key=>!['scope','workspaceId'].includes(key)))throw auditInvalid();
  if(clusterId===null){if(query.workspaceId!==undefined||query.scope!==undefined&&query.scope!=='global')throw auditInvalid();return {clusterId:null,workspaceId:null,mode:'global'};}
  auditUuid(clusterId);
  const workspaceId=query.workspaceId===undefined?null:auditUuid(query.workspaceId);
  const mode=query.scope??(workspaceId?'workspace':null);
  if(mode==='workspace'&&workspaceId)return {clusterId,workspaceId,mode};
  if(mode==='cluster'&&workspaceId===null)return {clusterId,workspaceId:null,mode};
  throw auditInvalid('请选择工作区，或显式指定完整集群审计范围');
}
export function auditQuery(clusterId:string|null,value:unknown):AuditQuery {
  if(!value||typeof value!=='object'||Array.isArray(value))throw auditInvalid();
  const raw=value as Record<string,unknown>;
  const allowed=new Set(['scope','workspaceId','actorId','entityType','entityId','action','result','workflowId','requestId','from','to','size','cursor']);
  if(Object.keys(raw).some(key=>!allowed.has(key)))throw auditInvalid();
  const size=raw.size===undefined?20:Number(raw.size);
  if(!Number.isInteger(size)||size<1||size>100)throw auditInvalid('每页条数应为 1–100');
  const filter:AuditFilter={actorId:raw.actorId===undefined?null:auditUuid(raw.actorId),entityType:text(raw.entityType,64),
    entityId:text(raw.entityId),action:text(raw.action,128),result:text(raw.result,64),
    workflowId:raw.workflowId===undefined?null:auditUuid(raw.workflowId),requestId:text(raw.requestId,128),
    from:date(raw.from),to:date(raw.to)};
  if(filter.from&&filter.to&&filter.from>filter.to)throw auditInvalid('开始时间不能晚于结束时间');
  const cursor=text(raw.cursor,24576)??undefined;
  return {...auditScope(clusterId,raw,false),filter,size,cursor};
}
