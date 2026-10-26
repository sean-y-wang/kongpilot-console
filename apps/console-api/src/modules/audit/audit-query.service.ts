import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { HistoricalEventAccessService } from '../authorization/historical-event-access.service';
import type { AuthorizationSnapshot } from '../authorization/authorization.service';
import { jsonDiff } from './audit.service';
import { AuditCursorService } from './audit-cursor.service';
import { AUDIT_READ_MAX_BYTES, AUDIT_READ_MAX_ROWS, AUDIT_SCOPE_JOIN, AUDIT_SELECT,
  type AuditPage,type AuditQuery,type AuditRow,type AuditSafeView,type AuditScope,auditInvalid,auditUuid } from './audit.types';

export interface AuditListState {from:string;to:string;upperSequence:string;last:{time:string;id:string}|null}
export interface AuditCapturedQuery {query:AuditQuery;state:AuditListState;permissionVersion:string}
const denied=()=>new ForbiddenException({code:'PERMISSION_DENIED',message:'当前审计权限已变更'});
const date=(value:Date|string):string=>new Date(value).toISOString();
function cascadeCounts(value:unknown):unknown {
  if(Array.isArray(value))return value.map(cascadeCounts);
  if(!value||typeof value!=='object')return value;
  return Object.fromEntries(Object.entries(value).map(([key,child])=>[
    key,['deleted','restored','archived','affected','nodes','children'].includes(key)&&Array.isArray(child)
      ?{count:child.length}:cascadeCounts(child)]));
}

@Injectable()
export class AuditQueryService {
  constructor(private readonly db:DbService,private readonly secrets:SecretService,
    private readonly access:HistoricalEventAccessService,private readonly cursors:AuditCursorService){}

  private binding(user:AuthUser,version:string,query:AuditQuery){
    return {actorId:user.id,permissionVersion:version,scope:{clusterId:query.clusterId,workspaceId:query.workspaceId,mode:query.mode},filter:query.filter,size:query.size};
  }
  async capture(user:AuthUser,query:AuditQuery):Promise<AuditCapturedQuery>{
    const snapshot=await this.access.assertAuditScope(user,query);
    const head=await this.db.one<{last_sequence:string}>('SELECT last_sequence::text FROM audit_chain_heads WHERE chain_scope=$1',
      [query.clusterId?`cluster:${query.clusterId}`:'global']);
    const to=query.filter.to??new Date().toISOString();
    const from=query.filter.from??new Date(Date.parse(to)-7*86400000).toISOString();
    const state:AuditListState={from,to,upperSequence:head?.last_sequence??'0',last:null};
    if(!/^\d+$/.test(state.upperSequence)||from>to)throw auditInvalid();
    if(await this.access.permissionVersion(user)!==snapshot.version)throw denied();
    return {query:{...query,cursor:undefined},state,permissionVersion:snapshot.version};
  }
  async list(user:AuthUser,query:AuditQuery):Promise<AuditPage>{
    const snapshot=await this.access.assertAuditScope(user,query);
    let state:AuditListState;
    if(query.cursor)state=this.cursors.open<AuditListState>('list',this.binding(user,snapshot.version,query),query.cursor);
    else state=(await this.capture(user,query)).state;
    this.validateState(state);
    return this.page(user,query,state,snapshot);
  }
  async capturedPage(user:AuthUser,captured:AuditCapturedQuery):Promise<{page:AuditPage;state:AuditListState;scannedRows:number}>{
    const snapshot=await this.access.assertAuditScope(user,captured.query);
    if(snapshot.version!==captured.permissionVersion)throw denied();
    const state=structuredClone(captured.state);
    const stats={scannedRows:0};const page=await this.page(user,captured.query,state,snapshot,stats);
    return {page,state,scannedRows:stats.scannedRows};
  }
  private validateState(state:AuditListState):void {
    if(!state||!/^\d+$/.test(state.upperSequence)||!Number.isFinite(Date.parse(state.from))
      ||!Number.isFinite(Date.parse(state.to))||state.from>state.to
      ||state.last&&(!Number.isFinite(Date.parse(state.last.time))||!auditUuid(state.last.id)))throw auditInvalid('审计分页状态无效');
  }
  async page(user:AuthUser,query:AuditQuery,state:AuditListState,snapshot:AuthorizationSnapshot,stats?:{scannedRows:number}):Promise<AuditPage>{
    let scanned=0,bytes=0,end=false,budget=false;const items:AuditSafeView[]=[];
    const whole=this.access.isWholeAudit(snapshot,query.clusterId);
    while(items.length<query.size&&scanned<AUDIT_READ_MAX_ROWS&&bytes<AUDIT_READ_MAX_BYTES){
      const params:unknown[]=[];
      const add=(value:unknown)=>{params.push(value);return `$${params.length}`;};
      const where=[`a.cluster_id IS NOT DISTINCT FROM ${add(query.clusterId)}::uuid`,
        `a.sequence<=${add(state.upperSequence)}::bigint`,`a.occurred_at>=${add(state.from)}::timestamptz`,
        `a.occurred_at<=${add(state.to)}::timestamptz`];
      if(query.mode==='global')where.push('a.workspace_id IS NULL');
      if(query.mode==='workspace')where.push(`a.workspace_id=${add(query.workspaceId)}::uuid`);
      const cols={actorId:'actor_id',entityType:'entity_type',entityId:'entity_id',action:'action',result:'result',workflowId:'workflow_id',requestId:'request_id'};
      for(const [key,col]of Object.entries(cols)){const value=query.filter[key as keyof typeof cols];if(value!==null)where.push(`a.${col}=${add(value)}`);}
      if(state.last)where.push(`(a.occurred_at,a.id)<(${add(state.last.time)}::timestamptz,${add(state.last.id)}::uuid)`);
      const limit=Math.min(100,AUDIT_READ_MAX_ROWS-scanned);
      const rows=await this.db.query<AuditRow>(`SELECT ${AUDIT_SELECT} FROM audit_events a ${AUDIT_SCOPE_JOIN}
        WHERE ${where.join(' AND ')} ORDER BY a.occurred_at DESC,a.id DESC LIMIT ${add(limit)}`,params);
      if(!rows.length){end=true;break;}
      for(const row of rows){
        const rowBytes=Number(row.record_bytes??Buffer.byteLength(canonicalJson(row)));
        if(!Number.isFinite(rowBytes)||rowBytes<0)throw auditInvalid('审计记录大小无效');
        if(bytes+rowBytes>AUDIT_READ_MAX_BYTES){
          // A single oversize row is not silently skipped; the caller receives an explicit error.
          if(scanned===0)throw auditInvalid('单条审计记录超过读取预算');
          budget=true;break;
        }
        bytes+=rowBytes;scanned++;state.last={time:date(row.occurred_at),id:row.id};
        if(this.access.canAuditReadSnapshot(snapshot,row))items.push(this.safeView(row,whole));
        if(items.length===query.size)break;
      }
      if(budget||items.length===query.size)break;
      if(rows.length<limit){end=true;break;}
    }
    budget ||= !end&&items.length<query.size&&(scanned>=AUDIT_READ_MAX_ROWS||bytes>=AUDIT_READ_MAX_BYTES);
    if(await this.access.permissionVersion(user)!==snapshot.version)throw denied();
    if(stats)stats.scannedRows=scanned;
    const nextCursor=end||!state.last?null:this.cursors.seal('list',this.binding(user,snapshot.version,query),state);
    return {items,nextCursor,size:query.size,total:null,scanLimitReached:budget};
  }
  /** Display-only: attach the current username of user actors (one batched read).
   * Kept out of safeView so exports and integrity material stay unchanged. */
  async withActorNames<T extends {actorId:string|null;actorType:string}>(views:T[]):Promise<(T&{actorUsername?:string})[]>{
    const ids=[...new Set(views.filter(v=>v.actorType==='user'&&v.actorId).map(v=>v.actorId as string))];
    if(!ids.length)return views;
    const rows=await this.db.query<{id:string;username:string}>('SELECT id,username FROM users WHERE id=ANY($1::uuid[])',[ids]).catch(()=>[]);
    const names=new Map(rows.map(r=>[r.id,r.username]));
    return views.map(v=>v.actorType==='user'&&v.actorId&&names.has(v.actorId)?{...v,actorUsername:names.get(v.actorId)}:v);
  }
  safeView(row:AuditRow,whole:boolean):AuditSafeView {
    const before=this.secrets.redact(whole?row.before:cascadeCounts(row.before));
    const after=this.secrets.redact(whole?row.after:cascadeCounts(row.after));
    return {id:row.id,actorId:row.actor_id,actorType:row.actor_type,sourceIp:row.source_ip,
      clusterId:row.cluster_id,workspaceId:row.workspace_id,entityType:row.entity_type,entityId:row.entity_id,
      action:row.action,before,after,jsonPatch:jsonDiff(before,after),workflowId:row.workflow_id,
      result:row.result,requestId:row.request_id,occurredAt:date(row.occurred_at),
      scopeQuality:row.history_scope?.quality??'legacy_unknown'};
  }
  async get(user:AuthUser,scope:AuditScope,id:string):Promise<AuditSafeView>{
    auditUuid(id);const snapshot=await this.access.assertAuditScope(user,scope);
    const row=await this.db.one<AuditRow>(`SELECT ${AUDIT_SELECT} FROM audit_events a ${AUDIT_SCOPE_JOIN}
      WHERE a.id=$1 AND a.cluster_id IS NOT DISTINCT FROM $2::uuid
      AND ($3::text<>'workspace' OR a.workspace_id=$4::uuid)
      AND ($3::text<>'global' OR a.workspace_id IS NULL)`,[id,scope.clusterId,scope.mode,scope.workspaceId]);
    if(!row)throw new NotFoundException({code:'AUDIT_EVENT_NOT_FOUND',message:'审计记录不存在'});
    if(!this.access.canAuditReadSnapshot(snapshot,row))throw new ForbiddenException({code:'PERMISSION_DENIED',message:'无此审计记录读取权限'});
    const view=this.safeView(row,this.access.isWholeAudit(snapshot,scope.clusterId));
    if(await this.access.permissionVersion(user)!==snapshot.version)throw denied();return view;
  }
}
