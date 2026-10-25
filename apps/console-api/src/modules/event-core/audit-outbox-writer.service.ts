import {Injectable} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import type {AuditOutboxReceipt,EventPayload,EventRecord,TrustedAuditScopeHints} from './event.types';
import {eventAuditScopeDigest,eventSourceScopeDigest,equalDigest,scopeFromHints,UUID} from './event-utils';
/** SQL-only transaction participant. Never obtains authorization or makes network requests. */
@Injectable()
export class AuditOutboxWriter {
 constructor(private readonly db:DbService,private readonly secrets:SecretService){}
 async fromAudit(receipt:AuditOutboxReceipt,hints:TrustedAuditScopeHints,tx:DbService):Promise<{eventId:string}|null> {
  const a=await tx.one<any>('SELECT * FROM audit_events WHERE id=$1',[receipt.id]);
  if(!a||a.chain_scope!==receipt.chainScope||String(a.sequence)!==receipt.sequence||!equalDigest(a.event_hash,receipt.eventHash)||new Date(a.occurred_at).toISOString()!==receipt.occurredAt)throw new Error('AUDIT_RECEIPT_INVALID');
  const scope=scopeFromHints(hints),digest=eventAuditScopeDigest(this.secrets,{auditEventId:a.id,auditEventHash:a.event_hash,clusterId:a.cluster_id,workspaceId:a.workspace_id,scope});
  await tx.exec('INSERT INTO audit_event_scopes(audit_event_id,audit_event_hash,cluster_id,workspace_id,scope,scope_hmac) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(audit_event_id) DO NOTHING',[a.id,a.event_hash,a.cluster_id,a.workspace_id,JSON.stringify(scope),digest]);
  const stored=await tx.one<any>('SELECT scope_hmac FROM audit_event_scopes WHERE audit_event_id=$1',[a.id]);if(!stored||!equalDigest(stored.scope_hmac,digest))throw new Error('AUDIT_SCOPE_CONFLICT');
  // Explicit queue actions are sealed by EventRepository, not duplicated here.
  const mapping=mapAuditEvent(a.action,a.result);if(!mapping)return null;
  const old=await tx.one<{id:string}>('SELECT id FROM event_records WHERE audit_event_id=$1 AND event_type=$2 AND phase=$3 AND occurrence_key=$4',[a.id,mapping.eventType,mapping.phase,'audit']);if(old)return {eventId:old.id};
  const id=randomUUID();const subject=scope.nativeType&&scope.nativeId?{type:scope.nativeType,id:scope.nativeId}:a.entity_id&&UUID.test(a.entity_id)?{type:a.entity_type,id:a.entity_id}:null;
  const text=await workflowEventText(tx,a.workflow_id,mapping);
  const payload:EventPayload={version:1,title:text.title,summary:text.summary,eventType:mapping.eventType,phase:mapping.phase,result:a.result,subject};
  const event:EventRecord={id,clusterId:a.cluster_id,workspaceId:a.workspace_id,eventType:mapping.eventType,phase:mapping.phase,sourceKind:'audit',sourceId:a.id,actorType:a.actor_id?'user':a.actor_type==='developer'?'developer':'system',actorId:a.actor_id,developerId:a.actor_type==='developer'&&scope.subject?.type==='portal_developers'?scope.subject.id:null,occurredAt:receipt.occurredAt,sourceScope:scope,sourceScopeHmac:'',payloadSafe:payload,payloadDigest:this.secrets.fingerprint(payload),auditEventId:a.id,auditEventHash:a.event_hash};
  // Developer subjects are not console users; unsupported attribution remains system/unknown.
  if(event.actorType==='developer'&&!event.developerId)event.actorType='system';
  event.sourceScopeHmac=eventSourceScopeDigest(this.secrets,event);
  await tx.exec(`INSERT INTO event_records(id,cluster_id,workspace_id,event_type,phase,source_kind,source_id,audit_event_id,workflow_id,actor_type,actor_id,developer_id,entity_type,entity_id,source_scope,source_scope_hmac,payload_safe,payload_digest,occurrence_key,occurred_at) VALUES($1,$2,$3,$4,$5,'audit',$6,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15::jsonb,$16,'audit',$17)`,[id,a.cluster_id,a.workspace_id,mapping.eventType,mapping.phase,a.id,a.workflow_id,event.actorType,event.actorId,event.developerId,a.entity_type,subject?.id??null,JSON.stringify(scope),event.sourceScopeHmac,JSON.stringify(payload),event.payloadDigest,receipt.occurredAt]);
  await tx.exec('INSERT INTO event_outbox(event_id) VALUES($1) ON CONFLICT(event_id) DO NOTHING',[id]);return {eventId:id};
 }
}
export function mapAuditEvent(action:string,result:string):{eventType:string;phase:'requested'|'node'|'aggregate'|'terminal';title:string}|null {
 // KP-008: business-schedule success fans out to outbox/delivery (1:1 with ticket).
 if(action==='workflow.business-schedule.author.command'||action==='workflow.business-schedule.activate.command')
  return result==='success'?{eventType:'workflow.executed',phase:'terminal',title:'业务定时工单已落账'}:null;
 if(action==='workflow.business-schedule.cancel.command')
  return result==='success'?{eventType:'workflow.cancelled',phase:'terminal',title:'业务定时工单已取消'}:null;
 if(action==='workflow.approval.progress')return result==='success'?{eventType:'workflow.approval.progress',phase:'aggregate',title:'工单审批进度已更新'}:null;
 if(action==='governance.drift.threshold_crossed')return result==='success'?{eventType:'config.drift',phase:'terminal',title:'配置漂移超过订阅阈值'}:null;
 if(action==='workflow.reconcile-migration-metadata')return result==='success'?{eventType:'workflow.executed',phase:'terminal',title:'迁移工单账本核验完成'}:null;
 if(['workflow.submit','workflow.approve','workflow.reject','workflow.cancel','workflow.execute'].includes(action)){
  const types:Record<string,string>={'workflow.submit':'workflow.submitted','workflow.approve':'workflow.approved','workflow.reject':'workflow.rejected','workflow.cancel':'workflow.cancelled','workflow.execute':result==='success'?'workflow.executed':'workflow.failed'};
  if(action==='workflow.execute'&&!['success','failed','uncertain'].includes(result))return null;
  if(action!=='workflow.execute'&&result!=='success')return null;
  return {eventType:types[action],phase:'terminal',title:'工单状态已更新'};
 }
 if(!['success','succeeded'].includes(result))return null;
 const fixed:Record<string,string>={create:'entity.created',update:'entity.updated',delete:'entity.deleted',restore:'entity.restored','workspace.migrate':'entity.updated','workspace.inherit':'entity.updated','portal.publication.draft':'entity.updated','portal.publication.publish':'entity.updated','portal.publication.unpublish':'entity.updated','portal.page.draft':'entity.updated','portal.page.publish':'entity.updated','portal.page.unpublish':'entity.updated','portal.settings.update':'entity.updated','portal.developer.review':'entity.updated','portal.application.update':'entity.updated','portal.metadata.archive':'entity.deleted','portal.metadata.restore':'entity.restored'};
 const eventType=fixed[action];return eventType?{eventType,phase:'terminal',title:eventType==='entity.created'?'对象已创建':eventType==='entity.deleted'?'对象已移入回收站':eventType==='entity.restored'?'对象已恢复':'配置已更新'}:null;
}

export const WORKFLOW_KIND_LABELS:Record<string,string>={'portal-publication':'门户 API 发布','portal-credential-issue':'门户凭证申请','portal-credential-rotate':'门户凭证轮换','portal-credential-revoke':'门户凭证吊销','portal-developer-review':'开发者审核','portal-metadata':'门户配置','event-metadata':'事件与通知配置',configuration_v2:'配置发布','configuration-metadata':'快照与 GitOps 配置','toolbox-operation':'运维工具操作','workspace-migration':'工作区迁移','governance-metadata':'配置治理','workflow-policy-metadata':'审批政策变更','native-change':'网关实体变更','iam-metadata':'身份与权限变更','metrics-setup':'监控通道配置','control-metadata':'集群与工作区配置变更','entity-annotation':'实体备注变更'};
const WORKFLOW_EVENT_VERBS:Record<string,string>={'workflow.submitted':'待审批','workflow.approval.progress':'审批进入下一阶段','workflow.approved':'工单已批准','workflow.rejected':'工单已驳回','workflow.cancelled':'工单已取消','workflow.executed':'工单已执行','workflow.failed':'工单执行失败'};
const clip=(v:string,n:number)=>v.length>n?v.slice(0,n-1)+'…':v;
/** Approver-facing text: operation, cluster and requester. Names only; never plan bodies or secrets. */
export function workflowNotificationText(eventType:string,fallback:string,w:{id:string;kind:string;cluster:string|null;workspace:string|null;requester:string|null}|null):{title:string;summary:string}{
 const verb=WORKFLOW_EVENT_VERBS[eventType];if(!w||!verb)return {title:fallback,summary:fallback};
 const op=WORKFLOW_KIND_LABELS[w.kind]??w.kind,cluster=clip(w.cluster??'未知集群',64),requester=clip(w.requester??'门户开发者',64),ws=clip(w.workspace??'',64);
 const title=clip(`${verb}：${op} · 集群 ${cluster} · 发起人 ${requester}`,256);
 const summary=`工单 ${w.id.slice(0,8)}（${op}）${eventType==='workflow.submitted'||eventType==='workflow.approval.progress'?'正在等待审批':'状态已更新'}；集群 ${cluster}${ws?`，工作区 ${ws}`:''}，发起人 ${requester}。`;
 return {title,summary};
}
async function workflowEventText(tx:DbService,workflowId:string|null,mapping:{eventType:string;title:string}):Promise<{title:string;summary:string}>{
 if(!workflowId||!mapping.eventType.startsWith('workflow.')||!WORKFLOW_EVENT_VERBS[mapping.eventType])return {title:mapping.title,summary:mapping.title};
 const w=await tx.one<any>('SELECT w.id,w.kind,c.name AS cluster,s.name AS workspace,u.username AS requester FROM workflows w LEFT JOIN clusters c ON c.id=w.cluster_id LEFT JOIN workspaces s ON s.cluster_id=w.cluster_id AND s.id=w.workspace_id LEFT JOIN users u ON u.id=w.requester_user_id WHERE w.id=$1',[workflowId]);
 return workflowNotificationText(mapping.eventType,mapping.title,w??null);
}
