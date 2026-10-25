import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson } from '../../infrastructure/secret.service';
import { HistoricalEventAccessService } from '../authorization/historical-event-access.service';
import { AuditCursorService } from './audit-cursor.service';
import { AUDIT_READ_MAX_BYTES,AUDIT_READ_MAX_ROWS,type AuditRow,auditInvalid } from './audit.types';

export type AuditIntegrityReason='AUDIT_SEQUENCE_GAP'|'AUDIT_PREVIOUS_HASH_MISMATCH'|'AUDIT_CONTENT_HASH_MISMATCH'
  |'AUDIT_HEAD_MISMATCH'|'AUDIT_RECORD_INVALID'|'AUDIT_BUDGET_REACHED';
export interface AuditIntegrityView {
  status:'verified'|'mismatch'|'partial'|'unavailable';scope:'cluster'|'global';observedAt:string;
  checkedRows:number;complete:boolean;intervalComplete:boolean;verifiedInterval?:{fromSequence:string;toSequence:string};
  reasonCodes:AuditIntegrityReason[];firstMismatch?:{eventId:string;reasonCode:AuditIntegrityReason};nextCursor:string|null;
}
interface IntegrityState {
  from:string;to:string;next:string;expectedHash:string;headSequence:string;headHash:string;prefixRows:number;
}
const decimal=/^[1-9]\d{0,18}$/;
const hash=/^[a-f\d]{64}$/;

/** Exactly the legacy nineteen fields; no event_hash, scope annotation or safe projection. */
export function auditCanonicalRecord(row:AuditRow):Record<string,unknown>{
  if(!row||!decimal.test(row.sequence)||BigInt(row.sequence)>9223372036854775807n
    ||row.millisecond_precision!==true||!hash.test(row.event_hash)
    ||row.prev_hash!=='GENESIS'&&!hash.test(row.prev_hash))throw new Error('AUDIT_RECORD_INVALID');
  const occurredAt=new Date(row.occurred_at);
  if(!Number.isFinite(occurredAt.getTime())||!Array.isArray(row.json_patch))throw new Error('AUDIT_RECORD_INVALID');
  for(const key of ['id','chain_scope','actor_type','entity_type','action','result'] as const)
    if(typeof row[key]!=='string'||!row[key])throw new Error('AUDIT_RECORD_INVALID');
  for(const key of ['actor_id','source_ip','cluster_id','workspace_id','entity_id','workflow_id','request_id'] as const)
    if(row[key]!==null&&typeof row[key]!=='string')throw new Error('AUDIT_RECORD_INVALID');
  return {id:row.id,chain_scope:row.chain_scope,sequence:row.sequence,actor_id:row.actor_id,actor_type:row.actor_type,
    source_ip:row.source_ip,cluster_id:row.cluster_id,workspace_id:row.workspace_id,entity_type:row.entity_type,
    entity_id:row.entity_id,action:row.action,before:row.before??null,after:row.after??null,json_patch:row.json_patch,
    workflow_id:row.workflow_id,result:row.result,request_id:row.request_id,prev_hash:row.prev_hash,
    occurred_at:occurredAt.toISOString()};
}

@Injectable()
export class AuditIntegrityService {
  constructor(private readonly db:DbService,private readonly access:HistoricalEventAccessService,
    private readonly cursors:AuditCursorService){}
  async verify(user:AuthUser,clusterId:string|null,query:Record<string,unknown>):Promise<AuditIntegrityView>{
    if(Object.keys(query).some(key=>!['fromSequence','toSequence','cursor'].includes(key)))throw auditInvalid();
    for(const key of ['fromSequence','toSequence'])if(query[key]!==undefined
      &&(typeof query[key]!=='string'||!decimal.test(query[key] as string)||BigInt(query[key] as string)>9223372036854775807n))throw auditInvalid('序号必须为正 bigint 十进制字符串');
    const snapshot=await this.access.assertWholeAudit(user,clusterId);
    const chain=clusterId?`cluster:${clusterId}`:'global';
    const filter={fromSequence:query.fromSequence??null,toSequence:query.toSequence??null};
    const binding={actorId:user.id,permissionVersion:snapshot.version,scope:{clusterId,chain},filter};
    let state:IntegrityState;
    if(query.cursor!==undefined){
      if(typeof query.cursor!=='string')throw auditInvalid();state=this.cursors.open<IntegrityState>('integrity',binding,query.cursor);
    }else{
      const head=await this.db.one<{last_sequence:string;last_hash:string}>('SELECT last_sequence::text,last_hash FROM audit_chain_heads WHERE chain_scope=$1',[chain]);
      const headSequence=head?.last_sequence??'0',headHash=head?.last_hash??'GENESIS';
      if(!/^\d{1,19}$/.test(headSequence)||headSequence!=='0'&&!hash.test(headHash)||headSequence==='0'&&headHash!=='GENESIS')throw auditInvalid('审计链头无效');
      if(headSequence==='0'&&query.fromSequence===undefined&&query.toSequence===undefined){
        await this.access.assertVersion(user,snapshot.version);
        return {status:'verified',scope:clusterId?'cluster':'global',observedAt:new Date().toISOString(),checkedRows:0,
          complete:true,intervalComplete:true,reasonCodes:[],nextCursor:null};
      }
      const from=String(query.fromSequence??'1'),to=String(query.toSequence??headSequence);
      if(BigInt(from)>BigInt(to)||BigInt(to)>BigInt(headSequence))throw auditInvalid('验证区间超出已捕获链范围');
      let expectedHash='GENESIS';
      if(from!=='1'){
        const predecessor=await this.db.one<{event_hash:string}>('SELECT event_hash FROM audit_events WHERE chain_scope=$1 AND sequence=$2::bigint',[chain,(BigInt(from)-1n).toString()]);
        if(!predecessor||!hash.test(predecessor.event_hash)){
          await this.access.assertVersion(user,snapshot.version);
          return {status:'mismatch',scope:clusterId?'cluster':'global',observedAt:new Date().toISOString(),checkedRows:0,
            complete:false,intervalComplete:false,reasonCodes:['AUDIT_SEQUENCE_GAP'],nextCursor:null};
        }
        expectedHash=predecessor.event_hash;
      }
      state={from,to,next:from,expectedHash,headSequence,headHash,prefixRows:0};
    }
    if(!state||![state.from,state.to,state.next,state.headSequence].every(value=>typeof value==='string'&&decimal.test(value))
      ||state.expectedHash!=='GENESIS'&&!hash.test(state.expectedHash)||!hash.test(state.headHash)
      ||!Number.isSafeInteger(state.prefixRows)||state.prefixRows<0||BigInt(state.from)>BigInt(state.next)
      ||BigInt(state.to)>BigInt(state.headSequence))throw auditInvalid('验证续页状态无效');
    let checkedRows=0,bytes=0,reason:AuditIntegrityReason|undefined,mismatchId:string|undefined,unavailable=false;
    while(BigInt(state.next)<=BigInt(state.to)&&checkedRows<AUDIT_READ_MAX_ROWS&&bytes<AUDIT_READ_MAX_BYTES){
      const rows=await this.db.query<AuditRow>(`SELECT a.*,a.sequence::text AS sequence,
        (a.occurred_at=date_trunc('milliseconds',a.occurred_at)) AS millisecond_precision,
        octet_length(row_to_json(a)::text) AS record_bytes FROM audit_events a
        WHERE a.chain_scope=$1 AND a.sequence>=$2::bigint AND a.sequence<=$3::bigint ORDER BY a.sequence LIMIT $4`,
        [chain,state.next,state.to,Math.min(100,AUDIT_READ_MAX_ROWS-checkedRows)]);
      if(!rows.length){reason='AUDIT_SEQUENCE_GAP';break;}
      for(const row of rows){
        const recordBytes=Number(row.record_bytes??0);
        if(!Number.isFinite(recordBytes)||recordBytes<0){reason='AUDIT_RECORD_INVALID';mismatchId=row.id;break;}
        if(bytes+recordBytes>AUDIT_READ_MAX_BYTES){reason='AUDIT_BUDGET_REACHED';unavailable=checkedRows===0&&recordBytes>AUDIT_READ_MAX_BYTES;break;}
        bytes+=recordBytes;
        if(row.sequence!==state.next){reason='AUDIT_SEQUENCE_GAP';mismatchId=row.id;break;}
        if(row.chain_scope!==chain||row.cluster_id!==clusterId||clusterId===null&&row.workspace_id!==null){reason='AUDIT_RECORD_INVALID';mismatchId=row.id;break;}
        if(row.prev_hash!==state.expectedHash){reason='AUDIT_PREVIOUS_HASH_MISMATCH';mismatchId=row.id;break;}
        let computed:string;
        try{computed=createHash('sha256').update(canonicalJson(auditCanonicalRecord(row))).digest('hex');}
        catch{reason='AUDIT_RECORD_INVALID';mismatchId=row.id;break;}
        if(computed!==row.event_hash){reason='AUDIT_CONTENT_HASH_MISMATCH';mismatchId=row.id;break;}
        state.expectedHash=computed;state.next=(BigInt(state.next)+1n).toString();checkedRows++;
      }
      if(reason)break;
    }
    const done=BigInt(state.next)>BigInt(state.to);
    if(!reason&&done&&state.to===state.headSequence&&state.expectedHash!==state.headHash)reason='AUDIT_HEAD_MISMATCH';
    if(!reason&&!done)reason='AUDIT_BUDGET_REACHED';
    await this.access.assertVersion(user,snapshot.version);
    const partial=reason==='AUDIT_BUDGET_REACHED',mismatch=!!reason&&!partial;
    const verifiedTo=(BigInt(state.next)-1n).toString();state.prefixRows+=checkedRows;
    return {status:unavailable?'unavailable':mismatch?'mismatch':partial?'partial':'verified',scope:clusterId?'cluster':'global',
      observedAt:new Date().toISOString(),checkedRows,complete:done&&!reason&&state.from==='1'&&state.to===state.headSequence,
      intervalComplete:done&&!reason,
      ...(BigInt(verifiedTo)>=BigInt(state.from)?{verifiedInterval:{fromSequence:state.from,toSequence:verifiedTo}}:{}),
      reasonCodes:reason?[reason]:[],...(mismatchId&&reason?{firstMismatch:{eventId:mismatchId,reasonCode:reason}}:{}),
      nextCursor:partial&&!unavailable?this.cursors.seal('integrity',binding,state):null};
  }
}
