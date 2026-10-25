import { BadRequestException,ConflictException,Injectable,NotFoundException } from '@nestjs/common';
import { createHash,randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { type MetricsFenceReceipt,type MetricsWriteInput } from './metrics.types';

const hex=/^[a-f0-9]{64}$/,uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
@Injectable()
export class MetricsWriteFenceService {
  constructor(private readonly db:DbService){}
  async beforeNativeWrite(input:MetricsWriteInput):Promise<MetricsFenceReceipt>{
    if(!input||!uuid.test(input.cid)||!uuid.test(input.operationId)||!hex.test(input.transportScope)||!hex.test(input.requestFingerprint)
      ||!['POST','PUT','PATCH','DELETE'].includes(input.method)||typeof input.path!=='string'||!input.path.startsWith('/')||input.path.length>4096
      ||typeof input.entityType!=='string'||input.entityType.length<1||input.entityType.length>64||input.entityId!==undefined&&(typeof input.entityId!=='string'||input.entityId.length>256))
      throw new BadRequestException({code:'INVALID_METRICS_FENCE',message:'原生写入归属阻断信息无效'});
    return this.db.transaction(async tx=>{
      await tx.exec('SELECT pg_advisory_xact_lock(hashtext($1))',[`kongos:metrics-transport:${input.transportScope}`]);
      const operation=await tx.one<any>('SELECT cluster_id,transport_scope,state FROM mutation_operations WHERE id=$1 FOR SHARE',[input.operationId]);
      if(!operation||operation.cluster_id!==input.cid||operation.transport_scope&&operation.transport_scope!==input.transportScope)
        throw new ConflictException({code:'METRICS_FENCE_OPERATION_MISMATCH',message:'写入操作与物理集群作用域不一致'});
      if(operation.state!=='running')throw new ConflictException({code:'METRICS_OPERATION_NOT_RUNNING',message:'写入操作已终止或结果不确定，不能再次发送'});
      const pathHash=createHash('sha256').update(input.path).digest('hex');
      const old=await tx.one<any>('SELECT * FROM metrics_write_fences WHERE operation_id=$1 AND request_fingerprint=$2',[input.operationId,input.requestFingerprint]);
      if(old){if(old.cluster_id!==input.cid||old.transport_scope!==input.transportScope||old.entity_type!==input.entityType
        ||old.entity_id!==(input.entityId??null)||old.method!==input.method||old.path_hash!==pathHash)
          throw new ConflictException({code:'METRICS_FENCE_CONFLICT',message:'原生写入阻断标识已用于另一项变更'});
        return {id:old.id,operationId:old.operation_id,transportScope:old.transport_scope,requestFingerprint:old.request_fingerprint,
          closed:Number(old.closed_count),clusterIds:old.cluster_ids};}
      const clusters=await tx.query<any>('SELECT id,admin_url,transport_scope FROM clusters WHERE deleted_at IS NULL ORDER BY id LIMIT 10001 FOR SHARE');
      if(clusters.length>10000)throw new ConflictException({code:'METRICS_CLUSTER_BUDGET',message:'物理集群别名枚举超过限制，写入未发送'});
      const ids=clusters.filter(row=>transportScopeFor(row.admin_url,row.transport_scope)===input.transportScope).map(row=>row.id);
      if(!ids.includes(input.cid))throw new NotFoundException({code:'METRICS_TRANSPORT_NOT_REGISTERED',message:'写入物理集群未登记'});
      for(const cid of ids)await tx.exec('INSERT INTO metrics_settings(cluster_id) VALUES($1) ON CONFLICT DO NOTHING',[cid]);
      const closed=await tx.exec(`UPDATE metrics_assignment_epochs SET closed_at=GREATEST(now(),valid_from),close_reason='native_write',
        retention_until=GREATEST(now(),valid_from)+interval '8 days' WHERE cluster_id=ANY($1::uuid[]) AND closed_at IS NULL`,[ids]);
      await tx.exec("UPDATE metrics_settings SET catalog_status='blocked',catalog_revision=catalog_revision+1,updated_at=now() WHERE cluster_id=ANY($1::uuid[])",[ids]);
      await tx.exec("UPDATE metrics_nodes SET status='blocked' WHERE cluster_id=ANY($1::uuid[])",[ids]);
      const id=randomUUID();await tx.exec(`INSERT INTO metrics_write_fences(id,cluster_id,transport_scope,operation_id,request_fingerprint,entity_type,
        entity_id,method,path_hash,closed_count,cluster_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::uuid[])`,
        [id,input.cid,input.transportScope,input.operationId,input.requestFingerprint,input.entityType,input.entityId??null,input.method,pathHash,closed,ids]);
      return {id,operationId:input.operationId,transportScope:input.transportScope,requestFingerprint:input.requestFingerprint,closed,clusterIds:ids};
    });
  }
  /** Transport acknowledgement never reopens an epoch; durable parent outcome is checked on every read/publish. */
  async settle(fenceId:string,outcome:'knownfailed'|'success'|'uncertain'):Promise<void>{
    if(!uuid.test(fenceId)||!['knownfailed','success','uncertain'].includes(outcome))throw new BadRequestException({code:'INVALID_METRICS_FENCE',message:'写入结果无效'});
    const state=outcome==='knownfailed'?'rejected':outcome==='success'?'acknowledged':'uncertain';
    const count=await this.db.exec("UPDATE metrics_write_fences SET state=$2,settled_at=now() WHERE id=$1 AND state='pending'",[fenceId,state]);
    if(!count){const row=await this.db.one<any>('SELECT state FROM metrics_write_fences WHERE id=$1',[fenceId]);
      if(!row)throw new NotFoundException({code:'METRICS_FENCE_NOT_FOUND',message:'写入阻断记录不存在'});
      if(row.state!==state)throw new ConflictException({code:'METRICS_FENCE_OUTCOME_CONFLICT',message:'写入阻断结果已记录'});}
  }
}
