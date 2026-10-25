import { BadRequestException,ConflictException,Injectable,NotFoundException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService } from '../audit/audit.service';
import { type MetricsSettingsView } from './metrics.types';

@Injectable()
export class MetricsSettingsService {
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly audit:AuditService){}
  async get(cid:string):Promise<MetricsSettingsView>{
    const row=await this.db.one<any>(`SELECT c.id,s.* FROM clusters c LEFT JOIN metrics_settings s ON s.cluster_id=c.id
      WHERE c.id=$1 AND c.deleted_at IS NULL`,[cid]);
    if(!row)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
    return {clusterId:cid,activeSourceId:row.active_source_id??null,provider:'prometheus',state:row.catalog_status??'uninitialized',
      revision:Number(row.revision??0),catalogRevision:Number(row.catalog_revision??0),credentialGeneration:Number(row.credential_generation??0),
      maxAgeMs:Number(row.max_age_ms??15000),lastVerifiedAt:row.last_verified_at?new Date(row.last_verified_at).toISOString():null,
      enabled:row.enabled??false,collectorEnabled:row.collector_enabled??false,capabilities:this.secrets.redact(row.safe_capabilities??{})};
  }
  /** SQL-only CAS used within an authorized durable metadata/mutation transaction. */
  async configure(cid:string,input:{revision:number;activeSourceId:string|null;enabled?:boolean;collectorEnabled?:boolean;capabilities?:Record<string,unknown>},
    context:{actorId:string;requestId?:string;ip?:string},transaction?:DbService):Promise<MetricsSettingsView>{
    if(!Number.isSafeInteger(input?.revision)||input.revision<0||typeof context?.actorId!=='string'
      ||input.enabled!==undefined&&typeof input.enabled!=='boolean'||input.collectorEnabled!==undefined&&typeof input.collectorEnabled!=='boolean'
      ||input.capabilities!==undefined&&(!input.capabilities||typeof input.capabilities!=='object'||Array.isArray(input.capabilities)))
      throw new BadRequestException({code:'INVALID_METRICS_SETTINGS',message:'监控设置参数无效'});
    return (transaction??this.db).transaction(async tx=>{
      const cluster=await tx.one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[cid]);
      if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
      if(input.activeSourceId){const source=await tx.one("SELECT id FROM data_sources WHERE cluster_id=$1 AND id=$2 AND type='prometheus' AND enabled=true AND deleted_at IS NULL FOR SHARE",[cid,input.activeSourceId]);
        if(!source)throw new BadRequestException({code:'METRICS_SOURCE_UNAVAILABLE',message:'必须选择当前集群启用的 Prometheus 数据源'});}
      const before=await tx.one<any>('SELECT * FROM metrics_settings WHERE cluster_id=$1 FOR UPDATE',[cid]);
      if(Number(before?.revision??0)!==input.revision)throw new ConflictException({code:'METRICS_SETTINGS_CHANGED',message:'监控设置已变更，请重新加载'});
      const capabilities=this.secrets.redact(input.capabilities??before?.safe_capabilities??{});
      if(Buffer.byteLength(JSON.stringify(capabilities))>16384)throw new BadRequestException({code:'METRICS_SETTINGS_TOO_LARGE',message:'监控能力信息超过限制'});
      if(!before)await tx.exec('INSERT INTO metrics_settings(cluster_id) VALUES($1)',[cid]);
      await tx.exec(`UPDATE metrics_settings SET active_source_id=$2,enabled=$3,collector_enabled=$4,safe_capabilities=$5::jsonb,
        revision=revision+1,catalog_revision=catalog_revision+1,updated_at=now() WHERE cluster_id=$1`,[cid,input.activeSourceId,input.enabled??before?.enabled??false,
        input.collectorEnabled??before?.collector_enabled??false,JSON.stringify(capabilities)]);
      const after=await tx.one<any>('SELECT * FROM metrics_settings WHERE cluster_id=$1',[cid]);
      await this.audit.append({actorId:context.actorId,clusterId:cid,entityType:'monitoring',action:'settings.configure',
        before,after,requestId:context.requestId,ip:context.ip},tx);
      return {clusterId:cid,activeSourceId:after.active_source_id,provider:'prometheus',state:after.catalog_status,revision:Number(after.revision),
        catalogRevision:Number(after.catalog_revision),credentialGeneration:Number(after.credential_generation),maxAgeMs:Number(after.max_age_ms),
        lastVerifiedAt:after.last_verified_at?new Date(after.last_verified_at).toISOString():null,enabled:after.enabled,
        collectorEnabled:after.collector_enabled,capabilities:this.secrets.redact(after.safe_capabilities)};
    });
  }
}
