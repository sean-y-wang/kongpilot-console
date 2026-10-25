import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { DbService } from '../../../infrastructure/db.service';
import { SecretService } from '../../../infrastructure/secret.service';
import type { ConnectionAuth } from '../../../infrastructure/kong/outbound';
import { metricsId } from '../vitals-query';
import type { VitalsSource } from '../vitals.types';
export interface MetricsSourceConnection extends VitalsSource { baseUrl: string; auth: ConnectionAuth | null; revision: number; }
@Injectable()
export class MetricsSourceService {
  constructor(private readonly db: DbService, private readonly secrets: SecretService) {}
  async list(cid: string): Promise<VitalsSource[]> {
    const rows = await this.db.query<any>("SELECT id,name,type,last_status,enabled FROM data_sources WHERE cluster_id=$1 AND deleted_at IS NULL AND type IN ('prometheus','loki') ORDER BY created_at,id LIMIT 1001", [cid]);
    if (rows.length > 1000) throw new ConflictException({ code: 'METRICS_SOURCE_BUDGET_EXHAUSTED', message: '监控数据源超过查询预算' });
    return rows.map(row => ({ id: row.id, name: row.name, type: row.type, status: row.enabled ? row.last_status : 'disabled', availability: row.enabled && row.last_status === 'healthy' ? 'available' : 'unavailable' }));
  }
  async read(cid: string, sourceId: string): Promise<MetricsSourceConnection> {
    metricsId(sourceId);
    const row = await this.db.one<any>("SELECT id,name,type,base_url,auth_secret,last_status,revision FROM data_sources WHERE cluster_id=$1 AND id=$2 AND enabled=true AND deleted_at IS NULL AND type IN ('prometheus','loki')", [cid, sourceId]);
    if (!row) throw new NotFoundException({ code: 'METRICS_SOURCE_UNAVAILABLE', message: '此监控数据源不存在、停用或不属于当前集群' });
    return { id: row.id, name: row.name, type: row.type, status: row.last_status, availability: row.last_status === 'healthy' ? 'available' : 'unavailable', baseUrl: row.base_url, auth: row.auth_secret ? this.secrets.decrypt<ConnectionAuth>(row.auth_secret, `data-source:${cid}:${sourceId}`) : null, revision: row.revision };
  }
  public(source: MetricsSourceConnection): VitalsSource { return { id: source.id, name: source.name, type: source.type, status: source.status, availability: source.availability }; }
  async assertCurrent(cid: string, before: MetricsSourceConnection): Promise<void> {
    const current = await this.read(cid, before.id);
    if (current.revision !== before.revision || current.baseUrl !== before.baseUrl || this.secrets.fingerprint(current.auth) !== this.secrets.fingerprint(before.auth)) throw new ConflictException({ code: 'METRICS_SOURCE_CHANGED', message: '监控查询期间数据源发生变化' });
  }
}
