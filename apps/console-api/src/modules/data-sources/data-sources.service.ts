import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { ConnectionAuth, authHeaders, outboundJson, validateOutboundUrl } from '../../infrastructure/kong/outbound';
import { AuthorizationService } from '../authorization/authorization.service';
import { IamMutationsService, type IamMutation } from '../iam/iam-mutations.service';
import { AuditService } from '../audit/audit.service';
import { Actor, ClustersService } from '../clusters/clusters.service';
import { deactivateSchema, parseDto } from '../clusters/cluster.dto';
import { createDataSourceSchema, updateDataSourceSchema } from './data-source.dto';
import type { ControlBusinessBridge, ControlBusinessMutation } from '../control-plane/control-metadata.types';

const PUBLIC_COLUMNS = 'id,cluster_id,name,type,base_url,enabled,last_status,last_probed_at,created_at,updated_at,revision,(auth_secret IS NOT NULL) AS auth_configured';

@Injectable()
export class DataSourcesService {
  private controlBridge?:Readonly<ControlBusinessBridge>;
  constructor(private readonly storageDb: DbService, private readonly secrets: SecretService, private readonly clusters: ClustersService, private readonly audit: AuditService,private readonly authz:AuthorizationService,private readonly operations:IamMutationsService) {}
  private get db():DbService{return this.controlBridge?.currentTransaction()??this.storageDb;}
  installControlMetadataBridge(bridge:ControlBusinessBridge):void{
    const methods=['currentTransaction','allocateId','execute','completed']as const;
    if(this.controlBridge||!bridge||methods.some(name=>typeof bridge[name]!=='function'))throw new Error('Control metadata requires one fixed business bridge');
    this.controlBridge=Object.freeze({currentTransaction:bridge.currentTransaction.bind(bridge),allocateId:bridge.allocateId.bind(bridge),execute:bridge.execute.bind(bridge),completed:bridge.completed.bind(bridge)});
  }
  private newId():string{return this.controlBridge?.allocateId()??randomUUID();}
  private completed<T>(context:IamMutation):Promise<{result:T}|null>{return this.controlBridge?this.controlBridge.completed<T>(context):this.operations.completed<T>(context);}
  private controlMutation<T>(mutation:ControlBusinessMutation,context:IamMutation,fn:(tx:DbService)=>Promise<T>):Promise<T>{
    const direct=()=>this.operations.execute(context,fn);
    return this.controlBridge?this.controlBridge.execute(mutation,fn,direct):direct();
  }

  async list(clusterId: string,actor:Actor): Promise<any[]> {
    const version=await this.authz.permissionVersion(actor.user);
    await this.authorize(actor,clusterId,'read');
    const rows=await this.db.query(`SELECT ${PUBLIC_COLUMNS} FROM data_sources WHERE cluster_id=$1 AND deleted_at IS NULL ORDER BY created_at ASC LIMIT 1001`,[clusterId]);if(rows.length>1000)throw new ConflictException('数据源数量超过查询预算');const result=await Promise.all(rows.map(row=>this.display(row,actor)));await this.stable(actor,version);return result;
  }
  private async authorize(actor:Actor,cid:string,action:string):Promise<void>{
    this.clusters.validateId(cid);await this.authz.assertCluster(actor.user,cid,'data-sources',action);
    const snapshot=await this.authz.snapshot(actor.user);if(snapshot.user.superAdmin)return;
    if(!snapshot.grants.some(g=>g.module==='data-sources'&&g.action===action&&g.scope_type==='global'&&g.workspace_id===null&&(!g.cluster_id||g.cluster_id===cid)))throw new ForbiddenException({code:'DATA_SOURCE_SCOPE_DENIED',message:'数据源属于集群共享配置，权限须覆盖整个集群'});
  }
  private async display(row:any,actor:Actor):Promise<any>{if(await this.authz.isPlatformAdmin(actor.user))return row;const {base_url,auth_configured,...safe}=row;return safe;}
  private async stable(actor:Actor,version:string):Promise<void>{if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED',message:'查询期间授权已变更，请重新加载'});}
  async get(clusterId:string,id:string,actor:Actor):Promise<any>{const version=await this.authz.permissionVersion(actor.user);await this.authorize(actor,clusterId,'read');const result=await this.display(await this.readRow(clusterId,id),actor);await this.stable(actor,version);return result;}
  private async readRow(clusterId: string, id: string,tx:DbService=this.db): Promise<any> {
    this.clusters.validateId(clusterId);this.clusters.validateId(id);
    const row = await tx.one(`SELECT ${PUBLIC_COLUMNS} FROM data_sources WHERE cluster_id=$1 AND id=$2 AND deleted_at IS NULL`, [clusterId, id]);
    if (!row) throw new NotFoundException({ code: 'DATA_SOURCE_NOT_FOUND', message: '数据源不存在或不属于此集群' });
    return row;
  }
  async create(clusterId: string, body: unknown, actor: Actor): Promise<any> {
    await this.authorize(actor,clusterId,'write');
    if(!await this.db.one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL',[clusterId]))throw new NotFoundException('集群不存在');
    const dto = parseDto(createDataSourceSchema, body);
    const url = validateOutboundUrl(dto.base_url).toString().replace(/\/$/, '');
    authHeaders(dto.auth);
    const id = this.newId();
    const encrypted = dto.auth && dto.auth.type !== 'none' ? this.secrets.encrypt(dto.auth, `data-source:${clusterId}:${id}`) : null;
    try {
      const context={actor,module:'data-sources',action:'write',cluster_id:clusterId,workspace_id:null,payload:dto};
      return await this.controlMutation({resource:'data-sources',operation:'create',clusterId,resourceId:id,module:'data-sources',action:'write',workspaceId:null,actor,payload:dto},context,async tx => {
        if(await tx.one('SELECT id FROM data_sources WHERE cluster_id=$1 AND lower(name)=lower($2) AND deleted_at IS NULL',[clusterId,dto.name]))throw new ConflictException({code:'DATA_SOURCE_NAME_EXISTS',message:'该集群内已存在同名数据源'});
        await tx.exec('INSERT INTO data_sources(id,cluster_id,name,type,base_url,auth_secret,enabled) VALUES ($1,$2,$3,$4,$5,$6,$7)', [id, clusterId, dto.name, dto.type, url, encrypted, dto.enabled]);
        const after = await tx.one(`SELECT ${PUBLIC_COLUMNS} FROM data_sources WHERE cluster_id=$1 AND id=$2`, [clusterId, id]);
        await this.audit.append({ actorId: actor.user?.id, clusterId, entityType: 'data_source', entityId: id, action: 'create', after: { ...after, auth_secret: encrypted }, requestId: actor.requestId, ip: actor.ip }, tx);
        return this.display(after,actor);
      });
    } catch (error: any) { this.rethrowUnique(error); }
  }
  async update(clusterId: string, id: string, body: unknown, actor: Actor): Promise<any> {
    await this.authorize(actor,clusterId,'write');
    const before = await this.readRow(clusterId,id);
    const previousSecret = await this.db.one<{ auth_secret: string | null }>('SELECT auth_secret FROM data_sources WHERE cluster_id=$1 AND id=$2 AND deleted_at IS NULL', [clusterId, id]);
    const dto = parseDto(updateDataSourceSchema, body);
    if (dto.auth !== undefined) authHeaders(dto.auth);
    const updates: Record<string, unknown> = { name: dto.name ?? before.name, type: dto.type ?? before.type, base_url: dto.base_url !== undefined ? validateOutboundUrl(dto.base_url).toString().replace(/\/$/, '') : before.base_url, enabled: dto.enabled ?? before.enabled };
    if (dto.auth !== undefined) updates.auth_secret = dto.auth && dto.auth.type !== 'none' ? this.secrets.encrypt(dto.auth, `data-source:${clusterId}:${id}`) : null;
    if (dto.base_url !== undefined || dto.auth !== undefined || dto.type !== undefined) Object.assign(updates, { last_status: 'unknown', last_probed_at: null });
    const entries = Object.entries(updates);
    try {
      const context={actor,module:'data-sources',action:'write',targetId:id,cluster_id:clusterId,workspace_id:null,payload:dto};
      return await this.controlMutation({resource:'data-sources',operation:'update',clusterId,resourceId:id,module:'data-sources',action:'write',workspaceId:null,actor,payload:dto},context,async tx => {
        const current=await this.readRow(clusterId,id,tx);if(current.revision!==dto.revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'数据源已变更，请刷新后重试'});
        if(await tx.one('SELECT id FROM data_sources WHERE cluster_id=$1 AND lower(name)=lower($2) AND id<>$3 AND deleted_at IS NULL',[clusterId,updates.name,id]))throw new ConflictException({code:'DATA_SOURCE_NAME_EXISTS',message:'该集群内已存在同名数据源'});
        const changed = await tx.exec(`UPDATE data_sources SET ${entries.map(([key], i) => `${key}=$${i + 4}`).join(',')},revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL`, [clusterId, id, dto.revision, ...entries.map(([, value]) => value)]);
        if (!changed) throw new ConflictException({ code: 'REVISION_CONFLICT', message: '数据源已被其他人修改，请刷新后重试' });
        const after = await tx.one(`SELECT ${PUBLIC_COLUMNS} FROM data_sources WHERE cluster_id=$1 AND id=$2`, [clusterId, id]);
        await this.audit.append({ actorId: actor.user?.id, clusterId, entityType: 'data_source', entityId: id, action: 'update', before: { ...before, auth_secret: previousSecret?.auth_secret ?? null }, after: { ...after, auth_secret: dto.auth !== undefined ? updates.auth_secret : previousSecret?.auth_secret ?? null }, requestId: actor.requestId, ip: actor.ip }, tx);
        return this.display(after,actor);
      });
    } catch (error: any) { this.rethrowUnique(error); }
  }
  async deactivate(clusterId: string, id: string, body: unknown, actor: Actor): Promise<any> {
    await this.authorize(actor,clusterId,'delete');
    const dto=parseDto(deactivateSchema,body);
    const cached=await this.completed<any>({actor,module:'data-sources',action:'delete',targetId:id,cluster_id:clusterId,workspace_id:null,payload:dto});if(cached)return cached.result;
    const before=await this.readRow(clusterId,id);
    if (dto.confirm_name !== before.name) throw new BadRequestException({ code: 'CONFIRMATION_MISMATCH', message: '请再次输入准确的数据源名称确认停用' });
    const context={actor,module:'data-sources',action:'delete',targetId:id,cluster_id:clusterId,workspace_id:null,payload:dto};
    return this.controlMutation({resource:'data-sources',operation:'deactivate',clusterId,resourceId:id,module:'data-sources',action:'delete',workspaceId:null,actor,payload:dto},context,async tx => {
      const current=await this.readRow(clusterId,id,tx);if(current.name!==dto.confirm_name)throw new BadRequestException({code:'CONFIRMATION_MISMATCH',message:'数据源名称已变化，请重新确认'});
      const changed = await tx.exec("UPDATE data_sources SET deleted_at=now(),enabled=false,last_status='disabled',revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL", [clusterId, id, dto.revision]);
      if (!changed) throw new ConflictException({ code: 'REVISION_CONFLICT', message: '数据源已被其他人修改，请刷新后重试' });
      await this.audit.append({ actorId: actor.user?.id, clusterId, entityType: 'data_source', entityId: id, action: 'deactivate', before, after: { ...before, enabled: false, last_status: 'disabled' }, requestId: actor.requestId, ip: actor.ip }, tx);
      return {id,deactivated:true};
    });
  }
  async probe(clusterId: string, id: string, actor: Actor): Promise<any> {
    await this.authorize(actor,clusterId,'write');
    const version=await this.authz.permissionVersion(actor.user);
    const before = await this.readRow(clusterId,id);
    if (!before.enabled) throw new BadRequestException({ code: 'DATA_SOURCE_DISABLED', message: '请先启用数据源再进行连接测试' });
    const row = await this.db.one<{ auth_secret: string | null }>('SELECT auth_secret FROM data_sources WHERE cluster_id=$1 AND id=$2 AND deleted_at IS NULL', [clusterId, id]);
    const auth = row?.auth_secret ? this.secrets.decrypt<ConnectionAuth>(row.auth_secret, `data-source:${clusterId}:${id}`) : null;
    const started = Date.now();
    let status = 'healthy';
    let message = '连接正常；网关数据是否存在将在监控模块单独核验';
    try {
      if (before.type === 'prometheus') {
        const response = await outboundJson(before.base_url, '/api/v1/query', 'GET', undefined, { query: 'vector(1)' }, auth);
        if (response.status !== 200 || response.body?.status !== 'success' || response.body?.data?.resultType !== 'vector' || !Array.isArray(response.body.data.result)) throw new Error('invalid_provider_response');
      } else {
        const ready = await outboundJson(before.base_url, '/ready', 'GET', undefined, {}, auth);
        if (ready.status !== 200) throw new Error('provider_not_ready');
        const labels = await outboundJson(before.base_url, '/loki/api/v1/labels', 'GET', undefined, {}, auth);
        if (labels.status !== 200 || labels.body?.status !== 'success' || (labels.body.data !== undefined && !Array.isArray(labels.body.data))) throw new Error('invalid_provider_response');
      }
    } catch { status = 'unhealthy'; message = '连接测试失败，请检查允许列表、地址、网络及认证信息'; }
    const latency = Date.now() - started;
    return this.storageDb.transaction(async tx => {
      await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR SHARE');
      await this.authorize(actor,clusterId,'write');await this.stable(actor,version);
      const current=await this.readRow(clusterId,id,tx);if(current.revision!==before.revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'探测期间数据源配置已变化，请重新探测'});
      const changed=await tx.exec('UPDATE data_sources SET last_status=$3,last_probed_at=now(),updated_at=now() WHERE cluster_id=$1 AND id=$2 AND revision=$4 AND deleted_at IS NULL AND enabled=true', [clusterId, id, status,before.revision]);
      if(changed!==1)throw new ConflictException({code:'REVISION_CONFLICT',message:'探测期间数据源配置已变化，请重新探测'});
      await tx.exec('INSERT INTO data_source_probes(id,cluster_id,data_source_id,status,latency_ms,safe_error) VALUES ($1,$2,$3,$4,$5,$6)', [randomUUID(), clusterId, id, status, latency, status === 'healthy' ? null : message]);
      await this.audit.append({ actorId: actor.user?.id, clusterId, entityType: 'data_source', entityId: id, action: 'probe', before: { status: before.last_status }, after: { status }, result: status === 'healthy' ? 'success' : 'failure', requestId: actor.requestId, ip: actor.ip }, tx);
      return {id,cluster_id:clusterId,status,latency_ms:latency,message,probed_at:new Date().toISOString()};
    });
  }
  private rethrowUnique(error: any): never { if (error?.code === '23505') throw new ConflictException({ code: 'DATA_SOURCE_NAME_EXISTS', message: '该集群内已存在同名数据源' }); throw error; }
}
