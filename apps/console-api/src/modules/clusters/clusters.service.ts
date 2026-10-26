import { BadRequestException, ConflictException, ForbiddenException, Injectable, Logger, NotFoundException, OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { authHeaders, validateOutboundUrl } from '../../infrastructure/kong/outbound';
import { AuditService } from '../audit/audit.service';
import type { EntityActor } from '../entities/entities.types';
import { AuthorizationService } from '../authorization/authorization.service';
import { IamMutationsService } from '../iam/iam-mutations.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { inspectRegistryEndpoint, assertRegistryEndpoint } from './endpoint-policy';
import { createClusterSchema, deactivateSchema, parseDto, updateClusterSchema } from './cluster.dto';
import { assertRegisteredProxyOrigin, validateProxyOrigin } from '../toolbox/proxy-probe';
import type { ControlBusinessBridge, ControlBusinessMutation } from '../control-plane/control-metadata.types';
import type { IamMutation } from '../iam/iam-mutations.service';

const PUBLIC_COLUMNS = 'id,name,environment,admin_url,proxy_origin,labels,execution_mode,status,version,capabilities,enabled_plugins,last_probed_at,created_at,updated_at,revision,(connection_secret IS NOT NULL) AS connection_configured';
export type Actor = EntityActor;

@Injectable()
export class ClustersService implements OnModuleInit {
  private readonly logger = new Logger(ClustersService.name);
  private controlBridge?:Readonly<ControlBusinessBridge>;
  constructor(private readonly storageDb: DbService, private readonly secrets: SecretService, private readonly kong: KongService, private readonly audit: AuditService, private readonly authz: AuthorizationService, private readonly operations:IamMutationsService, private readonly execution:KongExecutionContextService) {}
  private get db():DbService{return this.controlBridge?.currentTransaction()??this.storageDb;}
  installControlMetadataBridge(bridge:ControlBusinessBridge):void{
    const methods=['currentTransaction','allocateId','execute','completed']as const;
    if(this.controlBridge||!bridge||methods.some(name=>typeof bridge[name]!=='function'))throw new Error('Control metadata requires one fixed business bridge');
    this.controlBridge=Object.freeze({currentTransaction:bridge.currentTransaction.bind(bridge),allocateId:bridge.allocateId.bind(bridge),execute:bridge.execute.bind(bridge),completed:bridge.completed.bind(bridge)});
  }
  private completed<T>(context:IamMutation):Promise<{result:T}|null>{return this.controlBridge?this.controlBridge.completed<T>(context):this.operations.completed<T>(context);}
  private async directControlScope(id:string,tx:DbService=this.db,lock=false):Promise<void>{
    const cluster=await tx.one<{execution_mode:string;status:string}>('SELECT execution_mode,status FROM clusters WHERE id=$1 AND deleted_at IS NULL'+(lock?' FOR SHARE':''),[id]);
    if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在或已停用'});
    if(cluster.execution_mode!=='direct')throw new ConflictException({code:'APPROVAL_REQUIRED',message:'此集群配置变更须经工单审批'});
    if(cluster.status==='disabled')throw new ConflictException({code:'CLUSTER_DISABLED',message:'集群已停用，不能修改配置'});
  }
  private controlMutation<T>(mutation:ControlBusinessMutation,context:IamMutation,fn:(tx:DbService)=>Promise<T>):Promise<T>{
    const direct=async()=>{await this.directControlScope(mutation.clusterId);return this.operations.execute(context,async tx=>{await this.directControlScope(mutation.clusterId,tx,true);return fn(tx);});};
    return this.controlBridge?this.controlBridge.execute(mutation,fn,direct):direct();
  }

  async onModuleInit(): Promise<void> {
    const url = process.env.DEFAULT_KONG_ADMIN_URL;
    if (!url) return;
    validateOutboundUrl(url);
    let cluster = await this.db.one<{ id: string }>('SELECT id FROM clusters WHERE admin_url=$1 AND deleted_at IS NULL ORDER BY created_at LIMIT 1', [url.replace(/\/$/, '')]);
    if (!cluster) {
      const created = await this.bootstrap(url);
      cluster = { id: created.id };
    }
    void this.kong.probe(cluster.id).catch(() => this.logger.warn(JSON.stringify({ event: 'bootstrap_cluster_probe_failed', clusterId: cluster!.id })));
  }

  private async bootstrap(url:string):Promise<any>{
    const normalized=validateOutboundUrl(url).toString().replace(/\/$/,''),inspection=await inspectRegistryEndpoint(this.db,normalized);
    return this.db.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR UPDATE');
      const old=await tx.one('SELECT id FROM clusters WHERE admin_url=$1 AND deleted_at IS NULL',[normalized]);if(old)return old;
      await assertRegistryEndpoint(tx,inspection);const id=randomUUID();
      await tx.exec("INSERT INTO clusters(id,name,admin_url,labels) VALUES($1,'默认集群',$2,ARRAY['bootstrap'])",[id,normalized]);
      await this.audit.append({entityType:'clusters',entityId:id,clusterId:id,action:'cluster.bootstrap',after:{id,admin_url:normalized}},tx);return {id};
    });
  }
  private async display(row:any,actor:Actor):Promise<any>{
    if(await this.authz.isPlatformAdmin(actor.user))return row;const {admin_url,proxy_origin,connection_configured,...safe}=row;return {...safe,proxy_configured:!!proxy_origin};
  }
  private async stable(actor:Actor,version:string):Promise<void>{if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED',message:'查询期间授权已变更，请重新加载'});}
  async list(actor:Actor): Promise<any[]> {
    const version=await this.authz.permissionVersion(actor.user);
    const capabilities=await this.authz.capabilities(actor.user);
    const rows=await this.db.query<any>(`SELECT ${PUBLIC_COLUMNS} FROM clusters WHERE deleted_at IS NULL AND($1::boolean OR id=ANY($2::uuid[])) ORDER BY created_at ASC LIMIT 1001`,[capabilities.platformAdmin,capabilities.clusters]);
    if(rows.length>1000)throw new ConflictException({code:'CLUSTER_REGISTRY_BUDGET',message:'集群登记数量超过查询预算'});
    const result=capabilities.platformAdmin?rows:rows.map(row=>{const {admin_url,proxy_origin,connection_configured,...safe}=row;return {...safe,proxy_configured:!!proxy_origin};});await this.stable(actor,version);return result;
  }
  async get(id:string,actor:Actor):Promise<any>{const version=await this.authz.permissionVersion(actor.user);await this.authz.assertCluster(actor.user,id,'clusters','read');const result=await this.display(await this.readRow(id),actor);await this.stable(actor,version);return result;}

  private async readRow(id: string, tx:DbService=this.db): Promise<any> {
    this.validateId(id);
    const row = await tx.one(`SELECT ${PUBLIC_COLUMNS} FROM clusters WHERE id=$1 AND deleted_at IS NULL`, [id]);
    if (!row) throw new NotFoundException({ code: 'CLUSTER_NOT_FOUND', message: '集群不存在或已停用' });
    return row;
  }

  async create(body: unknown, actor: Actor): Promise<any> {
    await this.authz.assertConsole(actor.user,'clusters','write');
    const dto = parseDto(createClusterSchema, body);
    const cached=await this.operations.completed<any>({actor,module:'clusters',action:'write',cluster_id:null,workspace_id:null,payload:dto});if(cached)return cached.result;
    const url = validateOutboundUrl(dto.admin_url).toString().replace(/\/$/, '');
    const proxyOrigin=dto.proxy_origin?validateProxyOrigin(dto.proxy_origin,url):null;
    if(proxyOrigin)await assertRegisteredProxyOrigin(this.db,proxyOrigin);
    authHeaders(dto.connection_auth);
    const inspection=await inspectRegistryEndpoint(this.db,url);
    const id = randomUUID();
    const encrypted = dto.connection_auth && dto.connection_auth.type !== 'none' ? this.secrets.encrypt(dto.connection_auth, `cluster:${id}`) : null;
    try {
      return await this.operations.execute({actor,module:'clusters',action:'write',cluster_id:null,workspace_id:null,payload:dto},async tx => {
        await assertRegistryEndpoint(tx,inspection);
        if(await tx.one('SELECT id FROM clusters WHERE environment=$1 AND lower(name)=lower($2) AND deleted_at IS NULL',[dto.environment,dto.name]))throw new ConflictException({code:'CLUSTER_NAME_EXISTS',message:'该环境内已存在同名集群'});
        await tx.exec('INSERT INTO clusters(id,name,environment,admin_url,labels,execution_mode,connection_secret,proxy_origin) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, dto.name, dto.environment, url, dto.labels, dto.execution_mode, encrypted,proxyOrigin]);
        const after = await tx.one(`SELECT ${PUBLIC_COLUMNS} FROM clusters WHERE id=$1`, [id]);
        await this.audit.append({ actorId: actor.user?.id, entityType: 'cluster', entityId: id, clusterId: id, action: 'create', after: { ...after, connection_secret: encrypted }, requestId: actor.requestId, ip: actor.ip }, tx);
        return this.display(after,actor);
      });
    } catch (error: any) { this.rethrowUnique(error); }
  }

  async update(id: string, body: unknown, actor: Actor): Promise<any> {
    await this.authz.assertConsole(actor.user,'clusters','write');
    const before = await this.readRow(id);
    const previousSecret = await this.db.one<{ connection_secret: string | null }>('SELECT connection_secret FROM clusters WHERE id=$1 AND deleted_at IS NULL', [id]);
    const dto = parseDto(updateClusterSchema, body);
    const context={actor,module:'clusters',action:'write',targetId:id,cluster_id:null,workspace_id:null,payload:dto};
    const cached=await this.completed<any>(context);if(cached)return cached.result;
    const url = dto.admin_url !== undefined ? validateOutboundUrl(dto.admin_url).toString().replace(/\/$/, '') : before.admin_url;
    if (dto.connection_auth !== undefined) authHeaders(dto.connection_auth);
    const updates: Record<string, unknown> = { name: dto.name ?? before.name, environment: dto.environment ?? before.environment, admin_url: url, labels: dto.labels ?? before.labels, execution_mode: dto.execution_mode ?? before.execution_mode };
    if(dto.proxy_origin!==undefined)updates.proxy_origin=dto.proxy_origin?validateProxyOrigin(dto.proxy_origin,url):null;
    else if(dto.admin_url!==undefined&&before.proxy_origin)validateProxyOrigin(before.proxy_origin,url);
    if(updates.proxy_origin)await assertRegisteredProxyOrigin(this.db,updates.proxy_origin as string);
    if (dto.connection_auth !== undefined) updates.connection_secret = dto.connection_auth && dto.connection_auth.type !== 'none' ? this.secrets.encrypt(dto.connection_auth, `cluster:${id}`) : null;
    const inspection=dto.admin_url!==undefined?await inspectRegistryEndpoint(this.db,url,id):null;
    const connectionChanged = dto.admin_url !== undefined || dto.connection_auth !== undefined;
    if (connectionChanged) Object.assign(updates, { version: null, capabilities: '{}', enabled_plugins: [], status: 'unknown', last_probed_at: null, transport_scope:null });
    const entries = Object.entries(updates);
    try {
      const result=await this.controlMutation({resource:'clusters',operation:'update',clusterId:id,resourceId:id,module:'clusters',action:'write',workspaceId:null,actor,payload:dto},context,async tx => {
        if(inspection)await assertRegistryEndpoint(tx,inspection,id);
        const current=await this.readRow(id,tx);if(current.revision!==dto.revision)throw new ConflictException({code:'REVISION_CONFLICT',message:'配置已变更，请刷新后重试'});
        if(await tx.one('SELECT id FROM clusters WHERE environment=$1 AND lower(name)=lower($2) AND id<>$3 AND deleted_at IS NULL',[updates.environment,updates.name,id]))throw new ConflictException({code:'CLUSTER_NAME_EXISTS',message:'该环境内已存在同名集群'});
        const updated = await tx.exec(`UPDATE clusters SET ${entries.map(([key], i) => `${key}=$${i + 3}`).join(',')},revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND deleted_at IS NULL`, [id, dto.revision, ...entries.map(([, value]) => value)]);
        if (!updated) throw new ConflictException({ code: 'REVISION_CONFLICT', message: '配置已被其他人修改，请刷新后重试' });
        const after = await tx.one(`SELECT ${PUBLIC_COLUMNS} FROM clusters WHERE id=$1`, [id]);
        await this.audit.append({ actorId: actor.user?.id, entityType: 'cluster', entityId: id, clusterId: id, action: 'update', before: { ...before, connection_secret: previousSecret?.connection_secret ?? null }, after: { ...after, connection_secret: dto.connection_auth !== undefined ? updates.connection_secret : previousSecret?.connection_secret ?? null }, requestId: actor.requestId, ip: actor.ip }, tx);
        return this.display(after,actor);
      });
      this.kong.invalidate(id);return result;
    } catch (error: any) { this.rethrowUnique(error); }
  }

  async deactivate(id: string, body: unknown, actor: Actor): Promise<any> {
    await this.authz.assertConsole(actor.user,'clusters','delete');
    const dto = parseDto(deactivateSchema, body);
    const cached=await this.completed<any>({actor,module:'clusters',action:'delete',targetId:id,cluster_id:null,workspace_id:null,payload:dto});if(cached)return cached.result;
    const before = await this.readRow(id);
    if (dto.confirm_name !== before.name) throw new BadRequestException({ code: 'CONFIRMATION_MISMATCH', message: '请再次输入准确的集群名称确认停用' });
    const context={actor,module:'clusters',action:'delete',targetId:id,cluster_id:null,workspace_id:null,payload:dto};
    const result=await this.controlMutation({resource:'clusters',operation:'deactivate',clusterId:id,resourceId:id,module:'clusters',action:'delete',workspaceId:null,actor,payload:dto},context,async tx => {
      const current=await this.readRow(id,tx);if(current.name!==dto.confirm_name)throw new BadRequestException({code:'CONFIRMATION_MISMATCH',message:'集群名称已变化，请重新确认'});
      const updated = await tx.exec("UPDATE clusters SET deleted_at=now(),status='disabled',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND deleted_at IS NULL", [id, dto.revision]);
      if (!updated) throw new ConflictException({ code: 'REVISION_CONFLICT', message: '配置已被其他人修改，请刷新后重试' });
      await this.audit.append({ actorId: actor.user?.id, entityType: 'cluster', entityId: id, clusterId: id, action: 'deactivate', before, after: { ...before, status: 'disabled' }, requestId: actor.requestId, ip: actor.ip }, tx);
      return {id,deactivated:true};
    });
    this.kong.invalidate(id);
    return result;
  }

  async probe(id:string,actor:Actor):Promise<any>{
    await this.authz.assertConsole(actor.user,'clusters','write');await this.readRow(id);
    const version=await this.authz.permissionVersion(actor.user);
    const inspection=await this.execution.runActor({actor:actor.user,clusterId:id,module:'clusters',action:'write'},()=>this.kong.inspectProbe(id));
    return this.storageDb.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton FOR SHARE');
      await this.authz.assertConsole(actor.user,'clusters','write');await this.stable(actor,version);
      return this.kong.persistProbe(id,inspection,{id:actor.user.id,requestId:actor.requestId,ip:actor.ip},tx);
    });
  }
  async capabilities(id: string,actor:Actor): Promise<any> { const row = await this.get(id,actor); return { cluster_id: id, version: row.version, status: row.status, capabilities: row.capabilities, enabled_plugins: row.enabled_plugins, last_probed_at: row.last_probed_at }; }
  validateId(id: string): void { if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) throw new BadRequestException({ code: 'INVALID_ID', message: '资源 ID 格式无效' }); }
  private rethrowUnique(error: any): never { if (error?.code === '23505') throw new ConflictException({ code: 'CLUSTER_NAME_EXISTS', message: '该环境内已存在同名集群' }); throw error; }
}
