import { BadGatewayException, BadRequestException, ConflictException, HttpException, Injectable } from '@nestjs/common';
import { isIP } from 'node:net';
import { KongService } from '../../infrastructure/kong/kong.service';
import { CredentialStoreService } from '../credentials/credential-store.service';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';

export interface GraphNode {
  key: string;
  type: string;
  id: string;
  path: string;
  data: any;
  affected: boolean;
  dependencies: string[];
  restoreData?: any;
  restorable: boolean;
  reason?: string;
}

export interface RecycleGraph {
  rootKey: string;
  nodes: GraphNode[];
  complete: true;
  capturedAt: string;
  /** Immutable Target history is archived, but only current effective nodes are restored. */
  targetHistory?: Array<{ upstreamId: string; items: any[] }>;
  /** Optional only on archives captured before M3. */
  purpose?: 'recycle' | 'migration' | 'baseline';
  budget?: { pages:number; records:number; nodes:number; bytes?:number; maxPages:number; maxRecords:number; maxNodes:number; maxBytes?:number };
}

export interface CaptureOptions {
  parentId?: string;
  credentialKind?: string;
  purpose?: 'recycle' | 'migration' | 'baseline';
  budget?: {maxPages?:number;maxRecords?:number;maxNodes?:number;maxBytes?:number};
}

const ENTITIES = new Set(['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis']);
const CREDENTIAL_KINDS = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const;
const MAX_PAGES = 100;
const MAX_NODES = 10_000;
const PAGE_SIZE = 100;
const MAX_BYTES = 32*1024*1024;

function isCredential(type: string): boolean {
  return (CREDENTIAL_KINDS as readonly string[]).includes(type);
}

function segment(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > 1024 || value === '.' || value === '..' || /[\\/\u0000?#]/.test(value)) {
    throw new BadRequestException({ code: 'INVALID_GRAPH_ENTITY_ID', message: '对象图中的实体标识无效' });
  }
  return encodeURIComponent(value);
}

function entityPath(type: string, id: string, parentId?: string): string {
  if (type === 'targets') return `/upstreams/${segment(parentId)}/targets/${segment(id)}`;
  if (isCredential(type)) return `/consumers/${segment(parentId)}/${type}/${segment(id)}`;
  return `/${type}/${segment(id)}`;
}

function foreignId(value: any): string | undefined {
  if (value === null || value === undefined) return undefined;
  const id = typeof value === 'string' ? value : value?.id;
  if (typeof id !== 'string' || !id) {
    throw new BadGatewayException({ code: 'KONG_INVALID_ENTITY_GRAPH', message: 'Kong 返回了无效的对象关联，拒绝不完整归档' });
  }
  segment(id);
  return id;
}

function restoreBody(data: any): any {
  const { created_at: _created, updated_at: _updated, ...body } = structuredClone(data);
  return body;
}

/** Captures everything needed before destructive writes. This service never writes to Kong. */
@Injectable()
export class GraphCapturerService {
  constructor(private readonly kong: KongService, private readonly credentials: CredentialStoreService,private readonly execution:KongExecutionContextService) {}

  async capture(clusterId:string,entityType:string,entityId:string,options:CaptureOptions={}):Promise<RecycleGraph>{
    return this.captureGraph(clusterId,entityType,entityId,options,true);
  }
  /** Current raw witness only. Baseline purpose prevents reuse as an archive;
   * no credential plaintext custody or restoration recipe is manufactured. */
  async observe(clusterId:string,entityType:string,entityId:string,options:Omit<CaptureOptions,'purpose'>={}):Promise<RecycleGraph>{
    return this.captureGraph(clusterId,entityType,entityId,{...options,purpose:'baseline'},false);
  }
  private async captureGraph(clusterId: string, entityType: string, entityId: string, options: CaptureOptions, restoreMaterial:boolean): Promise<RecycleGraph> {
    if(options.purpose!==undefined&&!['recycle','migration','baseline'].includes(options.purpose))throw new BadRequestException('对象图用途无效');
    const limits={maxPages:options.budget?.maxPages??MAX_PAGES,maxRecords:options.budget?.maxRecords??MAX_NODES,maxNodes:options.budget?.maxNodes??MAX_NODES,maxBytes:options.budget?.maxBytes??MAX_BYTES};
    for(const [key,maximum] of Object.entries({maxPages:MAX_PAGES,maxRecords:MAX_NODES,maxNodes:MAX_NODES,maxBytes:MAX_BYTES})){
      const value=limits[key as keyof typeof limits];
      if(value===0)throw new ConflictException({code:'RECYCLE_CAPTURE_LIMIT',message:'本次对象图的剩余捕获预算已耗尽，未执行变更'});
      if(!Number.isInteger(value)||value<0||value>maximum)throw new BadRequestException({code:'INVALID_CAPTURE_BUDGET',message:'捕获预算必须是安全上限内的正整数'});
    }
    const type = entityType === 'credentials' ? options.credentialKind : entityType;
    if (!type || (!ENTITIES.has(type) && type !== 'targets' && !isCredential(type))) {
      throw new BadRequestException({ code: 'INVALID_GRAPH_ENTITY_TYPE', message: '不支持的回收站实体类型' });
    }
    if ((type === 'targets' || isCredential(type)) && !options.parentId) {
      throw new BadRequestException({ code: 'GRAPH_PARENT_REQUIRED', message: 'Target 或凭证归档必须指定所属实体' });
    }
    const session = new CaptureSession(this.kong, this.credentials, clusterId,options.purpose??'recycle',limits,restoreMaterial);
    return this.execution.runInternalRead(clusterId,'capture',()=>session.capture(type,entityId,options.parentId),
      {maxPages:limits.maxPages,maxRecords:limits.maxRecords,maxBytes:limits.maxBytes});
  }
}

/** All counters and collection caches belong to a single capture, never to a shared provider. */
class CaptureSession {
  private readonly nodes = new Map<string, GraphNode>();
  private readonly history: Array<{ upstreamId: string; items: any[] }> = [];
  private pages = 0;
  private records = 0;
  private bytes = 0;
  private plugins?: any[];

  constructor(private readonly kong: KongService, private readonly credentials: CredentialStoreService, private readonly clusterId: string,
    private readonly purpose:'recycle'|'migration'|'baseline',private readonly limits:{maxPages:number;maxRecords:number;maxNodes:number;maxBytes:number},private readonly restoreMaterial=true) {}

  private charge(value:any):void{
    const size=Buffer.byteLength(JSON.stringify(value),'utf8');
    if(this.bytes+size>this.limits.maxBytes)this.limit();
    this.bytes+=size;
  }

  async capture(type: string, id: string, parentId?: string): Promise<RecycleGraph> {
    const data = await this.kong.request(this.clusterId, 'GET', entityPath(type, id, parentId));
    const root = await this.add(type, data, true, parentId);

    if (type === 'targets') {
      await this.assertEffectiveTarget(root);
    } else if (type === 'services') {
      const routeIds = new Set<string>();
      for (const route of await this.listAll(`/services/${segment(root.id)}/routes`)) {
        const child = await this.add('routes', route, true);
        if (!child.dependencies.includes(root.key)) this.invalid('Service 的 Route 集合包含不匹配的所属关系');
        routeIds.add(child.id);
      }
      for (const plugin of await this.allPlugins()) {
        if (foreignId(plugin.service) === root.id || routeIds.has(foreignId(plugin.route) || '')) await this.add('plugins', plugin, true);
      }
    } else if (type === 'routes') {
      for (const plugin of await this.allPlugins()) if (foreignId(plugin.route) === root.id) await this.add('plugins', plugin, true);
    } else if (type === 'consumers') {
      for (const kind of CREDENTIAL_KINDS) {
        for (const credential of await this.listAll(`/consumers/${segment(root.id)}/${kind}`)) await this.add(kind, credential, true, root.id);
      }
      for (const plugin of await this.allPlugins()) if (foreignId(plugin.consumer) === root.id) await this.add('plugins', plugin, true);
    } else if (type === 'upstreams') {
      const history = await this.listAll(`/upstreams/${segment(root.id)}/targets/all`);
      this.charge(history);
      this.history.push({ upstreamId: root.id, items: structuredClone(history) });
      const effective = new Map<string, any>();
      for (const target of await this.listAll(`/upstreams/${segment(root.id)}/targets`)) {
        if (typeof target?.target !== 'string' || !target.target || typeof target.weight !== 'number' || !Number.isFinite(target.weight) || target.weight < 0) this.invalid('Target 状态数据无效');
        if (target.weight === 0) continue;
        const previous = effective.get(target.target);
        if (previous && previous.id !== target.id) this.invalid('有效 Target 集合存在同地址的冲突记录');
        effective.set(target.target, target);
      }
      const historicalIds = new Set(history.map(item => item?.id));
      for (const target of effective.values()) {
        if (!historicalIds.has(target.id)) this.invalid('Target 历史与有效状态在捕获期间变化，请重新归档');
        await this.add('targets', target, true, root.id);
      }
    } else if (type === 'certificates') {
      // PostgreSQL's Service client_certificate foreign key is restrictive. Detect it
      // before touching SNIs, rather than discovering it after a partial deletion.
      for (const service of this.purpose!=='migration'?await this.listAll('/services'):[]) {
        if (foreignId(service.client_certificate) === root.id) {
          if(this.purpose==='baseline'){await this.add('services',service,false);continue;}
          throw new ConflictException({ code: 'CERTIFICATE_IN_USE', message: '此证书仍被 Service 用作客户端证书；请先解除关联，尚未执行删除' });
        }
      }
      for (const sni of await this.listAll(`/certificates/${segment(root.id)}/snis`)) {
        const child = await this.add('snis', sni, true);
        if (!child.dependencies.includes(root.key)) this.invalid('证书的 SNI 集合包含不匹配的所属关系');
      }
    }

    this.assertDependencyDag();
    return {
      rootKey: root.key,
      nodes: [...this.nodes.values()],
      complete: true,
      capturedAt: new Date().toISOString(),
      purpose:this.purpose,
      budget:{pages:this.pages,records:this.records,nodes:this.nodes.size,bytes:this.bytes,...this.limits},
      ...(this.history.length ? { targetHistory: this.history } : {}),
    };
  }

  private invalid(message: string): never {
    throw new BadGatewayException({ code: 'KONG_INVALID_ENTITY_GRAPH', message });
  }

  private limit(): never {
    throw new ConflictException({ code: 'RECYCLE_CAPTURE_LIMIT', message: '对象图超过安全捕获预算（最多 100 页 / 10000 对象 / 32 MiB），未执行变更' });
  }

  private async assertEffectiveTarget(root: GraphNode): Promise<void> {
    if (typeof root.data.target !== 'string' || !root.data.target) this.invalid('Target 地址缺失，无法核验当前有效记录');
    const upstream = root.dependencies.map(key => this.nodes.get(key)).find(node => node?.type === 'upstreams');
    if (!upstream) this.invalid('Target 缺少已捕获的 Upstream 依赖');
    const notEffective = (): never => {
      throw new ConflictException({ code: 'TARGET_NOT_EFFECTIVE', message: '此 Target ID 已是历史或停用记录，删除已停止；请刷新当前有效 Target 后重试' });
    };
    // Kong 1.5's address GET uses a global endpoint-key lookup and may select
    // history belonging to another Upstream. Only the scoped effective list
    // proves which immutable UUID is currently active for this address.
    const current = (await currentEffectiveTarget(this.kong,this.clusterId,upstream.id,root.data.target,{
      maxPages:this.limits.maxPages-this.pages,maxRecords:this.limits.maxRecords-this.records,maxBytes:this.limits.maxBytes-this.bytes,
      onPage:(_page,usage)=>{this.pages+=usage.pages;this.records+=usage.records;this.bytes+=usage.bytes;},
    })).target;
    if(!current)notEffective();
    if (typeof current.id !== 'string' || typeof current.weight !== 'number' || !Number.isFinite(current.weight)) this.invalid('Kong 返回了无效的当前 Target 状态');
    if (current.id !== root.id || current.weight <= 0) notEffective();
    if (current.target !== root.data.target || (foreignId(current.upstream) && foreignId(current.upstream) !== upstream.id)) this.invalid('当前 Target 返回了不匹配的所属关系或地址');
  }

  private async listAll(path: string): Promise<any[]> {
    const result: any[] = [];
    const seenCursors = new Set<string>();
    const size=Math.min(PAGE_SIZE,this.limits.maxRecords-this.records);
    if(size<=0)this.limit();
    let cursor: string | undefined;
    do {
      if (this.pages >= this.limits.maxPages) this.limit();
      if(this.records+size>this.limits.maxRecords)this.limit();
      this.pages += 1;
      const page = await this.kong.list(this.clusterId, path, { size }, cursor);
      if (!Array.isArray(page?.items) || page.items.length > size) this.invalid('Kong 返回了无效的分页结果');
      this.records += page.items.length;
      if (this.records > this.limits.maxRecords) this.limit();
      this.charge(page.items);
      result.push(...page.items);
      if (page.nextCursor !== null && typeof page.nextCursor !== 'string') this.invalid('Kong 返回了无效的分页游标');
      if (page.nextCursor) {
        if (seenCursors.has(page.nextCursor)) {
          throw new ConflictException({ code: 'RECYCLE_PAGINATION_LOOP', message: 'Kong 分页游标重复，拒绝不完整归档' });
        }
        seenCursors.add(page.nextCursor);
      }
      cursor = page.nextCursor || undefined;
    } while (cursor);
    return result;
  }

  private async allPlugins(): Promise<any[]> {
    // 1.5's approved API has no nested service/route/consumer plugin collections.
    if (!this.plugins) this.plugins = await this.listAll('/plugins');
    return this.plugins;
  }

  private async reference(type: string, id: string): Promise<GraphNode> {
    const key = `${type}:${id}`;
    const existing = this.nodes.get(key);
    if (existing) return existing;
    if(this.nodes.size>=this.limits.maxNodes)this.limit();
    const data = await this.kong.request(this.clusterId, 'GET', entityPath(type, id));
    return this.add(type, data, false);
  }

  private async add(type: string, raw: any, affected: boolean, parentId?: string): Promise<GraphNode> {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || typeof raw.id !== 'string' || !raw.id) this.invalid('Kong 未返回完整实体 ID，拒绝不完整归档');
    const id = raw.id;
    segment(id);
    this.charge(raw);
    const data = structuredClone(raw);
    const contextual = type === 'targets' || isCredential(type);
    const ownerId = contextual ? foreignId(type === 'targets' ? data.upstream : data.consumer) || parentId : undefined;
    if (contextual && !ownerId) this.invalid('Target 或凭证缺少所属实体');
    if (contextual && parentId && ownerId !== parentId) this.invalid('Target 或凭证属于其他父对象，拒绝跨对象归档');
    const key = contextual ? `${type}:${ownerId}:${id}` : `${type}:${id}`;
    const existing = this.nodes.get(key);
    if (existing) {
      if (affected && !existing.affected) {
        existing.affected = true;
        if(this.restoreMaterial&&this.purpose!=='migration')existing.restoreData = await this.getRestoreBody(type, existing.data, ownerId);
      }
      return existing;
    }
    if (this.nodes.size >= this.limits.maxNodes) this.limit();
    const node: GraphNode = { key, type, id, path: entityPath(type, id, ownerId), data, affected, dependencies: [], restorable: true };
    // Register first: references to already captured parents must never recurse into cascades.
    this.nodes.set(key, node);
    const dependency = async (parentType: string, value: any, required = false): Promise<GraphNode | undefined> => {
      const referenceId = foreignId(value);
      if (!referenceId) {
        if (required) this.invalid('必需的对象依赖缺失，拒绝不完整归档');
        return undefined;
      }
      const parent = await this.reference(parentType, referenceId);
      if (!node.dependencies.includes(parent.key)) node.dependencies.push(parent.key);
      return parent;
    };
    if (type === 'services') {
      await dependency('certificates', data.client_certificate);
      if(data.ca_certificates!==null&&data.ca_certificates!==undefined){
        if(!Array.isArray(data.ca_certificates))this.invalid('Service 的 CA 引用必须为数组');
        for(const ca of data.ca_certificates)await dependency('ca_certificates',ca,true);
      }
      if (typeof data.host === 'string' && !isIP(data.host.replace(/^\[|\]$/g, '')) && /^[a-zA-Z\d_.-]+$/.test(data.host)) {
        // Service.host may be an ordinary DNS name. Only an actual Upstream match
        // is an implicit shared dependency; IP literals cannot name an Upstream
        // in 1.5 and must not trigger its rejecting hostname lookup.
        try {
          const upstream = await this.kong.request(this.clusterId, 'GET', `/upstreams/${segment(data.host)}`);
          const parent = await this.add('upstreams', upstream, false);
          if (!node.dependencies.includes(parent.key)) node.dependencies.push(parent.key);
        } catch (error) {
          if (!(error instanceof HttpException && error.getStatus() === 404)) throw error;
        }
      }
    }
    if (type === 'routes') await dependency('services', data.service);
    if (type === 'plugins') {
      await dependency('services', data.service);
      await dependency('routes', data.route);
      await dependency('consumers', data.consumer);
    }
    if (type === 'snis') await dependency('certificates', data.certificate, true);
    if (contextual) {
      const parent = await dependency(type === 'targets' ? 'upstreams' : 'consumers', ownerId, true);
      node.path = entityPath(type, id, parent!.id);
    }
    if (affected&&this.restoreMaterial&&this.purpose!=='migration') node.restoreData = await this.getRestoreBody(type, data, ownerId);
    return node;
  }

  private async getRestoreBody(type: string, data: any, parentId?: string): Promise<any> {
    if (!isCredential(type)) {
      const body = restoreBody(data);
      // Certificate GET may include expanded SNI names. SNI nodes have their own
      // original IDs and are restored separately, avoiding auto-generated duplicates.
      if (type === 'certificates') delete body.snis;
      this.charge(body);
      return body;
    }
    // Basic-auth's remote password is a hash, never a usable restore secret.
    // CredentialStore must fail closed if its encrypted original plaintext is absent.
    const payload = await this.credentials.getRestorePayload(this.clusterId, parentId!, type, data.id, structuredClone(data));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) this.invalid('凭证恢复数据无效');
    const body={ ...restoreBody(payload), id: data.id };
    this.charge(body);
    return body;
  }

  private assertDependencyDag(): void {
    const degree = new Map<string, number>();
    const children = new Map<string, string[]>();
    for (const node of this.nodes.values()) {
      degree.set(node.key, node.dependencies.length);
      for (const key of node.dependencies) {
        if (!this.nodes.has(key)) this.invalid('对象图包含未捕获的依赖');
        const list = children.get(key) || [];
        list.push(node.key);
        children.set(key, list);
      }
    }
    const ready = [...degree.entries()].filter(([, count]) => count === 0).map(([key]) => key);
    let visited = 0;
    for (let index = 0; index < ready.length; index++) {
      visited += 1;
      for (const key of children.get(ready[index]) || []) {
        const count = degree.get(key)! - 1;
        degree.set(key, count);
        if (count === 0) ready.push(key);
      }
    }
    if (visited !== this.nodes.size) this.invalid('对象图存在循环依赖，无法安全恢复');
  }
}
