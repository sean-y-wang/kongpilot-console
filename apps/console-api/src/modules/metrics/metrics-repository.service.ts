import { BadRequestException,ConflictException,Injectable,NotFoundException } from '@nestjs/common';
import { createHash,randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson,SecretService } from '../../infrastructure/secret.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { workspaceTag } from '../../infrastructure/kong/tags';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { type MetricsAssignment,type MetricsAllowedEpochOptions,type MetricsCatalogInput,type MetricsCatalogPage,
  type MetricsEventBindingInput,type MetricsEventBindingResult,type MetricsResolution } from './metrics.types';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i,hex=/^[a-f0-9]{64}$/;
const invalid=(code='INVALID_METRICS_CATALOG')=>new BadRequestException({code,message:'指标归属目录参数无效'});
const sha=(value:unknown)=>createHash('sha256').update(canonicalJson(value)).digest('hex');
export function metricsTimestamp(value:string|number):number {
  if(typeof value==='number'){if(Number.isSafeInteger(value)&&value>=0&&value<=8640000000000000)return value;throw invalid('INVALID_METRICS_TIMESTAMP');}
  if(typeof value!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value))throw invalid('INVALID_METRICS_TIMESTAMP');
  const parsed=Date.parse(value);if(!Number.isFinite(parsed)||new Date(parsed).toISOString().slice(0,19)!==value.slice(0,19))throw invalid('INVALID_METRICS_TIMESTAMP');return parsed;
}
const iso=(value:any)=>new Date(value).toISOString();
const assignment=(row:any):MetricsAssignment=>({epoch_id:row.id,cluster_id:row.cluster_id,node_id:row.node_id,entity_type:row.entity_type,
  entity_id:row.entity_id,workspace_id:row.workspace_id,service_id:row.service_id,route_id:row.route_id,consumer_id:row.consumer_id,
  tags:row.business_tags,service_label:row.service_label,route_label:row.route_label,valid_from:iso(row.valid_from),
  verified_until:iso(row.verified_until),closed_at:row.closed_at?iso(row.closed_at):null,quality:'verified'});
type Candidate={type:'services'|'routes'|'consumers';id:string;workspaceId:string;serviceId:string|null;routeId:string|null;consumerId:string|null;
  tags:string[];tagHash:string;configHash:string;pairHash:string;serviceLabel:string|null;routeLabel:string|null};
type LabelIssue={entity_type:Candidate['type'];source_pair_hash:string;quality:'unknown'|'ambiguous';reason_code:string};
@Injectable()
export class MetricsRepositoryService {
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly workspaces:WorkspaceResolverService){}
  private validateCid(cid:string):void{if(typeof cid!=='string'||!uuid.test(cid))throw invalid('INVALID_CLUSTER_ID');}
  private tags(value:unknown):string[]{
    if(value==null)return [];
    if(!Array.isArray(value)||value.length>1000||value.some(tag=>typeof tag!=='string'||!tag||tag.length>128))throw invalid();
    return [...value].sort();
  }
  private businessTags(value:string[]):string[]{return [...new Set(value.filter(tag=>!tag.startsWith('kos-ws-')))];}
  private async scope(cid:string,db=this.db):Promise<{scope:string;ids:string[];inactive:boolean}>{
    const row=await db.one<any>('SELECT id,admin_url,transport_scope,status,version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
    if(!row)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
    const scope=transportScopeFor(row.admin_url,row.transport_scope);
    const clusters=await db.query<any>('SELECT id,admin_url,transport_scope FROM clusters WHERE deleted_at IS NULL ORDER BY id LIMIT 10001');
    if(clusters.length>10000)throw invalid('METRICS_CLUSTER_BUDGET');
    return {scope,ids:clusters.filter(item=>transportScopeFor(item.admin_url,item.transport_scope)===scope).map(item=>item.id),
      inactive:['disabled','incompatible'].includes(row.status)||row.version!=null&&!/^1\.5\.\d+$/.test(row.version)};
  }
  private async blocked(scope:string,ids:string[],db=this.db):Promise<boolean>{
    const row=await db.one(`SELECT 1 FROM mutation_operations m WHERE
      (m.transport_scope=$1 OR(m.transport_scope IS NULL AND m.cluster_id=ANY($2::uuid[])))
      AND m.state IN ('pending','running','uncertain') LIMIT 1`,[scope,ids]);
    if(row)return true;
    // A fence with unresolved parent is authoritative even if transport was acknowledged.
    return !!await db.one(`SELECT 1 FROM metrics_write_fences f JOIN mutation_operations m ON m.id=f.operation_id
      WHERE f.transport_scope=$1 AND m.state IN ('pending','running','uncertain') LIMIT 1`,[scope]);
  }
  private async metadata(cid:string,db=this.db):Promise<any>{
    this.validateCid(cid);const physical=await this.scope(cid,db),row=await db.one<any>('SELECT * FROM metrics_settings WHERE cluster_id=$1',[cid]);
    return {...row,catalog_revision:Number(row?.catalog_revision??0),credential_generation:Number(row?.credential_generation??0),
      max_age_ms:Number(row?.max_age_ms??15000),scope:physical.scope,ids:physical.ids,blocked:physical.inactive||await this.blocked(physical.scope,physical.ids,db)};
  }
  private async unchanged(cid:string,old:any):Promise<void>{
    const now=await this.metadata(cid);
    if(now.catalog_revision!==old.catalog_revision||now.credential_generation!==old.credential_generation||now.blocked!==old.blocked)
      throw new ConflictException({code:'METRICS_CATALOG_CHANGED',message:'采集目录或凭证正在变更，请重新核验'});
    if(this.unavailable(now))throw new ConflictException({code:'METRICS_CATALOG_STALE',message:'采集归属证据在请求期间已失效'});
  }
  private async candidates(input:MetricsCatalogInput):Promise<{items:Candidate[];ambiguous:boolean;workspaces:any[];issues:LabelIssue[]}>{
    const items:Candidate[]=[],seen=new Map<string,string>();let ambiguous=false;
    const rawGroups=new Map<string,Set<string>>(),issues=new Map<string,LabelIssue>();
    const raw=(type:Candidate['type'],hash:string,id:string)=>{const key=`${type}:${hash}`;
      if(!rawGroups.has(key))rawGroups.set(key,new Set());rawGroups.get(key)!.add(id);};
    const issue=(type:Candidate['type'],hash:string,quality:'unknown'|'ambiguous',reason:string)=>{
      const key=`${type}:${hash}`;if(issues.get(key)?.quality==='ambiguous')return;
      issues.set(key,{entity_type:type,source_pair_hash:hash,quality,reason_code:reason});};
    const workspaceRows=await this.db.query<any>('SELECT id,code,is_default,revision,status FROM workspaces WHERE cluster_id=$1 ORDER BY id LIMIT 10001',[input.cid]);
    if(workspaceRows.length>10000)throw invalid('METRICS_WORKSPACE_BUDGET');
    const defaultWorkspace=workspaceRows.find(row=>row.is_default&&row.code==='default'&&row.status!=='deleted');
    if(!defaultWorkspace)throw new ConflictException({code:'METRICS_WORKSPACE_UNINITIALIZED',message:'集群默认工作区元数据尚未初始化'});
    const rowsByTag=new Map(workspaceRows.filter(row=>row.status!=='deleted').map(row=>[workspaceTag(row.code),row]));
    const usedWorkspaces=new Map<string,any>();
    const classify=(tags:string[]):any|null=>{
      const reserved=tags.filter(tag=>tag.startsWith('kos-ws-'));if(reserved.length>1)return null;
      const row=reserved.length?rowsByTag.get(reserved[0]):defaultWorkspace;if(!row)return null;
      usedWorkspaces.set(row.id,row);return row;
    };
    const add=(item:Candidate)=>{const identity=`${item.type}:${item.id}`;const old=seen.get(`${item.type}:${item.pairHash}`);
      if(old&&old!==identity)ambiguous=true;else seen.set(`${item.type}:${item.pairHash}`,identity);items.push(item);};
    const services=new Map<string,{value:any;hash:string}>();
    for(const pair of input.routePairs){
      const service=pair?.service,route=pair?.route;
      if(!service||!uuid.test(service.id)||typeof service.host!=='string'||!service.host||service.host.length>2048
        ||service.name!=null&&(typeof service.name!=='string'||!service.name||service.name.length>2048))throw invalid();
      const serviceTags=this.tags(service.tags),serviceMembership=classify(serviceTags);
      const serviceLabel=service.name??service.host,sig=sha({id:service.id,label:serviceLabel,tags:serviceTags});
      const servicePairHash=sha([serviceLabel,null]);raw('services',servicePairHash,service.id);
      if(route!==null&&(!route||!uuid.test(route.id)||!route.service||route.service.id!==service.id
        ||route.name!=null&&(typeof route.name!=='string'||!route.name||route.name.length>2048)))throw invalid();
      const routePairHash=route?sha([serviceLabel,route.name??route.id]):null;
      if(route&&routePairHash)raw('routes',routePairHash,`${service.id}:${route.id}`);
      const serviceSeen=services.has(service.id);
      if(serviceSeen&&services.get(service.id)!.hash!==sig)throw invalid('METRICS_NATIVE_SNAPSHOT_INCONSISTENT');
      services.set(service.id,{value:service,hash:sig});
      if(!serviceMembership){ambiguous=true;issue('services',servicePairHash,'unknown','METRICS_WORKSPACE_UNASSIGNED');
        if(routePairHash)issue('routes',routePairHash,'unknown','METRICS_WORKSPACE_UNASSIGNED');continue;}
      const sw=serviceMembership.id,st=this.businessTags(serviceTags);
      // Service-only mappings are retained only when their original label is globally unique.
      if(!serviceSeen)add({type:'services',id:service.id,workspaceId:sw,
        serviceId:service.id,routeId:null,consumerId:null,tags:st,tagHash:sha({service:st}),configHash:sig,
        pairHash:sha([serviceLabel,null]),serviceLabel,routeLabel:null});
      if(route===null)continue;
      if(!route||!uuid.test(route.id)||!route.service||route.service.id!==service.id||route.name!=null&&(typeof route.name!=='string'||!route.name||route.name.length>2048))throw invalid();
      const rt=this.tags(route.tags),membership=classify(rt);
      if(!membership||membership.id!==sw){ambiguous=true;issue('routes',routePairHash!,'unknown','METRICS_WORKSPACE_UNASSIGNED');continue;}
      const routeLabel=route.name??route.id,routeBusiness=this.businessTags(rt),tags=[...new Set([...st,...routeBusiness])].sort();
      add({type:'routes',id:route.id,workspaceId:sw,serviceId:service.id,routeId:route.id,consumerId:null,tags,
        tagHash:sha({service:st,route:routeBusiness}),configHash:sha({service:sig,route:{id:route.id,label:routeLabel,tags:rt,service:service.id}}),
        pairHash:sha([serviceLabel,routeLabel]),serviceLabel,routeLabel});
    }
    for(const consumer of input.consumers){
      if(!consumer||!uuid.test(consumer.id)||consumer.username!=null&&(typeof consumer.username!=='string'||consumer.username.length>2048)
        ||consumer.custom_id!=null&&(typeof consumer.custom_id!=='string'||consumer.custom_id.length>2048))throw invalid();
      const tags=this.tags(consumer.tags),membership=classify(tags);
      if(!membership){ambiguous=true;issue('consumers',sha(['consumer',consumer.id]),'unknown','METRICS_WORKSPACE_UNASSIGNED');continue;}
      const business=this.businessTags(tags);add({type:'consumers',id:consumer.id,workspaceId:membership.id,
        serviceId:null,routeId:null,consumerId:consumer.id,tags:business,tagHash:sha(business),
        configHash:sha({id:consumer.id,username:consumer.username??null,custom_id:consumer.custom_id??null,tags}),
        pairHash:sha(['consumer',consumer.id]),serviceLabel:null,routeLabel:null});
    }
    // Ambiguous label pairs never receive a workspace label. Other unique pairs may still be verified.
    for(const [key,ids] of rawGroups)if(ids.size>1){const [type,hash]=key.split(':');ambiguous=true;
      issue(type as Candidate['type'],hash,'ambiguous','METRICS_LABEL_AMBIGUOUS');}
    const duplicateIdentities=new Map<string,string>();for(const item of items){const key=`${item.type}:${item.id}`,old=duplicateIdentities.get(key);
      if(old&&old!==item.configHash)throw invalid('METRICS_NATIVE_SNAPSHOT_INCONSISTENT');duplicateIdentities.set(key,item.configHash);}
    const verified=[...new Map(items.filter(item=>!issues.has(`${item.type}:${item.pairHash}`)).map(item=>[`${item.type}:${item.id}`,item])).values()];
    if(verified.length>10000||issues.size>10000)throw invalid('METRICS_CATALOG_BUDGET');
    return {items:verified,ambiguous,workspaces:[...usedWorkspaces.values()],issues:[...issues.values()]};
  }
  async publishVerifiedCatalog(input:MetricsCatalogInput):Promise<{catalogRevision:number;opened:number;closed:number;blocked:boolean}>{
    this.validateCid(input?.cid);
    if(!hex.test(input.nodeId)||input.nodeId!==input.transportScope||!hex.test(input.transportScope)||!Number.isSafeInteger(input.expectedCatalogRevision)
      ||input.expectedCatalogRevision<0||typeof input.complete!=='boolean'||!Array.isArray(input.routePairs)||!Array.isArray(input.consumers)
      ||input.routePairs.length+input.consumers.length>10000||input.observedKongNodeId!=null&&(typeof input.observedKongNodeId!=='string'||!input.observedKongNodeId||input.observedKongNodeId.length>256)
      ||Buffer.byteLength(JSON.stringify(input))>8*1024*1024)throw invalid();
    const observed=metricsTimestamp(input.observedAt),now=Date.now();
    if(observed>now+1000||observed<now-15000)throw new ConflictException({code:'METRICS_NATIVE_PROOF_STALE',message:'原生对象证据已过期'});
    const proof=input.complete?await this.candidates(input):{items:[],ambiguous:false,workspaces:[],issues:[]};
    return this.db.transaction(async tx=>{
      await tx.exec('SELECT pg_advisory_xact_lock(hashtext($1))',[`kongos:metrics-transport:${input.transportScope}`]);
      const physical=await this.scope(input.cid,tx);if(physical.scope!==input.transportScope)throw invalid('METRICS_PHYSICAL_SCOPE_CHANGED');
      await tx.exec('INSERT INTO metrics_settings(cluster_id) VALUES($1) ON CONFLICT DO NOTHING',[input.cid]);
      const settings=await tx.one<any>('SELECT * FROM metrics_settings WHERE cluster_id=$1 FOR UPDATE',[input.cid]);
      if(Number(settings.catalog_revision)!==input.expectedCatalogRevision)throw new ConflictException({code:'METRICS_CATALOG_CHANGED',message:'采集目录已被配置变更失效'});
      const blocked=physical.inactive||await this.blocked(physical.scope,physical.ids,tx);
      const active=await tx.query<any>('SELECT * FROM metrics_assignment_epochs WHERE cluster_id=$1 AND closed_at IS NULL FOR UPDATE',[input.cid]);
      const closeRows=async(rows:any[],reason:string)=>{
        if(!rows.length)return 0;
        const count=await tx.exec(`UPDATE metrics_assignment_epochs SET closed_at=GREATEST($2::timestamptz,valid_from),close_reason=$3,
          retention_until=GREATEST($2::timestamptz,valid_from)+interval '8 days' WHERE id=ANY($1::uuid[]) AND closed_at IS NULL`,[rows.map(row=>row.id),new Date(observed).toISOString(),reason]);
        for(const row of rows)row.closed_at=new Date(Math.max(observed,new Date(row.valid_from).getTime())).toISOString();return count;
      };
      let closed=0,opened=0;
      if(blocked||!input.complete){closed+=await closeRows(active,blocked?'write_unresolved':'catalog_incomplete');
        const status=blocked?'blocked':'partial',change=closed>0||settings.catalog_status!==status;
        await tx.exec('UPDATE metrics_settings SET catalog_status=$2,catalog_revision=catalog_revision+$3,updated_at=now() WHERE cluster_id=$1',[input.cid,status,change?1:0]);
        return {catalogRevision:Number(settings.catalog_revision)+(change?1:0),opened:0,closed,blocked};}
      if(Date.now()-observed>Number(settings.max_age_ms))throw new ConflictException({code:'METRICS_NATIVE_PROOF_STALE',message:'原生对象证据已过期'});
      const currentWorkspaces=proof.workspaces.length?await tx.query<any>(`SELECT id,code,is_default,revision,status FROM workspaces
        WHERE cluster_id=$1 AND id=ANY($2::uuid[]) FOR SHARE`,[input.cid,proof.workspaces.map(row=>row.id)]):[];
      const currentWorkspacesById=new Map(currentWorkspaces.map(row=>[row.id,row]));
      if(currentWorkspaces.length!==proof.workspaces.length||proof.workspaces.some(original=>{
        const current=currentWorkspacesById.get(original.id);return !current||current.status==='deleted'||current.code!==original.code
          ||current.is_default!==original.is_default||current.revision!==original.revision;
      }))throw new ConflictException({code:'METRICS_WORKSPACE_CHANGED',message:'采集归属核验期间工作区元数据已变更'});
      const node=await tx.one<any>('SELECT observed_kong_node_id FROM metrics_nodes WHERE cluster_id=$1 AND node_id=$2',[input.cid,input.nodeId]);
      if(node?.observed_kong_node_id&&!input.observedKongNodeId)throw invalid('METRICS_NODE_PROOF_MISSING');
      const nodeChanged=!node||node.observed_kong_node_id!==(input.observedKongNodeId??null);
      if(node&&nodeChanged)
        closed+=await closeRows(active.filter(row=>row.node_id===input.nodeId),'native_node_changed');
      await tx.exec(`INSERT INTO metrics_nodes(cluster_id,node_id,transport_scope,observed_kong_node_id,last_seen_at) VALUES($1,$2,$3,$4,$5)
        ON CONFLICT(cluster_id,node_id) DO UPDATE SET observed_kong_node_id=EXCLUDED.observed_kong_node_id,last_seen_at=EXCLUDED.last_seen_at,status='verified'`,
        [input.cid,input.nodeId,input.transportScope,input.observedKongNodeId??null,new Date(observed).toISOString()]);
      const until=new Date(observed+Number(settings.max_age_ms)).toISOString(),validFrom=new Date(observed).toISOString();
      const oldIssues=await tx.query<any>('SELECT entity_type,source_pair_hash,quality,reason_code FROM metrics_label_issues WHERE cluster_id=$1 AND verified_until>$2',[input.cid,validFrom]);
      const issueKey=(issue:LabelIssue)=>`${issue.entity_type}:${issue.source_pair_hash}:${issue.quality}:${issue.reason_code}`;
      const issueChanged=canonicalJson(oldIssues.map(issueKey).sort())!==canonicalJson(proof.issues.map(issueKey).sort());
      await tx.exec('UPDATE metrics_label_issues SET verified_until=LEAST(verified_until,$2::timestamptz) WHERE cluster_id=$1',[input.cid,validFrom]);
      if(proof.issues.length)await tx.exec(`INSERT INTO metrics_label_issues(cluster_id,node_id,entity_type,source_pair_hash,quality,reason_code,last_verified_at,verified_until)
        SELECT $2,$3,r.entity_type,r.source_pair_hash,r.quality,r.reason_code,$4,$5 FROM jsonb_to_recordset($1::jsonb)
          AS r(entity_type text,source_pair_hash text,quality text,reason_code text)
        ON CONFLICT(cluster_id,node_id,entity_type,source_pair_hash) DO UPDATE SET quality=EXCLUDED.quality,reason_code=EXCLUDED.reason_code,
          last_verified_at=EXCLUDED.last_verified_at,verified_until=EXCLUDED.verified_until`,[JSON.stringify(proof.issues),input.cid,input.nodeId,validFrom,until]);
      const oldByKey=new Map(active.filter(row=>row.node_id===input.nodeId&&row.closed_at===null).map(row=>[`${row.entity_type}:${row.entity_id}`,row]));
      const keep:string[]=[],insert:Array<Record<string,unknown>>=[];
      for(const item of proof.items){
        const old=oldByKey.get(`${item.type}:${item.id}`);
        if(old&&old.workspace_id===item.workspaceId&&old.tags_fingerprint===item.tagHash&&old.config_fingerprint===item.configHash&&old.source_pair_hash===item.pairHash
          &&new Date(old.verified_until).getTime()>=observed){
          if(observed<new Date(old.last_verified_at).getTime())throw invalid('METRICS_NATIVE_PROOF_REORDERED');keep.push(old.id);continue;
        }
        insert.push({id:randomUUID(),entity_type:item.type,entity_id:item.id,workspace_id:item.workspaceId,service_id:item.serviceId,
          route_id:item.routeId,consumer_id:item.consumerId,business_tags:item.tags,tags_fingerprint:item.tagHash,config_fingerprint:item.configHash,
          source_pair_hash:item.pairHash,service_label:item.serviceLabel,route_label:item.routeLabel});
      }
      const kept=new Set(keep),closeIds=active.filter(row=>row.closed_at===null&&!kept.has(row.id)).map(row=>row.id);
      if(closeIds.length)closed+=await tx.exec(`UPDATE metrics_assignment_epochs SET closed_at=GREATEST($2::timestamptz,valid_from),close_reason='membership_or_proof_changed',
        retention_until=GREATEST($2::timestamptz,valid_from)+interval '8 days' WHERE id=ANY($1::uuid[]) AND closed_at IS NULL`,[closeIds,validFrom]);
      if(keep.length)await tx.exec('UPDATE metrics_assignment_epochs SET last_verified_at=$2,verified_until=$3 WHERE id=ANY($1::uuid[])',[keep,validFrom,until]);
      if(insert.length)opened=await tx.exec(`INSERT INTO metrics_assignment_epochs(id,cluster_id,node_id,entity_type,entity_id,workspace_id,service_id,route_id,
        consumer_id,business_tags,tags_fingerprint,config_fingerprint,source_pair_hash,service_label,route_label,valid_from,last_verified_at,verified_until)
        SELECT r.id,$2,$3,r.entity_type,r.entity_id,r.workspace_id,r.service_id,r.route_id,r.consumer_id,r.business_tags,r.tags_fingerprint,
          r.config_fingerprint,r.source_pair_hash,r.service_label,r.route_label,$4,$4,$5
        FROM jsonb_to_recordset($1::jsonb) AS r(id uuid,entity_type text,entity_id uuid,workspace_id uuid,service_id uuid,route_id uuid,consumer_id uuid,
          business_tags text[],tags_fingerprint text,config_fingerprint text,source_pair_hash text,service_label text,route_label text)`,
        [JSON.stringify(insert),input.cid,input.nodeId,validFrom,until]);
      if(Date.now()-observed>Number(settings.max_age_ms))throw new ConflictException({code:'METRICS_NATIVE_PROOF_STALE',message:'原生对象证据在发布期间已过期'});
      const change=opened>0||closed>0||nodeChanged||issueChanged||settings.catalog_status!=='ready';
      // An unchanged proof extends verification, never epoch opening or a cursor's original expiration.
      await tx.exec("UPDATE metrics_settings SET catalog_status='ready',catalog_revision=catalog_revision+$3,last_verified_at=$2,updated_at=now() WHERE cluster_id=$1",[input.cid,validFrom,change?1:0]);
      return {catalogRevision:Number(settings.catalog_revision)+(change?1:0),opened,closed,blocked:false};
    });
  }
  async getObservedNode(cid:string,nodeId:string):Promise<{clusterId:string;nodeId:string;transportScope:string;observedKongNodeId:string|null;lastSeenAt:string;status:string}|null>{
    this.validateCid(cid);if(!hex.test(nodeId))throw invalid();
    const row=await this.db.one<any>('SELECT * FROM metrics_nodes WHERE cluster_id=$1 AND node_id=$2',[cid,nodeId]);
    return row?{clusterId:cid,nodeId:row.node_id,transportScope:row.transport_scope,observedKongNodeId:row.observed_kong_node_id,
      lastSeenAt:iso(row.last_seen_at),status:row.status}:null;
  }
  private unavailable(meta:any):Exclude<MetricsResolution,{quality:'verified'}>|null{
    if(meta.blocked||meta.catalog_status==='blocked')return {quality:'blocked',assignment:null,reasonCode:'METRICS_WRITE_UNRESOLVED',catalogRevision:meta.catalog_revision};
    if(meta.catalog_status!=='ready')return {quality:'unknown',assignment:null,reasonCode:'METRICS_CATALOG_INCOMPLETE',catalogRevision:meta.catalog_revision};
    if(!meta.last_verified_at||new Date(meta.last_verified_at).getTime()+meta.max_age_ms<Date.now())return {quality:'stale',assignment:null,reasonCode:'METRICS_CATALOG_STALE',catalogRevision:meta.catalog_revision};
    return null;
  }
  async resolvePair(cid:string,serviceLabel:string,routeLabel?:string|null,nodeId?:string):Promise<MetricsResolution>{
    if(typeof serviceLabel!=='string'||!serviceLabel||serviceLabel.length>2048||routeLabel!=null&&(typeof routeLabel!=='string'||routeLabel.length>2048)||nodeId!==undefined&&!hex.test(nodeId))throw invalid();
    const meta=await this.metadata(cid),unavailable=this.unavailable(meta);if(unavailable)return unavailable;
    const type=routeLabel?'routes':'services',pair=sha([serviceLabel,routeLabel||null]);
    const rows=await this.db.query<any>(`SELECT * FROM metrics_assignment_epochs WHERE cluster_id=$1 AND entity_type=$2 AND source_pair_hash=$3
      AND closed_at IS NULL AND verified_until>=now() AND($4::text IS NULL OR node_id=$4) LIMIT 2`,[cid,type,pair,nodeId??null]);
    const issue=rows.length?null:await this.db.one<any>(`SELECT quality,reason_code FROM metrics_label_issues WHERE cluster_id=$1 AND entity_type=$2
      AND source_pair_hash=$3 AND verified_until>=now() AND($4::text IS NULL OR node_id=$4) ORDER BY quality LIMIT 1`,[cid,type,pair,nodeId??null]);
    await this.unchanged(cid,meta);
    if(rows.length!==1)return {quality:rows.length>1?'ambiguous':issue?.quality??'unknown',assignment:null,reasonCode:rows.length>1?'METRICS_LABEL_AMBIGUOUS':issue?.reason_code??'METRICS_LABEL_UNASSIGNED',catalogRevision:meta.catalog_revision};
    return {quality:'verified',assignment:assignment(rows[0]),catalogRevision:meta.catalog_revision};
  }
  async resolveConsumer(cid:string,consumerId:string,nodeId?:string):Promise<MetricsResolution>{
    if(!uuid.test(consumerId)||nodeId!==undefined&&!hex.test(nodeId))throw invalid();
    const meta=await this.metadata(cid),unavailable=this.unavailable(meta);if(unavailable)return unavailable;
    const rows=await this.db.query<any>(`SELECT * FROM metrics_assignment_epochs WHERE cluster_id=$1 AND entity_type='consumers' AND consumer_id=$2
      AND closed_at IS NULL AND verified_until>=now() AND($3::text IS NULL OR node_id=$3) LIMIT 2`,[cid,consumerId,nodeId??null]);await this.unchanged(cid,meta);
    return rows.length===1?{quality:'verified',assignment:assignment(rows[0]),catalogRevision:meta.catalog_revision}
      :{quality:rows.length>1?'ambiguous':'unknown',assignment:null,reasonCode:'METRICS_CONSUMER_UNASSIGNED',catalogRevision:meta.catalog_revision};
  }
  async catalog(cid:string,options:{cursor?:string;size?:number;includeConsumers?:boolean;maxLatenessMs?:number}={}):Promise<MetricsCatalogPage>{
    const size=options.size??100;if(!Number.isInteger(size)||size<1||size>256||options.maxLatenessMs!==undefined&&(!Number.isInteger(options.maxLatenessMs)||options.maxLatenessMs<0||options.maxLatenessMs>300000))throw invalid();
    const meta=await this.metadata(cid),unavailable=this.unavailable(meta);let after:string|null=null;
    if(options.cursor){try{const cursor=this.secrets.decrypt<any>(options.cursor,`metrics-catalog:${cid}`);
      if(cursor.revision!==meta.catalog_revision||cursor.generation!==meta.credential_generation||cursor.expires<Date.now()||cursor.size!==size||cursor.consumers!==(options.includeConsumers??true)
        ||cursor.lateness!==(options.maxLatenessMs??0)||!uuid.test(cursor.after))throw new Error();after=cursor.after;
    }catch{throw new ConflictException({code:'METRICS_CATALOG_CURSOR_STALE',message:'采集目录游标已失效，请从第一页核验'});}}
    if(unavailable)return {clusterId:cid,catalogRevision:meta.catalog_revision,credentialGeneration:meta.credential_generation,generatedAt:new Date().toISOString(),
      validUntil:null,blocked:unavailable.quality==='blocked',complete:false,items:[],nextCursor:null,warnings:[unavailable.reasonCode]};
    const rows=await this.db.query<any>(`SELECT * FROM metrics_assignment_epochs WHERE cluster_id=$1 AND($2::uuid IS NULL OR id>$2)
      AND($3::boolean OR entity_type<>'consumers') AND((closed_at IS NULL AND verified_until>=now())
      OR($4::integer>0 AND closed_at>=now()-($4*interval '1 millisecond'))) ORDER BY id LIMIT $5`,
      [cid,after,options.includeConsumers??true,options.maxLatenessMs??0,size+1]);
    await this.unchanged(cid,meta);const items=rows.slice(0,size).map(assignment),expires=new Date(meta.last_verified_at).getTime()+meta.max_age_ms;
    const nextCursor=rows.length>size?this.secrets.encrypt({revision:meta.catalog_revision,generation:meta.credential_generation,size,
      consumers:options.includeConsumers??true,lateness:options.maxLatenessMs??0,after:rows[size-1].id,expires},`metrics-catalog:${cid}`):null;
    return {clusterId:cid,catalogRevision:meta.catalog_revision,credentialGeneration:meta.credential_generation,generatedAt:new Date().toISOString(),validUntil:new Date(expires).toISOString(),
      blocked:false,complete:true,items,nextCursor,warnings:[]};
  }
  async currentAllowedEpochs(cid:string,options:MetricsAllowedEpochOptions={}):Promise<{catalogRevision:number;items:MetricsAssignment[];blocked:boolean;warnings:string[]}>{
    const arrays=[options.authorizedServiceIds??[],options.authorizedRouteIds??[],options.authorizedConsumerIds??[]];
    if(arrays.reduce((sum,list)=>sum+list.length,0)>256||arrays.some(list=>!Array.isArray(list)||list.some(id=>!uuid.test(id)))||options.workspaceId!==undefined&&!uuid.test(options.workspaceId)
      ||options.includeConsumerCandidates!==undefined&&typeof options.includeConsumerCandidates!=='boolean')throw invalid('METRICS_SELECTOR_BUDGET');
    const meta=await this.metadata(cid);if(options.expectedCatalogRevision!==undefined&&options.expectedCatalogRevision!==meta.catalog_revision)
      throw new ConflictException({code:'METRICS_CATALOG_CHANGED',message:'指标归属版本已变更'});
    const unavailable=this.unavailable(meta);if(unavailable)return {catalogRevision:meta.catalog_revision,items:[],blocked:unavailable.quality==='blocked',warnings:[unavailable.reasonCode]};
    if(options.platformHistory)throw invalid('METRICS_HISTORICAL_QUERY_DISABLED');
    const allIds=!['authorizedServiceIds','authorizedRouteIds','authorizedConsumerIds'].some(key=>Object.hasOwn(options,key));
    if(!allIds&&!arrays.some(list=>list.length))return {catalogRevision:meta.catalog_revision,items:[],blocked:false,warnings:[]};
    const rows=await this.db.query<any>(`SELECT * FROM metrics_assignment_epochs WHERE cluster_id=$1
      AND($2::uuid IS NULL OR workspace_id=$2) AND closed_at IS NULL AND verified_until>=now()
      AND($3::boolean OR(entity_type='services' AND service_id=ANY($4::uuid[])) OR(entity_type='routes' AND(route_id=ANY($5::uuid[]) OR service_id=ANY($4::uuid[])))
        OR(entity_type='consumers' AND(consumer_id=ANY($6::uuid[]) OR $7::boolean))) ORDER BY valid_from DESC,id DESC LIMIT 257`,
      [cid,options.workspaceId??null,allIds,...arrays,options.includeConsumerCandidates===true&&!Object.hasOwn(options,'authorizedConsumerIds')]);
    await this.unchanged(cid,meta);if(rows.length>256)throw invalid('METRICS_SELECTOR_BUDGET');
    return {catalogRevision:meta.catalog_revision,items:rows.map(assignment),blocked:false,warnings:[]};
  }
  async validateEventBindings(cid:string,input:MetricsEventBindingInput):Promise<MetricsEventBindingResult>{
    if(!input||!Number.isSafeInteger(input.credentialGeneration)||input.credentialGeneration<1||!Array.isArray(input.items)||input.items.length>256)throw invalid('METRICS_EVENT_BUDGET');
    let refs=0;const indices=new Set<number>(),parsed=input.items.map(item=>{
      if(!item||!Number.isSafeInteger(item.index)||item.index<0||indices.has(item.index))throw invalid();indices.add(item.index);
      const ids=[item.serviceId,item.routeId,item.consumerId,...(item.epochIds??[])].filter(id=>id!==undefined);
      if(ids.some(id=>typeof id!=='string'||!uuid.test(id))||(refs+=ids.length)>256)throw invalid('METRICS_EVENT_BUDGET');
      const start=metricsTimestamp(item.startedAt),end=metricsTimestamp(item.endedAt);
      if(end<start||end-start>300000||end>Date.now()+1000||start<Date.now()-300000)throw invalid('METRICS_EVENT_INTERVAL_INVALID');
      if(item.routeId&&!item.serviceId)throw invalid();return {...item,start,end};
    });
    const meta=await this.metadata(cid);if(meta.credential_generation!==input.credentialGeneration)
      throw new ConflictException({code:'METRICS_GENERATION_CHANGED',message:'采集凭证代次已变更'});
    const unavailable=this.unavailable(meta);
    if(unavailable)return {catalogRevision:meta.catalog_revision,credentialGeneration:meta.credential_generation,
      items:parsed.map(item=>({index:item.index,quality:unavailable.quality,reasonCode:'reasonCode' in unavailable?unavailable.reasonCode:'METRICS_UNAVAILABLE'}))};
    const serviceIds=[...new Set(parsed.map(item=>item.serviceId).filter(Boolean))],routeIds=[...new Set(parsed.map(item=>item.routeId).filter(Boolean))],consumerIds=[...new Set(parsed.map(item=>item.consumerId).filter(Boolean))];
    const rows=parsed.length?await this.db.query<any>(`SELECT * FROM metrics_assignment_epochs WHERE cluster_id=$1 AND
      ((entity_type='services' AND service_id=ANY($2::uuid[])) OR(entity_type='routes' AND route_id=ANY($3::uuid[])) OR(entity_type='consumers' AND consumer_id=ANY($4::uuid[])))
      AND verified_until>=now()-interval '5 minutes' ORDER BY valid_from DESC LIMIT 2049`,[cid,serviceIds,routeIds,consumerIds]):[];
    if(rows.length>2048)throw invalid('METRICS_EVENT_HISTORY_BUDGET');
    const results:MetricsEventBindingResult['items']=parsed.map(item=>{
      const within=(row:any)=>new Date(row.valid_from).getTime()<=item.start&&new Date(row.verified_until).getTime()>=item.end
        &&(!row.closed_at||new Date(row.closed_at).getTime()>=item.end)&&(!item.epochIds?.length||item.epochIds.includes(row.id));
      const routes=rows.filter(row=>row.entity_type==='routes'&&row.route_id===item.routeId&&row.service_id===item.serviceId&&within(row));
      const services=rows.filter(row=>row.entity_type==='services'&&row.service_id===item.serviceId&&within(row));
      const consumers=rows.filter(row=>row.entity_type==='consumers'&&row.consumer_id===item.consumerId&&within(row));
      const primary=item.routeId?routes:services;
      if(primary.length!==1||item.consumerId&&consumers.length!==1)return {index:item.index,quality:primary.length>1||consumers.length>1?'ambiguous':'unknown',reasonCode:'METRICS_EVENT_INTERVAL_UNASSIGNED'};
      const node=primary[0].node_id,workspace=primary[0].workspace_id;
      if(item.consumerId&&(consumers[0].workspace_id!==workspace||consumers[0].node_id!==node))return {index:item.index,quality:'unknown',reasonCode:'METRICS_EVENT_SCOPE_MISMATCH'};
      return {index:item.index,quality:'verified',...(item.routeId?{routeEpoch:assignment(primary[0])}:{serviceEpoch:assignment(primary[0])}),
        ...(item.consumerId?{consumerEpoch:assignment(consumers[0])}:{})};
    });await this.unchanged(cid,meta);return {catalogRevision:meta.catalog_revision,credentialGeneration:meta.credential_generation,items:results};
  }
}
