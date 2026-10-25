import { ConflictException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { GraphCapturerService, type GraphNode, type RecycleGraph } from '../recycle-bin/graph-capturer.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { AuditService } from '../audit/audit.service';
import { metadataAuditScope } from '../event-producers/native-audit-scope';
import { ConfigurationAccessService } from './configuration-access.service';
import type { ConfigPlan, ConfigurationAccessHandle, ConfigurationPlanStep } from './configuration.types';

type Claim={id:string;entryId:string;cid:string;wid:string;scopeWid:string;jobId:string;executionId:string;actorId:string;requestId?:string;ip?:string};
const refused=()=>new ConflictException({code:'CONFIGURATION_RECYCLE_GRAPH_CHANGED',message:'完整回收图与已确认的删除计划不一致，执行已停止'});
const nativeType=(step:ConfigurationPlanStep)=>step.credentialKind??step.entityType;
const nodeKey=(step:ConfigurationPlanStep)=>`${nativeType(step)}:${step.parentId?`${step.parentId}:`:''}${step.nativeId}`;
function owners(step:ConfigurationPlanStep):string[]{
  const p=step.before as any;
  if(step.entityType==='credentials')return[`consumers:${step.parentId}`];
  if(step.entityType==='targets')return[`upstreams:${step.parentId}`];
  if(step.entityType==='routes')return p.service?.id?[`services:${p.service.id}`]:[];
  if(step.entityType==='snis')return p.certificate?.id?[`certificates:${p.certificate.id}`]:[];
  if(step.entityType==='plugins')return['services','routes','consumers'].flatMap((type,index)=>{const id=p[['service','route','consumer'][index]]?.id;return id?[`${type}:${id}`]:[];});
  return[];
}

/** Metadata-only companion to the existing one-packet configuration executor.
 * It seals the complete recovery graph before children are removed, then uses
 * acknowledged native step receipts to settle its deletion facts. */
@Injectable()
export class ConfigurationRecycleGraphsService {
  private readonly claims=new WeakMap<ConfigurationAccessHandle,Claim[]>();
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly redis:RedisService,
    private readonly capture:GraphCapturerService,private readonly access:ConfigurationAccessService,
    private readonly authz:AuthorizationService,private readonly audit:AuditService){}
  async prepare(handle:ConfigurationAccessHandle,plan:ConfigPlan,executionId:string):Promise<void>{
    const deleting=plan.steps.filter(step=>step.mutationAction==='delete');if(deleting.length<2)return;
    const a=await this.access.description(handle);await this.access.assertCurrent(handle,{phase:'ledger',jobId:a.jobId});
    const e=await this.db.one<any>('SELECT * FROM configuration_executions WHERE id=$1 AND job_id=$2 AND state=\'executing\'',[executionId,a.jobId]);
    if(!e||e.actor_id!==a.actor.id||e.cluster_id!==a.scope.clusterId||e.workspace_id!==a.scope.workspaceId||e.plan_hash!==this.secrets.fingerprint(plan))throw refused();
    if(await this.db.one('SELECT id FROM configuration_recycle_graphs WHERE execution_id=$1',[executionId]))throw refused();
    const groups=new Map<string,ConfigurationPlanStep[]>();for(const step of deleting)groups.set(step.objectWorkspaceId,[...(groups.get(step.objectWorkspaceId)??[]),step]);
    for(const [wid,steps]of groups)if(steps.length>=2){const claim=await this.prepareGroup(handle,plan,e,steps,wid);this.claims.set(handle,[...(this.claims.get(handle)??[]),claim]);}
  }
  private async prepareGroup(handle:ConfigurationAccessHandle,plan:ConfigPlan,e:any,deleting:ConfigurationPlanStep[],wid:string):Promise<Claim>{
    const a=await this.access.description(handle),executionId=e.id;
    const byNode=new Map(deleting.map(step=>[nodeKey(step),step])),roots=deleting.filter(step=>!owners(step).some(key=>byNode.has(key)));
    if(!roots.length)throw refused();
    const nodes=new Map<string,GraphNode>();let pages=0,bytes=0;const histories:NonNullable<RecycleGraph['targetHistory']>=[];
    for(const root of roots){
      const graph=await this.capture.capture(a.scope.clusterId,root.entityType,root.nativeId!,{parentId:root.parentId??undefined,credentialKind:root.credentialKind??undefined,purpose:'recycle'});
      if(!graph.complete||graph.purpose==='migration')throw refused();pages+=graph.budget?.pages??0;
      for(const node of graph.nodes){const previous=nodes.get(node.key);if(previous&&this.secrets.fingerprint(previous.data)!==this.secrets.fingerprint(node.data))throw refused();
        nodes.set(node.key,previous?{...previous,affected:previous.affected||node.affected,dependencies:[...new Set([...previous.dependencies,...node.dependencies])]}:node);
      }
      histories.push(...(graph.targetHistory??[]));bytes+=Buffer.byteLength(JSON.stringify(graph));
      if(nodes.size>10000||bytes>32*1024*1024||pages>100)throw refused();
    }
    const affected=[...nodes.values()].filter(node=>node.affected);
    if(affected.length!==deleting.length||affected.some(node=>!byNode.has(node.key)))throw refused();
    for(const node of nodes.values()){
      const step=byNode.get(node.key);if(node.affected&&(!step||this.secrets.fingerprint(node.data)!==step.beforeHmac||!node.restorable||!node.restoreData))throw refused();
      await this.authz.assertArchivedEntity(a.actor,a.scope.clusterId,node.type,node.affected?'delete':'read',node.data,wid,[...nodes.values()]);
    }
    const first=roots[0],graph:RecycleGraph={rootKey:nodeKey(first),nodes:[...nodes.values()],complete:true,capturedAt:new Date().toISOString(),purpose:'recycle',...(histories.length?{targetHistory:histories}:{})};
    const root=nodes.get(graph.rootKey);if(!root)throw refused();
    const id=randomUUID(),entryId=randomUUID(),name=String(root.data.name??root.data.username??root.data.target??root.id),rootName=roots.length===1?name:`批量回收 · ${name} 等 ${roots.length} 个根对象`;
    const retention=Number(process.env.RECYCLE_RETENTION_DAYS??30);if(!Number.isInteger(retention)||retention<1||retention>3650)throw refused();
    await this.db.transaction(async tx=>{
      await this.access.assertCurrent(handle,{phase:'ledger',jobId:a.jobId},tx);await this.redis.assertLeaseOwnership();
      await tx.exec(`INSERT INTO recycle_entries(id,cluster_id,workspace_id,actor_id,root_type,original_id,root_name,parent_id,credential_kind,node_count,payload_secret,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+$12::integer*interval '1 day')`,[entryId,a.scope.clusterId,wid,a.actor.id,first.entityType,first.nativeId,rootName,first.parentId??null,first.credentialKind??null,graph.nodes.length,this.secrets.encrypt(graph,`recycle:${entryId}`),retention]);
      for(const node of graph.nodes)await tx.exec(`INSERT INTO recycle_nodes(entry_id,node_key,entity_type,original_id,affected,dependencies,delete_state,restore_state)
        VALUES($1,$2,$3,$4,$5,$6,$7,$7)`,[entryId,node.key,node.type,node.id,node.affected,node.dependencies,node.affected?'pending':'reference']);
      await tx.exec(`INSERT INTO configuration_recycle_graphs(id,cluster_id,workspace_id,job_id,execution_id,plan_id,plan_revision,plan_hash,actor_id,recycle_entry_id,graph_hmac,delete_count,object_workspace_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,[id,a.scope.clusterId,a.scope.workspaceId,a.jobId,executionId,e.plan_id,e.plan_revision,e.plan_hash,a.actor.id,entryId,this.secrets.fingerprint(graph),deleting.length,wid]);
      await tx.exec("UPDATE recycle_entries SET state='deleting',updated_at=now() WHERE id=$1",[entryId]);
      await this.audit.append({actorId:a.actor.id,clusterId:a.scope.clusterId,workspaceId:wid,entityType:'recycle_entries',entityId:entryId,requestId:a.requestId,ip:a.ip,action:'archive.configuration-graph',after:{configurationJobId:a.jobId,executionId,nodeCount:graph.nodes.length,deleteCount:deleting.length,rootCount:roots.length},result:'success',scopeHints:metadataAuditScope('recycle-bin','recycle_entries',entryId,wid)},tx);
    });
    return{id,entryId,cid:a.scope.clusterId,wid,scopeWid:a.scope.workspaceId,jobId:a.jobId!,executionId,actorId:a.actor.id,requestId:a.requestId,ip:a.ip};
  }
  async settle(handle:ConfigurationAccessHandle,terminal=false):Promise<void>{
    const claims=this.claims.get(handle);if(!claims)return;
    for(const c of claims)await this.db.transaction(async tx=>{
      const rows=await tx.query<any>(`SELECT s.id,s.recycle_entry_id,s.receipt_operation_id,r.root_type,r.credential_kind,r.original_id,r.parent_id
        FROM configuration_job_steps s JOIN recycle_entries r ON r.cluster_id=s.cluster_id AND r.id=s.recycle_entry_id
        JOIN mutation_operations m ON m.cluster_id=s.cluster_id AND m.id=s.receipt_operation_id
        WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.job_id=$3 AND s.execution_id=$4 AND s.state='succeeded'
        AND s.object_workspace_id=$6 AND m.actor_id=$5 AND m.state='succeeded' AND m.remote_completed AND m.action='delete'`,[c.cid,c.scopeWid,c.jobId,c.executionId,c.actorId,c.wid]);
      for(const row of rows){
        const key=`${row.credential_kind??row.root_type}:${row.parent_id?`${row.parent_id}:`:''}${row.original_id}`;
        if(!await tx.one('SELECT node_key FROM recycle_nodes WHERE entry_id=$1 AND node_key=$2 AND affected',[c.entryId,key]))throw refused();
        await tx.exec(`INSERT INTO configuration_recycle_components(cluster_id,workspace_id,graph_id,step_id,recycle_entry_id,operation_id)
          VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(cluster_id,recycle_entry_id) DO NOTHING`,[c.cid,c.scopeWid,c.id,row.id,row.recycle_entry_id,row.receipt_operation_id]);
        await tx.exec("UPDATE recycle_nodes SET delete_state='deleted',updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND affected=true",[c.entryId,key]);
      }
      const remaining=await tx.one<any>("SELECT count(*)::integer AS count FROM recycle_nodes WHERE entry_id=$1 AND affected=true AND delete_state<>'deleted'",[c.entryId]);
      const next=terminal?(remaining.count===0?'deleted':'partially_deleted'):'deleting';
      await tx.exec('UPDATE recycle_entries SET state=$2,updated_at=now() WHERE id=$1 AND state IN(\'deleting\',\'partially_deleted\')',[c.entryId,next]);
      if(terminal)await this.audit.append({actorId:c.actorId,clusterId:c.cid,workspaceId:c.wid,entityType:'recycle_entries',entityId:c.entryId,requestId:c.requestId,ip:c.ip,action:'archive.configuration-graph.result',after:{configurationJobId:c.jobId,state:next,remainingNodes:remaining.count},result:next==='deleted'?'success':'partial',scopeHints:metadataAuditScope('recycle-bin','recycle_entries',c.entryId,c.wid)},tx);
    });
    if(terminal)this.claims.delete(handle);
  }
}
