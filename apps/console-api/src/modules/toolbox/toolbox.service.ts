import { kongCapabilities } from '../../infrastructure/kong/kong-capabilities';
import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { WorkspaceMigrationService } from '../workspaces/workspace-migration.service';
import { ConfigurationService } from '../configuration/configuration.service';
import { EntityService } from '../entities/entities.service';
import { AuditService } from '../audit/audit.service';
import { metadataAuditScope } from '../event-producers/native-audit-scope';
import type { EntityActor } from '../entities/entities.types';
import { portalConfirm } from '../portal/portal-input';
import { cacheKey, routeDebugInput, toolboxId, toolboxObject, type RouteDebugInput } from './toolbox-input';
import { simulateRoutes, resolvePluginChain } from './route-matcher';
import { assertRegisteredProxyOrigin, proxyProbe } from './proxy-probe';

@Injectable()
export class ToolboxService {
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly kong:KongService,
    private readonly context:KongExecutionContextService,private readonly authz:AuthorizationService,private readonly workspaces:WorkspaceResolverService,
    private readonly entities:EntityService,private readonly configuration:ConfigurationService,private readonly migration:WorkspaceMigrationService,private readonly audit:AuditService){}
  private run<T>(cid:string,actor:EntityActor,fn:()=>Promise<T>):Promise<T>{return this.context.runActor({actor:actor.user,clusterId:toolboxId(cid),workspaceId:actor.workspaceId,module:'toolbox',action:'read'},fn);}
  async capabilities(cid:string,actor:EntityActor){return this.run(cid,actor,async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId);await this.authz.assertCluster(actor.user,cid,'toolbox','read',ws.id);
    const cluster=await this.db.one<any>('SELECT proxy_origin,execution_mode,version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
    const compatible=kongCapabilities(cluster.version??'').routeSimulation;
    return{clusterId:cid,workspaceId:ws.id,executionMode:cluster.execution_mode,routeSimulation:compatible,nodeStatus:await this.authz.hasWholeCluster(actor.user,cid,'toolbox','read'),cacheRead:await this.authz.hasWholeCluster(actor.user,cid,'toolbox','read'),cacheInvalidate:compatible&&await this.authz.hasWholeCluster(actor.user,cid,'toolbox','write'),proxyConfigured:!!cluster.proxy_origin,proxyProbe:compatible&&!!cluster.proxy_origin&&await this.authz.hasWholeCluster(actor.user,cid,'toolbox','write')};
  });}
  async status(cid:string,actor:EntityActor){return this.run(cid,actor,async()=>{
    await this.authz.assertWholeCluster(actor.user,cid,'toolbox','read');const status=await this.kong.request(cid,'GET','/status');
    return{clusterId:cid,scope:'registered_admin_node',status,available:true,observedAt:new Date().toISOString()};
  });}
  async readCache(cid:string,key:unknown,actor:EntityActor){return this.run(cid,actor,async()=>{
    await this.authz.assertWholeCluster(actor.user,cid,'toolbox','read');const name=cacheKey(key);let value:any=null,found=true;
    try{value=await this.kong.request(cid,'GET',`/cache/${encodeURIComponent(name)}`);}catch(error){if(error instanceof HttpException&&error.getStatus()===404)found=false;else throw error;}
    return{key:name,found,type:found?(Array.isArray(value)?'array':value===null?'null':typeof value):null,bytes:found?Buffer.byteLength(JSON.stringify(value)):0,rawValueReturned:false,observedAt:new Date().toISOString(),capabilities:{invalidate:await this.authz.hasWholeCluster(actor.user,cid,'toolbox','write')}};
  });}
  private async collect(cid:string,type:string,actor:EntityActor){
    const items:any[]=[],seen=new Set<string>();let cursor:string|undefined,pages=0,bytes=0,complete=true;
    do{if(++pages>20||items.length>=1000||bytes>2*1024*1024){complete=false;break;}
      const page=await this.entities.list(cid,type,{size:50,...(cursor?{cursor}:{})},actor);
      if(!Array.isArray(page.items))throw new ConflictException({code:'TOOLBOX_COLLECTION_INVALID'});
      bytes+=Buffer.byteLength(JSON.stringify(page.items));items.push(...page.items);
      if(page.nextCursor){if(seen.has(page.nextCursor))throw new ConflictException({code:'TOOLBOX_CURSOR_LOOP'});seen.add(page.nextCursor);cursor=page.nextCursor;}else cursor=undefined;
    }while(cursor);return{items,pages,bytes,complete};
  }
  /** Only server-side completeness checks use this bounded, unfiltered inventory.
   * Foreign objects are never included in the returned diagnostic projection. */
  private async inventoryIds(cid:string,type:string,actor:EntityActor){
    await this.authz.assertWholeCluster(actor.user,cid,type,'read');
    return this.context.runInternalRead(cid,'inventory',async()=>{
      const ids=new Set<string>(),seen=new Set<string>();let cursor:string|undefined,pages=0,bytes=0;
      do{
        if(pages>=20||ids.size>=1000||bytes>2*1024*1024)return{ids,complete:false};
        const page=await this.kong.list(cid,`/${type}`,{size:50},cursor,`toolbox-completeness:${actor.user.id}:${actor.workspaceId}:${type}`);pages++;
        bytes+=Buffer.byteLength(JSON.stringify(page.items));for(const item of page.items)ids.add(item.id);
        if(page.nextCursor){if(seen.has(page.nextCursor))throw new ConflictException({code:'TOOLBOX_CURSOR_LOOP'});seen.add(page.nextCursor);cursor=page.nextCursor;}else cursor=undefined;
      }while(cursor);return{ids,complete:true};
    },{paths:[`/${type}`],maxCalls:20,maxPages:20,maxRecords:1000,maxBytes:2*1024*1024,timeoutMs:10000});
  }
  async debug(cid:string,body:unknown,actor:EntityActor){const input=routeDebugInput(body);return this.run(cid,actor,()=>this.simulate(cid,input,actor,true));}
  private async simulate(cid:string,input:RouteDebugInput,actor:EntityActor,persist:boolean){
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),version=await this.authz.permissionVersion(actor.user);
    await this.authz.assertCluster(actor.user,cid,'toolbox','read',ws.id);
    const cluster=await this.db.one<any>('SELECT version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);if(!kongCapabilities(cluster?.version??'').routeSimulation)throw new ConflictException({code:'ROUTE_ADAPTER_UNAVAILABLE',message:'路由模拟仅在已探测的 Kong OSS 1.5.x 上开放'});
    const routes=await this.collect(cid,'routes',{...actor,workspaceId:ws.id}),result=await simulateRoutes(routes.items,input),reasonCodes=[...result.reasonCodes];
    let plugins={items:[] as any[],pages:0,bytes:0,complete:false};try{plugins=await this.collect(cid,'plugins',{...actor,workspaceId:ws.id});}catch(error){if(!(error instanceof ForbiddenException))throw error;reasonCodes.push('PLUGIN_SCOPE_NOT_AUTHORIZED');}
    const wholeRoutes=await this.authz.hasWholeWorkspace(actor.user,cid,ws.id,'routes','read'),wholePlugins=await this.authz.hasWholeWorkspace(actor.user,cid,ws.id,'plugins','read');
    let gatewayProjectionComplete=true;
    for(const [type,visible]of [['routes',routes],['plugins',plugins]] as const){
      if(!await this.authz.hasWholeCluster(actor.user,cid,type,'read')){gatewayProjectionComplete=false;reasonCodes.push('GATEWAY_INVENTORY_NOT_AUTHORIZED');continue;}
      const raw=await this.inventoryIds(cid,type,{...actor,workspaceId:ws.id}),visibleIds=new Set(visible.items.map(item=>item.id));
      if(!raw.complete||raw.ids.size!==visibleIds.size||[...raw.ids].some(id=>!visibleIds.has(id))){gatewayProjectionComplete=false;reasonCodes.push('OTHER_OR_UNCLASSIFIED_OBJECTS_MAY_COMPETE');}
    }
    if(!wholeRoutes)reasonCodes.push('AUTHORIZED_ROUTE_PROJECTION');if(!wholePlugins)reasonCodes.push('AUTHORIZED_PLUGIN_PROJECTION');
    let service:any=null;if(result.route?.serviceId){try{const detail=await this.entities.get(cid,'services',result.route.serviceId,{workspaceId:ws.id},{...actor,workspaceId:ws.id});service={id:detail.entity?.id??detail.id,name:detail.entity?.name??detail.name??null};}catch(error){if(!(error instanceof ForbiddenException||error instanceof HttpException&&error.getStatus()===404))throw error;reasonCodes.push('SERVICE_CONTEXT_UNAVAILABLE');gatewayProjectionComplete=false;}}
    if(input.consumerId)await this.entities.get(cid,'consumers',input.consumerId,{workspaceId:ws.id},{...actor,workspaceId:ws.id});
    const chain=result.route?resolvePluginChain(plugins.items,result.route.id,result.route.serviceId,input.consumerId):{selectionPrecedence:[],executionOrder:[],complete:true,reasonCodes:[]};
    const complete=result.complete&&routes.complete&&plugins.complete&&wholeRoutes&&wholePlugins&&gatewayProjectionComplete&&chain.complete;
    if(!routes.complete||!plugins.complete)reasonCodes.push('CAPTURE_BUDGET_EXHAUSTED');reasonCodes.push(...chain.reasonCodes);
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    const id=randomUUID(),view={id,clusterId:cid,workspaceId:ws.id,observedAt:new Date().toISOString(),engine:'kong_1_5_simulation',adapterVersion:result.engine,regexEngine:result.regexEngine,regexBudgetMs:result.regexBudgetMs,complete,confidence:complete?'simulated':'partial',route:result.route,service,candidates:result.candidates,selectionPrecedence:chain.selectionPrecedence,executionOrder:chain.executionOrder,reasonCodes,budget:{pages:routes.pages+plugins.pages,records:routes.items.length+plugins.items.length,bytes:routes.bytes+plugins.bytes}};
    if(Buffer.byteLength(JSON.stringify(view))>262144)throw new ConflictException({code:'TOOLBOX_REPORT_BUDGET'});
    if(persist)await this.db.transaction(async tx=>{
      if(await this.authz.permissionVersion(actor.user,tx)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
      await tx.exec('INSERT INTO toolbox_debug_runs(id,cluster_id,workspace_id,actor_id,kind,input_hmac,quality,safe_result) VALUES($1,$2,$3,$4,\'route-simulation\',$5,$6,$7::jsonb)',[id,cid,ws.id,actor.user.id,this.secrets.fingerprint(input),complete?'complete':'partial',JSON.stringify(view)]);
      await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'toolbox_debug_runs',entityId:id,requestId:actor.requestId,ip:actor.ip,action:'toolbox.route.simulated',after:{quality:view.confidence,routeId:view.route?.id??null,complete},result:'success',scopeHints:metadataAuditScope('toolbox','toolbox_debug_runs',id,ws.id)},tx);
    });
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    return view;
  }
  async probe(cid:string,body:unknown,actor:EntityActor){const value=toolboxObject(body,['routeId','input','confirmed','confirm_name']),routeId=toolboxId(value.routeId),input=routeDebugInput(value.input);return this.run(cid,actor,async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId);await this.authz.assertWholeCluster(actor.user,cid,'toolbox','write');
    const simulation=await this.simulate(cid,input,{...actor,workspaceId:ws.id},false);
    if(simulation.route?.id!==routeId)throw new ConflictException({code:'PROBE_ROUTE_CHANGED'});portalConfirm(value,simulation.route.name??routeId);
    const cluster=await this.db.one<any>('SELECT proxy_origin,revision FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);if(!cluster?.proxy_origin)throw new BadRequestException({code:'PROXY_NOT_CONFIGURED',message:'请先登记该集群的代理地址'});
    const epoch=await this.authz.permissionVersion(actor.user),id=randomUUID();
    const auditEvent={actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'toolbox_debug_runs',entityId:id,requestId:actor.requestId,ip:actor.ip};
    await this.audit.append({...auditEvent,action:'toolbox.proxy-probe.intent',after:{routeId,method:input.method},result:'pending'});
    let result:Record<string,unknown>;try{result=await proxyProbe(cluster.proxy_origin,input,async(destination)=>{
      await assertRegisteredProxyOrigin(this.db,cluster.proxy_origin,destination);
      await this.authz.assertWholeCluster(actor.user,cid,'toolbox','write');await this.entities.get(cid,'routes',routeId,{workspaceId:ws.id},{...actor,workspaceId:ws.id});
      const current=await this.db.one<any>('SELECT proxy_origin,revision FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);if(current?.revision!==cluster.revision||current?.proxy_origin!==cluster.proxy_origin||await this.authz.permissionVersion(actor.user)!==epoch)throw new ConflictException({code:'PROBE_SCOPE_CHANGED'});
    });}catch(error){await this.audit.append({...auditEvent,action:'toolbox.proxy-probe.result',after:{routeId,resultKnown:false},result:'failed'});throw error;}
    if(await this.authz.permissionVersion(actor.user)!==epoch)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    const safe={id,clusterId:cid,workspaceId:ws.id,simulationRouteId:routeId,actualRouteVerified:false,...result};
    await this.db.transaction(async tx=>{
      await tx.exec('INSERT INTO toolbox_debug_runs(id,cluster_id,workspace_id,actor_id,kind,input_hmac,quality,safe_result) VALUES($1,$2,$3,$4,\'proxy-probe\',$5,\'partial\',$6::jsonb)',[id,cid,ws.id,actor.user.id,this.secrets.fingerprint({routeId,input}),JSON.stringify(safe)]);
      await this.audit.append({...auditEvent,action:'toolbox.proxy-probe.result',after:safe,result:'success'},tx);
    });return safe;
  });}
  async batch(cid:string,body:unknown,actor:EntityActor){const value=toolboxObject(body,['action','roots','tags','enabled','targetWorkspaceId']);
    const ws=await this.workspaces.resolve(cid,actor.workspaceId);await this.authz.assertCluster(actor.user,cid,'batches','write',ws.id);
    if(!Array.isArray(value.roots)||!value.roots.length||value.roots.length>50)throw new BadRequestException({code:'BATCH_SELECTION_LIMIT'});
    if(value.action==='workspace-move')return{kind:'workspace-move',entity:await this.migration.plan(cid,{source_workspace_id:ws.id,target_workspace_id:toolboxId(value.targetWorkspaceId),roots:value.roots},{...actor,workspaceId:ws.id})};
    return this.configuration.createToolboxBatchPlan(cid,value,{...actor,workspaceId:ws.id});
  }
}
