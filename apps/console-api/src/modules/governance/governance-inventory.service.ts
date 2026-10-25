import { ConflictException, ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { decodeTag, encodeTag } from '../../infrastructure/kong/tags';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { EntityService } from '../entities/entities.service';
import { inspectCertificate } from '../entities/certificates';
import type { EntityActor } from '../entities/entities.types';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { EntityAnnotationsService } from '../workspaces/entity-annotations.service';
import { pluginMetadata } from '../plugin-center/plugin-metadata';
import { GovernanceAuthorityService } from './governance-authority.service';
import { GOVERNANCE_ENTITY_TYPES, GovernanceCaptureInput, GovernanceCoverage, GovernanceEntityType, GovernanceInventory, GovernanceInventoryObject, GovernanceReadHandle } from './governance-inventory.types';
import { authenticationAnonymousConsumerPlugin } from './logical-graph';

const UUID=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const PLUGIN_NAME=/^[a-z][a-z0-9_-]{0,63}$/;
export interface GovernanceInventoryCaptureOptions {requiredPluginSchemas?:readonly string[];}
const reason=(error:unknown):string=>error instanceof HttpException?String((error.getResponse() as any)?.code??`HTTP_${error.getStatus()}`):'GOVERNANCE_CAPTURE_FAILED';
const fatal=(code:string)=>/GOVERNANCE_(?:AUTHORITY|CREDENTIALS|PERMISSIONS|SCOPE|SESSION|OWNER|SCHEDULE|CONFIGURATION|NATIVE_CHANGE)|KONG_EXECUTION_CONTEXT_EXPIRED/.test(code);
const exhausted=(code:string)=>/BUDGET|KONG_EXECUTION_(?:CALL|RESPONSE)_LIMIT/.test(code);
const ptr=(value:string)=>value.replace(/~/g,'~0').replace(/\//g,'~1');

/** Public, bounded, authorized evidence. Never a recoverable M8 snapshot. */
@Injectable()
export class GovernanceInventoryService {
  private readonly nativeReceipts=new WeakMap<GovernanceInventory,{handle:GovernanceReadHandle;publicHmac:string;fingerprints:Readonly<Record<string,string>>}>();
  private readonly capabilities=new WeakMap<GovernanceReadHandle,{version:string;enabledHmac:string}>();
  private readonly enriching=new WeakSet<GovernanceInventory>();
  constructor(private readonly authority:GovernanceAuthorityService,private readonly kong:KongService,private readonly entities:EntityService,
    private readonly secrets:SecretService,private readonly workspaces:WorkspaceResolverService,private readonly annotations:EntityAnnotationsService,
    private readonly execution:KongExecutionContextService){}
  async captureActor(cid:string,input:GovernanceCaptureInput,actor:EntityActor,options:GovernanceInventoryCaptureOptions={}):Promise<{inventory:GovernanceInventory;handle:GovernanceReadHandle;privateMaterial:GovernanceReadHandle}>{
    const handle=await this.authority.acquireActor(cid,input,actor);return {inventory:await this.capture(handle,options),handle,privateMaterial:handle};
  }
  /** Explicitly private. Persist only in encrypted origin material; never
   * expose through reports, comparisons, safe diffs, logs or controllers. */
  async privateFingerprints(handle:GovernanceReadHandle,inventory:GovernanceInventory):Promise<Readonly<Record<string,string>>>{
    await this.authority.assertCurrent(handle);const receipt=this.nativeReceipts.get(inventory);
    if(!receipt||receipt.handle!==handle||receipt.publicHmac!==this.secrets.fingerprint(inventory))throw new ForbiddenException({code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED',message:'治理私有来源证据不属于当前真实采集'});
    return Object.freeze({...receipt.fingerprints});
  }
  private requiredSchemas(names:readonly string[]|undefined):string[]{
    if(names===undefined)return[];
    if(!Array.isArray(names)||names.length>200||names.some(name=>typeof name!=='string'||!PLUGIN_NAME.test(name)))throw new ConflictException({code:'GOVERNANCE_PLUGIN_SCHEMA_REQUIREMENTS_INVALID',message:'治理插件 schema 需求无效'});
    return [...new Set(names)].sort();
  }
  private configuredSchemas(inventory:GovernanceInventory):string[]{
    return this.requiredSchemas([...new Set(inventory.objects.filter(object=>object.entityType==='plugins').map(object=>object.payload.name as string))]);
  }
  private async probeCapabilities(handle:GovernanceReadHandle,cid:string,expectedVersion:string):Promise<string[]>{
    const root=await this.kong.request(cid,'GET','/');
    if(!/^1\.5\.\d+$/.test(root?.version??'')||root.version!==expectedVersion)throw new ConflictException({code:'GOVERNANCE_VERSION_CHANGED',message:'实际 Kong 版本不符合当前已探测的 1.5.x 巡检适配层'});
    const enabled=await this.kong.request(cid,'GET','/plugins/enabled'),names=enabled?.enabled_plugins;
    if(!Array.isArray(names)||names.length>200||names.some((name:any)=>typeof name!=='string'||!PLUGIN_NAME.test(name)))throw new ConflictException({code:'GOVERNANCE_ENABLED_INVALID',message:'网关插件能力清单无效'});
    const normalized=[...new Set(names as string[])].sort(),enabledHmac=this.secrets.fingerprint(normalized),previous=this.capabilities.get(handle);
    if(previous&&(previous.version!==root.version||previous.enabledHmac!==enabledHmac))throw new ConflictException({code:'GOVERNANCE_ENABLED_CHANGED',message:'治理采集期间实际插件能力已变化'});
    this.capabilities.set(handle,{version:root.version,enabledHmac});return normalized;
  }
  /** Complete the actual two-side schema union without repeating entity
   * collections. This accepts only the genuine unchanged capture instance;
   * existing private native fingerprints stay private and unchanged. */
  async enrichPluginSchemas(handle:GovernanceReadHandle,inventory:GovernanceInventory,requiredNames:readonly string[]):Promise<GovernanceInventory>{
    const required=this.requiredSchemas(requiredNames),fingerprints=await this.privateFingerprints(handle,inventory);
    if(this.enriching.has(inventory))throw new ConflictException({code:'GOVERNANCE_INVENTORY_ENRICHMENT_RUNNING',message:'当前治理采集正在补齐 schema'});
    const originalHmac=this.secrets.fingerprint(inventory);
    this.enriching.add(inventory);
    const pluginSchemas={...inventory.pluginSchemas},reasonCodes=[...inventory.reasonCodes];let incomplete=false;
    try{await this.authority.runRead(handle,async()=>{
      const names=await this.probeCapabilities(handle,inventory.scope.clusterId,inventory.version);
      if(this.secrets.fingerprint(names)!==this.secrets.fingerprint(inventory.enabledPlugins))throw new ConflictException({code:'GOVERNANCE_ENABLED_CHANGED',message:'补齐 schema 时实际插件能力已变化'});
      for(const name of required){
        if(!inventory.enabledPlugins.includes(name)){incomplete=true;reasonCodes.push('PLUGIN_SCHEMA_NOT_CAPTURED');continue;}
        if(Object.hasOwn(pluginSchemas,name))continue;
        if(this.execution.currentUsage().calls>=this.execution.current().limits.maxCalls){incomplete=true;reasonCodes.push('PLUGIN_SCHEMA_NOT_CAPTURED');break;}
        try{pluginSchemas[name]=this.schema(await this.kong.request(inventory.scope.clusterId,'GET',`/plugins/schema/${name}`));}
        catch(error){const code=reason(error);if(fatal(code))throw error;incomplete=true;reasonCodes.push('PLUGIN_SCHEMA_NOT_CAPTURED');if(exhausted(code))break;}
      }
      await this.authority.assertCurrent(handle);
    });
    await this.authority.assertCurrent(handle);
    if(this.secrets.fingerprint(inventory)!==originalHmac)throw new ForbiddenException({code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_REQUIRED',message:'治理采集在补齐 schema 时发生变化'});
    inventory.pluginSchemas=pluginSchemas;inventory.reasonCodes=[...new Set(reasonCodes)];if(incomplete)inventory.completeness='incomplete';
    inventory.usage={...this.authority.usage(handle)};inventory.observedUntil=new Date().toISOString();this.nativeReceipts.set(inventory,{handle,publicHmac:this.secrets.fingerprint(inventory),fingerprints});return inventory;
    }finally{this.enriching.delete(inventory);}
  }
  private cursorIdentity(cursor:string):string{
    // This is cycle detection only. EntityService/KongService verify the
    // signed cursor before using its offset for the next native request.
    try{const value=JSON.parse(Buffer.from(cursor.split('.')[0],'base64url').toString());return typeof value.offset==='string'?value.offset:cursor;}catch{return cursor;}
  }
  private schema(value:any):any{
    if(!value||typeof value!=='object'||!value.fields||typeof value.fields!=='object')throw new ConflictException({code:'GOVERNANCE_SCHEMA_INVALID',message:'网关 schema 缺少实体字段定义'});
    const queue:Array<{value:unknown;depth:number}>=[{value,depth:0}];let nodes=0;
    while(queue.length){const item=queue.pop()!;if(++nodes>10000||item.depth>32)throw new ConflictException({code:'GOVERNANCE_SCHEMA_BUDGET',message:'网关 schema 超出巡检解析预算'});
      if(item.value&&typeof item.value==='object')for(const [key,child] of Object.entries(item.value)){if(['__proto__','prototype','constructor'].includes(key))throw new ConflictException({code:'GOVERNANCE_SCHEMA_INVALID',message:'网关 schema 含保留键'});queue.push({value:child,depth:item.depth+1});}}
    return stripSensitiveSchemaDefaults(value,this.secrets);
  }
  private sanitize(raw:Record<string,any>,type:string):{payload:Record<string,unknown>;sensitiveFields:string[]}{
    const safe=this.secrets.redact(raw),sensitiveFields:string[]=[];
    const walk=(plain:any,masked:any,path:string,depth:number):any=>{
      if(depth>32)throw new ConflictException({code:'GOVERNANCE_PAYLOAD_DEPTH',message:'对象嵌套超出巡检预算'});
      if(typeof masked==='string'&&masked.startsWith('[REDACTED')||typeof plain==='string'&&masked!==plain){sensitiveFields.push(path);return undefined;}
      if(Array.isArray(plain))return plain.map((value,index)=>walk(value,masked?.[index],`${path}/${index}`,depth+1)??null);
      if(plain&&typeof plain==='object'){
        const result:Record<string,unknown>=Object.create(null);
        for(const [key,value] of Object.entries(plain)){
          if(['__proto__','prototype','constructor'].includes(key))throw new ConflictException({code:'GOVERNANCE_PAYLOAD_KEY',message:'对象包含不可支持的属性'});
          if(key==='cert'||key==='key'||type==='plugins'&&path===''&&key==='config'&&!pluginMetadata(String(raw.name??'')).known
            ||type==='plugins'&&path==='/config'&&['functions','script','code'].includes(key)){sensitiveFields.push(`${path}/${ptr(key)}`);continue;}
          const child=walk(value,masked?.[key],`${path}/${ptr(key)}`,depth+1);if(child!==undefined)result[key]=child;
        }return result;
      }return plain;
    };
    return {payload:walk(raw,safe,'',0),sensitiveFields:[...new Set(sensitiveFields)].sort()};
  }
  private async object(cid:string,type:GovernanceEntityType|'targets',display:any,physical:boolean,parent?:GovernanceInventoryObject):Promise<GovernanceInventoryObject>{
    if(!display||!UUID.test(display.id??''))throw new ConflictException({code:'GOVERNANCE_ENTITY_ID_INVALID',message:'网关返回了无效对象标识'});
    const raw=structuredClone(display);delete raw.console_scope_notice;
    const physicalTags=Array.isArray(raw.tags)?raw.tags.map((tag:string)=>physical?tag:encodeTag(tag)):raw.tags;
    const owner=parent?{state:'resolved' as const,workspace:parent.objectWorkspaceId?{id:parent.objectWorkspaceId}:null}:await this.workspaces.classify(cid,physicalTags);
    if(Array.isArray(raw.tags)&&physical)raw.tags=raw.tags.map(decodeTag);
    const result:GovernanceInventoryObject={entityType:type,nativeId:raw.id,...this.sanitize(raw,type),...(parent?{parentId:parent.nativeId}:{}),
      ...(owner.workspace?{objectWorkspaceId:owner.workspace.id}:{}),...(owner.state!=='resolved'?{scopeReason:'WORKSPACE_TAG_INVALID'}:{})};
    if(['certificates','ca_certificates'].includes(type)){
      try{const info=inspectCertificate(display.cert);result.certificate={state:'valid',fingerprint:info.fingerprint,expiresAt:info.expires_at,expired:info.expired};}
      catch{result.certificate={state:'invalid'};}
    }
    return result;
  }
  private async annotation(cid:string,object:GovernanceInventoryObject,actor:EntityActor):Promise<void>{
    if(object.entityType==='targets'||!object.objectWorkspaceId){object.annotations={state:'not_authorized'};return;}
    try{
      const rows=await this.annotations.getMany(cid,object.entityType,[{...object.payload,tags:Array.isArray(object.payload.tags)?object.payload.tags.map(value=>encodeTag(String(value))):[]}],actor,object.objectWorkspaceId);
      const row=rows[object.nativeId];if(!row||row.status==='deleted'){object.annotations={state:'absent'};return;}
      const description=this.secrets.redact(row.description??'');object.annotations={state:'readable',description:typeof description==='string'&&description.startsWith('[REDACTED')?'':description,ownerUserId:row.owner_user_id??null};
    }catch(error){
      // Annotation permission derives from the current native object and its
      // bindings. A broken FK can make that independent read unavailable;
      // it does not erase the already authorized inspection subject.
      if(!(error instanceof HttpException&&[403,404].includes(error.getStatus())))throw error;object.annotations={state:'not_authorized'};
    }
  }
  /** Per-packet promote source fence (approved 2026-10-25): re-read only the
   * collections that hold the selected source objects (one list per selected
   * top-level type, one per selected Upstream for Targets) through the same
   * real handle, and return the selected objects' private native fingerprints
   * for comparison against plan-time evidence. Absent objects are omitted. */
  async selectedFingerprints(handle:GovernanceReadHandle,selected:readonly Readonly<{entityType:string;nativeId:string;parentId?:string}>[]):Promise<Readonly<Record<string,string>>>{
    const top=new Set<string>(GOVERNANCE_ENTITY_TYPES);
    if(!Array.isArray(selected)||!selected.length||selected.length>10_000||selected.some(o=>!o||typeof o.nativeId!=='string'||!(top.has(o.entityType)||o.entityType==='targets'&&typeof o.parentId==='string')))
      throw new ConflictException({code:'GOVERNANCE_PROMOTE_SELECTED_OBJECTS_INVALID',message:'发布源对象选择无效'});
    const description=await this.authority.description(handle),scope=description.scope;
    if(description.projection)throw new ConflictException({code:'GOVERNANCE_PROMOTE_SELECTED_OBJECTS_INVALID',message:'发布源对象选择无效'});
    const paths=[...new Set(selected.map(o=>o.entityType==='targets'?`/upstreams/${o.parentId}/targets`:`/${o.entityType}`))].sort();
    const token=await this.authority.beginInventoryFingerprints(handle);
    try{
      await this.authority.runRead(handle,async()=>{
        for(const path of paths){let cursor:string|undefined;const cursors=new Set<string>();
          do{const page=await this.kong.list(scope.clusterId,path,{size:100},cursor,`governance:fence:${randomUUID()}`);
            if(!Array.isArray(page.items))throw new ConflictException({code:'GOVERNANCE_PAGE_INVALID',message:'巡检分页响应无效'});
            cursor=page.nextCursor??undefined;
            if(cursor){const identity=this.cursorIdentity(cursor);if(cursors.has(identity))throw new ConflictException({code:'GOVERNANCE_CURSOR_CYCLE',message:'网关分页游标循环，巡检未完整完成'});cursors.add(identity);}
          }while(cursor);}
        await this.authority.assertCurrent(handle);
      });
      await this.authority.assertCurrent(handle);
      const raw=await this.authority.sealInventoryFingerprints(handle,token),result:Record<string,string>=Object.create(null);
      for(const o of selected){const key=`${o.entityType}:${o.nativeId}`;if(/^[a-f\d]{64}$/.test(raw[key]??''))result[key]=raw[key];}
      return Object.freeze(result);
    }finally{this.authority.discardInventoryFingerprints(handle,token);}
  }
  async capture(handle:GovernanceReadHandle,options:GovernanceInventoryCaptureOptions={}):Promise<GovernanceInventory>{
    const required=this.requiredSchemas(options.requiredPluginSchemas);
    const description=await this.authority.description(handle),scope=description.scope;
    const inventory:GovernanceInventory={id:randomUUID(),scope,objects:[],schemas:Object.create(null),pluginSchemas:Object.create(null),enabledPlugins:[],version:'',coverage:Object.create(null),
      completeness:'incomplete',projection:description.projection,consistency:'console_fenced_best_effort',observedFrom:new Date().toISOString(),observedUntil:'',usage:{calls:0,pages:0,records:0,bytes:0},reasonCodes:[]};
    const token=await this.authority.beginInventoryFingerprints(handle);
    try{await this.authority.runRead(handle,async()=>{
      inventory.enabledPlugins=await this.probeCapabilities(handle,scope.clusterId,description.version);inventory.version=description.version;
      let stopped=false;
      for(const type of GOVERNANCE_ENTITY_TYPES){
        const coverage:GovernanceCoverage={state:'incomplete',extent:description.projection?'projection':scope.kind,eof:false,pages:0,records:0,reasonCodes:[]};inventory.coverage[type]=coverage;
        if(!description.permittedTypes.includes(type)){coverage.state='not_authorized';coverage.reasonCodes.push('NATIVE_READ_NOT_AUTHORIZED');continue;}
        if(stopped){coverage.reasonCodes.push('SHARED_BUDGET_EXHAUSTED');continue;}
        try{
          inventory.schemas[type]=this.schema(await this.kong.request(scope.clusterId,'GET',`/schemas/${type}`));
          let cursor:string|undefined;const cursors=new Set<string>(),ids=new Set<string>();
          do{
            const before=this.execution.currentUsage();
            const page=description.projection?await this.entities.list(scope.clusterId,type,{size:100,cursor,workspaceId:scope.workspaceId},description.actor)
              :await this.kong.list(scope.clusterId,`/${type}`,{size:100},cursor,`governance:${inventory.id}`);
            const after=this.execution.currentUsage();coverage.pages+=after.pages-before.pages;
            if(page.console_permission_projection){inventory.projection=true;coverage.extent='projection';}
            if(!Array.isArray(page.items))throw new ConflictException({code:'GOVERNANCE_PAGE_INVALID',message:'巡检分页响应无效'});
            for(const item of page.items){
              if(ids.has(item.id))throw new ConflictException({code:'GOVERNANCE_DUPLICATE_ENTITY',message:'巡检分页重复返回对象，无法证明完整覆盖'});ids.add(item.id);
              const object=await this.object(scope.clusterId,type,item,!description.projection);object.managedBoundary=await this.authority.managedBoundary(handle,{entityType:type,nativeId:object.nativeId,payload:object.payload});await this.annotation(scope.clusterId,object,description.actor);inventory.objects.push(object);coverage.records++;
            }
            cursor=page.nextCursor??undefined;
            if(cursor){const identity=this.cursorIdentity(cursor);if(cursors.has(identity))throw new ConflictException({code:'GOVERNANCE_CURSOR_CYCLE',message:'网关分页游标循环，巡检未完整完成'});cursors.add(identity);}
          }while(cursor);
          coverage.eof=true;coverage.state=description.projection||coverage.extent==='projection'?'projected':'complete';
        }catch(error){const code=reason(error);if(fatal(code))throw error;coverage.reasonCodes.push(code);if(exhausted(code))stopped=true;}
      }
      // Targets are captured below per upstream; their entity schema must be captured too, otherwise
      // the logical graph cannot normalize target objects (GOVERNANCE_SCHEMA_UNAVAILABLE).
      if(!stopped&&inventory.objects.some(object=>object.entityType==='upstreams')){
        try{inventory.schemas.targets=this.schema(await this.kong.request(scope.clusterId,'GET','/schemas/targets'));}
        catch(error){const code=reason(error);if(fatal(code))throw error;inventory.reasonCodes.push('TARGET_SCHEMA_NOT_CAPTURED');if(exhausted(code))stopped=true;}
      }
      for(const upstream of inventory.objects.filter(object=>object.entityType==='upstreams')){
        const key=`targets:${upstream.nativeId}`,coverage:GovernanceCoverage={state:'incomplete',extent:description.projection?'projection':scope.kind,eof:false,pages:0,records:0,reasonCodes:[]};inventory.coverage[key]=coverage;
        if(stopped){coverage.reasonCodes.push('SHARED_BUDGET_EXHAUSTED');continue;}
        try{
          let cursor:string|undefined;const cursors=new Set<string>(),ids=new Set<string>();
          do{
            const before=this.execution.currentUsage(),page=description.projection?await this.entities.targets(scope.clusterId,upstream.nativeId,{size:100,cursor,workspaceId:scope.workspaceId},description.actor)
              :await this.kong.list(scope.clusterId,`/upstreams/${upstream.nativeId}/targets`,{size:100},cursor,`governance:${inventory.id}`);
            coverage.pages+=this.execution.currentUsage().pages-before.pages;
            for(const item of page.items){if(ids.has(item.id))throw new ConflictException({code:'GOVERNANCE_DUPLICATE_ENTITY',message:'Target 分页重复返回对象'});ids.add(item.id);
              const object=await this.object(scope.clusterId,'targets',item,!description.projection,upstream);object.managedBoundary=await this.authority.managedBoundary(handle,{entityType:'targets',nativeId:object.nativeId,parentId:upstream.nativeId,payload:object.payload});inventory.objects.push(object);coverage.records++;}
            cursor=page.nextCursor??undefined;if(cursor){const identity=this.cursorIdentity(cursor);if(cursors.has(identity))throw new ConflictException({code:'GOVERNANCE_CURSOR_CYCLE',message:'Target 分页游标循环'});cursors.add(identity);}
          }while(cursor);coverage.eof=true;coverage.state=description.projection?'projected':'complete';
        }catch(error){const code=reason(error);if(fatal(code))throw error;coverage.reasonCodes.push(code);if(exhausted(code))stopped=true;}
      }
      if(scope.kind==='services')this.selectServices(inventory);
      for(const name of [...new Set([...this.configuredSchemas(inventory),...required])].sort()){if(stopped)break;if(!inventory.enabledPlugins.includes(name)){inventory.reasonCodes.push('PLUGIN_SCHEMA_NOT_CAPTURED');continue;}try{inventory.pluginSchemas[name]=this.schema(await this.kong.request(scope.clusterId,'GET',`/plugins/schema/${name}`));}
        catch(error){const code=reason(error);if(fatal(code))throw error;inventory.reasonCodes.push('PLUGIN_SCHEMA_NOT_CAPTURED');if(exhausted(code))stopped=true;}}
      const incomplete=Object.values(inventory.coverage).some(item=>!item.eof||!['complete','projected'].includes(item.state));
      inventory.completeness=incomplete||stopped||inventory.reasonCodes.length?'incomplete':'complete';
      if(incomplete)inventory.reasonCodes.push('COLLECTION_COVERAGE_INCOMPLETE');
      await this.authority.assertCurrent(handle);
    });
    inventory.usage={...this.authority.usage(handle)};inventory.observedUntil=new Date().toISOString();await this.authority.assertCurrent(handle);
    const raw=await this.authority.sealInventoryFingerprints(handle,token),fingerprints:Record<string,string>=Object.create(null);
    for(const object of inventory.objects){const key=`${object.entityType}:${object.nativeId}`;if(!/^[a-f\d]{64}$/.test(raw[key]??''))throw new ConflictException({code:'GOVERNANCE_PRIVATE_INVENTORY_RECEIPT_INCOMPLETE',message:'治理采集缺少真实来源验证证据'});fingerprints[key]=raw[key];}
    this.nativeReceipts.set(inventory,{handle,publicHmac:this.secrets.fingerprint(inventory),fingerprints:Object.freeze(fingerprints)});return inventory;
    }finally{this.authority.discardInventoryFingerprints(handle,token);}
  }
  private selectServices(inventory:GovernanceInventory):void{
    const roots=new Set(inventory.scope.rootIds),selected=new Set<string>(),byKey=new Map(inventory.objects.map(object=>[`${object.entityType}:${object.nativeId}`,object]));
    for(const id of roots){if(!byKey.has(`services:${id}`))throw new ForbiddenException({code:'GOVERNANCE_SERVICE_NOT_VISIBLE',message:'所选 Service 不在当前授权范围内'});selected.add(`services:${id}`);}
    for(const object of inventory.objects)if(object.entityType==='routes'&&roots.has(String((object.payload.service as any)?.id)))selected.add(`routes:${object.nativeId}`);
    for(const object of inventory.objects)if(object.entityType==='plugins'&&(['service','route'].some(field=>selected.has(`${field==='service'?'services':'routes'}:${(object.payload[field] as any)?.id}`))))selected.add(`plugins:${object.nativeId}`);
    for(let pass=0;pass<5;pass++)for(const key of [...selected]){
      const object=byKey.get(key)!;const references: Array<[string,unknown]>=object.entityType==='services'?[['certificates',(object.payload.client_certificate as any)?.id],...[...(object.payload.ca_certificates as any[]??[])].map(id=>['ca_certificates',typeof id==='string'?id:id?.id] as [string,unknown])]
        :object.entityType==='plugins'?[['consumers',(object.payload.consumer as any)?.id],...(authenticationAnonymousConsumerPlugin(object.payload.name)?[['consumers',(object.payload.config as any)?.anonymous] as [string,unknown]]:[])]:[];
      if(object.entityType==='services')for(const upstream of inventory.objects)if(upstream.entityType==='upstreams'&&upstream.payload.name===object.payload.host)references.push(['upstreams',upstream.nativeId]);
      for(const [type,id] of references)if(byKey.has(`${type}:${id}`))selected.add(`${type}:${id}`);
      if(object.entityType==='upstreams')for(const child of inventory.objects)if(child.entityType==='targets'&&child.parentId===object.nativeId)selected.add(`targets:${child.nativeId}`);
    }
    inventory.objects=inventory.objects.filter(object=>selected.has(`${object.entityType}:${object.nativeId}`)).map(object=>({...object,selected:roots.has(object.nativeId)&&object.entityType==='services',referenceOnly:!['services','routes','plugins'].includes(object.entityType)}));
    for(const item of Object.values(inventory.coverage))item.extent=inventory.projection?'projection':'services';
  }
}
