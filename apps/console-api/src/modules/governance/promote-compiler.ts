import { randomUUID } from 'node:crypto';
import { stringify } from 'yaml';
import { canonicalJson } from '../../infrastructure/secret.service';
import { decodeTag, encodeTag, workspaceTag } from '../../infrastructure/kong/tags';
import { CREDENTIAL_SCHEMAS } from '../entities/entities.types';
import { compareCapturedSchemas } from '../config-transfer/schema-comparison';
import { entitySchema, normalizeEntityPayload, schemaFields, UUID } from '../config-transfer/schema-normalization';
import { comparisonFail, comparisonSchemas } from './comparison-types';
import type { ComparisonInventory, ComparisonIssue, ComparisonObject, ComparisonPolicy, LogicalObject, PromoteCompilation, PromoteMapping, PromoteOptions } from './comparison-types';
import { assertComparisonJson, authenticationAnonymousConsumerPlugin, normalizeLogicalGraph, objectIdentity, safeComparisonValue, secretMarker } from './logical-graph';

const publicPolicy = (options: PromoteOptions): ComparisonPolicy => ({
  ...(options.identityAliases ? {identityAliases:options.identityAliases}:{}), includeEnvironmentFields:options.includeEnvironmentFields === true,
  includeSecrets:options.includeSecrets === true, includeCredentials:options.includeCredentials === true,
  ...(options.credentialKinds?{credentialKinds:options.credentialKinds}:{}),
});
const referenceId = (value: unknown): string | null => typeof value === 'string' ? value : value && typeof value === 'object' && !Array.isArray(value) && typeof (value as any).id === 'string' ? (value as any).id : null;
const nativeKey = (object: Pick<ComparisonObject,'entityType'|'nativeId'>): string => `${object.entityType}:${object.nativeId}`;
const logicalReferences = (value: unknown): string[] => {
  if (!value || typeof value !== 'object') return [];
  if (!Array.isArray(value) && Object.keys(value).length === 1 && typeof (value as any).logical_ref === 'string') return [(value as any).logical_ref];
  return Object.values(value).flatMap(logicalReferences);
};

/** Private recovery inputs are separate from the public inspection inventory. */
function withPrivateMaterial(source: ComparisonInventory, options: PromoteOptions, blockers: ComparisonIssue[]): ComparisonInventory {
  if (!options.includeSecrets && !options.includeCredentials) return source;
  if (!Array.isArray(options.privateSourceObjects) || !options.privateSourceObjects.length) { blockers.push({code:'GOVERNANCE_SECRET_MATERIAL_UNAVAILABLE'}); return source; }
  const material = new Map<string,ComparisonObject>();
  for (const object of options.privateSourceObjects) {
    assertComparisonJson(object.payload);
    const key = nativeKey(object);
    if (material.has(key) || !UUID.test(object.nativeId) || object.payload.id !== undefined && object.payload.id !== object.nativeId) comparisonFail('GOVERNANCE_PRIVATE_MATERIAL_IDENTITY');
    if(object.entityType==='credentials'){
      const explicitlySelected=!options.selectedObjectKeys||options.selectedObjectKeys.includes(objectIdentity(object))||options.selectedObjectKeys.includes(`consumers:${object.parentId}`);
      if(!options.includeCredentials||!explicitlySelected||options.credentialKinds&&!options.credentialKinds.includes(object.credentialKind!)){material.set(key,object);continue;}
      if(object.recovery?.state!=='complete'||!object.recovery.restorePayload){blockers.push({code:'GOVERNANCE_CREDENTIAL_RECOVERY_UNAVAILABLE',objectKey:objectIdentity(object)});material.set(key,object);continue;}
      assertComparisonJson(object.recovery.restorePayload);
      if(object.recovery.restorePayload.id!==object.nativeId||referenceId(object.recovery.restorePayload.consumer)!==object.parentId)comparisonFail('GOVERNANCE_PRIVATE_MATERIAL_IDENTITY');
      material.set(key,{...object,payload:structuredClone(object.recovery.restorePayload)});
    }else material.set(key,object);
  }
  const objects = source.objects.map(object => {
    const privateObject = material.get(nativeKey(object));
    if (!privateObject) { if (object.sensitiveFields?.length) blockers.push({code:'GOVERNANCE_SECRET_MATERIAL_UNAVAILABLE',objectKey:objectIdentity(object)}); return object; }
    if ((privateObject.parentId??null) !== (object.parentId??null) || (privateObject.credentialKind??null) !== (object.credentialKind??null)) comparisonFail('GOVERNANCE_PRIVATE_MATERIAL_IDENTITY');
    // Shared visible values must be the same actual source observation. A
    // secret recovery object cannot silently replace ordinary config fields.
    const equalVisible = (visible: unknown, privateValue: unknown, path=''): boolean => {
      if (secretMarker(visible) || object.sensitiveFields?.some(pointer => pointer === path || path.startsWith(`${pointer}/`))) return true;
      if (visible && typeof visible === 'object') return !!privateValue && typeof privateValue === 'object' && !Array.isArray(visible) === !Array.isArray(privateValue)
        && Object.entries(visible).every(([key,value]) => Object.hasOwn(privateValue,key) && equalVisible(value,(privateValue as any)[key],`${path}/${key.replace(/~/g,'~0').replace(/\//g,'~1')}`));
      return canonicalJson(visible) === canonicalJson(privateValue);
    };
    if (!equalVisible(object.payload,privateObject.payload)) comparisonFail('GOVERNANCE_PRIVATE_MATERIAL_OBSERVATION_MISMATCH');
    return {...object,payload:structuredClone(privateObject.payload)};
  });
  if (options.includeCredentials) {
    const consumers = new Set(source.objects.filter(object => object.entityType === 'consumers').map(object => object.nativeId));
    for (const object of material.values()) if (object.entityType === 'credentials' && !objects.some(current => nativeKey(current) === nativeKey(object))) {
      if (!object.parentId || !consumers.has(object.parentId) || referenceId(object.payload.consumer) !== object.parentId) comparisonFail('GOVERNANCE_PRIVATE_CREDENTIAL_PARENT');
      objects.push(object);
    }
  }
  return {...source,objects};
}

function selectedObjects(source: ComparisonInventory, logical: readonly LogicalObject[], options: PromoteOptions): Set<string> {
  const all = new Map(source.objects.map(object => [objectIdentity(object),object]));
  if (options.selectedObjectKeys && options.selectedServiceIds) comparisonFail('GOVERNANCE_PROMOTE_SELECTION_AMBIGUOUS');
  if (options.selectedObjectKeys) {
    if (!options.selectedObjectKeys.length || options.selectedObjectKeys.length > 10_000 || new Set(options.selectedObjectKeys).size !== options.selectedObjectKeys.length) comparisonFail('GOVERNANCE_PROMOTE_SELECTION_INVALID');
    for (const key of options.selectedObjectKeys) if (!all.has(key)) comparisonFail('GOVERNANCE_PROMOTE_SELECTION_NOT_CAPTURED');
    const selected=new Set(options.selectedObjectKeys);
    if(options.includeCredentials)for(const object of source.objects)if(object.entityType==='credentials'&&object.parentId&&(!options.credentialKinds||options.credentialKinds.includes(object.credentialKind!))&&selected.has(`consumers:${object.parentId}`))selected.add(objectIdentity(object));
    return selected;
  }
  const roots = options.selectedServiceIds ?? (source.scope.kind === 'services' ? source.scope.rootIds : null);
  if (!roots) return new Set(source.objects.filter(object => !object.referenceOnly).map(objectIdentity));
  if (!roots.length || roots.length > 50 || new Set(roots).size !== roots.length) comparisonFail('GOVERNANCE_PROMOTE_SELECTION_INVALID');
  const services = new Set(roots), routes = new Set<string>(), selected = new Set<string>();
  for (const id of roots) if (!UUID.test(id) || !source.objects.some(object => object.entityType === 'services' && object.nativeId === id && !object.referenceOnly)) comparisonFail('GOVERNANCE_PROMOTE_SERVICE_NOT_CAPTURED');
  for (const object of source.objects) if (object.entityType === 'services' && services.has(object.nativeId) || object.entityType === 'routes' && services.has(referenceId(object.payload.service) ?? '')) {
    selected.add(objectIdentity(object)); if (object.entityType === 'routes') routes.add(object.nativeId);
  }
  for (const object of source.objects) if (object.entityType === 'plugins' && (services.has(referenceId(object.payload.service) ?? '') || routes.has(referenceId(object.payload.route) ?? ''))) selected.add(objectIdentity(object));
  // Complete safe FK closure. Secret/environment fields already excluded from
  // logical payload do not pull unrelated source entities into a promotion.
  const byLogical = new Map(logical.map(object => [object.logicalKey,object]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const object of logical) if (selected.has(object.objectKey)) for (const key of [...logicalReferences(object.payload),...Object.values(object.referenceFields).flatMap(value=>typeof value==='string'?[value]:[...value])]) {
      const dependency = byLogical.get(key);
      if (dependency && !selected.has(dependency.objectKey)) { selected.add(dependency.objectKey); changed=true; }
    }
    for(const child of logical)if(child.entityType==='targets'&&child.parentLogicalKey&&selected.has(byLogical.get(child.parentLogicalKey)?.objectKey??'')&&!selected.has(child.objectKey)){selected.add(child.objectKey);changed=true;}
  }
  return selected;
}

/** Derive the Consumer closure from the exact server-frozen selection. Used
 * solely to narrow private credential checks; this creates no authority. */
export function promotionConsumerClosure(source:ComparisonInventory,options:PromoteOptions):ReadonlySet<string>{
  if(!options.includeCredentials)return new Set();
  const logical=normalizeLogicalGraph(source,publicPolicy(options)),selected=selectedObjects(source,logical.objects,options);
  return new Set(source.objects.filter(object=>object.entityType==='consumers'&&selected.has(objectIdentity(object))).map(object=>object.nativeId));
}

/** Produces only a target-side merge document. Execution remains in real M8. */
export function compilePromoteDocument(inputSource: ComparisonInventory, target: ComparisonInventory, options: PromoteOptions): PromoteCompilation {
  const blockers: ComparisonIssue[] = [], mappings: PromoteMapping[] = [], basicPasswordIntents: Record<string,'replace'> = {};
  for(const flag of ['includeEnvironmentFields','includeSecrets','includeCredentials']as const)if(options[flag]!==undefined&&typeof options[flag]!=='boolean')comparisonFail('GOVERNANCE_COMPARISON_INVALID_POLICY');
  if (inputSource.scope.kind !== target.scope.kind || !['workspace','services'].includes(inputSource.scope.kind)) blockers.push({code:'GOVERNANCE_PROMOTE_SCOPE_KIND'});
  if (inputSource.scope.clusterId === target.scope.clusterId && inputSource.scope.workspaceId === target.scope.workspaceId && inputSource.scope.transportScope === target.scope.transportScope) blockers.push({code:'GOVERNANCE_PROMOTE_SAME_SCOPE'});
  if (options.includeCredentials && !options.includeSecrets) blockers.push({code:'GOVERNANCE_PROMOTE_CREDENTIAL_SECRET_CONFIRMATION_REQUIRED'});
  const workspacePhysicalTag = workspaceTag(options.targetWorkspaceCode), policy = publicPolicy(options);
  assertComparisonJson(options.mapping ?? {}); assertComparisonJson(options.fieldOverrides ?? {});
  const source = withPrivateMaterial(inputSource,options,blockers), a = normalizeLogicalGraph(source,policy), b = normalizeLogicalGraph(target,policy);
  blockers.push(...a.issues,...b.issues);
  const sourceBundle = comparisonSchemas(source), targetBundle = comparisonSchemas(target);
  if (!/^1\.5\.\d+$/.test(source.version) || !/^1\.5\.\d+$/.test(target.version) || source.version !== target.version || sourceBundle.adapterVersion !== targetBundle.adapterVersion) blockers.push({code:'GOVERNANCE_PROMOTE_VERSION_CAPABILITY_MISMATCH'});
  const selected = selectedObjects(source,a.objects,options), bySource = new Map(source.objects.map(object => [objectIdentity(object),object]));
  const selectedLogical = a.objects.filter(object => selected.has(object.objectKey));
  const writableLogical = selectedLogical.filter(object=>!bySource.get(object.objectKey)?.referenceOnly);
  if(blockers.length)return{state:'blocked',mode:'merge',document:null,yaml:null,selectedObjectKeys:[...selected].sort(),mappings,exclusions:a.exclusions,blockers,basicPasswordIntents};
  const targetByLogical = new Map(b.objects.map(object => [object.logicalKey,object])), targetById = new Map(target.objects.map(object => [nativeKey(object),object]));
  const omittedTargetIdentities=new Map(Object.entries(b.identities).map(([key,logical])=>[logical,target.objects.find(object=>objectIdentity(object)===key)!]));
  const mapped = new Map<string,string>(), sourceIds = new Set(source.objects.map(object => object.nativeId)), allocated = new Set<string>();
  const mapObject = (object: LogicalObject): void => {
    const explicit = options.mapping?.[object.objectKey], matched = targetByLogical.get(object.logicalKey);
    let existing: ComparisonObject | undefined;
    if (explicit !== undefined) {
      if (!UUID.test(explicit)) comparisonFail('GOVERNANCE_PROMOTE_MAPPING_INVALID');
      existing = targetById.get(`${object.entityType}:${explicit}`);
      if (!existing || existing.credentialKind !== object.credentialKind) { blockers.push({code:'GOVERNANCE_PROMOTE_MAPPING_NOT_CAPTURED',objectKey:object.objectKey}); return; }
    } else if (matched) existing = targetById.get(`${matched.entityType}:${matched.nativeId}`);
    const readOnlyDependency=bySource.get(object.objectKey)?.referenceOnly===true;
    if(readOnlyDependency&&!existing){blockers.push({code:'GOVERNANCE_PROMOTE_REFERENCE_UNMAPPED',objectKey:object.objectKey});return;}
    if(!readOnlyDependency&&existing?.referenceOnly){blockers.push({code:'GOVERNANCE_PROMOTE_MAPPING_OUTSIDE_TARGET_SELECTION',objectKey:object.objectKey});return;}
    const id = existing?.nativeId ?? (options.allocateNativeId ?? (() => randomUUID()))(object.logicalKey);
    if (!UUID.test(id) || allocated.has(id) || !existing && (sourceIds.has(id) || target.objects.some(candidate => candidate.nativeId === id))) comparisonFail('GOVERNANCE_PROMOTE_ALLOCATED_ID_INVALID');
    allocated.add(id); mapped.set(object.logicalKey,id);
    mappings.push({sourceObjectKey:object.objectKey,logicalKey:object.logicalKey,targetNativeId:id,action:existing?'existing':'create'});
  };
  for (const object of selectedLogical) mapObject(object);
  for (const [key] of Object.entries(options.mapping ?? {})) if (!selected.has(key)) comparisonFail('GOVERNANCE_PROMOTE_MAPPING_OUTSIDE_SELECTION');
  for (const [key] of Object.entries(options.fieldOverrides ?? {})) if (!selected.has(key)) comparisonFail('GOVERNANCE_PROMOTE_OVERRIDE_OUTSIDE_SELECTION');
  // An omitted certificate/target can only serve as a dependency through an
  // exact existing target identity. No source UUID is a fallback mapping.
  for (const object of a.objects) if (!mapped.has(object.logicalKey) && targetByLogical.has(object.logicalKey)) mapped.set(object.logicalKey,targetByLogical.get(object.logicalKey)!.nativeId);
  for(const logical of Object.values(a.identities))if(!mapped.has(logical)&&omittedTargetIdentities.has(logical))mapped.set(logical,omittedTargetIdentities.get(logical)!.nativeId);
  const material: Array<{object:LogicalObject;payload:Record<string,unknown>;targetId:string}> = [];
  for (const object of writableLogical) {
    const sourceObject = bySource.get(object.objectKey)!, targetId = mapped.get(object.logicalKey);
    if (!targetId) continue;
    const existing = targetById.get(`${object.entityType}:${targetId}`);
    const overrides = options.fieldOverrides?.[object.objectKey] ?? {};
    if (Object.hasOwn(overrides,'id') || Object.hasOwn(overrides,'created_at') || Object.hasOwn(overrides,'updated_at') || Object.hasOwn(overrides,'ttl')) comparisonFail('GOVERNANCE_PROMOTE_OVERRIDE_IDENTITY');
    if(Object.keys(overrides).length&&!options.includeSecrets&&canonicalJson(safeComparisonValue(overrides,'',sourceObject.sensitiveFields))!==canonicalJson(overrides))blockers.push({code:'GOVERNANCE_PROMOTE_SECRET_OVERRIDE_CONFIRMATION_REQUIRED',objectKey:object.objectKey});
    const replaceReferences = (value: unknown, path=''): unknown => {
      if (!value || typeof value !== 'object') return value;
      if (!Array.isArray(value) && Object.keys(value).length === 1 && typeof (value as any).logical_ref === 'string') {
        const id = mapped.get((value as any).logical_ref);
        if (!id) { blockers.push({code:'GOVERNANCE_PROMOTE_REFERENCE_UNMAPPED',objectKey:object.objectKey,field:path}); return null; }
        return object.entityType==='plugins'&&path==='/config/anonymous'&&authenticationAnonymousConsumerPlugin(sourceObject.payload.name)?id:{id};
      }
      return Array.isArray(value) ? value.map((child,index) => replaceReferences(child,`${path}/${index}`))
        : Object.fromEntries(Object.entries(value).map(([key,child]) => [key,replaceReferences(child,`${path}/${key}`)]));
    };
    let payload:Record<string,unknown> = {...replaceReferences(object.payload) as Record<string,unknown>,...structuredClone(overrides),id:targetId};
    if(object.entityType==='services'&&!Object.hasOwn(overrides,'host')&&typeof object.referenceFields['/host']==='string'){
      const upstreamKey=object.referenceFields['/host'],upstreamId=mapped.get(upstreamKey),upstreamSource=a.objects.find(candidate=>candidate.logicalKey===upstreamKey);
      const upstreamTarget=upstreamId?targetById.get(`upstreams:${upstreamId}`):undefined;
      const promotedName=upstreamSource?(options.fieldOverrides?.[upstreamSource.objectKey]?.name??upstreamSource.payload.name):undefined;
      const name=upstreamSource&&writableLogical.some(candidate=>candidate.objectKey===upstreamSource.objectKey)?promotedName:upstreamTarget?.payload.name;
      if(!upstreamId||typeof name!=='string')blockers.push({code:'GOVERNANCE_PROMOTE_UPSTREAM_HOST_UNMAPPED',objectKey:object.objectKey,field:'/host'});
      else payload.host=name;
    }
    // Merge documents omit protected values instead of copying target secrets.
    // M8's target baseline supplies them for validation and exact preservation.
    if(payload.tags!==undefined&&payload.tags!==null&&(!Array.isArray(payload.tags)||payload.tags.some(tag=>typeof tag!=='string')))comparisonFail('GOVERNANCE_INVALID_TAGS');
    const suppliedTags=(Array.isArray(payload.tags)?payload.tags as string[]:[]).map(tag=>{
      const decoded=decodeTag(tag);
      if((tag.startsWith('kos-ws-')||tag.startsWith('kos-tag-'))&&encodeTag(decoded)!==tag)comparisonFail('GOVERNANCE_INVALID_TAGS');
      return decoded;
    });
    const tags = [...new Set([...suppliedTags.filter(tag => !tag.startsWith('workspace:')),`workspace:${options.targetWorkspaceCode}`])];
    payload.tags=tags;
    if(existing&&['targets','credentials'].includes(object.entityType)){
      const relation=object.entityType==='targets'?'upstream':'consumer';
      if(referenceId(payload[relation])!==(existing.parentId??referenceId(existing.payload[relation])))blockers.push({code:'GOVERNANCE_PROMOTE_PARENT_MAPPING_IMMUTABLE',objectKey:object.objectKey,field:`/${relation}`});
      if(object.entityType==='targets'&&Object.hasOwn(payload,'target')&&payload.target!==existing.payload.target)blockers.push({code:'GOVERNANCE_PROMOTE_TARGET_ADDRESS_IMMUTABLE',objectKey:object.objectKey,field:'/target'});
    }
    if (object.entityType === 'services' && !existing && (typeof payload.host !== 'string' || !payload.host.length)) blockers.push({code:'GOVERNANCE_PROMOTE_TARGET_HOST_REQUIRED',objectKey:object.objectKey,field:'/host'});
    if(object.entityType==='routes'&&!existing&&!['paths','hosts','methods','headers','snis','sources','destinations'].some(field=>payload[field]!==null&&payload[field]!==undefined&&(typeof payload[field]!=='object'||Object.keys(payload[field] as object).length)))blockers.push({code:'GOVERNANCE_PROMOTE_ROUTE_MATCH_REQUIRED',objectKey:object.objectKey});
    if (object.entityType === 'upstreams' && !existing && !writableLogical.some(child => child.entityType === 'targets' && child.parentLogicalKey === object.logicalKey)) blockers.push({code:'GOVERNANCE_PROMOTE_TARGETS_REQUIRED',objectKey:object.objectKey});
    if(object.entityType==='plugins'&&!existing&&a.exclusions.some(omission=>omission.objectKey===object.objectKey&&omission.reason==='unknown_plugin')&&!Object.hasOwn(overrides,'config'))blockers.push({code:'GOVERNANCE_PROMOTE_TARGET_PLUGIN_CONFIG_REQUIRED',objectKey:object.objectKey});
    const selectedSchemas = {entities:{[object.entityType === 'credentials' ? CREDENTIAL_SCHEMAS[object.credentialKind!] : object.entityType]:entitySchema(sourceBundle,object.entityType,object.credentialKind)},
      plugins:object.entityType==='plugins'?{[String(sourceObject.payload.name)]:source.pluginSchemas[String(sourceObject.payload.name)]}:{},enabledPlugins:object.entityType==='plugins'?[String(sourceObject.payload.name)]:[],kongVersion:source.version,adapterVersion:sourceBundle.adapterVersion,schemaHmac:'comparison'};
    const targetSchemas = {...selectedSchemas,entities:{[Object.keys(selectedSchemas.entities)[0]]:target.schemas[Object.keys(selectedSchemas.entities)[0]]},
      plugins:object.entityType==='plugins'?{[String(sourceObject.payload.name)]:target.pluginSchemas[String(sourceObject.payload.name)]}:{},kongVersion:target.version,adapterVersion:targetBundle.adapterVersion};
    if (object.entityType==='plugins' && !target.enabledPlugins.includes(String(sourceObject.payload.name))) blockers.push({code:'GOVERNANCE_PROMOTE_PLUGIN_UNAVAILABLE',objectKey:object.objectKey});
    try { if (!compareCapturedSchemas(selectedSchemas,targetSchemas).kong15ValidationEquivalent) blockers.push({code:'GOVERNANCE_PROMOTE_SCHEMA_INCOMPATIBLE',objectKey:object.objectKey}); }
    catch { blockers.push({code:'GOVERNANCE_PROMOTE_SCHEMA_INCOMPATIBLE',objectKey:object.objectKey}); }
    try {
      const effective={...(existing?.payload??{}),...payload};
      // Inventory omits secrets: exclude those missing target values from create
      // checks while M8's full baseline performs the final required validation.
      payload=normalizeEntityPayload(payload,targetBundle,object.entityType,object.credentialKind,false);
      if (!existing) normalizeEntityPayload(effective,targetBundle,object.entityType,object.credentialKind,true);
      const definitions=schemaFields(entitySchema(targetBundle,object.entityType,object.credentialKind));
      const knownIds=new Set([...target.objects.map(candidate => nativeKey(candidate)),...mappings.map(mapping=>`${selectedLogical.find(candidate=>candidate.objectKey===mapping.sourceObjectKey)!.entityType}:${mapping.targetNativeId}`)]);
      // This 1.5 FK is a scalar UUID rather than schema `foreign`. Validate
      // the final value too: explicit config overrides cannot bypass mapping
      // and reintroduce a source or unobserved Consumer ID.
      if(object.entityType==='plugins'&&authenticationAnonymousConsumerPlugin(payload.name)){
        const anonymous=(payload.config as Record<string,unknown>|undefined)?.anonymous;
        if(anonymous!==undefined&&anonymous!==null&&(typeof anonymous!=='string'||!knownIds.has(`consumers:${anonymous}`)))blockers.push({code:'GOVERNANCE_PROMOTE_REFERENCE_NOT_CAPTURED',objectKey:object.objectKey,field:'/config/anonymous'});
      }
      const checkReference=(value:unknown,definition:any,path:string):void=>{
        if(value===null||value===undefined)return;
        if(definition.type==='foreign'){
          const id=referenceId(value);
          if(!id||!knownIds.has(`${definition.reference}:${id}`))blockers.push({code:'GOVERNANCE_PROMOTE_REFERENCE_NOT_CAPTURED',objectKey:object.objectKey,field:path});
        }else if(Array.isArray(value))value.forEach((child,index)=>checkReference(child,definition.elements??{},`${path}/${index}`));
        else if(value&&typeof value==='object'){
          const children=definition.fields?schemaFields(definition):null;
          for(const[name,child]of Object.entries(value))checkReference(child,children?.[name]??definition.values??{},`${path}/${name}`);
        }
      };
      for(const[field,definition]of Object.entries(definitions))checkReference(payload[field],definition,`/${field}`);
    } catch (error) { blockers.push({code:'GOVERNANCE_PROMOTE_TARGET_SCHEMA_INVALID',objectKey:object.objectKey,...(typeof (error as any)?.path==='string'?{field:(error as any).path}:{})}); }
    if(object.entityType==='credentials'&&object.credentialKind==='basic-auth')basicPasswordIntents[`credentials:${object.credentialKind}:${referenceId(payload.consumer)}:${targetId}`]='replace';
    material.push({object,payload,targetId});
  }
  const result = (document:Record<string,unknown>|null):PromoteCompilation => ({state:blockers.length?'blocked':'ready',mode:'merge',document: blockers.length?null:document,
    yaml:blockers.length||!document?null:stringify(JSON.parse(canonicalJson(document)),{aliasDuplicateObjects:false,lineWidth:0,defaultStringType:'QUOTE_DOUBLE',sortMapEntries:true}),
    selectedObjectKeys:[...selected].sort(),mappings,exclusions:a.exclusions,blockers,basicPasswordIntents});
  if(blockers.length)return result(null);
  const document:Record<string,unknown>={_format_version:'1.1'},documentById=new Map(material.map(entry=>[`${entry.object.entityType}:${entry.targetId}`,entry.payload]));
  const append=(type:string,payload:Record<string,unknown>):void=>{(document[type]??=[]);(document[type]as unknown[]).push(payload);};
  const nested=(entry:typeof material[number],type:string,parentType:string,parentId:string|null,relation:string):void=>{
    let parent=parentId?documentById.get(`${parentType}:${parentId}`):null;
    // A selected SNI may rebind to an existing target certificate without
    // copying its PEM/private key. The target-side merge retains that material.
    if(!parent&&parentId&&['certificates','consumers','upstreams'].includes(parentType)&&targetById.has(`${parentType}:${parentId}`)){
      parent={id:parentId};documentById.set(`${parentType}:${parentId}`,parent);append(parentType,parent);
    }
    if(!parent){blockers.push({code:'GOVERNANCE_PROMOTE_PARENT_OUTSIDE_SELECTION',objectKey:entry.object.objectKey});return;}
    delete entry.payload[relation];(parent[type]??=[]);(parent[type]as unknown[]).push(entry.payload);
  };
  for(const entry of material){
    if(entry.object.entityType==='targets')nested(entry,'targets','upstreams',referenceId(entry.payload.upstream),'upstream');
    else if(entry.object.entityType==='credentials')nested(entry,CREDENTIAL_SCHEMAS[entry.object.credentialKind!],'consumers',referenceId(entry.payload.consumer),'consumer');
    else if(entry.object.entityType==='snis')nested(entry,'snis','certificates',referenceId(entry.payload.certificate),'certificate');
    else append(entry.object.entityType,entry.payload);
  }
  if(blockers.length)return result(null);
  // This is a schema/FK-validated document, never a fabricated CaptureGraph.
  // The real M8 import captures its own current target baseline and normalizes
  // this merge document again under its actual runtime access handle.
  try {
    if(Buffer.byteLength(canonicalJson(document))>8*1024*1024)blockers.push({code:'GOVERNANCE_PROMOTE_DOCUMENT_TOO_LARGE'});
    if(!material.length)blockers.push({code:'GOVERNANCE_PROMOTE_NO_SUPPORTED_OBJECTS'});
    // Ensure the physical reserved tag is derived correctly and cannot be replaced.
    if(!material.every(entry=>Array.isArray(entry.payload.tags)&&entry.payload.tags.map(tag=>encodeTag(tag as string)).includes(workspacePhysicalTag)))comparisonFail('GOVERNANCE_PROMOTE_WORKSPACE_TAG');
  }catch{blockers.push({code:'GOVERNANCE_PROMOTE_DOCUMENT_INVALID'});}
  return result(document);
}

/** KP-005 seal: credentials stay out of ready promote selection unless the
 * caller explicitly sets includeCredentials. Does not grant promote authority. */
export function assertPromoteCredentialDefaultExclusion(
  compilation: Pick<PromoteCompilation, 'selectedObjectKeys' | 'state' | 'document'>,
  options: Pick<PromoteOptions, 'includeCredentials'>,
): void {
  if (options.includeCredentials === true) return;
  if (compilation.selectedObjectKeys.some(key => key.startsWith('credentials:'))) {
    comparisonFail('GOVERNANCE_PROMOTE_CREDENTIAL_DEFAULT_EXCLUSION');
  }
  if (compilation.state === 'ready' && compilation.document) {
    const credentials = (compilation.document as { credentials?: unknown }).credentials;
    if (Array.isArray(credentials) && credentials.length) comparisonFail('GOVERNANCE_PROMOTE_CREDENTIAL_DEFAULT_EXCLUSION');
    if (credentials && typeof credentials === 'object' && !Array.isArray(credentials) && Object.keys(credentials).length) {
      comparisonFail('GOVERNANCE_PROMOTE_CREDENTIAL_DEFAULT_EXCLUSION');
    }
  }
}
