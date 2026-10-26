import { kongCapabilities } from '../../infrastructure/kong/kong-capabilities';
import {canonicalJson} from '../../infrastructure/secret.service';
import type {CapturedSchemaBundle} from '../configuration/configuration.types';

/** Named record field declaration order alone is insignificant. Defaults,
 * enums, checks and application arrays retain their exact order and values.
 * This diagnostic returns no schema values or execution authority. */
function namedFields(schema:unknown,kong15Defaults=false):unknown{
 let nodes=0;const seen=new WeakSet<object>();
 const copy=(value:any,depth=0):any=>{
  if(++nodes>50000||depth>32)throw Error('SCHEMA_COMPARISON_BUDGET');
  if(value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number'&&Number.isFinite(value))return value;
  if(!value||typeof value!=='object'||seen.has(value))throw Error('SCHEMA_COMPARISON_INVALID');
  if(!Array.isArray(value)&&![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw Error('SCHEMA_COMPARISON_INVALID');
  seen.add(value);const result:any=Array.isArray(value)?value.map(v=>copy(v,depth+1)):Object.fromEntries(Object.entries(value).map(([key,v])=>{
   if(['__proto__','prototype','constructor'].includes(key))throw Error('SCHEMA_COMPARISON_INVALID');return[key,copy(v,depth+1)];
  }));seen.delete(value);return result;
 };
 const definition=(value:any,depth=0):any=>{
  if(depth>32||!value||typeof value!=='object'||Array.isArray(value))throw Error('SCHEMA_COMPARISON_INVALID');
  const result={...value};
  // Kong 1.5 Schema.validate lazily mutates a string definition by setting
  // absent len_min to 1. Explicit 0 and all other constraints remain exact.
  if(kong15Defaults&&value.type==='string'&&!Object.hasOwn(value,'len_min'))result.len_min=1;
  if(Object.hasOwn(value,'fields')){
   const fields=value.fields;if(!fields||typeof fields!=='object')throw Error('SCHEMA_COMPARISON_INVALID');
   const entries:Array<[string,any]>=Array.isArray(fields)?fields.flatMap(entry=>{
    if(!entry||typeof entry!=='object'||Array.isArray(entry)||Object.keys(entry).length!==1)throw Error('SCHEMA_COMPARISON_INVALID');return Object.entries(entry);
   }):Object.entries(fields);
   if(new Set(entries.map(([name])=>name)).size!==entries.length)throw Error('SCHEMA_COMPARISON_INVALID');
   result.fields=Object.fromEntries(entries.sort(([a],[b])=>a<b?-1:a>b?1:0).map(([name,field])=>[name,definition(field,depth+1)]));
  }
  for(const child of ['elements','values','keys'])if(Object.hasOwn(value,child))result[child]=definition(value[child],depth+1);
  return result;
 };
 return definition(copy(schema));
}
/** Kong 1.5 may materialize an implicit string minimum during validation.
 * Compare definitions without rewriting stored approvals or native schemas.
 * Explicit limits, defaults, checks and non-field arrays stay exact. */
export function kong15SchemaValidationEquivalent(left:unknown,right:unknown,kongVersion:string):boolean{
 if(typeof kongVersion!=='string'||!kongCapabilities(kongVersion).full)return false;
 try{return canonicalJson(namedFields(left,true))===canonicalJson(namedFields(right,true));}catch{return false;}
}
export function compareCapturedSchemas(left:CapturedSchemaBundle,right:CapturedSchemaBundle){
 const equality=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
 const entries:Array<{kind:'entity'|'plugin';name:string;exactEqual:boolean;namedFieldOrderEquivalent:boolean;kong15ValidationEquivalent:boolean;valid:boolean;differences:Array<{path:string;kind:'missing'|'value'|'type'|'array-order'}>;differencesTruncated:boolean}>=[];
 const kong15=left.kongVersion===right.kongVersion&&kongCapabilities(left.kongVersion).full;
 const safeKey=(name:string)=>/^[A-Za-z0-9_-]{1,100}$/.test(name)?name:'[field]';
 const differences=(a:any,b:any)=>{
  const items:Array<{path:string;kind:'missing'|'value'|'type'|'array-order'}>=[];let total=0;
  const record=(path:string,x:any,y:any,present=true)=>{
   total++;if(items.length===32)return;
   const kind=!present?'missing':Array.isArray(x)&&Array.isArray(y)&&equality(x.map(v=>canonicalJson(v)).sort(),y.map(v=>canonicalJson(v)).sort())?'array-order':typeof x!==typeof y||Array.isArray(x)!==Array.isArray(y)?'type':'value';items.push({path,kind});
  };
  const visit=(x:any,y:any,path='')=>{
   for(const key of [...new Set([...Object.keys(x),...Object.keys(y)])].sort()){
    const next=path?`${path}.${safeKey(key)}`:safeKey(key),present=Object.hasOwn(x,key)&&Object.hasOwn(y,key);
    if(present&&equality(x[key],y[key]))continue;
    if(!present){record(next,x[key],y[key],false);continue;}
    if(key==='fields'){
     for(const name of [...new Set([...Object.keys(x.fields),...Object.keys(y.fields)])].sort()){
      const p=`${next}.${safeKey(name)}`;if(!Object.hasOwn(x.fields,name)||!Object.hasOwn(y.fields,name))record(p,x.fields[name],y.fields[name],false);else visit(x.fields[name],y.fields[name],p);
     }
    }else if(['elements','values','keys'].includes(key))visit(x[key],y[key],next);
    // Other metadata is atomic. Never disclose default/check payload keys or values.
    else record(next,x[key],y[key]);
   }
  };visit(a,b);return{differences:items,differencesTruncated:total>items.length};
 };
 for(const [kind,collection]of [['entity','entities'],['plugin','plugins']]as const){
  const a=left[collection],b=right[collection];
  for(const name of [...new Set([...Object.keys(a),...Object.keys(b)])].sort()){
   const present=Object.hasOwn(a,name)&&Object.hasOwn(b,name);let equivalent=false,validationEquivalent=false,exact=false,valid=present,safe={differences:[]as Array<{path:string;kind:'missing'|'value'|'type'|'array-order'}>,differencesTruncated:false};
   try{if(present){const x=namedFields(a[name]),y=namedFields(b[name]);equivalent=equality(x,y);validationEquivalent=kong15&&equality(namedFields(a[name],true),namedFields(b[name],true));exact=equality(a[name],b[name]);safe=differences(x,y);}}catch{valid=false;}
   entries.push({kind,name,exactEqual:exact,namedFieldOrderEquivalent:equivalent,kong15ValidationEquivalent:validationEquivalent,valid,...safe});
  }
 }
 const metadata={kongVersionEqual:left.kongVersion===right.kongVersion,adapterVersionEqual:left.adapterVersion===right.adapterVersion,enabledPluginsEqual:equality(left.enabledPlugins,right.enabledPlugins)};
 return{readOnly:true,normalization:'named-record-fields-v1',...metadata,exactEqual:Object.values(metadata).every(Boolean)&&entries.every(e=>e.exactEqual),
  namedFieldOrderEquivalent:Object.values(metadata).every(Boolean)&&entries.every(e=>e.valid&&e.namedFieldOrderEquivalent),
  kong15ValidationEquivalent:kong15&&Object.values(metadata).every(Boolean)&&entries.every(e=>e.valid&&e.kong15ValidationEquivalent),schemas:entries};
}
