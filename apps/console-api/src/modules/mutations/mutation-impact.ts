import { createHmac } from 'node:crypto';
import { canonicalJson } from '../../infrastructure/secret.service';

export interface MutationImpact {version:1;keyId:string;keys:string[];domains:string[];wildcards:string[];conservative?:boolean;}
export interface ImpactInput {entityType:string;entityId?:string|null;action:string;parentId?:string|null;credentialKind?:string|null;before?:unknown;payload?:unknown;result?:unknown;nodes?:ReadonlyArray<{type:string;id:string;data?:any}>;}
const native=new Set(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis']);
const credentialKinds=new Set(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls']);
const id=(value:any):string|undefined=>typeof value==='string'?value:typeof value?.id==='string'?value.id:undefined;
const token=(kind:string,value:unknown):string=>{
 const key=process.env.APP_SECRET;if(!key||key.length<32)throw new Error('APP_SECRET must contain at least 32 characters');
 return createHmac('sha256',key).update(`kongos:mutation-impact:v1:${kind}:`).update(canonicalJson(value)).digest('hex');
};
const validToken=(value:unknown)=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
export function validImpact(value:any):value is MutationImpact {
 return value?.version===1&&validToken(value.keyId)&&['keys','domains','wildcards'].every(name=>Array.isArray(value[name])&&value[name].length<=50000&&value[name].every(validToken));
}
export function impactOverlaps(left:MutationImpact,right:MutationImpact):boolean {
 if(left.keyId!==right.keyId)return true;
 const common=(a:string[],b:string[])=>{const values=new Set(a);return b.some(value=>values.has(value));};
 return common(left.keys,right.keys)||common(left.wildcards,right.domains)||common(right.wildcards,left.domains);
}
export function mergeImpact(...values:MutationImpact[]):MutationImpact {
 if(values.some(value=>value.keyId!==values[0].keyId))throw new Error('Mutation impact key mismatch');
 return {version:1,keyId:values[0].keyId,keys:[...new Set(values.flatMap(v=>v.keys))].sort(),domains:[...new Set(values.flatMap(v=>v.domains))].sort(),wildcards:[...new Set(values.flatMap(v=>v.wildcards))].sort(),conservative:values.some(v=>v.conservative)};
}
export function deriveImpact(input:ImpactInput):MutationImpact {
 const keys=new Set<string>(),domains=new Set<string>(),wildcards=new Set<string>();
 const addId=(type:string,value:any)=>{const valueId=id(value);if(valueId)keys.add(token('id',[type,valueId]));};
 const nativeDomain=token('domain','native');
 const add=(type:string,entityId:string|undefined,objects:any[],parentId?:string,credentialKind?:string)=>{
  const credential=type==='credentials'?credentialKind:credentialKinds.has(type)?type:undefined;
  const isNative=native.has(type)||type==='targets'||!!credential;
  if(isNative)domains.add(nativeDomain);
  const domain=token('domain',credential?['credentials',parentId??'*',credential]:type==='targets'?['targets',parentId??'*']:isNative?type:['metadata',type]);
  domains.add(domain);
  if(entityId)addId(credential??type,entityId);
  let identified=!!entityId;
  if(credential){if(parentId)addId('consumers',parentId);keys.add(token('credential-parent',[parentId??'*',credential]));identified=!!parentId;}
  if(type==='targets'&&parentId)addId('upstreams',parentId);
  for(const value of objects){
   const object=value?.entity??value;if(!object||typeof object!=='object'||Array.isArray(object))continue;
   if(object.id){addId(credential??type,object.id);identified=true;}
   // Only identifiers, never cert/key/config/password/API credential values enter searchable impact.
   if(native.has(type))for(const field of type==='consumers'?['username','custom_id']:['name'])if(typeof object[field]==='string'&&object[field]){keys.add(token('name',[type,field,object[field]]));identified=true;}
   if(type==='targets'&&typeof object.target==='string'){keys.add(token('target',[parentId??id(object.upstream)??'*',object.target]));identified=true;}
   if(type==='services'&&typeof object.host==='string')keys.add(token('name',['upstreams','name',object.host]));
   if(type==='certificates'&&Array.isArray(object.snis))for(const sni of object.snis){const name=typeof sni==='string'?sni:sni?.name;if(typeof name==='string')keys.add(token('name',['snis','name',name]));}
   if(type==='plugins'&&typeof object.name==='string'){
    keys.add(token('plugin-binding',[object.name,id(object.service)??null,id(object.route)??null,id(object.consumer)??null]));identified=true;
   }
   for(const [field,referenceType] of [['service','services'],['route','routes'],['consumer','consumers'],['upstream','upstreams'],['certificate','certificates'],['client_certificate','certificates']] as const)addId(referenceType,object[field]);
   if(Array.isArray(object.ca_certificates))for(const ca of object.ca_certificates)addId('ca_certificates',ca);
  }
  if(!identified)wildcards.add(domain);
 };
 add(input.entityType,input.entityId??undefined,[input.before,input.payload,input.result],input.parentId??undefined,input.credentialKind??undefined);
 for(const node of input.nodes??[]){
  const parent=node.type==='targets'?id(node.data?.upstream):credentialKinds.has(node.type)?id(node.data?.consumer):undefined;
  add(node.type,node.id,[node.data],parent);
 }
 return {version:1,keyId:token('key-id','current'),keys:[...keys].sort(),domains:[...domains].sort(),wildcards:[...wildcards].sort(),conservative:wildcards.size>0};
}
export function conservativeNativeImpact():MutationImpact {
 const domain=token('domain','native');return {version:1,keyId:token('key-id','current'),keys:[],domains:[domain],wildcards:[domain],conservative:true};
}
