import {ConflictException} from '@nestjs/common';
import type {SecretService} from '../../infrastructure/secret.service';
import type {GovernanceInventory} from './governance-inventory.types';

export interface GovernanceComparisonMaterial<T=GovernanceInventory>{inventory:T;nativeFingerprints:Readonly<Record<string,string>>|null;}
export interface GovernanceComparisonEnvelope<T=GovernanceInventory>{version:2;inventory:T;nativeFingerprints:Readonly<Record<string,string>>;}
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i,hex=/^[a-f\d]{64}$/;
const types=new Set(['services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis']);
const changed=()=>new ConflictException({code:'GOVERNANCE_COMPARISON_MATERIAL_CHANGED',message:'比较材料或私有来源验证记录已变化，请创建新比较'});
const object=(value:unknown):value is Record<string,any>=>!!value&&typeof value==='object'&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value));

/** Private data codec only, never an authority factory. Digests never become
 * public inventory properties, controller DTOs or a readable configuration. */
export function governanceComparisonEnvelope<T>(inventory:T,fingerprints:Readonly<Record<string,string>>):GovernanceComparisonEnvelope<T>{
 if(!object(inventory)||!Array.isArray(inventory.objects)||inventory.objects.length>10000||!object(fingerprints))throw changed();
 const expected=new Set<string>();for(const entry of inventory.objects){if(!object(entry)||!types.has(entry.entityType)||!uuid.test(entry.nativeId??''))throw changed();const key=`${entry.entityType}:${entry.nativeId}`;if(expected.has(key))throw changed();expected.add(key);}
 if(Object.keys(fingerprints).length!==expected.size||[...expected].some(key=>!Object.hasOwn(fingerprints,key)||!hex.test(fingerprints[key])))throw changed();
 const nativeFingerprints=Object.freeze(Object.fromEntries([...expected].sort().map(key=>[key,fingerprints[key]])));
 return{version:2,inventory,nativeFingerprints};
}

/** Single authenticated decoding path shared by repository and origin core.
 * Legacy raw inventories are readable history, never hidden-field proof. */
export function decryptComparisonMaterial<T=GovernanceInventory>(row:Record<string,any>,secrets:SecretService):{source:GovernanceComparisonMaterial<T>;target:GovernanceComparisonMaterial<T>}{
 if(!uuid.test(row.id??''))throw changed();
 const decode=(side:'source'|'target'):GovernanceComparisonMaterial<T>=>{
  let sealed:any;try{sealed=secrets.decrypt(row[`${side}_inventory_secret`],`governance:comparison-${side}:${row.id}`);}catch{throw changed();}
  if(secrets.fingerprint(sealed)!==row[`${side}_inventory_hmac`]||!object(sealed))throw changed();
  if(sealed.version===2){if(Object.keys(sealed).length!==3||!['version','inventory','nativeFingerprints'].every(key=>Object.hasOwn(sealed,key)))throw changed();const envelope=governanceComparisonEnvelope(sealed.inventory,sealed.nativeFingerprints);return{inventory:envelope.inventory as T,nativeFingerprints:envelope.nativeFingerprints};}
  if(!object(sealed.scope)||!Array.isArray(sealed.objects))throw changed();return{inventory:sealed as T,nativeFingerprints:null};
 };
 return{source:decode('source'),target:decode('target')};
}
