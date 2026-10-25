import type {CapturedSchemaBundle} from '../configuration/configuration.types';
import {compareCapturedSchemas} from './schema-comparison';

/** Only fresh, server-owned rollback compilation uses this relation. A schema
 * loaded solely for a current object being removed is not a historical restore
 * requirement. Every common definition, entity definition and capability stays
 * exact apart from the existing Kong 1.5 lazy string-minimum equivalence. */
export function rollbackSchemasCompatible(current:CapturedSchemaBundle,historic:CapturedSchemaBundle,desiredPluginNames:readonly string[]):boolean{
 try{
  if(desiredPluginNames.length>10000||desiredPluginNames.some(name=>typeof name!=='string'||!/^[a-z][a-z0-9_-]{0,63}$/.test(name))||new Set(desiredPluginNames).size>200)return false;
  for(const bundle of [current,historic])if(Object.keys(bundle.plugins).length>200||Object.keys(bundle.plugins).some(name=>!/^[a-z][a-z0-9_-]{0,63}$/.test(name)||!bundle.enabledPlugins.includes(name))||!compareCapturedSchemas(bundle,bundle).kong15ValidationEquivalent)return false;
  const desired=new Set(desiredPluginNames),shared=Object.keys(current.plugins).filter(name=>Object.hasOwn(historic.plugins,name)),required=[...new Set([...shared,...desired])].sort();
  if([...desired].some(name=>!Object.hasOwn(current.plugins,name)))return false;
  const left:Record<string,unknown>=Object.create(null),right:Record<string,unknown>=Object.create(null);
  for(const name of required){
   if(!current.enabledPlugins.includes(name)||!historic.enabledPlugins.includes(name)||!Object.hasOwn(historic.plugins,name))return false;
   left[name]=current.plugins[name];right[name]=historic.plugins[name];
  }
  return compareCapturedSchemas({...current,plugins:left},{...historic,plugins:right}).kong15ValidationEquivalent;
 }catch{return false;}
}
