import { prepareFormValues, formPayload, schemaFields, type KongSchema, type KongField } from '../../../apps/console-web/src/components/KongSchemaForm';
import { omitUnchangedHiddenMaps } from '../../../apps/console-web/src/components/schema-patch';
import { redactForDisplay } from '../../../apps/console-web/src/api/redaction';

/** Predict the wire body using the real product helpers. This prediction never
 * changes the browser's FormStore: production-schema-fill performs DOM actions. */
export function productionEditorSchema(root: KongSchema, plugin?: KongSchema, pluginNames?: readonly string[]): KongSchema {
  return { ...root, fields: schemaFields(root).map(([name, field]) => ({[name]: name === 'name' && pluginNames ? {...field,one_of:pluginNames} : name === 'config' && plugin ? {...field,type:'record',...plugin} : field})) };
}
function overlayField(field: KongField, current: any, desired: any): any {
  if (field.type === 'record' && schemaFields(field).length) return overlayValues(field, current ?? prepareFormValues(field,{},false,false), desired);
  if (field.type === 'map') return Object.entries(desired).map(([key,value]) => ({key,value:overlayField(field.values ?? {type:'string'},undefined,value)}));
  if (field.type === 'array' || field.type === 'set') return desired.map((value:any) => overlayField(field.elements ?? {type:'string'},undefined,value));
  return desired;
}
function overlayValues(schema: KongSchema, current: Record<string,any>, desired: Record<string,any>): Record<string,any> {
  const result = {...(current ?? prepareFormValues(schema,{},false,false))}, fields = new Map(schemaFields(schema));
  for (const [name,value] of Object.entries(desired)) {
    const field = fields.get(name); if (!field) throw Error('PRODUCTION_FORM_UNKNOWN_INPUT');
    result[name] = overlayField(field,result[name],value);
  }
  return result;
}
export function productionExpectedBody(root: KongSchema, desired: Record<string,any>, original?: Record<string,any>, plugin?: KongSchema): Record<string,any> {
  const editing = !!original, schema = productionEditorSchema(root,plugin), safe = original ? redactForDisplay(original) as Record<string,any> : {};
  const initial = prepareFormValues(root,safe,editing);
  if (Array.isArray(initial.tags)) initial.tags=initial.tags.filter((tag:string)=>!/^workspace:|^kos-ws-/i.test(tag));
  if (plugin) initial.config=prepareFormValues(plugin,initial.config,editing,false);
  const payload = formPayload(schema,overlayValues(schema,initial,desired),editing);
  return original ? omitUnchangedHiddenMaps(schema,payload,original) : payload;
}
export function productionNonSecretExpected(value: any, name = ''): any {
  if (/^(key|secret|password|token|provision_key|apikey|aws_key|aws_secret|client_secret|cert|rsa_private_key)$/i.test(name)) return undefined;
  if (Array.isArray(value)) return value.map(item=>productionNonSecretExpected(item)).filter(item=>item!==undefined);
  if (value && typeof value==='object') return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,productionNonSecretExpected(item,key)]).filter(([,item])=>item!==undefined));
  return value;
}
