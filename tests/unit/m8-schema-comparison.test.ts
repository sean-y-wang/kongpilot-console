import {describe,it,expect} from 'vitest';
import {compareCapturedSchemas,kong15SchemaValidationEquivalent} from '../../apps/console-api/src/modules/config-transfer/schema-comparison';
import {schemas} from './m8-config-transfer.fixture';

function fixture(){const left=schemas(),right=structuredClone(left);return{left,right};}
describe('M8 readonly named schema field comparison',()=>{
 it.each(['1.4.3','2.0.0','1.5.1-enterprise','1.5',''])('does not infer 1.5 schema equivalence for version %s',version=>{
  expect(kong15SchemaValidationEquivalent({fields:[]},{fields:[]},version)).toBe(false);
 });
 it('preserves explicit empty strings, non-string minima and arbitrary default payloads',()=>{
  const left={fields:[{value:{type:'string',len_min:0}},{payload:{type:'record',default:{type:'string'}}}]};
  expect(kong15SchemaValidationEquivalent(left,structuredClone(left),'1.5.1')).toBe(true);
  const right=structuredClone(left);(right.fields[1].payload!.default as any).len_min=1;
  expect(kong15SchemaValidationEquivalent(left,right,'1.5.1')).toBe(false);
  expect(kong15SchemaValidationEquivalent({type:'integer'},{type:'integer',len_min:1},'1.5.1')).toBe(false);
 });
 it('rejects malformed duplicate fields even when both schemas are identical',()=>{
  const schema={fields:[{name:{type:'string'}},{name:{type:'string'}}]};
  expect(kong15SchemaValidationEquivalent(schema,schema,'1.5.1')).toBe(false);
 });
 it('does not treat a stored fingerprint alone as schema content',()=>{const f=fixture();f.right.schemaHmac='different-opaque-hmac';expect(compareCapturedSchemas(f.left,f.right)).toMatchObject({exactEqual:true,namedFieldOrderEquivalent:true});});
 it('identifies outer and nested declaration order only without changing either graph',()=>{const f=fixture();(f.right.entities.services as any).fields.reverse();(f.right.plugins['correlation-id']as any).fields.reverse();const before=JSON.stringify(f);
  const result=compareCapturedSchemas(f.left,f.right);expect(result).toMatchObject({exactEqual:false,namedFieldOrderEquivalent:true});expect(result.schemas.filter(s=>!s.exactEqual).map(s=>s.name)).toEqual(['services','correlation-id']);expect(JSON.stringify(f)).toBe(before);
 });
 it('equates a valid named fields map with the same uniquely named array',()=>{const f=fixture(),schema:any=f.right.entities.services;schema.fields=Object.assign({},...schema.fields);expect(compareCapturedSchemas(f.left,f.right).namedFieldOrderEquivalent).toBe(true);});
 it.each([{type:'number'},{required:true},{default:7},{one_of:['two','one']},{entity_checks:[{at_least_one_of:['a','b']}]},
  {elements:{type:'string'}},{values:{type:'integer'}},{keys:{type:'number'}}])('retains actual field metadata %j',change=>{const f=fixture();const field=(f.right.entities.services as any).fields.find((item:any)=>item.retries).retries;Object.assign(field,change);
  expect(compareCapturedSchemas(f.left,f.right).namedFieldOrderEquivalent).toBe(false);
 });
 it('does not reorder default payloads even when they contain a fields property',()=>{const f=fixture(),a:any=f.left.plugins['correlation-id'],b:any=f.right.plugins['correlation-id'];a.fields[0][Object.keys(a.fields[0])[0]].default={fields:[{a:1},{b:2}]};b.fields[0][Object.keys(b.fields[0])[0]].default={fields:[{b:2},{a:1}]};expect(compareCapturedSchemas(f.left,f.right).namedFieldOrderEquivalent).toBe(false);});
 it.each(['kongVersion','adapterVersion','enabledPlugins']as const)('rejects changed bundle %s',key=>{const f=fixture();(f.right as any)[key]=key==='enabledPlugins'?[]:'different';expect(compareCapturedSchemas(f.left,f.right).namedFieldOrderEquivalent).toBe(false);});
 it('does not accept an added, removed or renamed plugin schema',()=>{const f=fixture();delete f.right.plugins['correlation-id'];f.right.plugins['different-plugin']=structuredClone(f.left.plugins['correlation-id']);const result=compareCapturedSchemas(f.left,f.right);expect(result.namedFieldOrderEquivalent).toBe(false);expect(result.schemas.filter(s=>!s.valid)).toHaveLength(2);});
 it.each(['duplicate','multi-key','scalar','cycle','depth','budget'])('fails closed for %s schema',kind=>{const f=fixture(),schema:any=f.right.entities.services;
  if(kind==='duplicate')schema.fields.push(structuredClone(schema.fields[0]));
  if(kind==='multi-key')schema.fields.push({a:{type:'string'},b:{type:'string'}});
  if(kind==='scalar')schema.fields.push({a:'invalid'});
  if(kind==='cycle')schema.fields.push({cycle:schema});
  if(kind==='depth'){let field:any={type:'string'};for(let i=0;i<34;i++)field={type:'array',elements:field};schema.fields.push({deep:field});}
  if(kind==='budget')schema.fields.push({wide:{type:'string',default:Array(50001).fill('x')}});
  const result=compareCapturedSchemas(f.left,f.right);expect(result.namedFieldOrderEquivalent).toBe(false);expect(result.schemas.find(s=>s.name==='services')?.valid).toBe(false);
 });
 it('never returns defaults, private schema contents or credential values',()=>{const f=fixture(),schema:any=f.right.plugins['correlation-id'];schema.fields[0][Object.keys(schema.fields[0])[0]].default='SyntheticPrivateSchemaMaterial';const result=compareCapturedSchemas(f.left,f.right);
  expect(JSON.stringify(result)).not.toContain('SyntheticPrivateSchemaMaterial');expect(Object.keys(result.schemas[0])).toEqual(['kind','name','exactEqual','namedFieldOrderEquivalent','kong15ValidationEquivalent','valid','differences','differencesTruncated']);expect(result.readOnly).toBe(true);
 });
 it('returns only definition paths and detects changed defaults without default object keys',()=>{const f=fixture(),schema:any=f.right.entities.services;schema.fields.find((v:any)=>v.retries).retries.default={SyntheticPrivateDefaultKey:'SyntheticPrivateDefaultValue'};const result=compareCapturedSchemas(f.left,f.right);expect(result.schemas.find(s=>s.name==='services')?.differences).toEqual([{path:'fields.retries.default',kind:'type'}]);expect(JSON.stringify(result)).not.toContain('SyntheticPrivateDefault');});
 it('identifies atomic metadata array order without treating it as equivalent',()=>{const f=fixture();Object.assign(f.left.entities.services,{entity_checks:[{a:1},{b:2}]});Object.assign(f.right.entities.services,{entity_checks:[{b:2},{a:1}]});const result=compareCapturedSchemas(f.left,f.right);expect(result.namedFieldOrderEquivalent).toBe(false);expect(result.schemas.find(s=>s.name==='services')?.differences).toEqual([{path:'entity_checks',kind:'array-order'}]);});
 it('bounds difference output and reports truncation',()=>{const f=fixture(),a:any=f.left.entities.services,b:any=f.right.entities.services;for(let i=0;i<35;i++){a.fields.push({['synthetic_'+i]:{type:'integer',default:0}});b.fields.push({['synthetic_'+i]:{type:'integer',default:1}});}const result=compareCapturedSchemas(f.left,f.right);expect(result.schemas.find(s=>s.name==='services')).toMatchObject({differences:expect.any(Array),differencesTruncated:true});expect(result.schemas.find(s=>s.name==='services')?.differences).toHaveLength(32);});
 it('recognizes only Kong 1.5 lazy string minimum one as the same validation',()=>{const f=fixture(),schema:any=f.right.entities.services;schema.fields.find((v:any)=>v.host).host.len_min=1;const result=compareCapturedSchemas(f.left,f.right);expect(result).toMatchObject({exactEqual:false,namedFieldOrderEquivalent:false,kong15ValidationEquivalent:true});expect(result.schemas.find(s=>s.name==='services')?.differences).toEqual([{path:'fields.host.len_min',kind:'missing'}]);});
 it.each([0,2,null,false,'1'])('preserves explicit minimum %j as different',minimum=>{const f=fixture();(f.right.entities.services as any).fields.find((v:any)=>v.host).host.len_min=minimum;expect(compareCapturedSchemas(f.left,f.right).kong15ValidationEquivalent).toBe(false);});
 it('does not apply the lazy minimum equivalence to non-string types or other versions',()=>{const f=fixture();(f.right.entities.services as any).fields.find((v:any)=>v.retries).retries.len_min=1;expect(compareCapturedSchemas(f.left,f.right).kong15ValidationEquivalent).toBe(false);delete (f.right.entities.services as any).fields.find((v:any)=>v.retries).retries.len_min;f.left.kongVersion=f.right.kongVersion='1.4.3';expect(compareCapturedSchemas(f.left,f.right).kong15ValidationEquivalent).toBe(false);});
 it.each(['kongVersion','adapterVersion','enabledPlugins']as const)('retains %s in validation equivalence',key=>{const f=fixture();(f.right as any)[key]=key==='enabledPlugins'?[]:'different';expect(compareCapturedSchemas(f.left,f.right).kong15ValidationEquivalent).toBe(false);});
});
