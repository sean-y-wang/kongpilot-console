import 'reflect-metadata';
import {beforeEach,describe,expect,it} from 'vitest';
import {randomBytes} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {PortalDocumentService} from '../../apps/console-api/src/modules/portal/portal-document.service';
let service:PortalDocumentService;
const spec=()=>({openapi:'3.0.3',info:{title:'Payments',version:'1.0'},paths:{'/pay':{post:{responses:{'200':{description:'OK'}}}}},servers:[{url:'https://internal.example.test'}]});
beforeEach(()=>{process.env.CONSOLE_ENCRYPTION_KEY=randomBytes(32).toString('hex');service=new PortalDocumentService(new SecretService());});
describe('Portal semantic OpenAPI publication',()=>{
 it('preserves password/key descriptors and required names while removing their values',()=>{
  const source:any=spec();source.components={schemas:{Login:{type:'object',required:['password','key'],properties:{password:{type:'string',format:'password',description:'Login password',default:'private-pass',example:'private-pass'},key:{type:'string',example:'private-api-key'},count:{type:'integer',default:2,example:3},secret_is_base64:{type:'boolean',default:false}}}}};
  const result=service.parse(source,'https://api.example.test');
  expect(result.document.components.schemas.Login.required).toEqual(['password','key']);
  expect(result.document.components.schemas.Login.properties.password).toEqual({type:'string',format:'password',description:'Login password'});
  expect(result.document.components.schemas.Login.properties.key).toEqual({type:'string'});
  expect(result.document.components.schemas.Login.properties.count.default).toBe(2);expect(result.document.components.schemas.Login.properties.secret_is_base64.default).toBe(false);
  expect(JSON.stringify(result.document)).not.toContain('private-pass');expect(result.report.redactedExampleCount).toBe(3);expect(result.hash).toMatch(/^[a-f0-9]{64}$/);
 });
 it('sanitizes nested examples but preserves public boolean flags and public data',()=>{
  const source:any=spec();source.paths['/pay'].post.requestBody={content:{'application/json':{example:{username:'reader',password:'private-pw',nested:{api_key:'private-key',count:2},credentials:true}}}};
  const output=service.parse(source,null).document;
  expect(output.paths['/pay'].post.requestBody.content['application/json'].example).toEqual({username:'reader',nested:{count:2},credentials:true});expect(output.servers).toBeUndefined();
 });
 it('removes secret values from parameter schemas using parameter names',()=>{
  const source:any=spec();source.paths['/pay'].post.parameters=[{in:'header',name:'Authorization',schema:{type:'string',default:'private-value'},example:'private-value'}];
  expect(service.parse(source,null).document.paths['/pay'].post.parameters[0]).toEqual({in:'header',name:'Authorization',schema:{type:'string'}});
 });
 it('retains properties literally called example/default and recursive internal references',()=>{
  const source:any=spec();source.components={schemas:{Node:{properties:{example:{type:'string'},default:{type:'number'},next:{$ref:'#/components/schemas/Node'}}}}};
  expect(service.parse(source,null).document.components.schemas.Node.properties).toEqual(source.components.schemas.Node.properties);
 });
 it('preserves default response descriptors and sanitizes their nested password schema',()=>{
  const source:any=spec();source.paths['/pay'].post.responses.default={description:'Fallback',content:{'application/json':{schema:{type:'object',required:['password'],properties:{password:{type:'string',format:'password',example:'private-value'},default:{type:'string'}}}}}};
  const response=service.parse(source,null).document.paths['/pay'].post.responses.default;
  expect(response.description).toBe('Fallback');expect(response.content['application/json'].schema.required).toEqual(['password']);expect(response.content['application/json'].schema.properties.password).toEqual({type:'string',format:'password'});expect(response.content['application/json'].schema.properties.default).toEqual({type:'string'});
 });
 it('preserves a business property literally named $ref and rejects refs removed by publication',()=>{
  const source:any=spec();source.components={schemas:{Body:{properties:{$ref:{type:'string'}}},Password:{type:'string',default:'private-value'},Pointer:{$ref:'#/components/schemas/Password/default'}}};
  expect(()=>service.parse(source,null)).toThrow();delete source.components.schemas.Pointer;
  expect(service.parse(source,null).document.components.schemas.Body.properties.$ref).toEqual({type:'string'});
 });
 it('accepts safe YAML and both OpenAPI3.1 and Swagger2 with only controlled proxy servers',()=>{
  const parsed=service.parse('openapi: 3.1.0\ninfo:\n  title: APIs\n  version: "1"\npaths: {}\nservers:\n  - url: https://original.test\n','https://public.test');expect(parsed.document.servers).toEqual([{url:'https://public.test'}]);
  const old:any={swagger:'2.0',info:{title:'Old',version:'1'},paths:{},host:'original.test',basePath:'/old',schemes:['http']};const clean=service.parse(old,'https://public.test').document;expect(clean.host).toBe('public.test');expect(clean.schemes).toEqual(['https']);expect(clean.basePath).toBe('/');const unbound=service.parse(old,null).document;expect(unbound.host).toBeUndefined();expect(unbound.schemes).toBeUndefined();
 });
 it('hashes the safe document deterministically and with keyed protection',()=>{
  const first=service.parse(spec(),null),second=service.parse(spec(),null);expect(first.hash).toBe(second.hash);process.env.CONSOLE_ENCRYPTION_KEY=randomBytes(32).toString('hex');expect(new PortalDocumentService(new SecretService()).parse(spec(),null).hash).not.toBe(first.hash);
 });
 it.each(['https://remote.test/schema.json','#remote','file:///secret','//remote.test/ref'])('rejects external ref %s without fetching',ref=>{const source:any=spec();source.components={schemas:{Ref:{$ref:ref}}};expect(()=>service.parse(source,null)).toThrow();});
 it('rejects dangling internal refs and prototype properties in JSON',()=>{const source:any=spec();source.components={schemas:{Ref:{$ref:'#/missing'}}};expect(()=>service.parse(source,null)).toThrow();expect(()=>service.parse('{"openapi":"3.0.3","info":{"title":"a","version":"1"},"paths":{},"__proto__":{"polluted":true}}',null)).toThrow();expect(({} as any).polluted).toBeUndefined();});
 it.each(['openapi: 3.0.3\ninfo: &i {title: APIs, version: "1"}\npaths: {}\nx-info: *i','openapi: 3.0.3\ninfo: !danger {title: APIs, version: "1"}\npaths: {}','openapi: 3.0.3\nopenapi: 3.1.0\ninfo: {title: APIs, version: "1"}\npaths: {}'])('rejects YAML aliases/custom tags/duplicate keys',value=>expect(()=>service.parse(value,null)).toThrow());
 it.each(['<script>alert(1)</script>','&lt;img src=x&gt;','https://user:password@upstream.test','javascript:alert(1)','java&#x09;script:alert(1)'])('rejects unsafe document text',description=>{const source:any=spec();source.info.description=description;expect(()=>service.parse(source,null)).toThrow();});
 it.each(['https://user:secret@public.test','https://public.test/path','https://public.test?key=x','data:text/plain,x'])('rejects invalid public proxy origin',origin=>expect(()=>service.parse(spec(),origin)).toThrow());
 it('rejects oversized, excessively deep, excessive nodes/operations and nonfinite object input',()=>{
  expect(()=>service.parse(' '.repeat(3*1024*1024+1),null)).toThrow();const depth:any=spec();let next=depth;for(let i=0;i<35;i++){next.extra={};next=next.extra;}expect(()=>service.parse(depth,null)).toThrow();const nodes:any=spec();nodes.extra=Array.from({length:50001},()=>null);expect(()=>service.parse(nodes,null)).toThrow();const operations:any=spec();operations.paths=Object.fromEntries(Array.from({length:2001},(_,i)=>[`/p${i}`,{get:{responses:{}}}]));expect(()=>service.parse(operations,null)).toThrow();const invalid:any=spec();invalid.extra=NaN;expect(()=>service.parse(invalid,null)).toThrow();
 });
 it('rejects cycles and getters without executing accessors',()=>{const cycle:any=spec();cycle.self=cycle;expect(()=>service.parse(cycle,null)).toThrow();let calls=0;const getter:any=spec();Object.defineProperty(getter,'getter',{enumerable:true,get(){calls++;return 'secret';}});expect(()=>service.parse(getter,null)).toThrow();const array:any=spec();array.extra=[];Object.defineProperty(array.extra,'0',{enumerable:true,get(){calls++;return 'secret';}});expect(()=>service.parse(array,null)).toThrow();expect(calls).toBe(0);});
 it('bounds recursive callback references and rejects an excessively long callback chain',()=>{
  const recursive:any=spec();recursive.components={callbacks:{Cycle:{$ref:'#/components/callbacks/Cycle'}}};recursive.paths['/pay'].post.callbacks={again:{$ref:'#/components/callbacks/Cycle'}};
  expect(service.parse(recursive,null).report.operationCount).toBe(1);
  const chain:any=spec();chain.components={callbacks:{}};for(let i=0;i<40;i++)chain.components.callbacks[`c${i}`]=i===39?{'{$request.body#/url}':{get:{responses:{}}}}:{$ref:`#/components/callbacks/c${i+1}`};
  expect(()=>service.parse(chain,null)).toThrowError(expect.objectContaining({response:expect.objectContaining({code:'PORTAL_DOCUMENT_BUDGET_EXCEEDED'})}));
 });
});
describe('Portal Markdown publication',()=>{
 it('retains normal headings, code, links and self images without HTML',()=>expect(service.markdown('# Guide\r\n\n[Docs](https://docs.example.test)\n![Logo](/assets/logo.png)\n`x < 2`')).toBe('# Guide\n\n[Docs](https://docs.example.test)\n![Logo](/assets/logo.png)\n`x < 2`'));
 it.each(['<img src=x>','[x](javascript:alert(1))','[x](java&#x09;script:alert(1))','[x](javascript&colon;alert(1))','![x](https://remote.test/x.png)','![x](//remote.test/x.png)','![x](&#104;ttps://remote.test/x.png)','![x](/\\remote.test/x.png)','![x][img]\n\n[img]: https://remote.test/x.png','[x](https://user:pass@remote.test)','![x](data:image/png;base64,abc)'])('rejects unsafe Markdown',value=>expect(()=>service.markdown(value)).toThrow());
 it('enforces Markdown byte budget',()=>expect(()=>service.markdown('a'.repeat(256*1024+1))).toThrow());
});
