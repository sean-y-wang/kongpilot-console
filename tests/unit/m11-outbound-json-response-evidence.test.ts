import {EventEmitter} from 'node:events';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
const wire=vi.hoisted(()=>({status:404,text:'{"message":"Not found"}'}));
vi.mock('node:dns/promises',()=>({lookup:vi.fn(async()=>[{address:'127.0.0.1',family:4}])}));
vi.mock('node:http',()=>({request:(_url:unknown,_options:unknown,onResponse:(response:any)=>void)=>{
 const request:any=new EventEmitter();request.write=vi.fn();request.destroy=(error:Error)=>request.emit('error',error);
 request.end=()=>queueMicrotask(()=>{const response:any=new EventEmitter();response.statusCode=wire.status;onResponse(response);
  if(wire.text)response.emit('data',Buffer.from(wire.text));response.emit('end');request.emit('close');});return request;
}}));
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
beforeEach(()=>vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','kong'));afterEach(()=>vi.unstubAllEnvs());
/** Real parsing code, controlled socket adapter; no runtime/network requests. */
describe('outbound JSON evidence distinguishes actual parsing from fallback objects',()=>{
 it.each(['{"message":"Not found"}','null','false','[]'])('records successful JSON parsing of raw %s without changing the enumerable result',async text=>{
  wire.text=text;const response=await outboundJson('http://kong:8001','/services/00000000-0000-4000-8000-000000000001');
  expect(response.jsonParsed).toBe(true);expect(response).toEqual({status:404,body:JSON.parse(text),bytes:Buffer.byteLength(text)});
  expect(Object.keys(response)).toEqual(['status','body','bytes']);expect(Reflect.set(response,'jsonParsed',false)).toBe(false);
 });
 it.each(['','<html>Not found</html>','{not-json'])('does not certify raw %j as JSON despite preserving the established fallback body',async text=>{
  wire.text=text;const response=await outboundJson('http://kong:8001','/services/00000000-0000-4000-8000-000000000001');
  expect(response.jsonParsed).toBe(false);expect(response.body).toEqual(text?{message:'上游返回非 JSON 响应'}:null);
  expect(JSON.stringify(response)).not.toContain('jsonParsed');expect(Object.getOwnPropertyDescriptor(response,'jsonParsed')).toMatchObject({writable:false,enumerable:false,configurable:false});
 });
});
