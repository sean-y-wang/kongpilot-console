import 'reflect-metadata';
import {describe,expect,it} from 'vitest';
import {createRequire} from 'node:module';
import {PortalAdminController} from '../../apps/console-api/src/modules/portal/portal.controller';
import {describeConsoleApi} from '../../apps/console-api/src/common/openapi';
const {PATH_METADATA}=createRequire(new URL('../../apps/console-api/package.json',import.meta.url))('@nestjs/common/constants');
const methods=['developer','application','applicationGrants','applicationRequests','requests','developers','applications'];
function document(){
 const prefix=Reflect.getMetadata(PATH_METADATA,PortalAdminController),paths:any={};
 for(const method of methods){const route=Reflect.getMetadata(PATH_METADATA,(PortalAdminController.prototype as any)[method]);const path='/api/v1/'+`${prefix}/${route}`.replace(/:([A-Za-z]+)/g,'{$1}');paths[path]={get:{responses:{200:{description:'ok'}},parameters:[{in:'query',name:'workspaceId',required:false,schema:{type:'string'}}]}};}
 paths['/api/v1/portal/publications']={get:{responses:{200:{description:'ok'}}}};
 paths['/api/v1/clusters/{clusterId}/portal/settings']={patch:{responses:{200:{description:'ok'}}}};
 return describeConsoleApi({openapi:'3.0.0',info:{title:'offline actual route metadata',version:'1'},paths}as any);
}
const query=(operation:any)=>operation.parameters.filter((p:any)=>p.in==='query');
describe('M6 actual console portal GET documentation',()=>{
 it('marks workspace required even when an inherited declaration was optional',()=>{const d=document();for(const[path,item]of Object.entries(d.paths)){if(!path.includes('/clusters/')||!item.get)continue;expect(query(item.get).filter((p:any)=>p.name==='workspaceId')).toEqual([{in:'query',name:'workspaceId',required:true,schema:{type:'string',format:'uuid'}}]);expect(item.get.security).toEqual([{cookie:[]}]);}});
 it('does not advertise list filters on root developer or application details',()=>{const d=document();for(const suffix of ['developers/{id}','applications/{id}'])expect(query(d.paths[`/api/v1/clusters/{clusterId}/portal/${suffix}`].get!).map((p:any)=>p.name)).toEqual(['workspaceId']);});
 it('documents bounded size and signed cursor on both relationships and the workspace alias',()=>{const d=document();for(const suffix of ['applications/{id}/grants','applications/{id}/requests','requests']){const op=d.paths[`/api/v1/clusters/{clusterId}/portal/${suffix}`].get!,q=query(op);expect(q.map((p:any)=>p.name)).toEqual(['workspaceId','size','cursor','state']);expect(q.find((p:any)=>p.name==='size').schema).toEqual({type:'integer',minimum:1,maximum:100,default:20});expect(q.find((p:any)=>p.name==='cursor').schema.description).toContain('权限版本');expect(q.some((p:any)=>p.name==='limit')).toBe(false);expect(op.parameters!.some(p=>'name'in p&&p.name==='X-Idempotency-Key')).toBe(false);}});
 it('keeps application archived and credential disabled states distinct from workflow terminal states',()=>{const d=document(),state=(suffix:string)=>query(d.paths[`/api/v1/clusters/{clusterId}/portal/${suffix}`].get!).find((p:any)=>p.name==='state').schema.enum;expect(state('applications')).toEqual(['active','disabled','archived']);expect(state('applications/{id}/grants')).toContain('disabled');expect(state('requests')).toContain('uncertain');expect(state('requests')).not.toContain('disabled');});
 it('documents public proof-authoritative categories without Console or Portal authentication',()=>{const op=document().paths['/api/v1/portal/publications'].get!;expect(op.security).toEqual([]);expect(query(op)).toEqual(expect.arrayContaining([expect.objectContaining({name:'clusterId',required:true}),expect.objectContaining({name:'workspaceId',required:true}),expect.objectContaining({name:'category',required:false}),expect.objectContaining({name:'search',required:false})]));expect(op.description).toContain('scanIncomplete');expect(op.description).toContain('500');});
 it('preserves existing metadata write body, CSRF and durable key contracts',()=>{const op=document().paths['/api/v1/clusters/{clusterId}/portal/settings'].patch!;expect(op.security).toEqual([{cookie:[]}]);expect(op.parameters).toContainEqual(expect.objectContaining({name:'X-CSRF-Token'}));expect(op.parameters).toContainEqual(expect.objectContaining({name:'X-Idempotency-Key',required:true}));expect((op.requestBody as any).content['application/json'].schema).toEqual({$ref:'#/components/schemas/PortalInput'});});
});
