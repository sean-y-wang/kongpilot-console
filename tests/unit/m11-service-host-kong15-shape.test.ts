import {describe,expect,it} from 'vitest';
import {validServiceHostReference,isServiceHostReferencePoint,isServiceHostTargetCollection} from '../../apps/console-api/src/modules/workflows/workflow-service-host-reference';

const serviceId='b1000000-0000-4000-8000-000000000001',parentId='b1000000-0000-4000-8000-000000000002';
const ref=(host:string)=>({host,serviceIds:[serviceId]});
const point=(host:string):any=>({clusterId:serviceId,workspaceId:parentId,path:`/upstreams/${encodeURIComponent(host)}`,
 kind:'point',entityType:'upstreams',secrets:false,required:false,allowAbsent:true,serviceHostReference:ref(host)});

/** Expected name shapes come from Kong tag1.5.1 check_hostname tests and the
 * original long-name acceptance counterexample. This is compiler validation,
 * not DNS reachability, a new SDK witness or destination authorization. */
describe('Service exact-name selector follows Kong1.5 name grammar',()=>{
 it('accepts the actual 67-character Kong-accepted single-label counterexample',()=>{
  const host='m11-b7cac3c8-configuration-after-revision-fixture-20261018-upstream';
  expect(host.length).toBe(67);expect(validServiceHostReference(ref(host))).toBe(true);
  expect(isServiceHostReferencePoint(point(host))).toBe(true);expect(point(host).path).toBe(`/upstreams/${host}`);
 });
 it.each([64,67,128,253,254,512])('does not invent a DNS name limit for %i character Kong names',length=>{
  const host='a'.repeat(length);expect(validServiceHostReference(ref(host))).toBe(true);expect(isServiceHostReferencePoint(point(host))).toBe(true);
 });
 it.each(['hello.com','hello.fr','test.hello.com','1991.io','hello.COM','HELLO.com','123helloWORLD.com','example.123','example-api.com',
  'example_api.com','localhost','3B-ww4c5e180e575a65lsy2b','-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n','Hello-Another-Way--fc4qua05auwb3674vfr0b',
  '2-u9tlzr9756bt3uc0v','MajiKoi5-783gue6qz075azm5e','de-jg4avhby1noc0d','d9juau41awczczp','_kong',`a.${'b'.repeat(100)}.c`])('accepts a Kong-valid name without changing its bytes: %s',host=>{
  expect(validServiceHostReference(ref(host))).toBe(true);expect(isServiceHostReferencePoint(point(host))).toBe(true);
 });
 it.each(['','/example','.example','example.','exam;ple','example.com/org','example-.org','example.org-','hello..example.com','hello-.example.com',
  'echo:80','echo:xx','echo:99999','http://echo','echo?offset=x','echo#fragment','echo\\target','echo%2ftarget','echo%252ftarget',
  '%2e%2e','..','.','echo@evil','echo\n','echo\r','echo\t','echo\0','écho','[::1]','::1','127.0.0.1','123','001.002.003.004'])('rejects non-name, IP, delimiter and encoding input: %j',host=>{
  expect(validServiceHostReference(ref(host))).toBe(false);expect(isServiceHostReferencePoint(point(host))).toBe(false);
 });
 it('keeps UUID name ambiguity, canonical selector shape and fixed UUID target parent restrictions',()=>{
  expect(validServiceHostReference(ref(parentId))).toBe(false);
  const host='m11-b7cac3c8-configuration-after-revision-fixture-20261018-upstream',p=point(host);
  for(const changed of [{...p,path:'/upstreams/other'},{...p,path:`/upstreams/${host}/targets`},{...p,entityId:parentId},{...p,required:true},
   {...p,secrets:true},{...p,query:{size:100}},{...p,serviceHostReference:{...p.serviceHostReference,serviceIds:[parentId,serviceId]}},
   {...p,serviceHostReference:{...p.serviceHostReference,extra:true}}])expect(isServiceHostReferencePoint(changed)).toBe(false);
  const targets:any={clusterId:serviceId,workspaceId:parentId,path:`/upstreams/${parentId}/targets`,kind:'collection',entityType:'targets',parentId,
   secrets:false,required:false,query:{size:100},serviceHostReference:ref(host)};
  expect(isServiceHostTargetCollection(targets)).toBe(true);
  expect(isServiceHostTargetCollection({...targets,parentId:host,path:`/upstreams/${host}/targets`})).toBe(false);
  expect(isServiceHostTargetCollection({...targets,query:{size:100,tags:'team:other'}})).toBe(false);
 });
});
