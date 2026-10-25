import {describe,it,expect} from 'vitest';
import {resolve} from 'node:path';
// Pure functions: no current env/private files, Docker, DB or material generation.
// @ts-expect-error deployment module is JavaScript.
import {metricsOperationOptions,metricsComposeArguments,metricsOperationEnvironment,productionMetricsConfiguration,PRODUCTION_METRICS_COMPOSE_FILES} from '../../deploy/scripts/metrics-operation-options.mjs';

const args=['--production','--project','kongos-acceptance','--env-file','/synthetic/production.env','--metrics-directory','/synthetic/metrics','--output','/synthetic/reports/enrollment.json'];
const options=()=>metricsOperationOptions(args,'enroll');
const valid=()=>{
 const hard={image:'kongos/console-api@sha256:'+'a'.repeat(64),user:'1000:1000',read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true']};
 const web=(name:string)=>({...structuredClone(hard),user:'101:101',networks:name==='console'?{frontend:{}}:{'portal-edge':{},'portal-entry':{}},ports:[{target:8443,published:name==='console'?'18443':'19443'}],volumes:[{type:'bind',source:resolve(`deploy/nginx/${name}-production.conf`),target:'/etc/nginx/conf.d/default.conf',read_only:true},{type:'bind',source:`/synthetic/tls/${name}`,target:'/run/kongos-tls',read_only:true}]});
 return {name:'kongos-acceptance',services:{'kong-db':{},'kong-migrations':{},kong:{ports:[{target:8000}]},'console-db':{},redis:{},'console-migrations':structuredClone(hard),'console-web':web('console'),'portal-web':web('portal'),'console-api':{...structuredClone(hard),networks:{frontend:{},'kong-admin':{},'console-storage':{},telemetry:{}},environment:{NODE_ENV:'production',COOKIE_SECURE:'true',TRUST_PROXY:'1',PUBLIC_ORIGINS:'https://console.example.test:18443',PORTAL_PUBLIC_ORIGINS:'https://portal.example.test:19443'}},prometheus:{volumes:[{type:'volume',source:'prometheus_data',target:'/prometheus'},{type:'bind',source:'/synthetic/metrics/prometheus',target:'/etc/prometheus',read_only:true}]},'telemetry-collector':{...structuredClone(hard),networks:{telemetry:{},'proxy-edge':{},observability:{}},volumes:[{type:'bind',source:'/synthetic/metrics/collector',target:'/run/kongos-metrics',read_only:true}]}},networks:{'kong-admin':{internal:true},'kong-storage':{internal:true},'console-storage':{internal:true},telemetry:{internal:true}},volumes:{prometheus_data:{name:'kongos-acceptance_prometheus_data'}}};
};

describe('explicit production metrics operation arguments',()=>{
 it('preserves both old development compose invocations and material/output defaults',()=>{
  const plain=metricsOperationOptions(['--discover'],'enroll');
  expect(metricsComposeArguments(plain,'enroll')).toEqual(['compose','--env-file','.env','-f','docker-compose.yml','-f','deploy/compose.development.yml']);
  expect(plain.metricsDirectory.endsWith('/deploy/private/metrics')).toBe(true);expect(plain.output).toBeNull();
  const multi=metricsOperationOptions(['--multicluster'],'storage');
  expect(metricsComposeArguments(multi,'storage')).toEqual(['compose','--env-file','.env','--env-file','.env.multicluster','-f','docker-compose.yml','-f','deploy/compose.development.yml','-f','deploy/compose.multicluster-test.yml','--profile','multicluster-test','-f','deploy/compose.metrics.yml','--profile','observability']);
  expect(multi.output.endsWith('/artifacts/M5/metrics-storage-permissions.json')).toBe(true);
 });
 it('uses only the four production files and the explicit local daemon/project/env',()=>{
  const compose=metricsComposeArguments(options(),'enroll');
  expect(compose.slice(0,6)).toEqual(['--host=unix:///var/run/docker.sock','compose','--project-name','kongos-acceptance','--env-file','/synthetic/production.env']);
  expect(compose.filter((_:string,i:number)=>compose[i-1]==='-f')).toEqual(PRODUCTION_METRICS_COMPOSE_FILES);
  expect(JSON.stringify(compose)).not.toMatch(/development|multicluster-test|portal-acceptance/);
 });
 it.each(['--project','--env-file','--metrics-directory','--output'])('rejects missing explicit production field %s',(key)=>{
  const omitted=[...args],i=omitted.indexOf(key);omitted.splice(i,2);expect(()=>metricsOperationOptions(omitted,'enroll')).toThrow('METRICS_OPERATION_ARGUMENTS_INVALID');
 });
 it.each(['--multicluster','--test-private-reference','--arbitrary-overlay'])('rejects production test/unknown flag %s',(flag)=>expect(()=>metricsOperationOptions([...args,flag],'enroll')).toThrow());
 it('rejects duplicate selectors, canonical old project, malformed names and cross-secret output destinations',()=>{
  expect(()=>metricsOperationOptions([...args,'--project','other'],'enroll')).toThrow();
  for(const project of ['kongos-console','UPPER','../old','--host','bad\nproject']){const a=[...args];a[a.indexOf('--project')+1]=project;expect(()=>metricsOperationOptions(a,'enroll')).toThrow();}
  for(const output of ['/synthetic/production.env','/synthetic/metrics','/synthetic/metrics/report.json']){const a=[...args];a[a.indexOf('--output')+1]=output;expect(()=>metricsOperationOptions(a,'enroll')).toThrow();}
  expect(()=>metricsOperationOptions(['--project','prod','--discover'],'enroll')).toThrow();
 });
 it('keeps proxy/CA/Docker auth, clears only conflicting Docker selectors and passes a public material path',()=>{
  const parent={DOCKER_HOST:'remote',DOCKER_CONTEXT:'remote',DOCKER_TLS:'1',DOCKER_TLS_VERIFY:'1',DOCKER_CERT_PATH:'/synthetic/certs',DOCKER_CONFIG:'/synthetic/docker',HTTPS_PROXY:'synthetic-proxy',NODE_EXTRA_CA_CERTS:'/synthetic/ca',OTHER:'keep'};
  const child=metricsOperationEnvironment(options(),parent);expect(child).toEqual({DOCKER_CONFIG:'/synthetic/docker',HTTPS_PROXY:'synthetic-proxy',NODE_EXTRA_CA_CERTS:'/synthetic/ca',OTHER:'keep',KONGOS_METRICS_DIRECTORY:'/synthetic/metrics'});expect(parent.DOCKER_HOST).toBe('remote');
  expect(metricsOperationEnvironment(metricsOperationOptions(['--discover'],'enroll'),parent)).toBe(parent);
 });
});

describe('effective production Compose boundaries without Docker',()=>{
 it('derives the actual new-project volume and only returns safe facts',()=>{
  const config=valid();(config.services['console-api'].environment as any).AUTH_PROVIDERS_JSON='SYNTHETIC_CONFIG_CANARY';
  const facts=productionMetricsConfiguration(options(),config);expect(facts.prometheusVolume).toBe('kongos-acceptance_prometheus_data');expect(facts.helperImage).toBe(config.services['console-api'].image);expect(JSON.stringify(facts)).not.toContain('SYNTHETIC_CONFIG_CANARY');
  expect(facts).toMatchObject({productionContractValid:true,runtimeVerified:false,productionRuntimeConfigured:true});
 });
 it('rejects wrong actual project, old/foreign/external volume and volume/bind substitution',()=>{
  const changes=[(c:any)=>c.name='kongos-console',(c:any)=>c.volumes.prometheus_data.name='kongos-console_prometheus_data',(c:any)=>c.volumes.prometheus_data.external=true,(c:any)=>c.services.prometheus.volumes[0].type='bind',(c:any)=>delete c.volumes.prometheus_data];
  for(const change of changes){const c=valid();change(c);expect(()=>productionMetricsConfiguration(options(),c)).toThrow('METRICS_PRODUCTION_CONFIGURATION_INVALID');}
 });
 it('rejects development cookies, host networking, source bind and wrong/writable credential directories',()=>{
  const changes=[(c:any)=>c.services['console-api'].environment.NODE_ENV='development',(c:any)=>c.services['console-api'].environment.COOKIE_SECURE='false',(c:any)=>c.services['console-api'].network_mode='host',(c:any)=>c.services.prometheus.network_mode='container:old',(c:any)=>c.services.prometheus.volumes[1].source='/synthetic/old/prometheus',(c:any)=>c.services['telemetry-collector'].volumes[0].read_only=false,(c:any)=>c.services['telemetry-collector'].volumes.push({type:'bind',source:'/synthetic/src',target:'/opt/kongos-collector',read_only:true}),(c:any)=>c.services['console-api'].volumes=[{type:'bind',target:'/app/apps/console-api/dist'}]];
  for(const change of changes){const c=valid();change(c);expect(()=>productionMetricsConfiguration(options(),c)).toThrow();}
 });
 it('delegates whole production policy before any operation while preserving safe errors',()=>{
  const changes=[(c:any)=>c.services['console-api'].environment.PORTAL_PUBLIC_ORIGINS='https://console.example.test:19443',(c:any)=>c.services['console-web'].user='0:0',(c:any)=>c.services.kong.ports.push({target:8001}),(c:any)=>c.services['console-migrations'].image='foreign:release',(c:any)=>c.services['telemetry-collector'].networks['kong-admin']={}];
  for(const change of changes){const c=valid();(c.services['console-api'].environment as any).APP_SECRET='SYNTHETIC_POLICY_CANARY';change(c);expect(()=>productionMetricsConfiguration(options(),c)).toThrow('PRODUCTION_COMPOSITION_INVALID');try{productionMetricsConfiguration(options(),c);}catch(e:any){expect(e.message).not.toContain('SYNTHETIC_POLICY_CANARY');}}
 });
});
