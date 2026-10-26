import {resolve,join,sep} from 'node:path';
import {assertProductionComposition} from './production-policy.mjs';

const fail=()=>{throw new Error('METRICS_OPERATION_ARGUMENTS_INVALID');};
const safePath=value=>{if(typeof value!=='string'||!value||value.length>4096||/[\r\n\u0000]/.test(value)||value.startsWith('-'))fail();return resolve(value);};
export const PRODUCTION_METRICS_COMPOSE_FILES=['docker-compose.yml','deploy/compose/compose.production.yml','deploy/compose/compose.metrics.yml','deploy/compose/compose.production-metrics.yml'];

/** Pure options: importing this module never reads deployment files or runs Docker. */
export function metricsOperationOptions(args,operation){
 if(!Array.isArray(args)||!['enroll','storage'].includes(operation))fail();
 const options={production:false,multicluster:false,rotate:false,captureTestReference:false,discover:false,selected:[],project:null,envFile:'.env',metricsDirectory:resolve('deploy/private/metrics'),output:operation==='storage'?resolve('artifacts/M5/metrics-storage-permissions.json'):null};
 const supplied=new Set();
 for(let index=0;index<args.length;index++){
  const arg=args[index];
  if(arg==='--production'){if(supplied.has(arg))fail();supplied.add(arg);options.production=true;}
  else if(arg==='--multicluster')options.multicluster=true;
  else if(arg==='--rotate-confirmed'&&operation==='enroll')options.rotate=true;
  else if(arg==='--test-private-reference'&&operation==='enroll')options.captureTestReference=true;
  else if(arg==='--discover'&&operation==='enroll')options.discover=true;
  else if(typeof arg==='string'&&arg.startsWith('--cluster=')&&operation==='enroll')options.selected.push(arg.slice(10));
  else if(['--project','--env-file','--metrics-directory','--output'].includes(arg)){
   if(supplied.has(arg)||typeof args[index+1]!=='string')fail();supplied.add(arg);const value=args[++index];
   if(arg==='--project'){if(!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(value))fail();options.project=value;}
   else if(arg==='--env-file')options.envFile=safePath(value);
   else if(arg==='--metrics-directory')options.metricsDirectory=safePath(value);
   else options.output=safePath(value);
  }else fail();
 }
 if(!options.production){if([...supplied].some(arg=>arg!=='--production'))fail();return options;}
 if(options.multicluster||options.captureTestReference||!options.project||['kongos-console','kongpilot-console'].includes(options.project)||!['--env-file','--metrics-directory','--output'].every(arg=>supplied.has(arg)))fail();
 if(options.output===options.envFile||options.output===options.metricsDirectory||options.output.startsWith(options.metricsDirectory+sep)||options.envFile===options.metricsDirectory||options.envFile.startsWith(options.metricsDirectory+sep))fail();
 return options;
}

export function metricsComposeArguments(options,operation){
 if(options.production)return ['--host=unix:///var/run/docker.sock','compose','--project-name',options.project,'--env-file',options.envFile,...PRODUCTION_METRICS_COMPOSE_FILES.flatMap(path=>['-f',path]),'--profile','observability'];
 return ['compose','--env-file','.env',...(options.multicluster?['--env-file','.env.multicluster']:[]),'-f','docker-compose.yml','-f','deploy/compose/compose.development.yml',...(options.multicluster?['-f','deploy/compose/compose.multicluster-test.yml','--profile','multicluster-test']:[]),...(operation==='storage'?['-f','deploy/compose/compose.metrics.yml','--profile','observability']:[])];
}

export function metricsOperationEnvironment(options,parent){
 if(!options.production)return parent;
 const env={...parent,KONGOS_METRICS_DIRECTORY:options.metricsDirectory};
 for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];
 return env;
}

/** Validate effective Compose facts in RAM; never serialize environment or secrets. */
export function productionMetricsConfiguration(options,config){
 const invalid=()=>{throw new Error('METRICS_PRODUCTION_CONFIGURATION_INVALID');};
 if(!options.production||!config||config.name!==options.project||!config.services||!config.volumes)invalid();
 const api=config.services['console-api'],prom=config.services.prometheus,collector=config.services['telemetry-collector'];
 if(!api||!prom||!collector||api.environment?.NODE_ENV!=='production'||String(api.environment?.COOKIE_SECURE)!=='true')invalid();
 if([api,prom,collector].some(s=>s.network_mode))invalid();
 const volume=prom.volumes?.find(m=>m.target==='/prometheus');const definition=volume&&config.volumes[volume.source];
 if(!volume||volume.type!=='volume'||!definition||definition.external===true||typeof definition.name!=='string'||!definition.name.startsWith(options.project+'_')||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(definition.name))invalid();
 const material=(service,target,source)=>service.volumes?.some(m=>m.type==='bind'&&m.target===target&&m.read_only===true&&resolve(m.source)===source);
 if(!material(prom,'/etc/prometheus',join(options.metricsDirectory,'prometheus'))||!material(collector,'/run/kongos-metrics',join(options.metricsDirectory,'collector')))invalid();
 if(collector.volumes?.some(m=>m.type==='bind'&&m.target==='/opt/kongos-collector')||api.volumes?.some(m=>m.type==='bind'&&m.target==='/app/apps/console-api/dist'))invalid();
 if(typeof api.image!=='string'||!api.image||/[\r\n\u0000]/.test(api.image))invalid();
 const policy=assertProductionComposition(config,{project:options.project,repository:process.cwd(),observability:true,gitops:false});
 return {project:config.name,prometheusVolume:definition.name,helperImage:api.image,materialDirectoryMatched:true,productionRuntimeConfigured:true,productionContractValid:policy.productionContractValid,runtimeVerified:policy.runtimeVerified};
}
