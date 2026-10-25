import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {chmodSync,existsSync,lstatSync,mkdtempSync,readFileSync,readdirSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureNotificationRepairSnapshot} from './verify-m7-notification-preference-repair-continuity.mjs';
import {outboxRepairChecks} from './verify-m7-outbox-repair-continuity.mjs';

const OUTPUT='artifacts/M7/observation-policy-cli-installation.json',READOUTPUT='artifacts/M7/observation-policy-cli-read-chain.json';
const FILE='apps/console-api/dist/infrastructure/event-observe-test.js';
const source='apps/console-api/src/infrastructure/event-observe-test.ts',expected='17d3a2c54ff525c56be05ad91546e449034dcb318232198824c01cd13340216e';
const digest=value=>createHash('sha256').update(value).digest('hex');
const docker=(args,input)=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{encoding:'utf8',input,stdio:['pipe','pipe','pipe'],timeout:60000});
function otherDist(path='apps/console-api/dist'){return readdirSync(path,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(item=>{const file=path+'/'+item.name;if(item.isSymbolicLink())throw Error('CLI_DIST_INVALID');return item.isDirectory()?otherDist(file):file===FILE?[]:[{path:file,sha256:digest(readFileSync(file))}];});}
function snapshot(){return{...captureNotificationRepairSnapshot(),otherDist:otherDist(),cliSHA256:digest(readFileSync(FILE))};}
function install(){
 if(existsSync(OUTPUT))throw Error('CLI_INSTALLATION_SEALED');
 if(digest(readFileSync(source))!==expected)throw Error('CLI_SOURCE_CHANGED');
 const before=snapshot(),result={allPassed:null,before,sourceSHA256:expected,commands:[],scope:'full isolated temporary compile; only auxiliary CLI JS installed; no API restart/other dist/environment/material/migration/static/business/native write'};
 writeFileSync(OUTPUT,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
 let directory,temporary;
 try{
  directory=mkdtempSync(resolve(tmpdir(),'kongos-m7-observation-policy-compile-'));chmodSync(directory,0o700);
  execFileSync(process.execPath,[resolve('node_modules/typescript/bin/tsc'),'-p',resolve('apps/console-api/tsconfig.json'),'--outDir',directory],{stdio:['pipe','pipe','pipe'],timeout:60000});result.commands.push({name:'isolated-complete-api-compilation',exitCode:0});
  if(digest(readFileSync(source))!==expected)throw Error('CLI_SOURCE_CHANGED');
  const built=readFileSync(resolve(directory,'infrastructure/event-observe-test.js'));temporary=FILE+'.observation-policy-installing';
  writeFileSync(temporary,built,{flag:'wx',mode:0o600});chmodSync(temporary,lstatSync(FILE).mode&0o777);renameSync(temporary,FILE);temporary=undefined;
  result.commands.push({name:'auxiliary-js-only-atomic-install',exitCode:0});
  const after=snapshot(),checks=outboxRepairChecks(before,after).filter(c=>c.name!=='API process restarted after compiled code');
  checks.push({name:'all container processes including API remain exact',passed:JSON.stringify(before.services)===JSON.stringify(after.services)});
  checks.push({name:'every other installed API dist byte remains exact',passed:JSON.stringify(before.otherDist)===JSON.stringify(after.otherDist)});
  checks.push({name:'Console and Portal static bytes remain exact',passed:JSON.stringify(before.consoleAssets)===JSON.stringify(after.consoleAssets)&&JSON.stringify(before.portalAssets)===JSON.stringify(after.portalAssets)});
  checks.push({name:'only new auxiliary CLI compiled JS installed',passed:after.cliSHA256===digest(built)&&after.cliSHA256!==before.cliSHA256});
  Object.assign(result,{after,checks,allPassed:checks.every(c=>c.passed)});
 }catch{result.allPassed=false;result.errorCode='CLI_ISOLATED_COMPILE_OR_INSTALL_FAILED';}
 finally{if(temporary&&existsSync(temporary))rmSync(temporary);if(directory)rmSync(directory,{recursive:true,force:true});writeFileSync(OUTPUT,JSON.stringify(result,null,2)+'\n');}
 console.log(JSON.stringify({allPassed:result.allPassed,checks:result.checks?.length??0,oldCliSHA256:before.cliSHA256,newCliSHA256:result.after?.cliSHA256??null,otherDistCount:before.otherDist.length}));if(!result.allPassed)process.exitCode=1;
}
export const OBSERVATION_POLICY_READ_PROGRAM=String.raw`
process.env.EVENT_DELIVERY_WORKER_ENABLED='false';process.env.EVENT_OUTBOX_WORKER_ENABLED='false';process.env.SKIP_MIGRATIONS='true';process.env.DEFAULT_KONG_ADMIN_URL='';process.env.METRICS_BRIDGE_ENABLED='false';
const {X509Certificate}=require('node:crypto');const {NestFactory}=require('@nestjs/core');
const base='/app/apps/console-api/dist/';const {AppModule}=require(base+'app.module');
const {EventObserverService}=require(base+'modules/event-observers/event-observer.service');const{EntityIndexService}=require(base+'modules/entities/entity-index.service');const{AuditExportService}=require(base+'modules/audit/audit-export.service');
const{KongExecutionContextService}=require(base+'infrastructure/kong/execution-context.service');const{KongService}=require(base+'infrastructure/kong/kong.service');const{WorkspaceResolverService}=require(base+'modules/workspaces/workspace-resolver.service');const{initializeObservationPolicy,safeObservationFailure}=require(base+'infrastructure/event-observe-test');
for(const type of[EventObserverService,EntityIndexService,AuditExportService])type.prototype.onModuleInit=()=>undefined;
(async()=>{if(process.env.NODE_ENV!=='development')throw Error();const app=await NestFactory.createApplicationContext(AppModule,{logger:false,abortOnError:false});try{initializeObservationPolicy(app);const cid='dff45535-ed8d-4851-b7a6-6376feac7f59',id='dc480bde-b580-4744-89e8-4c1d9f317ab2',path='/certificates/'+id,kong=app.get(KongService),execution=app.get(KongExecutionContextService),resolver=app.get(WorkspaceResolverService);const proof=await execution.runEventObservationRead(cid,['/',path],async()=>{const root=await kong.request(cid,'GET','/'),object=await kong.request(cid,'GET',path);const cert=new X509Certificate(object.cert),membership=await resolver.classify(cid,object.tags);return{version:root.version==='1.5.1'?'1.5.1':null,idMatches:object.id===id,x509Parsed:true,expiresAt:new Date(cert.validTo).toISOString(),membershipNondefault:membership.state==='resolved'&&membership.workspace?.id==='4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5'};});console.log(JSON.stringify({allPassed:proof.version==='1.5.1'&&proof.idMatches&&proof.x509Parsed&&proof.membershipNondefault,...proof,rawPublished:false,authorityObservations:0,sqlEnqueues:0,nativeWrites:0,scope:'read-chain self-test only; not warning acceptance'}));}finally{await app.close();}})().catch(error=>{console.log(JSON.stringify({allPassed:false,stage:'fixed-read-chain',...safeObservationFailure(error),rawPublished:false}));process.exitCode=1;});
`;
function readChain(){
 if(existsSync(READOUTPUT))throw Error('CLI_READ_CHAIN_SEALED');
 const installed=JSON.parse(readFileSync(OUTPUT,'utf8'));if(installed.allPassed!==true)throw Error('CLI_INSTALLATION_NOT_VERIFIED');
 const api=installed.after.services.find(s=>s.name==='console-api');
 let raw;try{raw=docker(['exec','-i',api.id,'node','-'],OBSERVATION_POLICY_READ_PROGRAM);}catch(error){if(error.status!==1||typeof error.stdout!=='string')throw Error('CLI_READ_CHAIN_EXEC_FAILED');raw=error.stdout;}
 if(Buffer.byteLength(raw)>4096)throw Error('CLI_READ_CHAIN_RESPONSE_INVALID');
 const proof=JSON.parse(raw);writeFileSync(READOUTPUT,JSON.stringify({observedAt:new Date().toISOString(),...proof},null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(proof));if(!proof.allPassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try{if(process.argv[2]==='--install')install();else if(process.argv[2]==='--read-chain-fixed')readChain();else throw Error('CLI_INSTALL_ARGUMENT_INVALID');}catch{process.stderr.write('OBSERVATION_POLICY_CLI_INSTALL_OR_READ_FAILED; no raw errors printed.\n');process.exitCode=1;}
