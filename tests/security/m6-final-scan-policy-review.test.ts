import {describe,expect,it,vi} from 'vitest';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {parseEnv} from 'node:util';
import ts from 'typescript';
import {assertFinalM6Evidence,finalM6RuntimeLogAdapter,finalM6RuntimeLogsPassed,finalM6SecretForms} from './lib/m6-final-scan-policy.mjs';
import {capturedPrivateSecrets,fixtureRuns} from './lib/m6-fixture-runs.mjs';

const serviceNames=['kong','kong-secondary','kong-portal','console-api','console-web','portal-web','telemetry-collector'];
const logs=()=>({allPassed:true,rawLogsPublished:false,services:serviceNames.map(service=>({service,knownSecretDetected:false}))});
const reference=()=>({phase:'cleanup-complete',testTag:'m6-isolated-offline',fixtures:[],secrets:['offline-new-browser-issued-key'],liveStartedAt:'2026-10-11T04:00:00.000Z',tokens:[{purpose:'collector_ingest',token:'offline-current-ingest-token'}],portalTestTargets:{primary:{id:randomUUID(),adminUrl:'http://kong-portal-admin-endpoint:8001',proxyOrigin:'http://127.0.0.1:10000'}},browserKeyScan:{phase:'scanner-material-verified',credentialId:randomUUID()}});
const evidence=()=>({http:{passed:1057,failed:0},browser:{passed:1,failed:0},manual:{allPassed:true},cleanup:{allPassed:true},material:{allPassed:true,keyValuePublished:false,keyRetainedPrivately:true,audited:true,scannerRevealPosts:1,nativeWrites:0}});
function runFinal(options:{failure?:string;reference?:any;evidence?:any;logs?:any;leaks?:string[];collectError?:boolean;released?:boolean}={}){
 const events:string[]=[],r=options.reference??reference(),e=options.evidence??evidence(),privatePath='/offline/private-reference.json',reportPath='artifacts/M6/runtime-secret-artifact-scan.json';
 const files=new Map<string,string>(),descriptors=new Map<number,{path:string;directory:boolean;generation:number}>();let nextFd=10,currentGeneration=0;
 const reportNames:any={'security-live':e.http,'browser-verification':e.browser,'UI-review':e.manual,'failed-fixture-cleanup':e.cleanup,'browser-issued-key-scan-material':e.material};
 files.set(privatePath,'offline-reference-not-read');files.set('/tmp/kongos-m6-continuation.json','offline-continuation');
 for(const [name,value]of Object.entries(reportNames))files.set(`artifacts/M6/${name}.json`,JSON.stringify(value));
 for(const path of ['.env','.env.multicluster','.env.portal','.env.portal-acceptance'])files.set(path,'OFFLINE_SECRET=offline-environment-material\n');
 const fail=(stage:string,generation:number)=>{if(options.failure===`${stage}-${generation}`)throw Error('OFFLINE_IO_FAILURE');};
 const scan=vi.fn((secrets:string[],paths:string[])=>{events.push('artifact-scan');return{scannedFiles:paths.length,embeddedFiles:0,leaks:options.leaks??[]};});
 const collect=vi.fn((h:any)=>{events.push('runtime-logs-after-cleanup');h.requireLive();if(options.collectError)throw Error('OFFLINE_DRIVER_DETAIL_NOT_PUBLIC');return options.logs??logs();});
 const removed:string[]=[];
 const sandbox:any={Buffer,parseEnv,process:{argv:['node','offline-final',...(options.released===false?[]:['--evidence-complete'])],pid:4242,exitCode:undefined},console:{log:vi.fn()},
  privateReference:vi.fn(()=>{events.push('private-reference-in-memory');return r;}),M6_REFERENCE:privatePath,fixtureRuns,capturedPrivateSecrets,
  assertFinalM6Evidence,finalM6SecretForms,finalM6RuntimeLogAdapter,finalM6RuntimeLogsPassed,
  existsSync:(path:string)=>files.has(path)||/^(apps\/.*\/dist|packages\/contracts\/dist|test-results|playwright-report|artifacts\/playwright-(results|report))$/.test(path),
  readFileSync:(path:string)=>{if(path===privatePath)throw Error('PRIVATE_FIXTURE_DIRECT_READ_FORBIDDEN');if(!files.has(path))throw Error('UNKNOWN_OFFLINE_FILE');return files.get(path);},
  readdirSync:()=>[{name:'offline-compiled-or-report.js',isDirectory:()=>false}],
  execFileSync:(command:string,args:string[])=>{expect(command).toBe('git');expect(args).toEqual(['ls-files','-z','--cached','--others','--exclude-standard']);return 'offline-source.ts\0offline-untracked.ts\0';},
  collectEnvironmentSecrets:(values:Record<string,string>)=>Object.values(values),findSecretArtifacts:scan,verifyM6RuntimeLogs:collect,
  openSync:(path:string,flags:string,mode?:number)=>{const directory=flags==='r';let generation=currentGeneration;if(!directory){expect(flags).toBe('wx');expect(mode).toBe(0o644);const match=/\.4242\.(\d+)\.tmp$/.exec(path);expect(match).toBeTruthy();generation=Number(match![1]);currentGeneration=generation;fail('open',generation);if(files.has(path))throw Error('TEMP_ALREADY_EXISTS');files.set(path,'');}events.push(`${directory?'open-directory':'open-file'}-${generation}`);const fd=nextFd++;descriptors.set(fd,{path,directory,generation});return fd;},
  writeFileSync:(fd:number,body:string)=>{const item=descriptors.get(fd)!;fail('write',item.generation);files.set(item.path,body);events.push('write-'+item.generation);},
  fsyncSync:(fd:number)=>{const item=descriptors.get(fd)!;fail(item.directory?'dir-sync':'file-sync',item.generation);events.push(`${item.directory?'dir-sync':'file-sync'}-${item.generation}`);},
  closeSync:(fd:number)=>{const item=descriptors.get(fd)!;events.push('close-'+item.generation);descriptors.delete(fd);},
  renameSync:(from:string,to:string)=>{const generation=currentGeneration;fail('rename',generation);expect(to).toBe(reportPath);files.set(to,files.get(from)!);files.delete(from);events.push('rename-'+generation);},
  rmSync:(path:string)=>{expect([privatePath,'/tmp/kongos-m6-continuation.json']).toContain(path);events.push('remove-'+path);removed.push(path);files.delete(path);},
 };
 const source=readFileSync('tests/security/finalize-m6-secret-scan.mjs','utf8'),tree=ts.createSourceFile('final.mjs',source,ts.ScriptTarget.ES2022,true,ts.ScriptKind.JS);
 const body=tree.statements.filter(s=>!ts.isImportDeclaration(s)).map(s=>s.getText(tree)).join('\n');let error;
 try{runInNewContext(body,sandbox);}catch(value){error=value;}
 return{r,e,events,files,removed,scan,collect,sandbox,error,privatePath,reportPath};
}
function actualRuntimeLogs(options:{stderrLeak?:boolean;collectionError?:boolean;missingPrimary?:boolean;cleanupPending?:boolean}={}){
 const r:any=reference();if(options.missingPrimary)delete r.portalTestTargets;if(options.cleanupPending)r.phase='HTTP-complete';
 const checks:any[]=[],h=finalM6RuntimeLogAdapter(r,['offline-new-browser-issued-key'],checks),commands:any[]=[],spawns:any[]=[],ids=new Map<string,string>();let collected=0;
 const exec=vi.fn((_command:string,args:string[])=>{commands.push(args);if(args[0]==='compose')return'a'.repeat(64);if(args[0]==='inspect')return'offline-project';const service=args.find(a=>a.startsWith('label=com.docker.compose.service='))!.split('=').at(-1)!;const id=createHash('sha256').update(service).digest('hex');ids.set(id,service);return id;});
 const spawn=vi.fn((_command:string,args:string[])=>{spawns.push(args);collected++;expect(args.slice(0,3)).toEqual(['logs','--since',r.liveStartedAt]);const service=ids.get(args[3]);return{status:options.collectionError&&collected===3?1:0,stdout:'offline-safe-stdout',stderr:options.stderrLeak&&service==='kong-portal'?'offline-new-browser-issued-key':'offline-safe-stderr'};});
 const source=readFileSync('tests/security/lib/m6-runtime-logs.mjs','utf8'),tree=ts.createSourceFile('logs.mjs',source,ts.ScriptTarget.ES2022,true,ts.ScriptKind.JS),declaration=tree.statements.find(s=>ts.isFunctionDeclaration(s)&&s.name?.text==='verifyM6RuntimeLogs')!;
 const code=declaration.getText(tree).replace(/^export\s+/,'')+'\nverifyM6RuntimeLogs;';const actual=runInNewContext(code,{Buffer,execFileSync:exec,spawnSync:spawn});let result,error;
 try{result=actual(h);}catch(value){error=value;}return{result,error,checks,commands,spawns,r};
}

describe('independent exact final evidence and seven fresh runtime log coverage',()=>{
 it.each([undefined,null,NaN,Infinity,-1,0,1.5,'1057'])('missing or invalid HTTP successful counter %s cannot release deletion',passed=>{const e:any=evidence();e.http.passed=passed;expect(()=>assertFinalM6Evidence(reference(),e)).toThrow('FINAL_M6_EVIDENCE_INCOMPLETE');});
 it('final log proof requires exactly all seven service identities, not a six-service fallback',()=>{const six=logs();six.services=six.services.filter(r=>r.service!=='kong-portal');expect(finalM6RuntimeLogsPassed(six)).toBe(false);expect(finalM6RuntimeLogsPassed(logs())).toBe(true);});
 it.each(['duplicate','foreign','unknown-leak','raw-output','missing-allPassed'])('final seven-service aggregation rejects %s',fault=>{const r:any=logs();if(fault==='duplicate')r.services[2]={...r.services[0]};if(fault==='foreign')r.services[2].service='foreign-kong';if(fault==='unknown-leak')delete r.services[2].knownSecretDetected;if(fault==='raw-output')r.rawLogsPublished=true;if(fault==='missing-allPassed')delete r.allPassed;expect(finalM6RuntimeLogsPassed(r)).toBe(false);});
 it('actual log collector reads fresh stdout AND stderr for seven fixed services after cleanup',()=>{const f=actualRuntimeLogs();expect(f.error).toBeUndefined();expect(f.spawns).toHaveLength(7);expect(f.result.services.map((r:any)=>r.service)).toEqual(serviceNames);expect(finalM6RuntimeLogsPassed(f.result)).toBe(true);expect(f.result.rawLogsPublished).toBe(false);});
 it('actual C3 stderr canary is rejected without placing the log or token in proof output',()=>{const f=actualRuntimeLogs({stderrLeak:true});expect(f.error).toBeTruthy();expect(f.spawns).toHaveLength(7);expect(JSON.stringify(f.checks)).not.toContain('offline-new-browser-issued-key');expect(f.checks.some(c=>c.passed===false)).toBe(true);});
 it('actual collection failure cannot become a successful fresh log proof',()=>{const f=actualRuntimeLogs({collectionError:true});expect(f.error).toBeTruthy();expect(f.result).toBeUndefined();expect(f.spawns).toHaveLength(3);});
 it('actual legacy missing-primary six-service log result fails final aggregation',()=>{const f=actualRuntimeLogs({missingPrimary:true});expect(f.error).toBeUndefined();expect(f.spawns).toHaveLength(6);expect(finalM6RuntimeLogsPassed(f.result)).toBe(false);});
 it('no actual collector command is attempted before cleanup-complete',()=>{const f=actualRuntimeLogs({cleanupPending:true});expect(f.error).toBeTruthy();expect(f.commands).toHaveLength(0);expect(f.spawns).toHaveLength(0);});
});

describe('actual final runner body in a memory-only file and process sandbox',()=>{
 it('requires explicit evidence-complete handoff before reading the private fixture',()=>{const f=runFinal({released:false});expect(f.error).toBeTruthy();expect(f.events).toHaveLength(0);expect(f.removed).toHaveLength(0);});
 it('uses current raw/JSON/URI/base64 key and Basic telemetry forms in source compiled and untracked artifact scan',()=>{
  const f=runFinal();expect(f.error).toBeUndefined();const [tokens,paths]=f.scan.mock.calls[0],key=f.r.secrets[0],ingest=Buffer.from('kongos:'+f.r.tokens[0].token).toString('base64');
  for(const value of [key,Buffer.from(key).toString('base64'),ingest,'Basic '+ingest,Buffer.from('Basic '+ingest).toString('base64'),'offline-environment-material'])expect(tokens).toContain(value);
  for(const path of ['offline-source.ts','offline-untracked.ts','apps/portal-web/dist/offline-compiled-or-report.js','apps/console-api/dist/offline-compiled-or-report.js','test-results/offline-compiled-or-report.js'])expect(paths).toContain(path);expect(f.events.indexOf('artifact-scan')).toBeLessThan(f.events.indexOf('runtime-logs-after-cleanup'));
 });
 it('durably syncs first complete report before removing only the two allowed test captures, then updates removed flag atomically',()=>{
  const f=runFinal();expect(f.error).toBeUndefined();expect(f.removed).toEqual([f.privatePath,'/tmp/kongos-m6-continuation.json']);const remove=f.events.indexOf('remove-'+f.privatePath);expect(f.events.indexOf('dir-sync-1')).toBeLessThan(remove);expect(f.events.indexOf('rename-2')).toBeGreaterThan(remove);expect(JSON.parse(f.files.get(f.reportPath)!)).toMatchObject({allPassed:true,privateReferenceRemoved:true,secretValuesPublished:false,base64SecretFormsIncluded:true});expect(f.sandbox.process.exitCode).toBe(0);
 });
 it.each(['open','write','file-sync','rename','dir-sync'])('first %s failure never deletes private captured material',failure=>{const f=runFinal({failure:failure+'-1'});expect(f.error).toBeTruthy();expect(f.removed).toHaveLength(0);expect(f.files.has(f.privatePath)).toBe(true);});
 it.each(['open','write','file-sync','rename'])('second %s failure preserves the first complete PASS proof after private material was deleted',failure=>{const f=runFinal({failure:failure+'-2'});expect(f.error).toBeTruthy();expect(f.removed).toContain(f.privatePath);expect(JSON.parse(f.files.get(f.reportPath)!)).toMatchObject({allPassed:true,privateReferenceRemoved:false,secretValuesPublished:false});});
 it.each(['six-services','artifact-leak','collection-error','service-leak'])('%s publishes a safe failed proof and retains private material',failure=>{
  const r:any=logs();if(failure==='six-services')r.services=r.services.filter((s:any)=>s.service!=='kong-portal');if(failure==='service-leak')r.services[2].knownSecretDetected=true;
  const f=runFinal({logs:r,leaks:failure==='artifact-leak'?['offline-public-report']:[],collectError:failure==='collection-error'});expect(f.error).toBeUndefined();expect(f.removed).toHaveLength(0);expect(f.files.has(f.privatePath)).toBe(true);const report=f.files.get(f.reportPath)!;expect(JSON.parse(report).allPassed).toBe(false);expect(report).not.toContain('OFFLINE_DRIVER_DETAIL_NOT_PUBLIC');expect(report).not.toContain(f.r.secrets[0]);expect(f.sandbox.process.exitCode).toBe(1);
 });
 it('missing scanner material evidence fails before artifact scanning or runtime collection and preserves private fixture',()=>{const e:any=evidence();e.material.allPassed=false;const f=runFinal({evidence:e});expect(f.error).toBeTruthy();expect(f.scan).not.toHaveBeenCalled();expect(f.collect).not.toHaveBeenCalled();expect(f.removed).toHaveLength(0);});
 it('current cleanup phase must already be complete before any source or runtime scan occurs',()=>{const r=reference();r.phase='HTTP-complete';const f=runFinal({reference:r});expect(f.error).toBeTruthy();expect(f.scan).not.toHaveBeenCalled();expect(f.collect).not.toHaveBeenCalled();expect(f.removed).toHaveLength(0);});
});
