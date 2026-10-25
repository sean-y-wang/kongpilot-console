// @ts-nocheck -- actual helper and actual inline ACK/dispose code in VM/RAM.
import {afterEach,describe,expect,it,vi} from 'vitest';
import {EventEmitter} from 'node:events';
import {mkdtempSync,readFileSync,openSync,writeSync,fsyncSync,closeSync,rmSync,constants} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {runInNewContext} from 'node:vm';
import {M8_COMPOSE,M8Harness,sha256} from './lib/m8-harness.mjs';

const toolHash='642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed';
const roots=new Set<string>();
afterEach(()=>{for(const root of roots)rmSync(root,{recursive:true,force:true});roots.clear();vi.useRealTimers();});

/** No actual env/current private path/process/network is touched. The fsync
 * file and directory are created here and contain only synthetic fixtures.
 * Both the parent helper and the emitted child ACK/finally source are real. */
function fixture(patch:any={},options:any={}){
 const root=mkdtempSync(join(tmpdir(),'kongos-m8-independent-private-output-'));roots.add(root);const file=join(root,'synthetic-ledger.json');
 const events:any[]=[],area={cid:randomUUID(),wid:randomUUID()},actor={user:{id:randomUUID()},sid:randomUUID()},originalActor=structuredClone(actor);
 const input={command:options.command??'sync',sessionId:randomUUID(),tokenSecret:'S'.repeat(43),stateYaml:'_format_version: "1.1"\nservices: []\n'},originalInput=structuredClone(input);
 const raw=Buffer.from('synthetic CLI private credential=ONLY_SOURCE_FIXTURE\n'),rawText=raw.toString('utf8');
 const result={command:input.command,toolBinarySha256:toolHash,toolVersion:'1.2.4',toolCommit:'8e68931',exitCode:0,
  timedOut:false,outputLimitReached:false,possibleUnknown:false,consoleJobSuccessProved:false,stderrBytes:raw.length,...patch};
 let rawSave=0,saveFailureTriggered=false,durableAtSpawn:any,durableAtAck:any,durableAtDispose:any;
 const disk=()=>JSON.parse(readFileSync(file,'utf8'));
 const h:any={state:{phase:'synthetic-ready',inFlight:null,requests:[],proxyChecks:[],cliIntents:[]},remember:vi.fn(),
  check:(v:any,label:string)=>{if(!v)throw Error(label);},assertWritable(){return M8Harness.prototype.assertWritable.call(h);},
  save(extra:any={}){
   Object.assign(h.state,extra);const intent=h.state.cliIntents.at(-1);if(intent?.rawCliStderr!==undefined){rawSave++;if(rawSave===options.failRawSave){saveFailureTriggered=true;events.push({type:'save-failed',rawSave});throw Error('SYNTHETIC_FSYNC_FAILED');}}
   const fd=openSync(file,constants.O_WRONLY|constants.O_CREAT|constants.O_TRUNC,0o600);try{writeSync(fd,JSON.stringify(h.state));fsyncSync(fd);}finally{closeSync(fd);}
   const dir=openSync(root,constants.O_RDONLY|constants.O_DIRECTORY);try{fsyncSync(dir);}finally{closeSync(dir);}
   events.push({type:'fsync',intent:structuredClone(intent)});
  }};
 const child:any=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin=new EventEmitter();
 const queued:string[]=[],pending:any[]= [];let closed=false;
 const push=(line:string)=>{if(pending.length)pending.shift()({value:line,done:false});else queued.push(line);};
 const lines={
  [Symbol.asyncIterator](){return{next:()=>queued.length?Promise.resolve({value:queued.shift(),done:false}):closed?Promise.resolve({done:true}):new Promise(resolve=>pending.push(resolve))};},
  close(){closed=true;while(pending.length)pending.shift()({done:true});}
 };
 child.stdin.write=vi.fn((text:string)=>{events.push({type:'stdin',text});push(text.replace(/\n$/,''));});
 child.stdin.end=vi.fn((text:string)=>{durableAtAck=disk();events.push({type:'ack',text});push(text.replace(/\n$/,''));});
 child.kill=vi.fn((signal:string)=>{events.push({type:'kill',signal});lines.close();return true;});
 const dispose=vi.fn(()=>{durableAtDispose=disk();events.push({type:'dispose'});raw.fill(0);});
 const runDeck=vi.fn(async(body:any,config:any)=>{events.push({type:'runDeck'});expect(body).toEqual(originalInput);expect(config).toEqual({origin:'http://console-web:8080'});return{safe:result,stderr:raw,dispose};});
 const spawn=vi.fn((program:string,args:string[],opts:any)=>{
  durableAtSpawn=disk();events.push({type:'spawn'});if(options.mutateAfterSpawn){input.stateYaml='caller mutation';input.command='diff';actor.sid=randomUUID();actor.user.id=randomUUID();}
  const code=args.at(-1).replace(/import\{[^}]*\}from'[^']*';/g,'');
  queueMicrotask(()=>{
   // Execute the actual child's finally/dispose contract without any imports,
   // sockets, credentials, child process or real runner module.
   const promise=runInNewContext(`(async()=>{${code}})()`,{createInterface:()=>lines,runDeck,process:{stdin:{},stdout:{write:(text:string)=>{events.push({type:'stdout'});child.stdout.emit('data',Buffer.from(text));}}},JSON,Error});
   Promise.resolve(promise).then(()=>child.emit('close',0,null),()=>child.emit('close',1,'SYNTHETIC_TERMINATION'));
  });return child;
 });
 const source=readFileSync(new URL('./lib/m8-deck-pool-continuation.mjs',import.meta.url),'utf8').replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+(?=(?:async\s+)?function|const)/g,'');
 const actual=runInNewContext(`${source}\n({runM8FixedDeckPrivateStderr})`,{
  spawn,randomUUID,sha256,M8_COMPOSE,M8_DECK124_CONTINUATION:{binarySha256:toolHash},Buffer,Date,Object,Promise,Error,URL,URLSearchParams,
  process:{env:{DOCKER_HOST:'tcp://synthetic.invalid',DOCKER_CONTEXT:'synthetic-remote',DOCKER_TLS:'1',DOCKER_TLS_VERIFY:'1',DOCKER_CERT_PATH:'/synthetic/certs',SYNTHETIC_ALLOWED:'only-synthetic'}},
  setTimeout,clearTimeout,
 });
 const run=()=>actual.runM8FixedDeckPrivateStderr(h,actor,area,input,{jobId:randomUUID()});
 const assertNoReplay=async()=>{await expect(run()).rejects.toThrow('M8_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');expect(spawn).toHaveBeenCalledTimes(1);expect(h.state.cliIntents).toHaveLength(1);};
 return{h,actor,originalActor,area,input,originalInput,rawText,result,events,child,spawn,dispose,runDeck,run,disk,assertNoReplay,
  get durableAtSpawn(){return durableAtSpawn;},get durableAtAck(){return durableAtAck;},get durableAtDispose(){return durableAtDispose;},get saveFailureTriggered(){return saveFailureTriggered;}};
}

describe('independent decK pool private stderr durable ACK SOURCE contracts',()=>{
 it('fsyncs original intent before spawn and raw stderr before ACK and actual inline disposal',async()=>{
  const f=fixture();await expect(f.run()).resolves.toMatchObject({command:'sync',exitCode:0,consoleJobSuccessProved:false});
  const before=f.durableAtSpawn.cliIntents[0];expect(before).toMatchObject({state:'prepared',input:f.originalInput,inputSha256:sha256(JSON.stringify(f.originalInput)),
   actorId:f.originalActor.user.id,sessionId:f.originalActor.sid,clusterId:f.area.cid,workspaceId:f.area.wid,fixedOrigin:'http://console-web:8080',observer:false});
  for(const saved of[f.durableAtAck,f.durableAtDispose])expect(saved.cliIntents[0]).toMatchObject({rawCliStderr:f.rawText,rawCliStderrSha256:sha256(Buffer.from(f.rawText)),rawStderrPrivatelyFsyncedBeforeDispose:true});
  const ix=(type:string)=>f.events.findIndex(e=>e.type===type);expect(ix('fsync')).toBeLessThan(ix('spawn'));
  const rawFsync=f.events.findIndex(e=>e.type==='fsync'&&e.intent?.rawCliStderr===f.rawText);expect(rawFsync).toBeLessThan(ix('ack'));expect(ix('ack')).toBeLessThan(ix('dispose'));
  expect(f.child.stdin.end).toHaveBeenCalledExactlyOnceWith('PRIVATE_FSYNC_ACK\n');expect(f.dispose).toHaveBeenCalledTimes(1);expect(f.h.state.cliIntents[0].state).toBe('response_observed');
 });
 it('uses only fixed local Docker/no-build and the literal standard origin, with no observer',async()=>{
  const f=fixture();await f.run();const [program,args,options]=f.spawn.mock.calls[0],code=args.at(-1);
  expect(program).toBe('docker');expect(args[0]).toBe('--host=unix:///var/run/docker.sock');expect(args).toContain('--no-deps');expect(args).toContain('never');expect(args).not.toContain('--build');
  expect(options.shell).toBe(false);expect(options.env).toEqual({SYNTHETIC_ALLOWED:'only-synthetic'});expect(code).toContain("runDeck(v,{origin:'http://console-web:8080'})");expect(code).not.toMatch(/observer|kong:8001|proxy/i);
  expect(f.runDeck).toHaveBeenCalledTimes(1);
 });
 it('retains known diff exit 1 as observed, with durable stderr and disposal, without relabeling it unknown',async()=>{
  const f=fixture({exitCode:1},{command:'diff'});await expect(f.run()).rejects.toThrow('fixed CLI success is independent');
  const intent=f.h.state.cliIntents[0];expect(intent.state).toBe('response_observed');expect(intent.safeResult).toMatchObject({command:'diff',exitCode:1,possibleUnknown:false});
  expect(f.h.state.phase).toBe('synthetic-ready');expect(f.disk().cliIntents[0].rawCliStderr).toBe(f.rawText);expect(f.child.stdin.end).toHaveBeenCalledTimes(1);expect(f.dispose).toHaveBeenCalledTimes(1);
 });
 it('stops sync possibleUnknown even with a zero CLI/docker exit and forbids replay',async()=>{
  const f=fixture({possibleUnknown:true});await expect(f.run()).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');
  expect(f.h.state).toMatchObject({phase:'stopped-cli-unknown'});expect(f.h.state.cliIntents[0]).toMatchObject({state:'response_unknown',rawStderrPrivatelyFsyncedBeforeDispose:true});await f.assertNoReplay();
 });
 it.each(['toolBinarySha256','toolVersion','toolCommit'])('rejects a DTO from wrong fixed %s without ACK or replay',async(field)=>{
  const value=field==='toolBinarySha256'?'f'.repeat(64):field==='toolVersion'?'1.1.0':'acdb161',f=fixture({[field]:value});
  await expect(f.run()).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');expect(f.h.state.cliIntents[0].state).toBe('response_unknown');
  expect(f.child.stdin.end).not.toHaveBeenCalled();expect(f.child.kill).toHaveBeenCalled();expect(f.dispose).toHaveBeenCalledTimes(1);await f.assertNoReplay();
 });
 it.each([1,2])('fails closed when private ACK fsync %s fails, and does not ACK or replay',async(which)=>{
  const f=fixture({}, {failRawSave:which});await expect(f.run()).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');
  expect(f.saveFailureTriggered).toBe(true);expect(f.child.stdin.end).not.toHaveBeenCalled();expect(f.dispose).toHaveBeenCalledTimes(1);
  expect(f.h.state.cliIntents[0].state).toBe('response_unknown');expect(f.h.state.cliIntents[0].rawStderrPrivatelyFsyncedBeforeDispose).toBe(which===2);
  if(which===1)expect(f.durableAtDispose.cliIntents[0]).not.toHaveProperty('rawCliStderr');else expect(f.durableAtDispose.cliIntents[0].rawCliStderr).toBe(f.rawText);
  await f.assertNoReplay();
 });
 it('keeps the original serialized body and actor/SID when caller objects change after intent fsync',async()=>{
  const f=fixture({}, {mutateAfterSpawn:true});await f.run();const intent=f.h.state.cliIntents[0];
  expect(intent).toMatchObject({actorId:f.originalActor.user.id,sessionId:f.originalActor.sid,input:f.originalInput,inputSha256:sha256(JSON.stringify(f.originalInput))});
  expect(f.child.stdin.write).toHaveBeenCalledExactlyOnceWith(JSON.stringify(f.originalInput)+'\n');expect(f.runDeck).toHaveBeenCalledTimes(1);
 });
});
