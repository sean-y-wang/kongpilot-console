import {describe,expect,it} from 'vitest';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {setTimeout as waitForProcessExit} from 'node:timers/promises';
import {boundedPcre1SecurityCommand,preparePcre1Ci} from '../../deploy/scripts/prepare-pcre1-ci.mjs';

describe('fixed native PCRE quality prerequisite',()=>{
 it('runs actual Python with literal argv and no secret environment',async()=>{const r=await boundedPcre1SecurityCommand(['-c','import os,sys,json;print(json.dumps({"argv":sys.argv[1:],"keys":list(os.environ)}))','$(id);literal'],{cwd:process.cwd(),timeoutMs:3000});expect(r.exitCode).toBe(0);const data=JSON.parse(r.stdout.toString());expect(data.argv).toEqual(['$(id);literal']);for(const k of ['DATABASE_URL','APP_SECRET','GITHUB_TOKEN','NODE_AUTH_TOKEN','DECK_KONG_ADDR'])expect(data.keys).not.toContain(k);});
 it('kills the actual Python compiler process group including a grandchild keeping stdout open',async()=>{const script='import subprocess,time,sys,json; p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(100)"]); print(json.dumps({"pid":p.pid}),flush=True);time.sleep(100)';const start=Date.now(),r=await boundedPcre1SecurityCommand(['-c',script],{cwd:process.cwd(),timeoutMs:500});expect(r.timed).toBe(true);expect(r.exitCode).not.toBe(0);expect(Date.now()-start).toBeLessThan(3500);const pid=JSON.parse(r.stdout.toString()).pid;let state='absent';const deadline=Date.now()+500;do{state='absent';try{state=readFileSync('/proc/'+pid+'/stat','utf8').split(' ')[2];}catch{}if(['absent','Z','X'].includes(state))break;await waitForProcessExit(10);}while(Date.now()<deadline);expect(['absent','Z','X']).toContain(state);});
 it('bounds actual native-test output and fails instead of accumulating an oversized report',async()=>{const r=await boundedPcre1SecurityCommand(['-c','import sys;sys.stdout.buffer.write(b"x"*(3*1024*1024));sys.stdout.flush()'],{cwd:process.cwd(),timeoutMs:3000});expect(r.limited).toBe(true);expect(r.stdout.length).toBeLessThanOrEqual(2*1024*1024);expect(r.exitCode).not.toBe(0);});
 it.each([Buffer.from('untrusted archive'),Buffer.alloc(4*1024*1024+1)])('rejects archive tampering/byte overflow before compiling or running any native source',async archive=>{
  let compile=0,native=0;
  await expect(preparePcre1Ci({download:async()=>archive,prepare:async()=>{compile++;throw Error('must not compile');},runSecurity:async()=>{native++;throw Error('must not execute');}})).rejects.toThrow('PCRE_CI_FIXED_ARCHIVE_INVALID');
  expect(compile).toBe(0);expect(native).toBe(0);
 });
 it.each(['--url=https://untrusted.invalid/pcre.tgz','--directory=/tmp/untrusted','--force','--insecure'])('refuses CLI capability override %s without downloading or executing a helper',flag=>{
  const child=spawnSync(process.execPath,['deploy/scripts/prepare-pcre1-ci.mjs',flag],{cwd:process.cwd(),env:{PATH:process.env.PATH},timeout:3000,encoding:'utf8'});
  expect(child.status).toBe(1);expect(child.stdout).toBe('');expect(JSON.parse(child.stderr)).toEqual({completed:false,code:'PCRE_CI_ARGUMENTS_FORBIDDEN'});
 });
});
