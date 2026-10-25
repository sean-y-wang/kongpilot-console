// @ts-nocheck -- actual ESM tool and filesystem operations; every fixed lab
// path is redirected to a fresh synthetic temp directory before any access.
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {chmodSync,existsSync,linkSync,mkdirSync,mkdtempSync,readFileSync,rmSync,statSync,symlinkSync,unlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';

const isolation=vi.hoisted(()=>({directory:'',accesses:[],descriptors:new Set(),failLock:false,failWrite:false,unsafeLock:false,symlinkTemp:false}));
vi.mock('node:fs',async importOriginal=>{
 const fs=await importOriginal(),lab='/dev/shm/kongpilot-release-lab';
 const local=path=>{
  if(typeof path!=='string'||!isolation.directory)throw Error('ONLY_SYNTHETIC_TEMP_FILES_ALLOWED');
  isolation.accesses.push(path);
  if(path==='/dev/shm')return tmpdir();
  if(path===lab)return isolation.directory;
  if(path.startsWith(`${lab}/`))return join(isolation.directory,path.slice(lab.length+1));
  if(path===isolation.directory||resolve(path).startsWith(`${isolation.directory}/`))return path;
  throw Error('ONLY_SYNTHETIC_TEMP_FILES_ALLOWED');
 };
 return{...fs,
  existsSync:path=>fs.existsSync(local(path)),lstatSync:path=>fs.lstatSync(local(path)),
  openSync:(path,...args)=>{const fd=fs.openSync(local(path),...args);isolation.descriptors.add(fd);return fd;},
  fstatSync:fd=>{if(!isolation.descriptors.has(fd))throw Error('FOREIGN_DESCRIPTOR_FORBIDDEN');return fs.fstatSync(fd);},
  closeSync:fd=>{if(!isolation.descriptors.delete(fd))throw Error('FOREIGN_DESCRIPTOR_FORBIDDEN');return fs.closeSync(fd);},
  readFileSync:(path,...args)=>{if(typeof path==='number'){if(!isolation.descriptors.has(path))throw Error('FOREIGN_DESCRIPTOR_FORBIDDEN');return fs.readFileSync(path,...args);}return fs.readFileSync(local(path),...args);},
  mkdirSync:(path,options)=>{const dest=local(path);if(path.endsWith('.lock')&&isolation.failLock)throw Object.assign(Error('SyntheticLockDenied'),{code:'EACCES'});const result=fs.mkdirSync(dest,options);if(path.endsWith('.lock')&&isolation.unsafeLock)fs.chmodSync(dest,0o755);return result;},
  writeFileSync:(path,bytes,options)=>{const dest=local(path);if(path.includes('.tmp.')&&isolation.failWrite)throw Error('SyntheticTempWriteDenied');if(path.includes('.tmp.')&&isolation.symlinkTemp)fs.symlinkSync(join(isolation.directory,'victim.json'),dest);return fs.writeFileSync(dest,bytes,options);},
  renameSync:(from,to)=>fs.renameSync(local(from),local(to)),rmdirSync:path=>fs.rmdirSync(local(path)),unlinkSync:path=>fs.unlinkSync(local(path)),
 };
});
import{ReleaseHarness}from'../security/lib/release-harness.mjs';
const ledger=()=>join(isolation.directory,'m10-harness.json');
const packet=label=>({label,method:'POST',path:'/synthetic',key:randomUUID(),state:'response_observed',status:201,requestId:randomUUID(),body:{label},actorId:null,sessionId:null});
const response=()=>({status:201,headers:{getSetCookie:()=>[],get:()=>null},arrayBuffer:async()=>Buffer.from(JSON.stringify({data:{ok:true},meta:{requestId:randomUUID()}}))});
beforeEach(()=>{
 isolation.directory=mkdtempSync(join(tmpdir(),'kongpilot-harness-cas-synthetic-'));isolation.accesses=[];isolation.descriptors=new Set();isolation.failLock=false;isolation.failWrite=false;isolation.unsafeLock=false;isolation.symlinkTemp=false;
 chmodSync(isolation.directory,0o700);writeFileSync(join(isolation.directory,'lab.env'),'LAB_BOOTSTRAP_USER=synthetic\nLAB_BOOTSTRAP_PASSWORD=SyntheticUnusedOnly\n',{mode:0o600});
 vi.stubEnv('RELEASE_LAB_READY','true');vi.stubEnv('RELEASE_LAB_API','http://172.29.250.10:5445/api/v1');vi.stubGlobal('fetch',vi.fn(async()=>response()));
});
afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();expect(isolation.descriptors.size).toBe(0);rmSync(isolation.directory,{recursive:true,force:true});isolation.directory='';});

describe('ReleaseHarness private ledger CAS and short save mutex',()=>{
 it('rejects a second instance from the same snapshot and preserves the first original request bytes exactly',()=>{
  const a=new ReleaseHarness('M10'),b=new ReleaseHarness('M10',{resume:true});a.state.requests.push(packet('original-A'));a.save();const committed=readFileSync(ledger());
  b.state.requests.push(packet('stale-B'));expect(()=>b.save()).toThrow('RELEASE_LEDGER_STALE_SNAPSHOT');expect(readFileSync(ledger())).toEqual(committed);
  expect(JSON.parse(committed).requests.map(p=>p.label)).toEqual(['original-A']);expect(existsSync(`${ledger()}.lock`)).toBe(false);
 });
 it('keeps sequential saves compatible with the existing version 1 format and private mode',()=>{
  const a=new ReleaseHarness('M10');a.state.requests.push(packet('first'));a.save();a.state.phase='second';a.state.requests.push(packet('second'));a.save();
  const stored=JSON.parse(readFileSync(ledger(),'utf8'));expect(stored).toEqual(a.state);expect(stored.version).toBe(1);expect(stored).not.toHaveProperty('savedDigest');expect(statSync(ledger()).mode&0o777).toBe(0o600);
 });
 it('resumes without rewriting or normalizing the original ledger bytes',()=>{
  const a=new ReleaseHarness('M10'),original=JSON.stringify({...a.state,requests:[packet('original-format')]});writeFileSync(ledger(),original,{mode:0o600});const b=new ReleaseHarness('M10',{resume:true});
  expect(readFileSync(ledger(),'utf8')).toBe(original);expect(b.state.requests[0].label).toBe('original-format');b.state.phase='explicit-next-intent';b.save();expect(JSON.parse(readFileSync(ledger(),'utf8')).phase).toBe('explicit-next-intent');
 });
 it('rejects a malformed resumed ledger without exposing its private text or rewriting it',()=>{
  new ReleaseHarness('M10');const original='{SyntheticPrivateFixtureMustNotAppear';writeFileSync(ledger(),original,{mode:0o600});
  expect(()=>new ReleaseHarness('M10',{resume:true})).toThrow('RELEASE_LEDGER_FORMAT_INVALID');expect(readFileSync(ledger(),'utf8')).toBe(original);expect(fetch).not.toHaveBeenCalled();
 });
 it.each(['GET','POST'])('rejects a stale %s request before fetch or auth renewal',async method=>{
  const a=new ReleaseHarness('M10'),b=new ReleaseHarness('M10',{resume:true});a.state.requests.push(packet('original-A'));a.save();const committed=readFileSync(ledger()),session={user:{id:randomUUID()},sid:randomUUID(),cookie:'kongos_access=e30.eyJleHAiOjB9.synthetic',csrf:'SyntheticCSRF'};
  await expect(b.request(session,'/synthetic',method,{label:'must-not-send'})).rejects.toThrow('RELEASE_LEDGER_STALE_SNAPSHOT');expect(fetch).not.toHaveBeenCalled();expect(readFileSync(ledger())).toEqual(committed);
 });
 it('detects a conflict at prepared-packet save after the initial freshness gate and still sends nothing',async()=>{
  const a=new ReleaseHarness('M10'),b=new ReleaseHarness('M10',{resume:true}),originalSave=b.save.bind(b);let saves=0,committed;
  b.save=()=>{if(++saves===2){a.state.requests.push(packet('A-won-before-prepare'));a.save();committed=readFileSync(ledger());}return originalSave();};
  await expect(b.request(null,'/auth/login','POST',{username:'synthetic',password:'SyntheticNeverSent'})).rejects.toThrow('RELEASE_LEDGER_STALE_SNAPSHOT');
  expect(fetch).not.toHaveBeenCalled();expect(readFileSync(ledger())).toEqual(committed);expect(b.state.requests[0].state).toBe('prepared');
 });
 it.each(['directory','file'])('does not remove an existing %s lock or overwrite the original file',kind=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger());if(kind==='directory')mkdirSync(`${ledger()}.lock`,{mode:0o700});else writeFileSync(`${ledger()}.lock`,'synthetic-existing-lock',{mode:0o600});
  a.state.requests.push(packet('blocked'));expect(()=>a.save()).toThrow('RELEASE_LEDGER_LOCK_UNAVAILABLE');expect(readFileSync(ledger())).toEqual(committed);expect(existsSync(`${ledger()}.lock`)).toBe(true);
 });
 it('does not overwrite when acquiring a lock is denied',()=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger());isolation.failLock=true;a.state.phase='blocked';expect(()=>a.save()).toThrow('RELEASE_LEDGER_LOCK_UNAVAILABLE');expect(readFileSync(ledger())).toEqual(committed);
 });
 it('rejects an unsafe created lock before any file replacement',()=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger());isolation.unsafeLock=true;a.state.phase='blocked';expect(()=>a.save()).toThrow('RELEASE_LEDGER_LOCK_INVALID');expect(readFileSync(ledger())).toEqual(committed);
 });
 it('cleans its valid short lock after a write fault without replacing the old ledger',()=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger());isolation.failWrite=true;a.state.phase='blocked';expect(()=>a.save()).toThrow('SyntheticTempWriteDenied');expect(readFileSync(ledger())).toEqual(committed);expect(existsSync(`${ledger()}.lock`)).toBe(false);
 });
 it.each(['path','directory','milestone','all-identity'])('rejects changed %s before touching any other milestone or path',kind=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger()),accessCount=isolation.accesses.length;
  if(kind==='path')a.privatePath='/dev/shm/kongpilot-release-lab/m9-harness.json';if(kind==='directory')a.directory='/tmp/unauthorized';if(kind==='milestone')a.milestone='M9';
  if(kind==='all-identity'){a.milestone=a.state.milestone='M9';a.privatePath='/dev/shm/kongpilot-release-lab/m9-harness.json';}
  expect(()=>a.save()).toThrow('RELEASE_LEDGER_SAVE_PATH_INVALID');expect(isolation.accesses.length).toBe(accessCount);expect(readFileSync(ledger())).toEqual(committed);
 });
 it.each(['symlink','hardlink','public-mode'])('rejects a %s ledger and does not alter its bytes',kind=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger()),victim=join(isolation.directory,'victim.json');
  if(kind==='symlink'){writeFileSync(victim,committed,{mode:0o600});unlinkSync(ledger());symlinkSync(victim,ledger());}
  if(kind==='hardlink')linkSync(ledger(),victim);if(kind==='public-mode')chmodSync(ledger(),0o644);
  a.state.phase='blocked';expect(()=>a.save()).toThrow('RELEASE_LEDGER_PERMISSIONS_INVALID');expect(readFileSync(ledger())).toEqual(committed);
 });
 it('never follows a precreated temporary symlink while replacing a private ledger',()=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger()),victim=join(isolation.directory,'victim.json');writeFileSync(victim,'SyntheticVictimUntouched',{mode:0o600});isolation.symlinkTemp=true;
  a.state.phase='blocked';expect(()=>a.save()).toThrow();expect(readFileSync(victim,'utf8')).toBe('SyntheticVictimUntouched');expect(readFileSync(ledger())).toEqual(committed);expect(existsSync(`${ledger()}.lock`)).toBe(false);
 });
 it('rejects weakened private-directory permissions before a lock or file mutation',()=>{
  const a=new ReleaseHarness('M10'),committed=readFileSync(ledger());chmodSync(isolation.directory,0o755);expect(()=>a.save()).toThrow('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');expect(readFileSync(ledger())).toEqual(committed);expect(existsSync(`${ledger()}.lock`)).toBe(false);
 });
 it('persists an observed synthetic response with the same sequential CAS writer',async()=>{
  const a=new ReleaseHarness('M10');await a.request(null,'/auth/login','POST',{username:'synthetic',password:'SyntheticNeverLive'});
  const stored=JSON.parse(readFileSync(ledger(),'utf8'));expect(stored.requests).toHaveLength(1);expect(stored.requests[0]).toMatchObject({state:'response_observed',status:201,path:'/auth/login'});expect(fetch).toHaveBeenCalledOnce();
 });
});
