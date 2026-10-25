import {afterEach,describe,expect,it} from 'vitest';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {chmodSync,lstatSync,mkdtempSync,readFileSync,readdirSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {CAPTURE_TRANSFER_PROGRAM,cleanupCapturePath,decryptCaptureTransfer,publishCaptureReference,validateCaptureBundle} from '../../deploy/scripts/capture-existing-metrics-test-reference.mjs';
const dirs:string[]=[];
const cid='10000000-0000-4000-8000-000000000001';
function fixture(){
 const dir=mkdtempSync('/dev/shm/kongos-metrics-capture-');dirs.push(dir);chmodSync(dir,0o700);
 const path=join(dir,'capture.json'),tokens=[['native_scrape','bff'],['collector_scrape','collector'],['collector_catalog','bff'],['collector_ingest','collector']].map(([purpose,audience],i)=>({clusterId:cid,generation:2,purpose,audience,token:String.fromCharCode(65+i).repeat(43)}));
 const data={tokens,secrets:tokens.map(x=>x.token),users:[]};writeFileSync(path,JSON.stringify(data),{mode:0o600});
 const ack={captureId:'10000000-0000-4000-8000-000000000003',path,clusterIds:[cid],generations:{[cid]:2},count:4};return{dir,path,data,ack,key:randomBytes(32)};
}
function transfer(f:ReturnType<typeof fixture>,ack:any=f.ack){return execFileSync(process.execPath,['-e',CAPTURE_TRANSFER_PROGRAM],{input:JSON.stringify({ack,key:f.key.toString('hex')}),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:3000,maxBuffer:131072});}
afterEach(()=>{for(const dir of dirs.splice(0))rmSync(dir,{recursive:true,force:true});});
describe('M6 private current-generation encrypted capture pipe',()=>{
 it('executes actual tmpfs transfer with ciphertext-only stdout and validates full four-purpose family',()=>{
  const f=fixture(),raw=transfer(f);for(const token of f.data.secrets)expect(raw).not.toContain(token);expect(raw).not.toContain('tokens');
  const envelope=JSON.parse(raw);expect(envelope.version).toBe(1);const decoded=decryptCaptureTransfer(envelope,f.ack,f.key);expect(validateCaptureBundle(decoded,f.ack)).toEqual(f.data);
 });
 it('rejects replay under another capture/key/path/generation binding and ciphertext/tag tampering',()=>{
  const f=fixture(),e=JSON.parse(transfer(f));
  for(const ack of [{...f.ack,captureId:'10000000-0000-4000-8000-000000000004'},{...f.ack,path:'/dev/shm/kongos-metrics-capture-ABC123/capture.json'},{...f.ack,generations:{[cid]:3}}])expect(()=>decryptCaptureTransfer(e,ack,f.key)).toThrow('METRICS_CAPTURE_TRANSFER_INVALID');
  expect(()=>decryptCaptureTransfer(e,f.ack,randomBytes(32))).toThrow();
  for(const altered of [{...e,tag:'0'.repeat(32)},{...e,ciphertext:Buffer.from('tampered').toString('base64')},{...e,version:2},{...e,extra:1},{...e,ciphertext:'a'.repeat(87385)}])expect(()=>decryptCaptureTransfer(altered,f.ack,f.key)).toThrow('METRICS_CAPTURE_TRANSFER_INVALID');
 });
 it.each(['public-file','public-directory','symlink','oversize','unsafe-path'])('rejects unsafe %s before any ciphertext stdout',kind=>{
  const f=fixture();let ack=f.ack;
  if(kind==='public-file')chmodSync(f.path,0o644);if(kind==='public-directory')chmodSync(f.dir,0o755);
  if(kind==='symlink'){rmSync(f.path);const other=join(f.dir,'other.json');writeFileSync(other,'synthetic-only',{mode:0o600});symlinkSync(other,f.path);}
  if(kind==='oversize')writeFileSync(f.path,'x'.repeat(65537));if(kind==='unsafe-path')ack={...f.ack,path:'/tmp/forbidden-capture.json'};
  try{transfer(f,ack);throw new Error('accepted unsafe transfer');}catch(error:any){expect(error.status).toBe(2);expect(error.stdout).toBe('');expect(error.stderr).toBe('METRICS_CAPTURE_TRANSFER_FAILED\n');}
 });
 it('publishes a0600 reference atomically without replacing existing data, with no temporary residues',()=>{
  const f=fixture(),target=join(f.dir,'host-reference.json');publishCaptureReference(target,f.data);expect(lstatSync(target).mode&0o777).toBe(0o600);const prior=readFileSync(target,'utf8');
  expect(()=>publishCaptureReference(target,{...f.data,users:[{id:'cannot-overwrite'}]})).toThrow();expect(readFileSync(target,'utf8')).toBe(prior);expect(readdirSync(f.dir).filter(x=>x.startsWith('.kongos-m6-reference-'))).toEqual([]);
 });
 it('retains only independently safe cleanup paths even when acknowledgement metadata fails',()=>{
  const f=fixture();expect(cleanupCapturePath({...f.ack,count:0,generations:{}})).toBe(f.path);
  for(const path of ['/tmp/file','/dev/shm/kongos-metrics-capture-ABC123/../other','/dev/shm/kongos-metrics-capture-ABC123/capture.json/extra','/dev/shm/kongos-metrics-capture-ABC123/capture.json\n'])expect(cleanupCapturePath({path})).toBeNull();
 });
});
