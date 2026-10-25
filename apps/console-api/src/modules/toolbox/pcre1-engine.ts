import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';

export const PCRE1_PROFILE=Object.freeze({version:'8.45',api:'PCRE1 8-bit',anchored:true,jit:false,
  semantics:'Kong1.5 original-index then uri_postfix strip-regex',patternLimit:64,patternBytes:2048,subjectBytes:8192,
  matchLimit:100000,recursionLimit:256,nativeWallMs:200,parentWallMs:250,memoryBytes:64*1024*1024,concurrency:4});
const archiveSha='4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09';
const helper=resolve(__dirname,'../../../native-bin/kongpilot-pcre1'),manifest=resolve(__dirname,'../../../native-bin/pcre1-build.json');
export type Pcre1Match={match?:boolean;unsupported?:boolean;reason?:string};
const sha=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
let active=0;
function installed():boolean{
 try{
  const m=lstatSync(manifest),b=lstatSync(helper);
  if(!m.isFile()||m.isSymbolicLink()||m.size>4096||!b.isFile()||b.isSymbolicLink()||b.nlink!==1||b.size>4*1024*1024||(b.mode&0o777)!==0o555)return false;
  const data=JSON.parse(readFileSync(manifest,'utf8'));
  return data.format==='kongpilot-pcre1-engine-v1'&&data.version==='8.45'&&data.archiveSha256===archiveSha&&data.binaryBytes===b.size
   &&/^[a-f0-9]{64}$/.test(data.binarySha256)&&sha(readFileSync(helper))===data.binarySha256;
 }catch{return false;}
}
/** Native diagnostics have no gateway, session or mutation capability. No
 * shell/argv pattern, inherited secret environment, file or network access. */
export async function boundedPcre1Matches(patterns:string[],subject:string,timeoutMs=250):Promise<Record<string,Pcre1Match>>{
 const initial:Record<string,Pcre1Match>=Object.create(null),allowed:string[]=[],seen=new Set<string>();
 for(const pattern of patterns){
  if(seen.has(pattern))continue;seen.add(pattern);
  if(allowed.length>=PCRE1_PROFILE.patternLimit||typeof pattern!=='string'||!pattern.length||Buffer.byteLength(pattern)>PCRE1_PROFILE.patternBytes||pattern.includes('\0'))initial[pattern]={unsupported:true,reason:'PCRE_PATTERN_BUDGET'};
  else allowed.push(pattern);
 }
 const fail=(reason:string)=>Object.assign(initial,Object.fromEntries(allowed.map(p=>[p,{unsupported:true,reason}])));
 if(!allowed.length)return initial;
 if(typeof subject!=='string'||Buffer.byteLength(subject)>PCRE1_PROFILE.subjectBytes)return fail('PCRE_SUBJECT_BUDGET');
 if(!Number.isFinite(timeoutMs)||timeoutMs<=0)return fail('PCRE_DEADLINE_EXCEEDED');
 if(active>=PCRE1_PROFILE.concurrency)return fail('PCRE_ENGINE_BUSY');
 if(!installed())return fail('PCRE_ENGINE_UNAVAILABLE');
 const body=Buffer.from(subject),parts:Buffer[]=[Buffer.from('KPPCRE1\0'),Buffer.alloc(12),body];
 parts[1].writeUInt32BE(1,0);parts[1].writeUInt32BE(allowed.length,4);parts[1].writeUInt32BE(body.length,8);
 for(const pattern of allowed){const b=Buffer.from(pattern),length=Buffer.alloc(4);length.writeUInt32BE(b.length);parts.push(length,b);}
 const frame=Buffer.concat(parts),limit=16+allowed.length;
 active++;
 return new Promise(resolveResult=>{
  let child:ReturnType<typeof spawn>;
  try{child=spawn(helper,[],{cwd:'/',env:{LANG:'C',LC_ALL:'C'},stdio:['pipe','pipe','ignore'],windowsHide:true});}
  catch{active--;resolveResult(fail('PCRE_ENGINE_UNAVAILABLE'));return;}
  let finished=false,bytes=0;const output:Buffer[]=[];
  const finish=(value:Record<string,Pcre1Match>)=>{if(finished)return;finished=true;clearTimeout(timer);if(child.exitCode===null)child.kill('SIGKILL');resolveResult(value);};
  const timer=setTimeout(()=>finish(fail('PCRE_DEADLINE_EXCEEDED')),Math.min(PCRE1_PROFILE.parentWallMs,timeoutMs));
  child.once('error',()=>finish(fail('PCRE_ENGINE_UNAVAILABLE')));
  child.stdin!.once('error',()=>finish(fail('PCRE_ENGINE_FAILURE')));
  child.stdout!.on('data',(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>limit){finish(fail('PCRE_OUTPUT_INVALID'));return;}output.push(chunk);});
  child.once('close',(code,signal)=>{
   active--;if(finished)return;
   if(code!==0||signal){finish(fail(signal==='SIGALRM'||signal==='SIGXCPU'||signal==='SIGKILL'?'PCRE_DEADLINE_EXCEEDED':'PCRE_ENGINE_FAILURE'));return;}
   const result=Buffer.concat(output);
   if(result.length!==limit||!result.subarray(0,8).equals(Buffer.from('KPPCR01\0'))||result.readUInt32BE(8)!==1||result.readUInt32BE(12)!==allowed.length||result.subarray(16).some(code=>code>4)){finish(fail('PCRE_OUTPUT_INVALID'));return;}
   const matches=Object.fromEntries(allowed.map((p,i)=>[p,result[16+i]<=1?{match:result[16+i]===1}:{unsupported:true,reason:result[16+i]===2?'PCRE_COMPILE_ERROR':result[16+i]===3?'PCRE_MATCH_LIMIT':'PCRE_MATCH_ERROR'}]));
   finish(Object.assign(initial,matches));
  });
  child.stdin!.end(frame);
 });
}
