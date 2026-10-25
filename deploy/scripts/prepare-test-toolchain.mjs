#!/usr/bin/env node
/** Fixed public decK test prerequisite; no runtime credentials, arbitrary URLs, flags or archive extraction. */
import { get } from 'node:https';
import { createHash, randomUUID } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { chmodSync, fchmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
export const DECK_TEST_TOOLCHAIN=Object.freeze({version:'1.2.4',commit:'8e68931',archive:'https://github.com/Kong/deck/releases/download/v1.2.4/deck_1.2.4_linux_amd64.tar.gz',archiveSha256:'6eef6dc36a8c251f10f0e3ffa40ec5289d42de131ad043f76ad45d2de390beae',binarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed',binaryBytes:10498048});
export const DEFAULT_DECK_TEST_DIRECTORY='/tmp/kongos-deck124-cli';
const ARCHIVE_MAX=16*1024*1024,CLEAR_MAX=32*1024*1024,ENTRY_MAX=64;
const fail=code=>{throw new Error(code);};const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function checkedToolDirectory(raw,{create=false}={}){
 if(typeof raw!=='string'||!isAbsolute(raw)||raw.includes('\0')||raw.includes('\\')||raw.split('/').some(part=>part==='..'||part==='.'))fail('DECK_TEST_DIRECTORY_INVALID');
 const path=resolve(raw),root=parse(path).root;let current=root;
 for(const part of path.slice(root.length).split(sep).filter(Boolean)){current=join(current,part);let s;try{s=lstatSync(current);}catch(error){if(error.code!=='ENOENT')throw error;}if(!s){if(current!==path||!create)fail('DECK_TEST_DIRECTORY_MISSING');try{mkdirSync(path,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}s=lstatSync(path);}if(s.isSymbolicLink()||!s.isDirectory())fail('DECK_TEST_SYMLINK_OR_DIRECTORY_INVALID');if(current===path&&(s.uid!==process.getuid()||(s.mode&0o022)!==0))fail('DECK_TEST_DIRECTORY_OWNERSHIP_REQUIRED');}
 return path;
}
export function verifiedTestBinary(path){let fd;try{fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const s=fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||s.size!==DECK_TEST_TOOLCHAIN.binaryBytes||![0o555,0o755].includes(s.mode&0o777))fail('X');const data=readFileSync(fd);if(sha(data)!==DECK_TEST_TOOLCHAIN.binarySha256)fail('X');const now=lstatSync(path);if(now.isSymbolicLink()||now.dev!==s.dev||now.ino!==s.ino)fail('X');return true;}catch{fail('DECK_TEST_EXISTING_BINARY_UNVERIFIED');}finally{if(fd!==undefined)closeSync(fd);}}
function octal(field){const text=field.toString('ascii').replace(/[\0 ]+$/g,'').trim();if(!/^[0-7]+$/.test(text))fail('DECK_TEST_TAR_NUMBER_INVALID');const value=parseInt(text,8);if(!Number.isSafeInteger(value))fail('DECK_TEST_TAR_NUMBER_INVALID');return value;}
function text(field){const end=field.indexOf(0),part=end<0?field:field.subarray(0,end);if(part.some(b=>b<0x20||b>0x7e))fail('DECK_TEST_TAR_NAME_INVALID');return part.toString('ascii');}
/** Reads bounded regular files into memory. Never asks tar or a shell to create paths. */
export function parseDeckTar(clear){if(!Buffer.isBuffer(clear)||clear.length>CLEAR_MAX||clear.length%512!==0)fail('DECK_TEST_TAR_SIZE_INVALID');const result=new Map();let at=0,entries=0,ended=false;
 while(at<clear.length){const h=clear.subarray(at,at+512);if(h.every(b=>b===0)){if(clear.length-at<1024||!clear.subarray(at).every(b=>b===0))fail('DECK_TEST_TAR_TRAILER_INVALID');ended=true;break;}if(++entries>ENTRY_MAX)fail('DECK_TEST_TAR_ENTRY_BUDGET');
  let checksum=0;for(let i=0;i<512;i++)checksum+=i>=148&&i<156?32:h[i];if(checksum!==octal(h.subarray(148,156)))fail('DECK_TEST_TAR_CHECKSUM_INVALID');
  const name=text(h.subarray(0,100)),prefix=text(h.subarray(345,500)),type=h[156],size=octal(h.subarray(124,136)),mode=octal(h.subarray(100,108));
  if(!['deck','LICENSE','README.md','CHANGELOG.md'].includes(name)||prefix||![0,48].includes(type)||result.has(name)||text(h.subarray(157,257))||text(h.subarray(257,263)).slice(0,5)!=='ustar'||size>CLEAR_MAX||(mode&0o022)!==0)fail('DECK_TEST_TAR_ENTRY_INVALID');
  const start=at+512,end=start+size,next=start+Math.ceil(size/512)*512;if(end>clear.length||next>clear.length||!clear.subarray(end,next).every(b=>b===0))fail('DECK_TEST_TAR_DATA_INVALID');result.set(name,Buffer.from(clear.subarray(start,end)));at=next;
 }
 if(!ended||result.size!==4||!result.has('deck'))fail('DECK_TEST_TAR_CONTENTS_INVALID');return result;
}
export function unpackVerifiedArchive(archive){if(!Buffer.isBuffer(archive)||archive.length>ARCHIVE_MAX||sha(archive)!==DECK_TEST_TOOLCHAIN.archiveSha256)fail('DECK_TEST_ARCHIVE_SHA256_INVALID');let clear;try{clear=gunzipSync(archive,{maxOutputLength:CLEAR_MAX});return parseDeckTar(clear);}catch(error){if(/^DECK_TEST_/.test(error?.message??''))throw error;fail('DECK_TEST_ARCHIVE_GZIP_INVALID');}finally{clear?.fill(0);}}
export function allowedReleaseRedirect(value){let u;try{u=new URL(value);}catch{fail('DECK_TEST_RELEASE_REDIRECT_INVALID');}if(u.protocol!=='https:'||u.username||u.password||u.hash||u.port&&u.port!=='443'||!['github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'].includes(u.hostname))fail('DECK_TEST_RELEASE_REDIRECT_INVALID');return u;}
export async function downloadOfficialDeckArchive(){let current=new URL(DECK_TEST_TOOLCHAIN.archive);const deadline=Date.now()+90000;
 for(let hop=0;hop<6;hop++){
  const response=await new Promise((ok,reject)=>{const request=get(current,{rejectUnauthorized:true,headers:{'user-agent':'KongPilot-fixed-test-toolchain','accept':'application/octet-stream'},timeout:Math.max(1,Math.min(15000,deadline-Date.now()))},ok);request.once('error',()=>reject(new Error('DECK_TEST_DOWNLOAD_FAILED')));request.once('timeout',()=>request.destroy(new Error('DECK_TEST_DOWNLOAD_TIMEOUT')));});
  if([301,302,303,307,308].includes(response.statusCode)){const location=response.headers.location;response.destroy();if(typeof location!=='string')fail('DECK_TEST_RELEASE_REDIRECT_INVALID');current=allowedReleaseRedirect(new URL(location,current).href);if(Date.now()>=deadline)fail('DECK_TEST_DOWNLOAD_TIMEOUT');continue;}
  if(response.statusCode!==200){response.destroy();fail('DECK_TEST_DOWNLOAD_STATUS');}const chunks=[];let bytes=0;try{for await(const chunk of response){bytes+=chunk.length;if(bytes>ARCHIVE_MAX||Date.now()>=deadline){response.destroy();fail('DECK_TEST_DOWNLOAD_LIMIT');}chunks.push(chunk);}return Buffer.concat(chunks);}catch(error){if(/^DECK_TEST_/.test(error?.message??''))throw error;fail('DECK_TEST_DOWNLOAD_FAILED');}
 }
 fail('DECK_TEST_RELEASE_REDIRECT_LIMIT');
}
function directoryFence(path,fd,identity){try{checkedToolDirectory(path);const current=lstatSync(path),opened=fstatSync(fd);if(!opened.isDirectory()||current.dev!==identity.dev||current.ino!==identity.ino||opened.dev!==identity.dev||opened.ino!==identity.ino||current.uid!==process.getuid()||(current.mode&0o022)!==0)fail('X');}catch{fail('DECK_TEST_DIRECTORY_CHANGED');}}
export async function prepareDeckTestToolchain({directory=DEFAULT_DECK_TEST_DIRECTORY,download=downloadOfficialDeckArchive}={}){
 const dir=checkedToolDirectory(directory,{create:true}),identity=lstatSync(dir),directoryFd=openSync(dir,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW),descriptorPath=`/proc/self/fd/${directoryFd}`;let stage,fd,files;
 try{
  directoryFence(dir,directoryFd,identity);const binary=join(descriptorPath,'deck');let existing;try{existing=lstatSync(binary);}catch(error){if(error.code!=='ENOENT')throw error;}
  if(existing){verifiedTestBinary(binary);directoryFence(dir,directoryFd,identity);return{completed:true,version:DECK_TEST_TOOLCHAIN.version,binarySha256:DECK_TEST_TOOLCHAIN.binarySha256,binaryVerified:true,downloaded:false,credentialsUsed:false};}
  const archive=await download();directoryFence(dir,directoryFd,identity);files=unpackVerifiedArchive(archive);const bytes=files.get('deck');if(bytes.length!==DECK_TEST_TOOLCHAIN.binaryBytes||sha(bytes)!==DECK_TEST_TOOLCHAIN.binarySha256)fail('DECK_TEST_BINARY_SHA256_INVALID');
  stage=join(descriptorPath,`.deck-install-${randomUUID()}`);fd=openSync(stage,'wx',0o600);writeFileSync(fd,bytes);fsyncSync(fd);fchmodSync(fd,0o555);closeSync(fd);fd=undefined;directoryFence(dir,directoryFd,identity);
  try{linkSync(stage,binary);}catch(error){if(error.code==='EEXIST')fail('DECK_TEST_BINARY_APPEARED_DURING_INSTALL');throw error;}unlinkSync(stage);stage=undefined;verifiedTestBinary(binary);directoryFence(dir,directoryFd,identity);fsyncSync(directoryFd);
  return{completed:true,version:DECK_TEST_TOOLCHAIN.version,archiveSha256:DECK_TEST_TOOLCHAIN.archiveSha256,binarySha256:DECK_TEST_TOOLCHAIN.binarySha256,binaryVerified:true,downloaded:true,credentialsUsed:false};
 }finally{if(fd!==undefined)closeSync(fd);if(stage)try{unlinkSync(stage);}catch(error){if(error.code!=='ENOENT')throw error;}for(const value of files?.values()??[])value.fill(0);closeSync(directoryFd);}
}
export async function prepareCli(args){if(args.length)fail('DECK_TEST_ARGUMENTS_FORBIDDEN');if(process.platform!=='linux'||process.arch!=='x64')fail('DECK_TEST_LINUX_X64_REQUIRED');return prepareDeckTestToolchain();}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))prepareCli(process.argv.slice(2)).then(value=>process.stdout.write(JSON.stringify(value)+'\n')).catch(error=>{process.stderr.write(JSON.stringify({completed:false,code:/^DECK_TEST_[A-Z0-9_]+$/.test(error?.message??'')?error.message:'DECK_TEST_PRIVATE_PREPARATION_FAILED',credentialsUsed:false})+'\n');process.exitCode=1;});
