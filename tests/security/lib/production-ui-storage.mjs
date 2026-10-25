import { closeSync, fsyncSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';
export const PRODUCTION_UI_REFERENCE='/tmp/kongos-production-ui-runtime-secrets.json';
export const PRODUCTION_UI_JOURNAL='/tmp/kongos-production-ui-original-journal.json';
export function readProductionPrivateFile(path) {
  if(![PRODUCTION_UI_REFERENCE,PRODUCTION_UI_JOURNAL].includes(path))throw Error('PRODUCTION_FIXED_PRIVATE_FILE_REQUIRED');
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600||stat.size>32*1024*1024)throw Error('PRODUCTION_PRIVATE_REFERENCE_BOUNDARY');
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const opened=fstatSync(fd);if(!opened.isFile()||opened.uid!==process.getuid()||(opened.mode&0o777)!==0o600||opened.size>32*1024*1024||opened.ino!==stat.ino||opened.dev!==stat.dev)throw Error('PRODUCTION_PRIVATE_REFERENCE_CHANGED');const bytes=readFileSync(fd);try{return {value:JSON.parse(bytes),bytes};}catch{throw Error('PRODUCTION_PRIVATE_REFERENCE_NOT_JSON');}}finally{closeSync(fd);}
}
export function readProductionUiReference(){return readProductionPrivateFile(PRODUCTION_UI_REFERENCE).value;}
export function durableProductionJson(path,value,initial=false,mode=0o600) {
  const parent=dirname(path);mkdirSync(parent,{recursive:true,mode:0o700});
  const bytes=JSON.stringify(value,null,2)+'\n';if(Buffer.byteLength(bytes)>32*1024*1024)throw Error('PRODUCTION_JOURNAL_SIZE_BOUND');
  const target=initial?path:`${path}.${randomUUID()}.tmp`,fd=openSync(target,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,mode);
  try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}
  if(!initial)renameSync(target,path);
  const dir=openSync(parent,constants.O_RDONLY);try{fsyncSync(dir);}finally{closeSync(dir);}
}
export function productionCookies(origin,cookie) {
  return cookie.split('; ').map(pair=>{const at=pair.indexOf('='),name=pair.slice(0,at),value=pair.slice(at+1);if(!['kongos_access','kongos_refresh','kongos_csrf'].includes(name)||!value)throw Error('PRODUCTION_EXACT_AUTH_COOKIE_NAMES_REQUIRED');
    return {name,value,domain:new URL(origin).hostname,path:name==='kongos_refresh'?'/api/v1/auth':'/api',httpOnly:true,secure:true,sameSite:'Strict'};});
}
