import {randomBytes} from 'node:crypto';
import {chmodSync,lstatSync,readFileSync,renameSync,unlinkSync,writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
export function ensurePortalEnvironment(filename,{random=()=>randomBytes(32).toString('hex')}={}) {
  const path=resolve(filename),info=lstatSync(path);
  if(!info.isFile()||info.isSymbolicLink()||info.uid!==process.getuid()||(info.mode&0o777)!==0o600||info.size>131072)throw new Error('PORTAL_ENV_PRIVATE_FILE_REQUIRED');
  const original=readFileSync(path,'utf8');
  const values=new Map();
  for(const line of original.split(/\r?\n/)){const match=line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);if(match){if(values.has(match[1]))throw new Error('PORTAL_ENV_DUPLICATE_KEY');values.set(match[1],match[2]);}}
  let token=values.get('PORTAL_SECRET');
  const additions=[];
  if(token===undefined){token=random();additions.push(`PORTAL_SECRET=${token}`);}
  if(!/^[a-f0-9]{64}$/.test(token)||token===values.get('APP_SECRET')||token===values.get('CONSOLE_ENCRYPTION_KEY'))throw new Error('PORTAL_ENV_SECRET_INVALID');
  if(!values.has('PORTAL_PUBLIC_ORIGINS'))additions.push('PORTAL_PUBLIC_ORIGINS=http://127.0.0.1:8082,http://localhost:8082');
  if(!values.has('PORTAL_WEB_PORT'))additions.push('PORTAL_WEB_PORT=8082');
  if(additions.length){
    const temporary=resolve(dirname(path),`.kongos-portal-env-${randomBytes(8).toString('hex')}`);
    try{writeFileSync(temporary,original+(original.endsWith('\n')?'':'\n')+additions.join('\n')+'\n',{mode:0o600,flag:'wx'});chmodSync(temporary,0o600);renameSync(temporary,path);}finally{try{unlinkSync(temporary);}catch{}}
  }
  return {createdPortalSecret:!values.has('PORTAL_SECRET'),existingValuesPreserved:true,privateMode0600:true};
}
