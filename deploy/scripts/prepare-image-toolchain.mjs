/** Fixed public Buildx binary. No Docker, deployment, auth file or caller URL. */
import {get} from 'node:https';
import {createHash} from 'node:crypto';
import {chmodSync,existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {checkedToolDirectory,allowedReleaseRedirect} from './prepare-test-toolchain.mjs';
export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>{throw Error(code);};
export async function downloadImageTool(tool){let url=allowedReleaseRedirect(tool.url),end=Date.now()+120000;for(let redirects=0;redirects<5;redirects++){
 const response=await new Promise((ok,reject)=>{const q=get(url,{timeout:Math.max(1,Math.min(15000,end-Date.now())),rejectUnauthorized:true,headers:{'user-agent':'KongPilot-fixed-image-toolchain'}},ok);q.once('error',()=>reject(Error('IMAGE_TOOL_DOWNLOAD_FAILED')));q.once('timeout',()=>q.destroy(Error('IMAGE_TOOL_DOWNLOAD_TIMEOUT')));});
 if([301,302,303,307,308].includes(response.statusCode)){const next=response.headers.location;response.destroy();if(typeof next!=='string')fail('IMAGE_TOOL_REDIRECT_INVALID');url=allowedReleaseRedirect(new URL(next,url).href);continue;}
 if(response.statusCode!==200){response.destroy();fail('IMAGE_TOOL_DOWNLOAD_STATUS');}const chunks=[];let size=0;for await(const chunk of response){size+=chunk.length;if(size>tool.maxBytes||Date.now()>=end){response.destroy();fail('IMAGE_TOOL_DOWNLOAD_BUDGET');}chunks.push(chunk);}return Buffer.concat(chunks);
 }fail('IMAGE_TOOL_REDIRECT_LIMIT');}
export async function prepareImageToolchain({directory,tool,download=downloadImageTool}={}){if(process.platform!=='linux'||process.arch!=='x64')fail('IMAGE_TOOL_LINUX_AMD64_REQUIRED');const root=checkedToolDirectory(directory),plugins=join(root,'cli-plugins');if(existsSync(plugins))fail('IMAGE_TOOL_NEW_PLUGIN_DIRECTORY_REQUIRED');mkdirSync(plugins,{mode:0o700});const output=join(plugins,'docker-buildx');const bytes=await download(tool);if(!Buffer.isBuffer(bytes)||bytes.length>tool.maxBytes||sha(bytes)!==tool.sha256)fail('IMAGE_TOOL_BINARY_SHA_MISMATCH');writeFileSync(output,bytes,{flag:'wx',mode:0o555});if(lstatSync(output).isSymbolicLink())fail('IMAGE_TOOL_BINARY_SYMLINK');chmodSync(output,0o555);writeFileSync(join(root,'config.json'),'{"auths":{}}\n',{flag:'wx',mode:0o600});return{version:tool.version,sha256:tool.sha256,bytes:bytes.length,credentialsUsed:false};}
