import {constants,openSync,closeSync,fstatSync,readSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {posix} from 'node:path';
import {RAM_BASE_IMAGE,RAM_LIMITS} from './production-ram-policy.mjs';
const bad=()=>{throw new Error('RAM_BASE_ARCHIVE_BOUND_UNPROVEN');};
const rounded=(n,block)=>Math.ceil(n/block)*block;
function read(fd,offset,size){const b=Buffer.alloc(size);let done=0;while(done<size){const n=readSync(fd,b,done,size-done,offset+done);if(!n)bad();done+=n;}return b;}
const text=b=>b.toString('utf8').split('\0')[0];
function octal(b){const value=text(b).trim();if(!/^[0-7]+$/.test(value))bad();const n=parseInt(value,8);if(!Number.isSafeInteger(n)||n<0)bad();return n;}
function path(value){const clean=value.replace(/^\.\//,'').replace(/\/$/,'');if(!clean||clean.startsWith('/')||clean!==posix.normalize(clean)||clean.split('/').includes('..')||/[\x00-\x1f]/.test(clean))bad();return clean;}
function pax(b){const out={};let at=0;while(at<b.length){const space=b.indexOf(32,at);if(space<0)bad();const n=Number(b.subarray(at,space).toString());if(!Number.isSafeInteger(n)||n<4||at+n>b.length||b[at+n-1]!==10)bad();const line=b.subarray(space+1,at+n-1).toString(),eq=line.indexOf('=');if(eq<1)bad();const key=line.slice(0,eq);if(key.startsWith('GNU.sparse'))bad();out[key]=line.slice(eq+1);at+=n;}return out;}
/** Reads metadata only; never extracts archive files, follows links or prints names. */
export function scanTar(fd,start,length,visit){
 let offset=start,local={},global={},entries=0,paxBytes=0;const end=start+length;
 while(offset+512<=end){const header=read(fd,offset,512);if(header.every(n=>n===0)){offset+=512;continue;}
  const expected=octal(header.subarray(148,156));let checksum=0;for(let i=0;i<512;i++)checksum+=i>=148&&i<156?32:header[i];if(checksum!==expected)bad();
  const kind=String.fromCharCode(header[156]||48);let size=octal(header.subarray(124,136)),name=text(header.subarray(0,100)),prefix=text(header.subarray(345,500));if(prefix)name=prefix+'/'+name;
  const body=offset+512;
  if(['x','g'].includes(kind)){if(size>65536||body+size>end)bad();const values=pax(read(fd,body,size));paxBytes+=size;if(kind==='g'){if(values.path||values.size||values.linkpath)bad();global={...global,...values};}else local=values;offset=body+rounded(size,512);continue;}
  if(['L','K','S'].includes(kind))bad();
  const attrs={...global,...local};if(attrs.size!==undefined){if(!/^\d+$/.test(attrs.size))bad();size=Number(attrs.size);if(!Number.isSafeInteger(size))bad();}
  if(body+size>end||!['0','1','2','3','4','5','6','7'].includes(kind))bad();
  if(attrs.path)name=attrs.path;if(name==='.'||name==='./'){if(kind!=='5')bad();name='__root_directory__';}else name=path(name);
  visit({name,kind,size,body,link:attrs.linkpath??text(header.subarray(157,257))});entries++;if(entries>100000)bad();local={};offset=body+rounded(size,512);
 }
 if(offset!==end||Object.keys(local).length)bad();return{entries,paxBytes};
}
function hashRange(fd,start,length){const hash=createHash('sha256');for(let offset=0;offset<length;){const size=Math.min(65536,length-offset);hash.update(read(fd,start+offset,size));offset+=size;}return hash.digest('hex');}
export function estimateBaseArchiveAllocation(filename,{blockBytes=4096,expectedImageId=RAM_BASE_IMAGE}={}){
 if(!/^sha256:[a-f0-9]{64}$/.test(expectedImageId)||!Number.isSafeInteger(blockBytes)||blockBytes<512||blockBytes>65536||!/^\/(?:dev\/shm|tmp)\//.test(filename))bad();
 const fd=openSync(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const initial=fstatSync(fd);if(!initial.isFile()||initial.uid!==process.getuid()||initial.nlink!==1||(initial.mode&0o077)!==0||initial.size<1024||initial.size>RAM_LIMITS.archive)bad();
  const outer=new Map();scanTar(fd,0,initial.size,entry=>{if(outer.has(entry.name))bad();outer.set(entry.name,entry);});
  const manifest=outer.get('manifest.json');if(!manifest||manifest.kind!=='0'||manifest.size>65536)bad();
  const rows=JSON.parse(read(fd,manifest.body,manifest.size));if(!Array.isArray(rows)||rows.length!==1)bad();const row=rows[0];
  if(!row||!Array.isArray(row.Layers)||!row.Layers.length||row.Layers.length>128||new Set(row.Layers).size!==row.Layers.length)bad();
  const config=outer.get(path(row.Config));if(!config||config.kind!=='0'||config.size>262144||'sha256:'+hashRange(fd,config.body,config.size)!==expectedImageId)bad();
  const configObject=JSON.parse(read(fd,config.body,config.size)),diffIds=configObject.rootfs?.diff_ids;if(!Array.isArray(diffIds)||diffIds.length!==row.Layers.length)bad();
  let regularAllocatedBytes=0,entries=0,paxBytes=0,hardLinks=0;const sizes=new Map(),links=[];
  for(let i=0;i<row.Layers.length;i++){
   const entry=outer.get(path(row.Layers[i]));if(!entry||entry.kind!=='0'||'sha256:'+hashRange(fd,entry.body,entry.size)!==diffIds[i])bad();
   const layer=scanTar(fd,entry.body,entry.size,e=>{if(['0','7'].includes(e.kind)){regularAllocatedBytes+=rounded(e.size,blockBytes);sizes.set(e.name,Math.max(sizes.get(e.name)??0,e.size));}else if(e.kind==='1'){hardLinks++;links.push(path(e.link));}});entries+=layer.entries;paxBytes+=layer.paxBytes;
  }
  let hardLinkAllocatedBytes=0;for(const link of links){if(!sizes.has(link))bad();hardLinkAllocatedBytes+=rounded(sizes.get(link),blockBytes);}
  const metadataUpperBytes=entries*blockBytes*8+rounded(paxBytes,blockBytes)+16*1024**2;
  const allocatedRootfsUpperBytes=regularAllocatedBytes+hardLinkAllocatedBytes+metadataUpperBytes;
  const final=fstatSync(fd);if(final.size!==initial.size||final.mtimeMs!==initial.mtimeMs||final.ctimeMs!==initial.ctimeMs||!Number.isSafeInteger(allocatedRootfsUpperBytes))bad();
  return{kind:'conservative-public-layer-allocation-bound',imageId:expectedImageId,archiveBytes:initial.size,archiveSha256:hashRange(fd,0,initial.size),blockBytes,layers:row.Layers.length,entries,hardLinks,regularAllocatedBytes,hardLinkAllocatedBytes,metadataUpperBytes,allocatedRootfsUpperBytes,logicalImageSizeUsedAsBound:false,allLayerDiffIdsMatched:true};
 }catch(error){if(error?.message==='RAM_BASE_ARCHIVE_BOUND_UNPROVEN')throw error;bad();}finally{closeSync(fd);}
}
