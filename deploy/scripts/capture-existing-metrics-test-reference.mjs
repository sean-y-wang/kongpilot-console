import {execFileSync} from 'node:child_process';
import {existsSync,linkSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {createDecipheriv,randomBytes} from 'node:crypto';
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const purposes={native_scrape:'bff',collector_scrape:'collector',collector_catalog:'bff',collector_ingest:'collector'};
export function validateCaptureAck(ack,clusterIds){
  if(!ack||Object.keys(ack).some(key=>!['captureId','path','clusterIds','generations','count'].includes(key))||!uuid.test(ack.captureId)||!/^\/dev\/shm\/kongos-metrics-capture-[A-Za-z0-9]{6}\/capture\.json$/.test(ack.path)||!Array.isArray(ack.clusterIds)||JSON.stringify([...ack.clusterIds].sort())!==JSON.stringify([...clusterIds].sort())||ack.count!==clusterIds.length*4||!ack.generations||Object.keys(ack.generations).length!==clusterIds.length||clusterIds.some(cid=>!Number.isSafeInteger(ack.generations[cid])||ack.generations[cid]<1))throw new Error('METRICS_CAPTURE_ACK_INVALID');
  return ack;
}
export function validateCaptureBundle(bundle,ack){
  if(!bundle||Object.keys(bundle).some(key=>!['tokens','secrets','users'].includes(key))||!Array.isArray(bundle.tokens)||bundle.tokens.length!==ack.count||!Array.isArray(bundle.secrets)||bundle.secrets.length!==ack.count||!Array.isArray(bundle.users)||bundle.users.length!==0)throw new Error('METRICS_CAPTURE_BUNDLE_INVALID');
  const pairs=new Set(),tokens=new Set();
  for(const row of bundle.tokens){if(!row||Object.keys(row).some(key=>!['clusterId','generation','purpose','audience','token'].includes(key))||!ack.clusterIds.includes(row.clusterId)||row.generation!==ack.generations[row.clusterId]||!Object.hasOwn(purposes,row.purpose)||purposes[row.purpose]!==row.audience||!/^[A-Za-z0-9_-]{43,128}$/.test(row.token)||pairs.has(`${row.clusterId}:${row.purpose}`)||tokens.has(row.token))throw new Error('METRICS_CAPTURE_BUNDLE_INVALID');pairs.add(`${row.clusterId}:${row.purpose}`);tokens.add(row.token);}
  if(bundle.secrets.some(token=>!tokens.has(token))||new Set(bundle.secrets).size!==tokens.size)throw new Error('METRICS_CAPTURE_BUNDLE_INVALID');
  return bundle;
}
export function captureTransferAAD(ack){
  if(!Array.isArray(ack?.clusterIds)||ack.clusterIds.length<1||ack.clusterIds.length>8||new Set(ack.clusterIds).size!==ack.clusterIds.length||ack.clusterIds.some(cid=>!uuid.test(cid)))throw new Error('METRICS_CAPTURE_ACK_INVALID');
  validateCaptureAck(ack,ack.clusterIds);
  const clusterIds=[...ack.clusterIds].sort(),generations=Object.fromEntries(clusterIds.map(cid=>[cid,ack.generations[cid]]));
  return JSON.stringify({stage:'M6',captureId:ack.captureId,path:ack.path,clusterIds,generations,count:ack.count});
}
export function cleanupCapturePath(parsedAck){
  return typeof parsedAck?.path==='string'&&/^\/dev\/shm\/kongos-metrics-capture-[A-Za-z0-9]{6}\/capture\.json$/.test(parsedAck.path)?parsedAck.path:null;
}
export function publishCaptureReference(target,bundle){
  const staged=resolve(dirname(target),`.kongos-m6-reference-${randomBytes(8).toString('hex')}`);
  try{writeFileSync(staged,JSON.stringify(bundle)+'\n',{mode:0o600,flag:'wx'});linkSync(staged,target);}finally{rmSync(staged,{force:true});}
}
// Docker archive-copy cannot read /dev/shm on this runtime. The trusted
// container process validates the private tmpfs inode, then emits encrypted
// bytes only into an attached subprocess pipe. The one-use transfer key is
// stdin-only and never becomes a file, environment variable, argv or log.
export const CAPTURE_TRANSFER_PROGRAM=String.raw`
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');let fd,key;
try{
 const raw=fs.readFileSync(0);if(raw.length>2048)throw Error();const a=JSON.parse(raw),q=a.ack,uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
 if(Object.keys(a).sort().join(',')!=='ack,key'||typeof a.key!=='string'||a.key.length!==64||!/^[a-f0-9]{64}$/.test(a.key)||!q||Object.keys(q).sort().join(',')!=='captureId,clusterIds,count,generations,path'||typeof q.path!=='string'||!/^\/dev\/shm\/kongos-metrics-capture-[A-Za-z0-9]{6}\/capture\.json$/.test(q.path)||!uuid.test(q.captureId)||!Array.isArray(q.clusterIds)||q.clusterIds.length<1||q.clusterIds.length>8||new Set(q.clusterIds).size!==q.clusterIds.length||q.clusterIds.some(cid=>!uuid.test(cid))||q.count!==q.clusterIds.length*4||!q.generations||Object.keys(q.generations).sort().join(',')!==[...q.clusterIds].sort().join(',')||q.clusterIds.some(cid=>!Number.isSafeInteger(q.generations[cid])||q.generations[cid]<1))throw Error();
 const clusterIds=[...q.clusterIds].sort(),generations=Object.fromEntries(clusterIds.map(cid=>[cid,q.generations[cid]])),aad=JSON.stringify({stage:'M6',captureId:q.captureId,path:q.path,clusterIds,generations,count:q.count});
 const directory=fs.lstatSync(path.dirname(q.path));if(!directory.isDirectory()||directory.isSymbolicLink()||directory.uid!==process.getuid()||(directory.mode&511)!==448||fs.statfsSync('/dev/shm',{bigint:true}).type!==0x01021994n)throw Error();
 fd=fs.openSync(q.path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&511)!==384||s.size<1||s.size>65536||s.nlink!==1)throw Error();
 const data=fs.readFileSync(fd);if(data.length!==s.size)throw Error();key=Buffer.from(a.key,'hex');const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(aad));const ciphertext=Buffer.concat([cipher.update(data),cipher.final()]);data.fill(0);
 process.stdout.write(JSON.stringify({version:1,iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:ciphertext.toString('base64')}));
}catch{process.stderr.write('METRICS_CAPTURE_TRANSFER_FAILED\n');process.exitCode=2;}finally{if(fd!==undefined)fs.closeSync(fd);if(key)key.fill(0);}
`;
export function decryptCaptureTransfer(transfer,ack,key){
  if(!transfer||Object.keys(transfer).sort().join(',')!=='ciphertext,iv,tag,version'||transfer.version!==1||!Buffer.isBuffer(key)||key.length!==32||typeof transfer.iv!=='string'||transfer.iv.length!==24||!/^[a-f0-9]{24}$/.test(transfer.iv)||typeof transfer.tag!=='string'||transfer.tag.length!==32||!/^[a-f0-9]{32}$/.test(transfer.tag)||typeof transfer.ciphertext!=='string'||transfer.ciphertext.length>87384)throw new Error('METRICS_CAPTURE_TRANSFER_INVALID');
  const encrypted=Buffer.from(transfer.ciphertext,'base64');
  if(encrypted.length<1||encrypted.length>65536||encrypted.toString('base64')!==transfer.ciphertext)throw new Error('METRICS_CAPTURE_TRANSFER_INVALID');
  let plaintext;
  try{const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(transfer.iv,'hex'));decipher.setAAD(Buffer.from(captureTransferAAD(ack)));decipher.setAuthTag(Buffer.from(transfer.tag,'hex'));plaintext=Buffer.concat([decipher.update(encrypted),decipher.final()]);return JSON.parse(plaintext.toString('utf8'));}
  catch{throw new Error('METRICS_CAPTURE_TRANSFER_INVALID');}
  finally{plaintext?.fill(0);}
}
if(import.meta.url===`file://${resolve(process.argv[1]||'')}`){
  const stage=process.argv[2],multicluster=process.argv.includes('--multicluster');
  if(stage!=='M6'||!process.argv.includes('--test-only')){console.error('Existing metric capture requires explicit M6 --test-only.');process.exit(2);}
  const compose=['compose','--env-file','.env',...(multicluster?['--env-file','.env.multicluster']:[]),'-f','docker-compose.yml','-f','deploy/compose/compose.development.yml',...(multicluster?['-f','deploy/compose/compose.multicluster-test.yml','--profile','multicluster-test']:[]),'-f','deploy/compose/compose.metrics.yml','--profile','observability'];
  const target='/tmp/kongos-m6-runtime-secrets.json';
  let parsedAck,ack,transferKey,phase='preflight';
  try{
    if(existsSync(target))throw new Error('METRICS_CAPTURE_DESTINATION_EXISTS');
    const clusterIds=JSON.parse(readFileSync('deploy/private/metrics/manifest.json','utf8')).clusters.map(row=>row.clusterId);
    if(clusterIds.length<1||clusterIds.length>8||new Set(clusterIds).size!==clusterIds.length||clusterIds.some(cid=>!uuid.test(cid)))throw new Error('METRICS_CAPTURE_CLUSTER_IDS_INVALID');
    phase='trusted-cli';parsedAck=JSON.parse(execFileSync('docker',[...compose,'exec','-T','console-api','node','dist/infrastructure/metrics-test-capture.js'],{input:JSON.stringify({clusterIds}),encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:65536,timeout:15000}));ack=validateCaptureAck(parsedAck,clusterIds);
    phase='encrypted-transfer';transferKey=randomBytes(32);
    const encrypted=JSON.parse(execFileSync('docker',[...compose,'exec','-T','console-api','node','-e',CAPTURE_TRANSFER_PROGRAM],{input:JSON.stringify({ack,key:transferKey.toString('hex')}),encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:131072,timeout:5000}));
    phase='validate-family';const bundle=validateCaptureBundle(decryptCaptureTransfer(encrypted,ack,transferKey),ack);
    phase='atomic-reference';
    publishCaptureReference(target,bundle);
    console.log(JSON.stringify({stage,path:target,mode0600:true,count:ack.count,generations:ack.generations,plaintextTransferStdout:false,enrollmentPerformed:false,rotationPerformed:false}));
  }catch{console.error(`EXISTING_METRICS_TEST_CAPTURE_FAILED phase=${phase}; no token values printed.`);process.exitCode=1;}
  finally{
    transferKey?.fill(0);
    const path=cleanupCapturePath(parsedAck);
    if(path){const cleanup="const fs=require('fs'),path=require('path');const input=JSON.parse(fs.readFileSync(0,'utf8'));if(!/^\\/dev\\/shm\\/kongos-metrics-capture-[A-Za-z0-9]{6}\\/capture\\.json$/.test(input.path))process.exit(2);const dir=path.dirname(input.path),s=fs.lstatSync(dir);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&511)!==448)process.exit(2);fs.rmSync(dir,{recursive:true,force:true});";try{execFileSync('docker',[...compose,'exec','-T','console-api','node','-e',cleanup],{input:JSON.stringify({path}),stdio:['pipe','pipe','pipe'],timeout:5000});}catch{console.error('METRICS_CAPTURE_TMPFS_CLEANUP_FAILED');process.exitCode=1;}}
  }
}
