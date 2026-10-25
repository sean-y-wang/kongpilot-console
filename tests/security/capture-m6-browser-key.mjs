import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {closeSync,existsSync,fsyncSync,openSync,readFileSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {privateReference,M6_REFERENCE} from './lib/m6-reference.mjs';
import {BROWSER_KEY_SCAN_SQL,captureBrowserKeyScanMaterial} from './lib/m6-browser-key-scan.mjs';

// This is an independent, one-use scanner-material entry. The browser runner
// never imports it; no credentials or database access occur before its flag.
if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_BROWSER_KEY_SCAN_READY!=='true')throw new Error('Separate Root browser-key scanner material release required');
const artifact='artifacts/M6/browser-issued-key-scan-material.json';
if(existsSync(artifact))throw new Error('Original browser-key scanner attempt cannot be rearmed');
let phase='completed-browser-reference-guard',temporary,reference;
const hash=b=>createHash('sha256').update(b).digest('hex');
try{
 const report=JSON.parse(readFileSync('artifacts/M6/browser-verification.json','utf8'));
 reference=privateReference(M6_REFERENCE,true);let expectedSha=hash(readFileSync(M6_REFERENCE));
 const originalSha=expectedSha;
 const persist=async next=>{
  privateReference(M6_REFERENCE,true);
  if(hash(readFileSync(M6_REFERENCE))!==expectedSha)throw new Error('Private reference changed during scanner material capture');
  temporary=M6_REFERENCE+'.browser-key-'+randomUUID();const bytes=JSON.stringify(next),fd=openSync(temporary,'wx',0o600);
  try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}
  renameSync(temporary,M6_REFERENCE);temporary=undefined;expectedSha=hash(bytes);
 };
 const consoleJars=(reference.browserRemaining?.latestNamedJars??[]).filter(j=>Array.isArray(j)&&j.some(v=>v.name==='kongos_access'));
 if(consoleJars.length!==1||consoleJars[0].filter(v=>v.name==='kongos_access').length!==1||consoleJars[0].some(v=>v.domain!=='127.0.0.1'||v.path!==(v.name==='kongos_refresh'?'/api/v1/auth':'/api')||typeof v.value!=='string'))throw new Error('Exact saved Console browser jar required for read-only proofs');
 const consoleCookie=consoleJars[0].map(v=>`${v.name}=${v.value}`).join('; ');
 const safeWire=async(origin,path,context,method='GET',body,key)=>{
  if(!path.startsWith('/api/v1/')||path.includes('?')||path.includes('#'))throw new Error('Fixed BFF scanner path required');
  const url=new URL(path,origin);url.searchParams.set('workspaceId',context.fixture.workspaceId);
  if(origin==='http://127.0.0.1:8082')url.searchParams.set('clusterId',context.fixture.clusterId);
  const headers={Cookie:origin==='http://127.0.0.1:8082'?context.cookie:consoleCookie};
  if(method==='POST')Object.assign(headers,{'Content-Type':'application/json','Origin':origin,'X-Portal-CSRF':context.csrf,'X-Idempotency-Key':key});
  const response=await fetch(url,{method,headers,body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(15000)});
  const bytes=new Uint8Array(await response.arrayBuffer());if(bytes.byteLength>65536)throw new Error('Scanner BFF response exceeded fixed budget');
  let payload;try{payload=JSON.parse(new TextDecoder().decode(bytes));}catch{throw new Error('Scanner BFF response was not parseable');}
  return{status:response.status,data:payload.data,requestId:response.headers.get('x-request-id')??payload.requestId};
 };
 const read=(origin,path,context)=>safeWire(origin,path,context).then(r=>{if(r.status!==200)throw new Error('Read-only scanner BFF proof unavailable');return r.data;});
 const program=`const pg=require('pg');let input='';process.stdin.on('data',v=>{input+=v;if(Buffer.byteLength(input)>8192)process.exitCode=2;});process.stdin.on('end',async()=>{let pool,client;try{if(process.exitCode)throw Error();const args=JSON.parse(input);if(!Array.isArray(args)||args.length!==5)throw Error();pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});client=await pool.connect();await client.query('BEGIN READ ONLY');await client.query("SET LOCAL statement_timeout='10s'");const rows=(await client.query(${JSON.stringify(BROWSER_KEY_SCAN_SQL)},args)).rows;await client.query('ROLLBACK');process.stdout.write(JSON.stringify(rows));}catch{if(client)await client.query('ROLLBACK').catch(()=>{});process.exitCode=2;}finally{client?.release();await pool?.end();}});`;
 phase='original-session-and-issued-tuple-proofs';
 const result=await captureBrowserKeyScanMaterial(reference,report,{
  released:true,persist,
  readSql:async(sql,args)=>{if(sql!==BROWSER_KEY_SCAN_SQL)throw new Error('Fixed scanner SQL required');try{return JSON.parse(execFileSync('docker',['compose','exec','-T','console-api','node','-e',program],{input:JSON.stringify(args),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:32768}));}catch{throw new Error('Fixed scanner SQL proof unavailable; raw diagnostics withheld');}},
  portalGet:(path,c)=>read('http://127.0.0.1:8082','/api/v1/portal'+path,c),
  consoleReceipt:c=>read('http://127.0.0.1:8080',`/api/v1/clusters/${c.fixture.clusterId}/workflows/receipts/by-key/${c.executionKey}`,c),
  consoleGet:(path,c)=>read('http://127.0.0.1:8080',`/api/v1/clusters/${c.fixture.clusterId}`+path,c),
  portalReveal:(path,body,key,c)=>{phase='single-prejournaled-owner-scanner-reveal';return safeWire('http://127.0.0.1:8082','/api/v1/portal'+path,c,'POST',body,key);},
 });
 writeFileSync(artifact,JSON.stringify({performedAt:new Date().toISOString(),...result,originalReferenceSha256:originalSha,mode0600:true,originalBrowserLoginNotReplayed:true,originalReferenceAndHistoryPreserved:true,independentScannerMaterialAction:true},null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({allPassed:true,scannerRevealPosts:1,nativeWrites:0,keyRetainedPrivately:true,secretsPublished:false}));
}catch{
 const safe={performedAt:new Date().toISOString(),allPassed:false,phase,privatePhase:reference?.browserKeyScan?.phase??null,originalRequestPrivatelyRetained:!!reference?.browserKeyScan?.key,noAutomaticReplay:true,secretsPublished:false};
 if(!existsSync(artifact))writeFileSync(artifact,JSON.stringify(safe,null,2)+'\n',{flag:'wx'});
 console.error('M6_BROWSER_KEY_SCAN_STOPPED; original request retained and raw diagnostics withheld.');process.exitCode=1;
}finally{if(temporary)rmSync(temporary,{force:true});}
