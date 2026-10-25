import{readFileSync,writeFileSync}from'node:fs';
import{execFileSync}from'node:child_process';
import{createHash}from'node:crypto';
import{captureOutboxRepairSnapshot,outboxRepairChecks}from'./verify-m7-outbox-repair-continuity.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex'),freezePath='artifacts/M8/root-deck-schema-set-envelope-fix-freeze.json',freezeHash='daf2f061162a7952e66cf2c95ab92ca23a0f02f971e3c127dee393dc104143b7',closePath='artifacts/M8/deck-set-original-unknown-sync-close.json',closeHash='18a28da1091cf28a89ad1a7341b7644bd72ab8cd78b07cce89d95ecf234974fd';
if(process.env.M8_DECK_SET_API_RELOAD_READY!=='true')throw Error('M8_SET_API_ONLY_RELOAD_RELEASE_REQUIRED');
const run=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:30000});
const freezeBytes=readFileSync(freezePath),closeBytes=readFileSync(closePath),f=JSON.parse(freezeBytes),closed=JSON.parse(closeBytes);
if(hash(freezeBytes)!==freezeHash||hash(closeBytes)!==closeHash||!closed.allPassed||closed.originalUnknownCliRetained!==true||closed.newNativeWrites!==0)throw Error('M8_SET_EXACT_CLOSURE_AND_SOURCE_REQUIRED');
for(const ref of [...f.apiSources,...f.compiledAPI.files,...f.sql000Through011])if(hash(readFileSync(ref.path))!==ref.sha256)throw Error('M8_SET_SOURCE_FREEZE_CHANGED');
const output='artifacts/M8/deck-schema-set-api-repair-continuity.json';
const snapshot=async()=>{
 const v=captureOutboxRepairSnapshot(),assets=[];
 for(const base of ['http://127.0.0.1:8080','http://127.0.0.1:8082']){
  const page=await fetch(base,{signal:AbortSignal.timeout(10000)}),bytes=Buffer.from(await page.arrayBuffer());if(page.status!==200)throw Error('M8_SET_STATIC_NOT_READY');
  assets.push({base,path:'/',status:200,sha256:hash(bytes)});
  const paths=[...new Set([...bytes.toString().matchAll(/(?:src|href)="(\/assets\/[^"<>]+)"/g)].map(m=>m[1]))];
  for(const path of paths){const r=await fetch(base+path,{signal:AbortSignal.timeout(10000)}),b=Buffer.from(await r.arrayBuffer());if(r.status!==200)throw Error('M8_SET_STATIC_NOT_READY');assets.push({base,path,status:r.status,sha256:hash(b)});}
 }v.actualStaticAssets=assets;return v;
};
let before,after,error,checks=[];
try{
 before=await snapshot();writeFileSync('artifacts/M8/deck-schema-set-api-repair-before.json',JSON.stringify(before,null,2)+'\n',{flag:'wx'});
 const api=before.services.find(s=>s.name==='console-api');if(!api||api.health!=='healthy'||before.services.length!==22)throw Error('M8_SET_PROTECTED_RUNTIME_REQUIRED');
 const info=JSON.parse(run(['inspect',api.id]))[0],mount=info.Mounts.find(m=>m.Destination==='/app/apps/console-api/dist');
 if(mount?.RW!==false||mount.Source!==`${process.cwd()}/apps/console-api/dist`)throw Error('M8_SET_EXACT_READONLY_BIND_REQUIRED');
 run(['restart',api.id]);
 for(let n=0;n<50;n++){const current=JSON.parse(run(['inspect',api.id]))[0];if(current.State.Health?.Status==='healthy'&&Date.parse(current.State.StartedAt)>Date.parse(api.startedAt))break;if(n===49)throw Error('M8_SET_API_RELOAD_NOT_READY');await new Promise(r=>setTimeout(r,1000));}
 const program=`const fs=require('fs'),p=require('path'),c=require('crypto');const a=[];function walk(d){for(const n of fs.readdirSync(d).sort()){const f=p.join(d,n);if(fs.statSync(f).isDirectory())walk(f);else if(f.endsWith('.js'))a.push({path:f.replace('/app/',''),sha256:c.createHash('sha256').update(fs.readFileSync(f)).digest('hex')});}}walk('/app/apps/console-api/dist');console.log(JSON.stringify(a));`;
 const installed=JSON.parse(run(['exec',api.id,'node','-e',program])),expected=f.compiledAPI.files.map(x=>({path:x.path,sha256:x.sha256}));
 checks.push({name:'actual installed223 readonly API JavaScript matches the exact frozen schema-set repair',passed:installed.length===223&&JSON.stringify(installed)===JSON.stringify(expected)});
 after=await snapshot();writeFileSync('artifacts/M8/deck-schema-set-api-repair-after.json',JSON.stringify(after,null,2)+'\n',{flag:'wx'});
 checks.push(...outboxRepairChecks(before,after),{name:'actual Console and Portal HTTP static files unchanged',passed:JSON.stringify(before.actualStaticAssets)===JSON.stringify(after.actualStaticAssets)}, {name:'all22 identities and18 healthy running services retained',passed:after.services.length===22&&after.services.filter(s=>s.status==='running'&&s.health==='healthy').length===18});
 if(checks.some(c=>!c.passed))throw Error('M8_SET_CONTINUITY_CHECK_FAILED');
}catch(e){error=e;}
const report={version:1,milestone:'M8',label:'deck-schema-set-api-only-repair',performedAt:new Date().toISOString(),allPassed:!error,passed:checks.filter(c=>c.passed).length,failed:error?Math.max(1,checks.filter(c=>!c.passed).length):0,checks,freeze:{path:freezePath,sha256:freezeHash},originalSyncClose:{path:closePath,sha256:closeHash},sourceCount:223,installedJsCount:223,compiledChanged:2,compiledUnchanged:221,apiRestarts:before?1:0,builds:0,recreates:0,migrations:0,webChanges:0,portalChanges:0,nginxReloads:0,authenticationWrites:0,businessWrites:0,nativeWrites:0,cliIntents:0,errorCode:error?.message??null};
writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({path:output,sha256:hash(readFileSync(output)),allPassed:report.allPassed,passed:report.passed,failed:report.failed,errorCode:report.errorCode}));if(error)process.exitCode=1;
