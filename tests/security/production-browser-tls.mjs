import{chromium}from'@playwright/test';
import{execFileSync}from'node:child_process';
import{existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync}from'node:fs';
import{homedir}from'node:os';
import{join}from'node:path';
import{X509Certificate,createHash}from'node:crypto';
import{durableJson}from'./lib/m8-harness.mjs';

if(process.env.PRODUCTION_TLS_EXCLUSIVE_READY!=='true')throw Error('PRODUCTION_TLS_EXCLUSIVE_HANDOFF_REQUIRED');
const continuation=process.argv.includes('--known-public-trust-continuation');
const certificate='artifacts/Production/root-production-public-ca.pem',ca=readFileSync(certificate),digest=b=>createHash('sha256').update(b).digest('hex'),der=digest(new X509Certificate(ca).raw),db=join(homedir(),'.pki/nssdb'),nickname='KongOS production m08-a3 '+der.slice(0,12),path=continuation?'artifacts/Production/root-production-browser-node-tls-text-checked.json':'artifacts/Production/root-production-browser-node-tls.json',trustPath='artifacts/Production/root-production-nss-trust-installed.json';
if(existsSync(path)||!continuation&&existsSync(trustPath))throw Error('PRODUCTION_TLS_ORIGINAL_REPORT_EXISTS');
const command=args=>execFileSync('certutil',args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:10000});
let created=false;
if(!existsSync(db)){const parent=join(homedir(),'.pki');if(!existsSync(parent))mkdirSync(parent,{mode:0o700});mkdirSync(db,{mode:0o700});command(['-N','-d','sql:'+db,'--empty-password']);created=true;}
const stat=lstatSync(db);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o022))throw Error('PRODUCTION_NSS_DIRECTORY_INVALID');
function publicTrust(){const text=command(['-L','-d','sql:'+db]);return text.split('\n').flatMap(line=>{const match=/^(.*?)\s{2,}([A-Za-z,]+)\s*$/.exec(line);if(!match||match[1].trim()==='Certificate Nickname')return[];const name=match[1].trim();try{const pem=command(['-L','-d','sql:'+db,'-n',name,'-a']);return[{nickname:name,flags:match[2],derSha256:digest(new X509Certificate(pem).raw)}];}catch{throw Error('PRODUCTION_NSS_PUBLIC_CERT_READ_FAILED');}}).sort((a,b)=>a.nickname.localeCompare(b.nickname));}
const installed=continuation?JSON.parse(readFileSync(trustPath)):null;
const before=continuation?installed.beforePublicTrust:publicTrust();
if(continuation){const previous=JSON.parse(readFileSync('artifacts/Production/root-production-browser-node-tls.json'));if(installed.rootDerSha256!==der||installed.db!==db||installed.nickname!==nickname||installed.allPassed!==true||previous.allPassed!==false||previous.authenticationWrites!==0||previous.businessWrites!==0||previous.checks.length!==6||previous.checks.filter(v=>v.passed).length!==4)throw Error('PRODUCTION_TLS_FIXED_KNOWN_TRUST_REQUIRED');}
else{if(before.some(r=>r.nickname===nickname||r.derSha256===der))throw Error('PRODUCTION_NSS_CERT_ALREADY_PRESENT_NO_OVERWRITE');command(['-A','-d','sql:'+db,'-n',nickname,'-t','C,,','-i',certificate]);}
const after=publicTrust(),actual=after.find(r=>r.nickname===nickname);if(actual?.derSha256!==der||actual.flags!=='C,,'||JSON.stringify(after.filter(r=>r.nickname!==nickname))!==JSON.stringify(before))throw Error('PRODUCTION_NSS_TRUST_INSTALL_INVALID');
if(!continuation)durableJson(trustPath,{performedAt:new Date().toISOString(),allPassed:true,db,nickname,rootDerSha256:der,createdNewDatabase:created,beforePublicTrust:before,oldPublicTrustPreserved:true,privateKeysRead:false,cleanupPending:true},0o644,true);
let browser,context;const checks=[];let error;
try{
 browser=await chromium.launch({headless:true,executablePath:'/usr/bin/chromium'});context=await browser.newContext({serviceWorkers:'block'});const page=await context.newPage();
 for(const origin of['https://localhost:18443','https://127.0.0.1:19443']){
  const r=await page.goto(origin+'/healthz',{waitUntil:'domcontentloaded'});checks.push({name:'strict Chromium real TLS health',origin,passed:r?.status()===200&&(await page.locator('body').innerText()).trim()==='ok',actualStatus:r?.status()});
  const n=await context.request.get(origin+'/healthz');checks.push({name:'strict Node request channel real TLS health',origin,passed:n.status()===200&&(await n.text()).trim()==='ok'});
 }
 let mismatch;try{await page.goto('https://127.0.0.1:18443/healthz');}catch(e){mismatch=/ERR_CERT_COMMON_NAME_INVALID/.test(String(e));}checks.push({name:'Chromium rejects reachable wrong SAN hostname',passed:mismatch===true});
 let nodeMismatch;try{await context.request.get('https://127.0.0.1:18443/healthz');}catch(e){nodeMismatch=/Hostname\/IP does not match|not in the cert|ERR_TLS_CERT_ALTNAME_INVALID/.test(String(e));}checks.push({name:'Node rejects reachable wrong SAN hostname',passed:nodeMismatch===true});
 if(checks.some(v=>!v.passed))throw Error('PRODUCTION_TLS_ASSERTION_FAILED');
}catch(e){error=true;}finally{await context?.close();await browser?.close();}
durableJson(path,{performedAt:new Date().toISOString(),allPassed:!error,passed:checks.filter(v=>v.passed).length,failed:checks.filter(v=>!v.passed).length+(error?1:0),checks,rootDerSha256:der,certificateValidationDisabled:false,authenticationWrites:0,businessWrites:0,systemHostsChanged:false,homeChanged:false,nssTrustReport:trustPath,nssCleanupPending:true},0o644,true);console.log(JSON.stringify({allPassed:!error,checks:checks.length,failed:checks.filter(v=>!v.passed).length}));process.exitCode=error?1:0;
