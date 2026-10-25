import{createServer}from'node:https';import{request}from'node:https';
import{mkdtempSync,readFileSync,chmodSync,writeFileSync,existsSync}from'node:fs';import{execFileSync}from'node:child_process';
import{join}from'node:path';import{chromium}from'@playwright/test';
import{durableProductionJson}from'./lib/production-ui-storage.mjs';
const continuation=process.env.TLS_NEGATIVE_NODE_LOOKUP_CONTINUATION==='true';
const reportPath=continuation?'artifacts/Production/root-production-untrusted-expired-tls-node-address-corrected.json':'artifacts/Production/root-production-untrusted-expired-tls-actual.json';
if(existsSync(reportPath))throw Error('TLS_NEGATIVE_REPORT_EXISTS');
const dir=continuation?JSON.parse(readFileSync('/tmp/kongos-production-tls-negative-private-reference.json')).directory:mkdtempSync('/dev/shm/kongos-production-tls-negative-');chmodSync(dir,0o700);
if(continuation){const original=JSON.parse(readFileSync('artifacts/Production/root-production-untrusted-expired-tls-actual.json'));if(original.passed!==2||original.failed!==2||original.checks.filter(c=>c.name.startsWith('Node')).some(c=>c.actualCode!=='ERR_INVALID_IP_ADDRESS'))throw Error('TLS_EXACT_LOOKUP_FAILURE_REQUIRED');}
const ca=readFileSync('artifacts/Production/root-production-public-ca.pem');
const sign='/dev/shm/kongos-production-ram-m08-20261012-a3/private/production/tls/ca';
const openssl=args=>{try{return execFileSync('openssl',args,{stdio:['ignore','pipe','pipe']});}catch{throw Error('TLS_NEGATIVE_CERTIFICATE_GENERATION_FAILED');}};
if(!continuation){
openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'untrusted.key'),'-out',join(dir,'untrusted.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost']);
openssl(['req','-new','-newkey','rsa:2048','-nodes','-keyout',join(dir,'expired.key'),'-out',join(dir,'expired.csr'),'-subj','/CN=localhost']);
writeFileSync(join(dir,'extensions'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n',{mode:0o600});
writeFileSync(join(dir,'index'),'',{mode:0o600});writeFileSync(join(dir,'serial'),'0997\n',{mode:0o600});
writeFileSync(join(dir,'ca.cnf'),`[ca]\ndefault_ca=local\n[local]\ndatabase=${dir}/index\nserial=${dir}/serial\nnew_certs_dir=${dir}\ncertificate=${sign}/ca.crt\nprivate_key=${sign}/ca.key\ndefault_md=sha256\npolicy=policy\nx509_extensions=server\n[policy]\ncommonName=supplied\n[server]\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n`,{mode:0o600});
openssl(['ca','-batch','-notext','-config',join(dir,'ca.cnf'),'-startdate','20251001000000Z','-enddate','20251002000000Z','-in',join(dir,'expired.csr'),'-out',join(dir,'expired.crt')]);
for(const name of['untrusted.key','expired.key'])chmodSync(join(dir,name),0o600);
}
const checks=[];let browser;
try{
 browser=await chromium.launch({headless:true,executablePath:'/usr/bin/chromium'});
 for(const [kind,nodeCode,browserCode]of[['untrusted','DEPTH_ZERO_SELF_SIGNED_CERT','ERR_CERT_AUTHORITY_INVALID'],['expired','CERT_HAS_EXPIRED','ERR_CERT_DATE_INVALID']]){
  const server=createServer({key:readFileSync(join(dir,kind+'.key')),cert:readFileSync(join(dir,kind+'.crt'))},(_,res)=>res.end('TLS must reject this response'));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;
  try{
   const code=await new Promise(resolve=>{const req=request({hostname:'127.0.0.1',servername:'localhost',port,ca,rejectUnauthorized:true},res=>{res.resume();resolve('ACCEPTED');});req.on('error',e=>resolve(e.code));req.end();});
   checks.push({name:`Node rejects ${kind} certificate`,passed:code===nodeCode,actualCode:code});
   const context=await browser.newContext();const page=await context.newPage();let error='ACCEPTED';try{await page.goto(`https://localhost:${port}`,{timeout:15000});}catch(e){error=e.message.includes(browserCode)?browserCode:'UNEXPECTED_BROWSER_ERROR';}await context.close();
   checks.push({name:`Chromium rejects ${kind} certificate`,passed:error===browserCode,actualCode:error});
  }finally{await new Promise(r=>server.close(r));}
 }
}finally{await browser?.close();}
if(!continuation)durableProductionJson('/tmp/kongos-production-tls-negative-private-reference.json',{directory:dir,secrets:['untrusted.key','expired.key'].map(n=>readFileSync(join(dir,n),'utf8'))},true);
const report={performedAt:new Date().toISOString(),allPassed:checks.every(c=>c.passed),checks,passed:checks.filter(c=>c.passed).length,failed:checks.filter(c=>!c.passed).length,tlsVerificationDisabled:false,productionBusinessRequests:0};durableProductionJson(reportPath,report,true,0o644);console.log(JSON.stringify(report));
