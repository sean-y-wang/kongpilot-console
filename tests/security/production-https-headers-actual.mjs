import{readFileSync,existsSync}from'node:fs';import{durableProductionJson}from'./lib/production-ui-storage.mjs';
const path='artifacts/Production/root-production-https-response-cookie-headers-actual.json';if(existsSync(path))throw Error('HTTPS_HEADER_REPORT_EXISTS');
const checks=[],responses=[];
for(const origin of['https://localhost:18443','https://127.0.0.1:19443']){
 const r=await fetch(origin+'/',{redirect:'manual',signal:AbortSignal.timeout(10000)});await r.arrayBuffer();
 const fields=Object.fromEntries(['content-security-policy','x-frame-options','x-content-type-options','strict-transport-security','referrer-policy','permissions-policy'].map(k=>[k,r.headers.get(k)]));
 checks.push({name:'actual HTTPS response has CSP, DENY framing, one nosniff and HSTS',origin,passed:r.status===200&&!!fields['content-security-policy']&&fields['x-frame-options']==='DENY'&&fields['x-content-type-options']==='nosniff'&&fields['strict-transport-security']?.includes('max-age=31536000')&&!!fields['referrer-policy']&&!!fields['permissions-policy']});responses.push({origin,status:r.status,fields});
}
const state=JSON.parse(readFileSync('/tmp/kongos-production-runtime-secrets.json'));
const auth=state.requests.filter(p=>['/api/v1/auth/login','/api/v1/auth/refresh'].includes(p.path)&&p.status===201);
const cookies=auth.flatMap(p=>(p.responseCookies??[]).filter(c=>/^kongos_(access|refresh|csrf)=/.test(c)));
const flags=cookies.map(c=>({name:c.slice(0,c.indexOf('=')),secure:/;\s*Secure(?:;|$)/i.test(c),httpOnly:/;\s*HttpOnly(?:;|$)/i.test(c),sameSite:/;\s*SameSite=Strict(?:;|$)/i.test(c),path:(c.match(/;\s*Path=([^;]+)/i)||[])[1]}));
checks.push({name:'actual server Set-Cookie flags are Secure, HttpOnly and SameSite Strict',passed:flags.length>=3&&flags.every(c=>c.secure&&c.httpOnly&&c.sameSite&&c.path===(c.name==='kongos_refresh'?'/api/v1/auth':'/api'))});
const report={performedAt:new Date().toISOString(),allPassed:checks.every(c=>c.passed),checks,responses,cookieFlags:flags,authenticationRequestsReplayed:0,tlsVerificationDisabled:false};durableProductionJson(path,report,true,0o644);console.log(JSON.stringify({allPassed:report.allPassed,checks:checks.length,actualCookiesChecked:flags.length}));
