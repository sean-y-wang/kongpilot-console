import { request as httpsRequest } from 'node:https';
import { randomUUID,createHash } from 'node:crypto';
const must=(c,k)=>{if(!c)throw Error(k);};
export function ordinaryV3HttpsContract(tls,suffix,input) {
  must(tls?.requiresTLS===true&&tls.rejectUnauthorized===true&&['127.0.0.1','localhost','::1'].includes(tls.hostname)
    &&Number.isInteger(tls.port)&&tls.port>0&&! [8001,8444,5445].includes(tls.port)
    &&tls.servername==='kongpilot-v3-acceptance.invalid'&&/^[a-f\d]{64}$/.test(tls.publicCaSha256),'V3_AUTHORIZED_HTTPS_PROFILE_REQUIRED');
  const origin=new URL(tls.origin);
  must(origin.protocol==='https:'&&origin.pathname==='/'&&!origin.search&&!origin.hash&&!origin.username&&!origin.password
    &&Number(origin.port)===tls.port&&(origin.hostname==='[::1]'?'::1':origin.hostname)===tls.hostname
    &&typeof tls.ca==='string'&&tls.ca.includes('BEGIN CERTIFICATE')&&!tls.ca.includes('PRIVATE KEY')
    &&createHash('sha256').update(tls.ca).digest('hex')===tls.publicCaSha256,'V3_EXACT_PUBLIC_CA_ORIGIN_REQUIRED');
  must(/^[a-f\d-]{36}$/.test(suffix)&&['GET','POST'].includes(input?.method),'V3_FIXED_HTTPS_METHOD_REQUIRED');
  const root=`/v3-oauth2-${suffix}`;
  must(input.method==='GET'?input.path===root:[`${root}/oauth2/authorize`,`${root}/oauth2/token`].includes(input.path),'V3_FIXED_HTTPS_PATH_REQUIRED');
  must(Array.isArray(input.expected)&&input.expected.length>0&&input.expected.every(n=>[200,400,401].includes(n)),'V3_FIXED_HTTPS_EXPECTATION_REQUIRED');
  must(input.method==='POST'?input.form&&input.headers===undefined:input.form===undefined,'V3_EXPLICIT_OAUTH_FORM_OR_GET_REQUIRED');
  must(Object.keys(input.headers??{}).every(k=>k==='authorization')&&Object.values(input.headers??{}).every(v=>typeof v==='string'&&!/[\r\n]/.test(v)),'V3_ONLY_FIXED_BEARER_HEADER_REQUIRED');
  if(input.form)must(Object.entries(input.form).every(([k,v])=>/^[a-z_]+$/.test(k)&&typeof v==='string'&&v.length<=4096&&!/[\r\n]/.test(v)),'V3_BOUNDED_FORM_REQUIRED');
  return {root,body:input.form?new URLSearchParams(input.form).toString():'',timeoutMs:10_000};
}
/** Business TLS only. Private mirrored journal is durable before the actual
 * single send. No redirects, retries, Native facts or token replay guarantees. */
export async function ordinaryV3HttpsOnce(h,g,label,tls,input) {
  const contract=ordinaryV3HttpsContract(tls,g.suffix,input);h.assertWritable();g.oauthPackets??=[];
  const full=`m11-v3-https-${g.suffix}-${label}`;must(!g.oauthPackets.some(p=>p.label===full)&&!h.state.requests.some(p=>p.label===full),'V3_ORIGINAL_TLS_REQUEST_EXISTS_NO_REPLAY');
  const p={label:full,key:randomUUID(),transport:'business-https',method:input.method,path:tls.origin+input.path,
    body:structuredClone(input.form??null),headers:structuredClone(input.headers??{}),servername:tls.servername,publicCaSha256:tls.publicCaSha256,
    rejectUnauthorized:true,preparedAt:new Date().toISOString(),state:'prepared',idempotencyGuarantee:false};
  g.oauthPackets.push(p);h.state.requests.push(p);h.save();
  let actual;
  try{actual=await new Promise((accept,reject)=>{
    let settled=false;const done=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):accept(value);};
    const req=httpsRequest({hostname:tls.hostname,port:tls.port,servername:tls.servername,ca:tls.ca,rejectUnauthorized:true,method:input.method,path:input.path,
      headers:{host:tls.servername,...(input.headers??{}),...(input.form?{'content-type':'application/x-www-form-urlencoded','content-length':Buffer.byteLength(contract.body)}:{})}},res=>{
      if(res.socket?.authorized!==true){res.destroy();done(Error('V3_TLS_NOT_AUTHORIZED'));return;}
      const chunks=[];let size=0;res.on('data',chunk=>{size+=Buffer.byteLength(chunk);if(size>65536){res.destroy();done(Error('V3_TLS_RESPONSE_LIMIT'));}else chunks.push(Buffer.from(chunk));});
      res.on('aborted',()=>done(Error('V3_TLS_INTERRUPTED')));res.on('error',()=>done(Error('V3_TLS_INTERRUPTED')));
      res.on('end',()=>done(null,{status:res.statusCode,bytes:Buffer.concat(chunks)}));
    });const timer=setTimeout(()=>{req.destroy();done(Error('V3_TLS_DEADLINE'));},contract.timeoutMs);req.on('error',()=>done(Error('V3_TLS_REQUEST_FAILED')));req.end(contract.body);
  });}catch{p.state='response_unknown';h.save();throw Error('V3_TLS_UNKNOWN_ORIGINAL_RETAINED_NO_REPLAY');}
  let body;try{body=JSON.parse(actual.bytes.toString('utf8'));}catch{body=null;}
  Object.assign(p,{state:'response_observed',status:actual.status,responseData:body,responseHash:createHash('sha256').update(actual.bytes).digest('hex')});h.save();
  must(input.expected.includes(actual.status)&&body&&typeof body==='object','V3_ACTUAL_TLS_STATUS_AND_JSON_REQUIRED_NO_RETRY');
  return {status:actual.status,body,tlsAuthorized:true};
}
