import{execFileSync}from'node:child_process';import{randomUUID}from'node:crypto';
import{productionDigest}from'./production-http-harness.mjs';
import{CREDENTIAL_KINDS,jwtAuthorization,hmacAuthorization}from'./m8-native-acceptance.mjs';
const socket='unix:///dev/shm/kongos-production-ram-m08-20261012-a3/run/docker-production.sock';
export async function productionProxy(h,fixture,path,{method='GET',headers={},body,tls=false,restored=false,expected}={}){
 if(!path.startsWith(`/m8/${h.state.testTag}/`)||!['GET','POST'].includes(method))throw Error('PRODUCTION_PROXY_FIXED_FIXTURE_REQUIRED');
 const project=restored?'kongos-restore-m08-20261012-a3':'kongos-prod-m08-20261012-a3';
 const details=JSON.parse(execFileSync('docker',[`--host=${socket}`,'inspect',`${project}-kong-1`],{stdio:['ignore','pipe','pipe']}))[0];
 const address=details.NetworkSettings.Networks[project+'_proxy-edge'].IPAddress;
 const certificate=h.state.requests.find(p=>p.method==='POST'&&p.responseData?.entity?.id===fixture.certificate.id&&p.path.endsWith('/entities/certificates'))?.body.cert;
 if(tls&&!certificate)throw Error('PRODUCTION_ORIGINAL_TLS_CERTIFICATE_REQUIRED');
 const packet={key:randomUUID(),path,method,headers,body:body??null,tls,restored,project,clusterId:fixture.area.cid,workspaceId:fixture.area.wid,originalConsumerId:fixture.consumer.id,state:'prepared',startedAt:new Date().toISOString(),bodySha256:productionDigest(JSON.stringify(body??null))};
 h.state.proxyChecks??=[];h.state.proxyChecks.push(packet);h.remember(body);for(const[k,v]of Object.entries(headers))if(/authorization|apikey/i.test(k))h.state.secrets.push(v);h.save();
 const code=`const fs=require('fs'),p=JSON.parse(fs.readFileSync(0,'utf8'));let n=0;const done=(status,b,authorized)=>process.stdout.write(JSON.stringify({status,body:b,authorized}));if(p.tls){const q=require('https').request({hostname:p.address,port:8443,servername:p.servername,ca:p.certificate,rejectUnauthorized:true,path:p.path,method:p.method,headers:p.headers,timeout:10000},r=>{const authorized=r.socket?.authorized===true;const chunks=[];r.on('data',b=>{n+=b.length;if(n>1048576){r.destroy();process.exitCode=1;}else chunks.push(b)});r.on('end',()=>done(r.statusCode,Buffer.concat(chunks).toString(),authorized));});q.on('error',()=>process.exit(1));q.end(p.body===null?undefined:JSON.stringify(p.body));}else{fetch('http://127.0.0.1:'+p.port+p.path,{method:p.method,headers:p.headers,signal:AbortSignal.timeout(10000),redirect:'manual',...(p.body===null?{}:{body:JSON.stringify(p.body)})}).then(async r=>done(r.status,await r.text(),null)).catch(()=>process.exit(1));}`;
 let result;try{result=JSON.parse(execFileSync('docker',['--host=unix:///var/run/docker.sock','exec','-i','kongos-ram-tool-m08-20261012-a3','node','-e',code],{input:JSON.stringify({address,port:restored?28000:18000,path,method,headers,body:body??null,tls,certificate,servername:`${h.state.testTag}.invalid`}),stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:2*1024**2}));}catch{packet.state='response_unknown';h.save();throw Error('PRODUCTION_PROXY_RESPONSE_UNKNOWN_NO_POST_REPLAY');}
 let payload;try{payload=JSON.parse(result.body);}catch{}h.remember(payload,true);Object.assign(packet,{state:'response_observed',status:result.status,responseSha256:productionDigest(result.body),responseData:payload??null,tlsAuthorized:result.authorized});h.save();
 if(tls)h.check(result.authorized===true,'actual native proxy verifies original SNI certificate');
 if(expected!==undefined)h.check(result.status===expected,'actual native proxy status matches expectation',{status:result.status,expected});
 return{...result,payload};
}
export async function productionSixCredentials(h,fixture,stage,restored=false){
 const checks=[];
 for(const kind of CREDENTIAL_KINDS){
  const input=fixture.inputs[kind],path=fixture.routes[kind].proxyPath+'/echo';let headers;
  if(['key-auth','acls'].includes(kind))headers={apikey:fixture.inputs['key-auth'].key};
  else if(kind==='basic-auth')headers={Authorization:'Basic '+Buffer.from(input.username+':'+input.password).toString('base64')};
  else if(kind==='jwt')headers={Authorization:jwtAuthorization(input)};
  else if(kind==='hmac-auth'){const date=new Date().toUTCString();headers={Date:date,Authorization:hmacAuthorization(input,date)};}
  else{const token=await productionProxy(h,fixture,fixture.routes.oauth2.proxyPath+'/oauth2/token',{method:'POST',tls:true,restored,headers:{'Content-Type':'application/json'},body:{grant_type:'client_credentials',client_id:input.client_id,client_secret:input.client_secret},expected:200});h.check(typeof token.payload?.access_token==='string','actual TLS OAuth client-credentials issues fresh token');headers={Authorization:'Bearer '+token.payload.access_token};}
  let actual;const until=Date.now()+20000;
  do{actual=await productionProxy(h,fixture,path,{headers,tls:kind==='oauth2',restored});if(actual.status===200)break;await new Promise(r=>setTimeout(r,500));}while(Date.now()<until);
  h.check(actual.status===200&&actual.payload?.consumerId===fixture.consumer.id&&actual.payload?.upstream==='kongos-test','actual six credential types reach exact original Consumer',{kind,stage});checks.push({kind,passed:true,consumerId:fixture.consumer.id});
 }
 h.state.credentialStages??=[];h.state.credentialStages.push({stage,restored,checks});h.save();return checks;
}
