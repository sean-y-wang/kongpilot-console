import { createHash } from 'node:crypto';
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const uuid=v=>typeof v==='string'&&/^[a-f\d-]{36}$/i.test(v);

/** OAuth token_type describes the authorization scheme. The opaque access
 * token remains secret. Only an original successful, verified TLS token
 * exchange can classify this captured value as public metadata. */
export function verifiedPublicOAuthTokenType(state,value,actualSecretMaterials=[]){
 if(typeof value!=='string'||value.toLowerCase()!=='bearer'||actualSecretMaterials.includes(value))return false;
 const f=state.nativeFixture;if(!f?.inputs?.oauth2||!f.routes?.oauth2)return false;
 let genuineSecret=false;
 const inspect=node=>{if(!node||typeof node!=='object')return;for(const[k,v]of Object.entries(node)){if(typeof v==='string'&&/^(?:password|secret|key|client_secret|provision_key|private_key|access_token|refresh_token|csrfToken)$/i.test(k)&&v===value)genuineSecret=true;else if(v&&typeof v==='object')inspect(v);}};
 inspect(f.inputs);inspect(state.requests?.map(p=>p.body));
 if(genuineSecret)return false;
 return (state.proxyChecks??[]).some(p=>uuid(p.key)&&p.method==='POST'&&p.state==='response_observed'&&p.status===200&&p.tls===true&&p.tlsAuthorized===true
  &&p.clusterId===f.area.cid&&p.workspaceId===f.area.wid&&p.originalConsumerId===f.consumer.id
  &&['kongos-prod-m08-20261012-a3','kongos-restore-m08-20261012-a3'].includes(p.project)
  &&p.path===f.routes.oauth2.proxyPath+'/oauth2/token'&&p.bodySha256===digest(p.body)
  &&p.body?.grant_type==='client_credentials'&&p.body.client_id===f.inputs.oauth2.client_id&&p.body.client_secret===f.inputs.oauth2.client_secret
  &&p.responseData?.token_type===value&&typeof p.responseData.access_token==='string'&&p.responseData.access_token.length>=16&&p.responseData.access_token!==value);
}
