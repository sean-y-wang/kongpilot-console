import { describe, expect, it } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
// @ts-expect-error shared JavaScript tool policy.
import { verifiedPublicOAuthTokenType } from './lib/production-secret-scan-provenance.mjs';
const fixture=()=>{
 const f={area:{cid:randomUUID(),wid:randomUUID()},consumer:{id:randomUUID()},inputs:{oauth2:{client_id:'synthetic-client',client_secret:'synthetic-secret-only'}},routes:{oauth2:{proxyPath:'/m8/synthetic/oauth2'}}};
 const body={grant_type:'client_credentials',...f.inputs.oauth2};
 return{nativeFixture:f,requests:[],proxyChecks:[{key:randomUUID(),method:'POST',state:'response_observed',status:200,tls:true,tlsAuthorized:true,clusterId:f.area.cid,workspaceId:f.area.wid,originalConsumerId:f.consumer.id,project:'kongos-prod-m08-20261012-a3',path:f.routes.oauth2.proxyPath+'/oauth2/token',body,bodySha256:createHash('sha256').update(JSON.stringify(body)).digest('hex'),responseData:{token_type:'bearer',access_token:'synthetic-opaque-access-token-only'}}]};
};
describe('actual OAuth token type provenance without suppressing real credentials',()=>{
 it('classifies only the public token_type and retains opaque tokens',()=>{const s=fixture();expect(verifiedPublicOAuthTokenType(s,'bearer')).toBe(true);expect(verifiedPublicOAuthTokenType(s,s.proxyChecks[0].responseData.access_token)).toBe(false);});
 it('requires the original complete TLS body and exact Consumer/cluster identity',()=>{for(const change of [(p:any)=>p.tlsAuthorized=false,(p:any)=>p.clusterId=randomUUID(),(p:any)=>p.state='response_unknown',(p:any)=>p.body.client_id='changed',(p:any)=>p.originalConsumerId=randomUUID()]){const s=fixture();change(s.proxyChecks[0]);expect(verifiedPublicOAuthTokenType(s,'bearer')).toBe(false);}});
 it('keeps the value secret if it is an actual password/key or deployment secret',()=>{const s:any=fixture();s.requests=[{body:{password:'bearer'}}];expect(verifiedPublicOAuthTokenType(s,'bearer')).toBe(false);expect(verifiedPublicOAuthTokenType(fixture(),'bearer',['bearer'])).toBe(false);});
});
