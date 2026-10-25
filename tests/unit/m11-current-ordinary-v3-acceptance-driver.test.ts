import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {request as httpsRequest} from 'node:https';
import {readFileSync} from 'node:fs';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {CREDENTIAL_KINDS,ORDINARY_V3_FIELD,ORDINARY_V3_PRODUCT_PATCH,ORDINARY_V3_STAGES,ordinaryV3Gate,ordinaryV3Session,ordinaryV3Policy,ordinaryV3Vote,
  ordinaryV3GraphSpecs,ordinaryV3Archive,ordinaryV3Inputs,ordinaryV3PublicSummary,ordinaryV3CaseSelection,runOrdinaryV3Stage} from '../security/m11-current-ordinary-v3-acceptance.mjs';
import {ordinaryV3ReceiptProof} from '../security/lib/ordinary-v3-readonly-proof.mjs';
import {syntheticV3Certificate} from './helpers/m11-v3-public-synthetic-tls-fixture.mjs';
import {ordinaryV3HttpsContract,ordinaryV3HttpsOnce} from '../security/lib/ordinary-v3-https-probe.mjs';
vi.mock('node:https',()=>({request:vi.fn()}));
const attestation=()=>({operatorConfirmed:true,noUnknownReplay:true,productPatchSha256:ORDINARY_V3_PRODUCT_PATCH,deployedSourceDigest:'ab'.repeat(32),deployedAt:new Date().toISOString()});
const session=()=>{const user={id:randomUUID()},sid=randomUUID(),claims=Buffer.from(JSON.stringify({sub:user.id,sid,exp:Math.floor(Date.now()/1000)+3600})).toString('base64url');return{user,sid,cookie:`kongos_access=e30.${claims}.source-only`};};
const scope=()=>({m9:Object.fromEntries(['upstreamId','targetId','serviceId','routeId','pluginId'].map(k=>[k,randomUUID()])),consumerId:randomUUID(),credentialIds:Object.fromEntries(CREDENTIAL_KINDS.map(k=>[k,randomUUID()])),certificateId:randomUUID(),sniId:randomUUID()});
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','a9'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-v3-proof-test-key'.repeat(3));});afterEach(()=>vi.unstubAllEnvs());
describe('Root-only ordinary V3 driver pure Source contracts, no live ledger/HTTP/SQL',()=>{
  it('requires an explicit safe fixture for a new cohort and preserves the default selector',()=>{
    expect(ordinaryV3CaseSelection({}).field).toBe(ORDINARY_V3_FIELD);
    for(const [id,field]of [['../old','fixture'],['original','fixture'],['next','__proto__'],['next',undefined]]){
      expect(()=>ordinaryV3CaseSelection({RELEASE_LAB_M11_CURRENT_ORDINARY_V3_CASE:id,RELEASE_LAB_M11_CURRENT_ORDINARY_V3_FIXTURE:field})).toThrow();
    }
  });
  it('allocates a fresh case without altering or replaying the failed original case',async()=>{
    const admin=session(),reviewer=session(),m9=scope().m9,old={version:1,m9,stages:{'init-fixtures':{state:'stopped-no-replay'}},inputs:{key:'old-private-source-only'}};
    const original=JSON.stringify(old),env={RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY:'true',RELEASE_LAB_M11_CURRENT_ORDINARY_V3_CASE:'fresh-source-case',RELEASE_LAB_M11_CURRENT_ORDINARY_V3_FIXTURE:'freshFixture'};
    const h:any={state:{cid:randomUUID(),wid:randomUUID(),sessions:{admin},metadataAcceptance:{reviewerSession:reviewer,freshFixture:m9},requests:[],[ORDINARY_V3_FIELD]:old},save:vi.fn(),assertWritable:vi.fn(),request:vi.fn(async()=>{throw Error('CONTROLLED_READ_STOP');}),once:vi.fn()};
    const result=await runOrdinaryV3Stage(h,'init-fixtures',{env,attestation:attestation(),certificate:syntheticV3Certificate});
    expect(result.passed).toBe(false);expect(JSON.stringify(old)).toBe(original);expect(h.once).not.toHaveBeenCalled();
    const selection=ordinaryV3CaseSelection(env),fresh=h.state[selection.field];
    expect(fresh.caseBinding).toEqual(selection);expect(fresh.inputs['key-auth'].key).not.toBe(old.inputs.key);expect(fresh.stages['init-fixtures'].state).toBe('stopped-no-replay');
    await expect(runOrdinaryV3Stage(h,'init-fixtures',{env,attestation:attestation(),certificate:syntheticV3Certificate})).rejects.toThrow('V3_ORIGINAL_FIELD_EXISTS_NO_REPLAY');
  });
  it('refuses shared graph fixtures after any prior graph-changing stage has started',async()=>{
    const admin=session(),reviewer=session(),m9=scope().m9;
    const h:any={state:{cid:randomUUID(),wid:randomUUID(),sessions:{admin},metadataAcceptance:{reviewerSession:reviewer,freshFixture:m9},requests:[],[ORDINARY_V3_FIELD]:{m9,stages:{'init-fixtures':{state:'succeeded'},'delete-service':{state:'stopped-no-replay'}}}},save:vi.fn(),assertWritable:vi.fn(),request:vi.fn(),once:vi.fn()};
    await expect(runOrdinaryV3Stage(h,'init-fixtures',{env:{RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY:'true',RELEASE_LAB_M11_CURRENT_ORDINARY_V3_CASE:'fresh-source-case',RELEASE_LAB_M11_CURRENT_ORDINARY_V3_FIXTURE:'freshFixture'},attestation:attestation(),certificate:syntheticV3Certificate})).rejects.toThrow('V3_PRIOR_GRAPH_ALREADY_USED');
    expect(h.save).not.toHaveBeenCalled();expect(h.request).not.toHaveBeenCalled();expect(h.once).not.toHaveBeenCalled();
  });
  it('rejects an unconfirmed deployment before touching even an injected harness state',async()=>{
    const h:any={get state(){throw Error('PRIVATE_STATE_MUST_NOT_BE_READ');}};
    await expect(runOrdinaryV3Stage(h,'delete-service',{env:{},attestation:attestation()})).rejects.toThrow('V3_ROOT_EXPLICIT_EXECUTION_GATE_REQUIRED');
  });
  it.each(['patch','operator','source','date','replay','stage'])('rejects missing exact %s deployment binding',kind=>{
    const a:any=attestation();if(kind==='patch')a.productPatchSha256='ab'.repeat(32);if(kind==='operator')a.operatorConfirmed=false;if(kind==='source')delete a.deployedSourceDigest;if(kind==='date')a.deployedAt='3000-01-01';if(kind==='replay')a.noUnknownReplay=false;
    expect(()=>ordinaryV3Gate({RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY:'true'},a,kind==='stage'?'retry-delete-service':'delete-service')).toThrow();
  });
  it('checks actual access sub/SID and rejects stale sessions before Harness can refresh',()=>{
    const s=session();expect(ordinaryV3Session(s)).toBe(s);expect(()=>ordinaryV3Session({...s,sid:randomUUID()})).toThrow();expect(()=>ordinaryV3Session(s,Date.now()+3600_000)).toThrow('V3_FRESH_SESSION_REQUIRED_NO_REFRESH');
  });
  it('requires the actual independent one-stage policy and integer vote tuple from current detail',()=>{
    const a=randomUUID(),r=randomUUID(),policy={format:2,kind:'native-change',status:'active',policy:{version:2,kind:'native-change',allowSelfApproval:false,distinctAcrossStages:true,stages:[{mode:'any',threshold:1,selector:{users:[r]}}]}};
    expect(ordinaryV3Policy({items:[policy]},a,r)).toBe(policy);expect(()=>ordinaryV3Policy({items:[policy]},r,r)).toThrow();
    const d={state:'pending',revision:3,planHash:'ab'.repeat(32),approval:{format:2,candidateVersion:2,stages:[{state:'active',level:1,revision:4}]}};
    expect(ordinaryV3Vote(d)).toEqual({revision:3,planHash:d.planHash,confirmed:true,confirm_name:'native-change',execute:false,level:1,stageRevision:4,candidateVersion:2});
    expect(()=>ordinaryV3Vote({...d,approval:{...d.approval,candidateVersion:'copied-hmac'}})).toThrow();
  });
  it('creates distinct random original secrets for all six DAOs with a real synthetic matching X509/key pair',()=>{
    const a=ordinaryV3Inputs(randomUUID(),syntheticV3Certificate),b=ordinaryV3Inputs(randomUUID(),syntheticV3Certificate);
    expect(a['key-auth'].key).not.toBe(b['key-auth'].key);expect(a['basic-auth'].password).not.toBe(b['basic-auth'].password);expect(a.oauth2.redirect_uris[0]).toMatch(/^https:/);expect(Object.keys(a)).toEqual(expect.arrayContaining(CREDENTIAL_KINDS));
    expect(()=>ordinaryV3Inputs(randomUUID(),{...syntheticV3Certificate,key:'invalid'})).toThrow();
  });
  it.each(['service','route','upstream','consumer','certificate'])('%s verifies every affected original ID and explicit reference manifest',kind=>{
    const s:any=ordinaryV3GraphSpecs(scope())[kind],nodes=s.members.map(([type,id]:string[])=>({key:`${type}:${id}`,type,id,affected:true,dependencies:[]}));
    for(const[type,id]of s.references??[])nodes.push({key:`${type}:${id}`,type,id,affected:false,dependencies:[]});
    const preview={entry:{id:randomUUID(),original_id:s.id,state:'restored',mutation_id:null,node_count:nodes.length},graph:{complete:true,nodes},nodes:nodes.map(n=>({node_key:n.key,entity_type:n.type,original_id:n.id,affected:n.affected,dependencies:[],delete_state:n.affected?'deleted':'reference',restore_state:n.affected?'restored':'reference',restored_id:n.affected?n.id:null}))};
    expect(ordinaryV3Archive(preview,s,'restored').affectedCount).toBe(s.members.length);
    const changed=structuredClone(preview);changed.graph.nodes[0].id=randomUUID();expect(()=>ordinaryV3Archive(changed,s,'restored')).toThrow();
    const extra=structuredClone(preview);extra.graph.nodes.push({key:'foreign',id:randomUUID(),type:'plugins',affected:true,dependencies:[]});extra.entry.node_count++;expect(()=>ordinaryV3Archive(extra,s,'restored')).toThrow();
  });
  it('public evidence exposes fixed states/counts only, never raw credentials, cookies or private proof',()=>{
    const secret='DO-NOT-PUBLISH-TEST-ONLY',g:any={inputs:{password:secret},evidenceKey:secret,credentialIds:{a:randomUUID()},graphs:{},functionalVerification:{secret},stages:{'restore-consumer':{state:'succeeded'}},operations:{a:{stage:'restore-consumer',label:'known-label',state:'observed',status:201,body:{password:secret},headers:{cookie:secret},responseData:{key:secret}}}};
    const text=JSON.stringify(ordinaryV3PublicSummary(g,'restore-consumer',true));expect(text).not.toContain(secret);expect(text).toContain('pending-root-readonly-worker');expect(text).toContain('overallM11Accepted":false');
  });
  it('keeps graph stages ordered with restoration before another parent removal; config and authentication remain separate',()=>{
    for(const t of ['service','route','upstream','consumer','certificate'])expect(ORDINARY_V3_STAGES.indexOf(`restore-${t}`)).toBeGreaterThan(ORDINARY_V3_STAGES.indexOf(`delete-${t}`));
    const source=readFileSync(new URL('../security/m11-current-ordinary-v3-acceptance.mjs',import.meta.url),'utf8');expect(source).not.toContain('/admin');expect(source).not.toContain('/auth/refresh');expect(source).not.toContain('execFile');
    const worker=readFileSync(new URL('../security/m11-current-ordinary-v3-readonly-worker.mjs',import.meta.url),'utf8');expect(worker).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');expect(worker).not.toContain('INSERT INTO');expect(worker).not.toContain('UPDATE ');expect(worker).not.toContain('DELETE FROM');
  });
  it.each([false,true])('runs the actual driver prepare/submit/current-vote/execute flow with a controlled %s BFF outcome, never a live request',async unknown=>{
    const original:any=scope(),admin=session(),reviewer=session(),deployment=attestation(),cid=randomUUID(),wid=randomUUID(),suffix=randomUUID();let phase='pending';
    const g:any={...original,version:1,clusterId:cid,workspaceId:wid,suffix,subjects:{admin:admin.user.id,reviewer:reviewer.user.id},deployment,inputs:{},operations:{},intents:{},graphs:{},evidenceKey:'ab'.repeat(32),stages:Object.fromEntries(ORDINARY_V3_STAGES.slice(0,3).map(s=>[s,{state:'succeeded'}]))};
    const spec:any=ordinaryV3GraphSpecs(g).route,eid=randomUUID(),bid=randomUUID(),wf=randomUUID(),entry=randomUUID(),intent=randomUUID();
    const nodes=[...spec.members.map(([type,id]:string[])=>({key:`${type}:${id}`,type,id,affected:true,dependencies:[]})),...spec.references.map(([type,id]:string[])=>({key:`${type}:${id}`,type,id,affected:false,dependencies:[]}))];
    const definition={items:[{format:2,kind:'native-change',status:'active',policy:{version:2,kind:'native-change',allowSelfApproval:false,distinctAcrossStages:true,stages:[{mode:'any',threshold:1,selector:{users:[reviewer.user.id]}}]}}]};
    const detail=()=>({entity:{state:phase,revision:1,planHash:'ab'.repeat(32),approval:{format:2,candidateVersion:1,approvalSetId:randomUUID(),stages:[{state:'active',level:1,revision:1}]},capabilities:{execute:phase==='approved'}},nativeChange:{packets:spec.members.map(()=>({state:'succeeded',nativeStatus:204})),baseline:{nativeAuthority:false,baseline:{baselineId:bid}}}});
    const preview={entry:{id:entry,original_id:spec.id,state:'deleted',mutation_id:null,node_count:nodes.length},graph:{complete:true,nodes},nodes:nodes.map(n=>({node_key:n.key,entity_type:n.type,original_id:n.id,affected:n.affected,dependencies:[],delete_state:n.affected?'deleted':'reference',restore_state:n.affected?'pending':'reference'}))};
    const h:any={state:{cid,wid,sessions:{admin},metadataAcceptance:{reviewerSession:reviewer},requests:[],[ORDINARY_V3_FIELD]:g},save:vi.fn(),assertWritable:vi.fn(),request:vi.fn(async(_actor:any,p:string,_method:string,_body:any,options:any)=>{
      if(options.expected.includes(404))return{status:404};
      if(p===`/clusters/${cid}`)return{data:{version:'1.5.1',execution_mode:'approval'}};
      if(p.includes('/workflow-definitions?'))return{data:definition};if(p.includes(`/workflows/${wf}?`))return{data:detail()};
      if(p.includes(`/entities/routes/${spec.id}?`))return{data:{entity:{id:spec.id,name:'fixed-route'}}};
      if(p.includes(`/recycle-bin/${entry}?`))return{data:preview};if(p.includes('/recycle-bin?'))return{data:{items:[preview.entry]}};
      throw Error('Unexpected controlled read');
    }),once:vi.fn(async(label:string,actor:any,p:string,_method:string,body:any,options:any)=>{
      h.state.requests.push({label,key:options.key});let data:any;
      if(p.includes('/entity-changes/prepare?'))data={id:intent,revision:1,materialHmac:'ab'.repeat(32),review:{impact:{nativePackets:2},changes:spec.members.map(([entityType,nativeId]:string[])=>({entityType,nativeId,action:'delete'}))}};
      else if(p.includes('/submit?'))data={workflowId:wf};else if(p.includes('/approve?')){expect(actor).toBe(reviewer);expect(body.candidateVersion).toBe(1);expect(body.stageRevision).toBe(1);phase='approved';data={};}
      else if(p.includes('/execute?')){if(unknown){const error=Error('private-password-marker:'+ 'm'.repeat(5000));error.name='private-name-marker:'+ 'n'.repeat(300);error.stack='private-api-key-marker:'+ 's'.repeat(17000);throw error;}phase='succeeded';data={state:'succeeded',executionId:eid,baselineId:bid};}
      else throw Error('Unexpected controlled write');return{data,status:201,requestId:randomUUID()};
    })};
    const result=await runOrdinaryV3Stage(h,'delete-route',{env:{RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY:'true'},attestation:deployment});
    expect(result.passed).toBe(!unknown);expect(h.once).toHaveBeenCalledTimes(4);expect(new Set(h.once.mock.calls.map((c:any)=>c[5].key)).size).toBe(4);
    const count=h.once.mock.calls.length;await expect(runOrdinaryV3Stage(h,'delete-route',{env:{RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY:'true'},attestation:deployment})).rejects.toThrow('V3_STAGE_ALREADY_STARTED_NO_REPLAY');expect(h.once).toHaveBeenCalledTimes(count);
    if(unknown){
      const failed=g.stages['delete-route'],original=failed.failure;
      expect(failed.state).toBe('stopped-no-replay');expect(original.previousState.state).toBe('started');expect(original.previousState.failure).toBeUndefined();
      expect(original.error.name).toHaveLength(256);expect(original.error.message).toHaveLength(4096);expect(original.error.stack).toHaveLength(16384);
      expect(original.error.name).toMatch(/^private-name-marker:/);expect(original.error.message).toMatch(/^private-password-marker:/);expect(original.error.stack).toMatch(/^private-api-key-marker:/);
      expect(original.error.truncated).toEqual({name:true,message:true,stack:true});expect(original.observedAt).toBe(failed.finishedAt);
      const publicText=JSON.stringify(result)+JSON.stringify(ordinaryV3PublicSummary(g,'delete-route',false));
      expect(publicText).not.toContain('private-password-marker');expect(publicText).not.toContain('private-name-marker');expect(publicText).not.toContain('private-api-key-marker');expect(publicText).not.toContain('failure');
      await expect(runOrdinaryV3Stage(h,'delete-route',{env:{RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY:'true'},attestation:deployment})).rejects.toThrow('V3_STAGE_ALREADY_STARTED_NO_REPLAY');
      expect(g.stages['delete-route'].failure).toBe(original);expect(h.once).toHaveBeenCalledTimes(count);
    }else{expect(g.graphs.route.affectedCount).toBe(2);expect(g.stages['delete-route'].failure).toBeUndefined();}
  });
});
describe('Controlled HTTPS Source adapter: never calls an actual network',()=>{
  const tls=()=>({requiresTLS:true,rejectUnauthorized:true,origin:'https://127.0.0.1:5463',hostname:'127.0.0.1',port:5463,servername:'kongpilot-v3-acceptance.invalid',ca:syntheticV3Certificate.cert,publicCaSha256:createHash('sha256').update(syntheticV3Certificate.cert).digest('hex')});
  it.each(['admin','origin','ca','servername','bypass','path','newline','method'])('closes changed %s before transport',kind=>{
    const t:any=tls(),suffix=randomUUID(),input:any={method:'GET',path:`/v3-oauth2-${suffix}`,expected:[401]};
    if(kind==='admin')t.port=8001;if(kind==='origin')t.origin='https://elsewhere.invalid:5463';if(kind==='ca')t.ca+='changed';if(kind==='servername')t.servername='kong.invalid';if(kind==='bypass')t.rejectUnauthorized=false;if(kind==='path')input.path='/admin';if(kind==='newline')input.headers={authorization:'Bearer test\r\nInjected: true'};if(kind==='method')input.method='DELETE';
    expect(()=>ordinaryV3HttpsContract(t,suffix,input)).toThrow();
  });
  it.each([false,true])('journals the original TLS %s response before returning and never retries',async unknown=>{
    const t=tls(),g:any={suffix:randomUUID()},h:any={state:{requests:[]},assertWritable:vi.fn(),save:vi.fn()};
    vi.mocked(httpsRequest).mockImplementation(((options:any,callback:any)=>{
      expect(options.rejectUnauthorized).toBe(true);expect(options.servername).toBe(t.servername);expect(options.hostname).toBe('127.0.0.1');
      const req:any=new EventEmitter();req.destroy=vi.fn();req.end=()=>queueMicrotask(()=>{if(unknown){req.emit('error',new Error('synthetic-secret-not-published'));return;}const response:any=new EventEmitter();response.socket={authorized:true};response.statusCode=401;response.destroy=vi.fn();callback(response);response.emit('data',Buffer.from('{"error":"invalid_token"}'));response.emit('end');});return req;
    }) as any);
    const call=ordinaryV3HttpsOnce(h,g,'negative',t,{method:'GET',path:`/v3-oauth2-${g.suffix}`,headers:{authorization:'Bearer synthetic-private'},expected:[401]});
    if(unknown)await expect(call).rejects.toThrow('V3_TLS_UNKNOWN_ORIGINAL_RETAINED_NO_REPLAY');else await expect(call).resolves.toMatchObject({status:401,tlsAuthorized:true});
    expect(h.state.requests).toHaveLength(1);expect(h.state.requests[0]).toBe(g.oauthPackets[0]);expect(h.state.requests[0].state).toBe(unknown?'response_unknown':'response_observed');
    const calls=vi.mocked(httpsRequest).mock.calls.length;await expect(ordinaryV3HttpsOnce(h,g,'negative',t,{method:'GET',path:`/v3-oauth2-${g.suffix}`,expected:[401]})).rejects.toThrow('V3_ORIGINAL_TLS_REQUEST_EXISTS_NO_REPLAY');expect(vi.mocked(httpsRequest)).toHaveBeenCalledTimes(calls);
  });
});

function proofFixture(method:'POST'|'DELETE'='POST'){
  const secrets=new SecretService(),f=(v:any)=>secrets.fingerprint(v),source:any={id:randomUUID(),clusterId:randomUUID(),workspaceId:randomUUID(),workflowId:randomUUID(),workflowExecutionId:randomUUID(),executionActorId:randomUUID(),issuedAt:'2026-10-18T10:00:00.000Z',expiresAt:'2026-10-18T10:05:00.000Z'},baseline={baselineId:randomUUID(),pinId:randomUUID()},entryId=randomUUID(),operationId=randomUUID(),id=randomUUID();
  const before=method==='DELETE'?{id,name:'synthetic'}:null,body=method==='POST'?{id,name:'synthetic'}:null,raw=method==='POST'?body:null;
  const packet:any={key:'p1',order:1,nativeType:'services',nativeId:id,method,canonicalPath:method==='POST'?'/services':`/services/${id}`,mutationAction:method==='POST'?'restore':'delete',permissionAction:method==='POST'?'write':'delete',beforeHmac:f(before),bodyHmac:f(body)};
  const attempt:any={id:randomUUID(),cluster_id:source.clusterId,workspace_id:source.workspaceId,source_id:source.id,baseline_id:baseline.baselineId,pin_id:baseline.pinId,workflow_execution_id:source.workflowExecutionId,packet_key:packet.key,packet_order:1,method,path_hmac:f(packet.canonicalPath),native_type:'services',native_id:id,parent_id:null,credential_kind:null,original_native_id:null,permission_action:packet.permissionAction,mutation_action:packet.mutationAction,body_hmac:packet.bodyHmac,before_hmac:packet.beforeHmac,created_at:'2026-10-18T10:00:01.000Z'};
  const mutation:any={id:operationId,state:'succeeded',remote_started:true,remote_completed:true,entity_change_source_id:source.id,entity_change_baseline_id:baseline.baselineId,entity_change_attempt_id:attempt.id,entity_change_packet_key:packet.key,cluster_id:source.clusterId,workspace_id:source.workspaceId,actor_id:source.executionActorId,workflow_id:source.workflowId,entity_id:id,entity_type:'services',action:packet.mutationAction,idempotency_key:`entity-${source.workflowExecutionId}-1`,before_secret:secrets.encrypt(before,`mutation:${operationId}:before`),payload_secret:secrets.encrypt(body,`mutation:${operationId}:payload`),result_secret:secrets.encrypt(raw,`mutation:${operationId}:result`)};
  const receipt:any={attempt_id:attempt.id,cluster_id:source.clusterId,workspace_id:source.workspaceId,source_id:source.id,baseline_id:baseline.baselineId,pin_id:baseline.pinId,workflow_execution_id:source.workflowExecutionId,packet_key:packet.key,entry_id:entryId,node_key:`services:${id}`,operation_id:operationId,native_id:id,operation_key:mutation.idempotency_key,direction:method==='POST'?'restore':'delete',result_hmac:f(raw)};
  const binding={sourceId:source.id,baselineId:baseline.baselineId,pinId:baseline.pinId,packetKey:packet.key,attemptId:attempt.id};
  const verification={version:1,clusterId:source.clusterId,workspaceId:source.workspaceId,entryId,nodeKey:receipt.node_key,packetKey:packet.key,attemptId:attempt.id,operationId,canonicalPath:packet.canonicalPath,nativeId:id,status:404};
  if(method==='DELETE')receipt.verification_hmac=f(verification);
  const events=['send-intent','outcome'].map(kind=>{const fact:any={version:1,kind,binding,observedAt:'2026-10-18T10:00:02.000Z',...(kind==='outcome'?{outcome:'succeeded',nativeStatus:method==='DELETE'?204:201}:{}),evidence:kind==='send-intent'?{operationId,method,pathHmac:f(packet.canonicalPath),bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac}:{operationId,mutationState:'succeeded',remoteCompleted:true,responseHmac:f(raw),...(method==='DELETE'?{deleteVerification:verification}:{})}};return{...attempt,attempt_id:attempt.id,event_kind:kind,outcome:kind==='outcome'?'succeeded':null,native_status:kind==='outcome'?method==='DELETE'?204:201:null,error_code:null,fact_ciphertext:secrets.encrypt(fact,`entity-change-packet-fact:${source.clusterId}:${source.workspaceId}:${attempt.id}:${kind}`),fact_hmac:f(fact),observed_at:fact.observedAt,created_at:fact.observedAt};});
  return{data:{source,baseline,packet,attempt,mutation,events,receipt,entryId},crypto:{fingerprint:f,decrypt:(v:string,aad:string)=>secrets.decrypt(v,aad)}};
}
describe('V3 readonly SQL receipt proof: genuine synthetic AEAD, controlled rows only',()=>{
  it.each(['POST','DELETE'] as const)('validates original %s result and reciprocal tuple without granting authority',method=>{const x=proofFixture(method);expect(ordinaryV3ReceiptProof(x.data,x.crypto)).toMatchObject({nativeStatus:method==='POST'?201:204,configurationVerified:true,functionalVerification:'pending'});});
  it.each(['source','packet','attempt','operation','payload','result','status','receipt','event','namespace','delete404'] as const)('rejects changed %s provenance',variant=>{
    const x=proofFixture(variant==='delete404'?'DELETE':'POST'),d:any=x.data;
    if(variant==='source')d.source.id=randomUUID();if(variant==='packet')d.packet.nativeId=randomUUID();if(variant==='attempt')d.attempt.path_hmac='00'.repeat(32);if(variant==='operation')d.mutation.remote_completed=false;
    if(variant==='payload')d.mutation.payload_secret=d.mutation.before_secret;if(variant==='result')d.mutation.result_secret=d.mutation.payload_secret;
    if(variant==='status')d.events[1].native_status=200;if(variant==='receipt')d.receipt.result_hmac='00'.repeat(32);if(variant==='event')d.events[0].fact_hmac='00'.repeat(32);if(variant==='namespace')d.mutation.configuration_job_id=randomUUID();if(variant==='delete404')d.receipt.verification_hmac='00'.repeat(32);
    expect(()=>ordinaryV3ReceiptProof(d,x.crypto)).toThrow();
  });
});
