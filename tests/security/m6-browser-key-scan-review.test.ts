import {describe,expect,it,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import {BROWSER_KEY_SCAN_SQL,browserKeyScanCheckpoint,captureBrowserKeyScanMaterial} from './lib/m6-browser-key-scan.mjs';
import {FIRST_BROWSER_LOGIN_REQUEST} from './lib/m6-browser-remaining.mjs';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {normalizedNativeRequests} from '../../apps/console-api/src/modules/workflows/approved-execution.types';

const sha=(value:any)=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(){
 const cid=randomUUID(),wid=randomUUID(),owner=randomUUID(),sid=randomUUID(),wf=randomUUID(),app=randomUUID(),executor=randomUUID(),executeKey=randomUUID();
 const claim={kind:'portal_developer',iss:'kongos-portal',aud:'kongos-portal',sub:owner,cid,wid,sid,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+900};
 const access='offline.'+Buffer.from(JSON.stringify(claim)).toString('base64url')+'.untrusted-fixture-signature';
 const jar=[{name:'kongos_portal_access',value:access},{name:'kongos_portal_refresh',value:sid+'.'+'r'.repeat(64)},{name:'kongos_portal_csrf',value:'c'.repeat(43)}].map(c=>({...c,domain:'127.0.0.1',path:'/api/v1/portal'}));
 const reference:any={browser:{clusterId:cid,workspaceId:wid,publicationId:randomUUID()},portalUsers:[{id:owner,label:'developer-a'}],consoleAdministrator:{user:{id:executor}},
  browserWorkflowId:wf,browserApplication:{id:app,ownerId:owner,tenant:{clusterId:cid,workspaceId:wid}},
  browserRemaining:{phase:'remaining-browser-completed',originalLoginRequestId:FIRST_BROWSER_LOGIN_REQUEST,originalSessionId:sid,latestNamedJars:[jar]},
  writeAttempts:[{source:'browser-remaining',method:'POST',path:`/api/v1/clusters/${cid}/workflows/${wf}/execute`,key:executeKey,actorId:executor,clusterId:cid,workspaceId:wid,state:'response_observed',httpStatus:201}],
  secrets:['offline-original-material'],priorFixtureRuns:[{checkpoint:{secrets:['offline-historical-material']}}]};
 const grant=randomUUID(),credential=randomUUID(),consumer=randomUUID(),acl=randomUUID(),kongId=randomUUID();
 const bindings=[{type:'consumers',id:consumer,parentId:null,credentialKind:null},{type:'credentials',id:acl,parentId:consumer,credentialKind:'acls'},{type:'credentials',id:kongId,parentId:consumer,credentialKind:'key-auth'}].map(b=>({...b,stepId:randomUUID(),operationId:randomUUID()}));
 const before:any={workflow_id:wf,workflow_state:'succeeded',cluster_id:cid,workspace_id:wid,subject_id:grant,plan_revision:1,plan_hash:'a'.repeat(64),execution_id:randomUUID(),execution_state:'succeeded',execution_actor_id:executor,
  grant_id:grant,application_id:app,publication_id:reference.browser.publicationId,developer_id:owner,grant_state:'active',current_generation:1,current_credential_id:credential,consumer_id:consumer,acl_id:acl,acl_credential_ref_id:randomUUID(),
  credential_id:credential,generation:1,credential_state:'active',kong_id:kongId,credential_ref_id:randomUUID(),last_revealed_at:null,cipher_sha:'b'.repeat(64),native_steps:3,native_bindings:bindings,active_refs:2,unsettled_steps:0,unresolved_native:0,scanner_reveal_audited:false};
 const after={...structuredClone(before),last_revealed_at:new Date().toISOString(),scanner_reveal_audited:true};
 const receipt:any={workflowId:wf,clusterId:cid,workspaceId:wid,state:'succeeded',executionId:before.execution_id,planHash:before.plan_hash,steps:[...bindings.map(b=>({id:b.stepId,operationId:b.operationId,state:'succeeded',remoteCompleted:true})),{id:randomUUID(),operationId:null,state:'succeeded',remoteCompleted:true}]};
 const requestId=randomUUID(),raw='offline-scan-material-'+randomUUID(),saved:any[]=[],sequence:string[]=[];
 const cookieProof={accessIndex:0,refreshIndex:1,csrfIndex:2,sessionId:sid,expiresAt:new Date(Date.now()+3_600_000).toISOString(),credentialEpoch:1,accessExpired:false,currentSessionVerified:true,originalLoginAudited:true};
 const credentials:any={items:[{id:credential,grantId:grant,state:'active',generation:1,revision:2,capabilities:{reveal:true}}]};
 const deps:any={released:true,
  readCookies:vi.fn(async()=>{sequence.push('cookies');return cookieProof;}),
  readSql:vi.fn(async(sql:string,args:any[])=>{expect(sql).toBe(BROWSER_KEY_SCAN_SQL);sequence.push(args[4]?'sql-after':'sql-before');return[args[4]?after:before];}),
  portalGet:vi.fn(async(path:string)=>{sequence.push('portal-read');if(path==='/auth/me')return{id:owner,clusterId:cid,workspaceId:wid};if(path.endsWith('/credentials'))return credentials;return{items:[{id:grant,applicationId:app,publicationId:reference.browser.publicationId,state:'active',generation:1,workflowId:wf}]};}),
  consoleReceipt:vi.fn(async()=>receipt),consoleGet:vi.fn(async(path:string)=>({entity:{id:path.split('/').at(-1),...(path.startsWith('/consumers/')?{consumer:{id:consumer}}:{})}})),
  persist:vi.fn(async(r:any)=>{sequence.push('persist');saved.push(structuredClone(r));}),
  portalReveal:vi.fn(async()=>{sequence.push('reveal');return{status:201,data:{key:raw,generation:1,credentialId:credential},requestId};})};
 return{reference,report:{passed:1,failed:0,remainingOnly:true},before,after,receipt,deps,credentials,cookieProof,raw,saved,sequence,requestId};
}

describe('independent post-browser scanner material authority and no replay',()=>{
 it('anchors CREATE identity to the actual immutable logical-null/native manifest split',()=>{
  const fakeSecrets={fingerprint:(v:any)=>sha(v)};
  const native=new PortalNativeService({} as any,fakeSecrets as SecretService,{} as any,{} as any,{} as any,{} as any);
  const consumerId=randomUUID(),wf=randomUUID(),step=native.nativeStep(1,'consumers','create',{id:consumerId,username:'offline-private'},null,{workflowId:wf});
  expect(step.entityId).toBeUndefined();const manifest=normalizedNativeRequests(step.nativeRequests,fakeSecrets);
  expect(manifest).toMatchObject([{method:'POST',native_type:'consumers',native_id:consumerId,parent_id:null,credential_kind:null}]);
  expect(BROWSER_KEY_SCAN_SQL).not.toContain('m.entity_id=s.entity_id::text');
  expect(BROWSER_KEY_SCAN_SQL).toContain("->>'native_id'");
  expect(BROWSER_KEY_SCAN_SQL).toContain('s.entity_id IS NULL');
 });
 it('blocks another saved Portal session before SQL, BFF reads or a journal',async()=>{
  const f=fixture();f.cookieProof.sessionId=randomUUID();const before=sha(f.reference);
  await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow();
  expect(f.deps.readSql).not.toHaveBeenCalled();expect(f.deps.portalReveal).not.toHaveBeenCalled();expect(sha(f.reference)).toBe(before);
 });
 it.each([
  ['credential current pointer',(f:any)=>f.before.current_credential_id=randomUUID()],['inactive generation',(f:any)=>f.before.generation=2],
  ['key credential UUID',(f:any)=>f.before.native_bindings[2].id=randomUUID()],['duplicate operation',(f:any)=>f.before.native_bindings[2].operationId=f.before.native_bindings[1].operationId],
  ['missing terminal metadata',(f:any)=>f.before.unsettled_steps=1],['foreign current Portal owner',(f:any)=>f.deps.portalGet.mockResolvedValue({id:randomUUID()})],
  ['foreign receipt execution',(f:any)=>f.receipt.executionId=randomUUID()],['different sealed receipt hash',(f:any)=>f.receipt.planHash='c'.repeat(64)],
  ['wrong fresh child parent',(f:any)=>f.deps.consoleGet.mockImplementation(async(path:string)=>({entity:{id:path.split('/').at(-1),consumer:{id:randomUUID()}}}))],
 ])('does not view material after %s changes',async(_label,change)=>{
  const f=fixture();change(f);const before=sha(f.reference);await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow();
  expect(f.deps.portalReveal).not.toHaveBeenCalled();expect(f.deps.persist).not.toHaveBeenCalled();expect(sha(f.reference)).toBe(before);
 });
 it('retains the exact new credential, original session, revision and body before the sole owner reveal',async()=>{
  const f=fixture(),historical=sha(f.reference.priorFixtureRuns);const result=await captureBrowserKeyScanMaterial(f.reference,f.report,f.deps);
  const first=f.saved[0],attempt=first.writeAttempts.at(-1);expect(first.browserKeyScan).toMatchObject({phase:'before-single-owner-reveal',sessionId:f.reference.browserRemaining.originalSessionId,workflowId:f.reference.browserWorkflowId,executionKey:f.reference.writeAttempts[0].key,credentialId:f.before.credential_id});
  expect(attempt.body).toEqual({clusterId:f.before.cluster_id,workspaceId:f.before.workspace_id,revision:2});expect(attempt.actorId).toBe(f.before.developer_id);expect(attempt.key).toBe(first.browserKeyScan.key);
  expect(f.sequence.indexOf('persist')).toBeLessThan(f.sequence.indexOf('reveal'));expect(f.deps.portalReveal).toHaveBeenCalledOnce();
  expect(f.reference.writeEvidence).toEqual([{method:'POST',path:attempt.path,requestId:f.requestId}]);
  expect(sha(f.reference.priorFixtureRuns)).toBe(historical);expect(JSON.stringify(result)).not.toContain(f.raw);expect(f.reference.secrets).toContain(f.raw);
  expect(f.deps.readSql.mock.calls.map(c=>c[1][4])).toEqual([null,f.requestId]);expect(f.deps.consoleGet.mock.calls.map(c=>c[0])).toEqual([`/entities/consumers/${f.before.consumer_id}`,`/consumers/${f.before.consumer_id}/credentials/acls/${f.before.acl_id}`,`/consumers/${f.before.consumer_id}/credentials/key-auth/${f.before.kong_id}`]);
 });
 it('keeps an unexpected bounded response key as private scanner material and forbids a second request',async()=>{
  const f=fixture();f.deps.portalReveal.mockResolvedValue({status:403,data:{key:f.raw,credentialId:f.before.credential_id,generation:1},requestId:f.requestId});
  await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow('cannot be safely accepted');expect(f.reference.secrets).toContain(f.raw);
  expect(f.saved.some(r=>r.secrets.includes(f.raw))).toBe(true);expect(f.reference.browserKeyScan.phase).toBe('unverified-response');
  await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow();expect(f.deps.portalReveal).toHaveBeenCalledOnce();
 });
 it.each([
  ['cipher',(f:any)=>f.after.cipher_sha='e'.repeat(64)],['request audit',(f:any)=>f.after.scanner_reveal_audited=false],['current identity',(f:any)=>f.after.kong_id=randomUUID()],
 ])('does not mark verification complete after post-response %s mismatch',async(_label,change)=>{
  const f=fixture();change(f);await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow();
  expect(f.reference.secrets).toContain(f.raw);expect(f.reference.browserKeyScan.phase).toBe('raw-key-retained');expect(f.deps.portalReveal).toHaveBeenCalledOnce();
  const originalKey=f.reference.browserKeyScan.key;await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow();expect(f.reference.browserKeyScan.key).toBe(originalKey);expect(f.deps.portalReveal).toHaveBeenCalledOnce();
 });
 it('keeps the original durable reveal intent if transport is unknown, without login, refresh or retry',async()=>{
  const f=fixture();f.deps.portalReveal.mockRejectedValue(Error('offline secret driver detail'));
  await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow('retained without replay');expect(f.reference.browserKeyScan.phase).toBe('result-unknown');
  expect(f.deps.portalGet.mock.calls.some(c=>/login|refresh/.test(c[0]))).toBe(false);expect(f.saved.at(-1).writeAttempts.at(-1).state).toBe('before-single-send');
  await expect(captureBrowserKeyScanMaterial(f.reference,f.report,f.deps)).rejects.toThrow();expect(f.deps.portalReveal).toHaveBeenCalledOnce();
 });
});

describe('actual fixed scanner runner wire contract without transport',()=>{
 function actualWire(){
  const source=readFileSync('tests/security/capture-m6-browser-key.mjs','utf8'),tree=ts.createSourceFile('runner.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
  const block=tree.statements.find(ts.isTryStatement)?.tryBlock;
  const statement=block?.statements.find(node=>ts.isVariableStatement(node)&&node.declarationList.declarations.some(d=>ts.isIdentifier(d.name)&&d.name.text==='safeWire'));
  if(!statement)throw Error('Actual scanner wire declaration missing');
  const fetch=vi.fn(async()=>new Response(JSON.stringify({data:{key:'offline-response-material'},meta:{requestId:randomUUID()}}),{status:201,headers:{'x-request-id':randomUUID()}}));
  const sandbox:any={URL,fetch,AbortSignal:{timeout:()=>new AbortController().signal},Uint8Array,TextDecoder,JSON,Error,consoleCookie:'offline-console-cookie'};
  vm.runInNewContext(statement.getText(tree)+';this.wire=safeWire;',sandbox);
  return{wire:sandbox.wire,fetch};
 }
 it('sends the one Portal view with the actual PortalGuard CSRF header and explicit original tenant',async()=>{
  const f=fixture(),context=browserKeyScanCheckpoint(f.reference,f.report),{wire,fetch}=actualWire();
  const path=`/api/v1/portal/applications/${context.applicationId}/grants/${f.before.grant_id}/credentials/${f.before.credential_id}/reveal`,key=randomUUID();
  await wire('http://127.0.0.1:8082',path,context,'POST',{clusterId:context.fixture.clusterId,workspaceId:context.fixture.workspaceId,revision:2},key);
  expect(fetch).toHaveBeenCalledOnce();const [url,options]=fetch.mock.calls[0] as any;
  expect(url.origin).toBe('http://127.0.0.1:8082');expect(url.searchParams.get('clusterId')).toBe(context.fixture.clusterId);expect(url.searchParams.get('workspaceId')).toBe(context.fixture.workspaceId);
  expect(options.headers['X-Portal-CSRF']).toBe(context.csrf);expect(options.headers['X-CSRF-Token']).toBeUndefined();expect(options.headers.Cookie).toBe(context.cookie);expect(options.headers.Origin).toBe(url.origin);expect(options.headers['X-Idempotency-Key']).toBe(key);expect(options.redirect).toBe('error');
  const guard=readFileSync('apps/console-api/src/modules/portal-auth/portal-auth.guard.ts','utf8');expect(guard).toContain("req.get('x-portal-csrf')");
 });
 it.each(['/consumers','/api/v1/portal/auth/me?clusterId=foreign','/api/v1/portal/auth/me#alternate'])('rejects nonfixed path %s before any fetch',async path=>{
  const f=fixture(),{wire,fetch}=actualWire();await expect(wire('http://127.0.0.1:8082',path,browserKeyScanCheckpoint(f.reference,f.report))).rejects.toThrow('Fixed BFF');expect(fetch).not.toHaveBeenCalled();
 });
});
