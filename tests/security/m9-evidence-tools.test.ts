import { describe,it,expect } from 'vitest';
import {createHash} from 'node:crypto';
import { collectSecretMaterial,buildSecretMatcher,excludeControlledRejectedDraftProbe } from './lib/m9-secret-scan.mjs';
import { applyAuditPatch,knownCompletedOriginal,verifyMigrationComponentAudit,verifyRequestAuditIdentities } from './lib/m9-native-audit-worker.mjs';

describe('M9 actual-evidence secret collection',()=>{
  it('excludes the same public UUID from packet and idempotency headers',()=>{
    const publicId='11111111-2222-4333-8444-555555555555';
    const values=collectSecretMaterial({requests:[{key:publicId,headers:{'X-Idempotency-Key':publicId},body:{entityId:publicId}}]},{});
    expect(values.some(row=>row.value===publicId)).toBe(false);
  });
  it('collects a credential body API Key while excluding a cache operation key',()=>{
    const apiKey='ActualSyntheticApiKey!2026',cacheKey='kongpilot.synthetic.missing';
    const values=collectSecretMaterial({requests:[
      {key:'22222222-2222-4333-8444-555555555555',path:'/clusters/x/consumers/y/credentials/key-auth',body:{key:apiKey}},
      {key:'33333333-2222-4333-8444-555555555555',path:'/clusters/x/toolbox/cache/invalidate',body:{key:cacheKey},responseData:{key:cacheKey}},
    ]},{});
    expect(values.some(row=>row.value===apiKey&&row.kinds.includes('api-key'))).toBe(true);
    expect(values.some(row=>row.value===cacheKey)).toBe(false);
  });
  it('collects cookie objects from the browser private material handoff',()=>{
    const cookie='ActualSyntheticRefreshCookie!2026',csrf='ActualSyntheticBrowserCsrf!2026';
    const values=collectSecretMaterial({}, {}, {cookies:[{name:'kongos_refresh',value:cookie},{name:'kongos_csrf',value:csrf}]});
    expect(values.some(row=>row.value===cookie&&row.kinds.includes('cookie'))).toBe(true);
    expect(values.some(row=>row.value===csrf&&row.kinds.includes('csrf'))).toBe(true);
  });
  it('retains original unknown authentication header material without using its request identity',()=>{
    const token='OriginalUnknownCookieToken!2026',csrf='OriginalUnknownCsrf!2026',key='44444444-2222-4333-8444-555555555555';
    const values=collectSecretMaterial({requests:[{key,state:'response_unknown',path:'/auth/refresh',headers:{Cookie:'kongos_refresh='+token,'X-CSRF-Token':csrf}}]},{});
    expect(values.some(row=>row.value===token)).toBe(true);expect(values.some(row=>row.value===csrf)).toBe(true);
    expect(values.some(row=>row.value===key)).toBe(false);
  });
  it('collects nested decK consumer credentials and environment encryption materials',()=>{
    const key='ActualSyntheticDeckKey!2026',secret='c'.repeat(64),user='55555555-2222-4333-8444-555555555555';
    const values=collectSecretMaterial({}, {LAB_CONSOLE_ENCRYPTION_KEY:secret,LAB_BOOTSTRAP_USER:user}, {exports:[{consumers:[{username:'fixture',keyauth_credentials:[{key}]}]}]});
    expect(values.some(row=>row.value===key)).toBe(true);expect(values.some(row=>row.value===secret)).toBe(true);
    expect(values.some(row=>row.value===user)).toBe(false);
  });
  it('excludes redacted summaries and encrypted ciphertext from actual secret material',()=>{
    const values=collectSecretMaterial({fixtures:{credential:{secret:'[REDACTED:synthetic]',payload_secret:'v1.abcdef.ghijkl.mnopqr'}}},{});
    expect(values).toEqual([]);
  });
  it('bounds individual retained secret material size',()=>{
    expect(()=>collectSecretMaterial({password:'x'.repeat(16385)},{})).toThrow('SECRET_MATERIAL_SIZE_BUDGET');
  });
});

describe('M9 single controlled noncredential draft probe scope',()=>{
  const candidate='UnitOnlyPublicProbe2026',source="await h.request(admin,path('drafts'),'POST',{payload:{password:'"+candidate+"'}},{expected:[400]});";
  const tuple={index:0,requestId:'probe-request',actorId:'probe-actor',path:'/clusters/fixture/drafts',method:'POST',startedAt:'2026-10-12T00:00:00.000Z',sourcePath:'unit-native.mjs',sourceByteOffset:Buffer.byteLength(source.slice(0,source.indexOf(candidate)))};
  const packet=()=>({...tuple,state:'response_observed',status:400,errorCode:'DRAFT_SECRET_FORBIDDEN',body:{payload:{password:candidate}}});
  it('removes only a source-linked unissued rejected probe from a clone and retains original material',()=>{
    const original={requests:[packet()]},result=excludeControlledRejectedDraftProbe(original,{}, {},source,tuple);
    expect(original.requests[0].body.payload.password).toBe(candidate);expect(result.material.requests[0].body.payload).not.toHaveProperty('password');
    expect(result.evidence.sourceLiteralLinked).toBe(true);expect(JSON.stringify(result.evidence)).not.toContain(candidate);
  });
  it('refuses an issued/session/environment value or any additional occurrence',()=>{
    expect(()=>excludeControlledRejectedDraftProbe({requests:[packet()],sessions:{admin:{password:candidate}}},{},{},source,tuple)).toThrow();
    expect(()=>excludeControlledRejectedDraftProbe({requests:[packet()]},{LAB_BOOTSTRAP_PASSWORD:candidate},{},source,tuple)).toThrow();
    expect(()=>excludeControlledRejectedDraftProbe({requests:[packet()]},{},{cookies:[{name:'kongos_refresh',value:candidate}]},source,tuple)).toThrow();
  });
  it('never generalizes to other failed codes/statuses, source calls, offsets or packet identities',()=>{
    expect(()=>excludeControlledRejectedDraftProbe({requests:[{...packet(),status:403,errorCode:'FORBIDDEN'}]},{},{},source,tuple)).toThrow();
    expect(()=>excludeControlledRejectedDraftProbe({requests:[{...packet(),requestId:'other'}]},{},{},source,tuple)).toThrow();
    expect(()=>excludeControlledRejectedDraftProbe({requests:[packet()]},{},{},source.replace("path('drafts')","path('services')"),tuple)).toThrow();
    expect(()=>excludeControlledRejectedDraftProbe({requests:[packet()]},{},{},source,{...tuple,sourceByteOffset:tuple.sourceByteOffset+1})).toThrow();
  });
});

describe('M9 original known-native-complete failure evidence',()=>{
  const proof={source:'own-lab-readonly-sql',nativeComplete:true,
    scope:{clusterId:'cid',sourceWorkspaceId:'source',targetWorkspaceId:'target'},workflow:{id:'wf',state:'uncertain'},
    execution:{id:'execution',state:'uncertain',originalRequestId:'request',originalIdempotencyKey:'public-ledger-key'},
    migration:{id:'migration',state:'succeeded'},mutation:{id:'operation',state:'succeeded',remoteStarted:true,remoteCompleted:true},
    step:{id:'step',state:'succeeded',operationId:'operation'},components:[{key:'consumers:consumer',type:'consumers',id:'consumer',state:'succeeded'}]};
  const packet=()=>({state:'response_observed',status:503,errorCode:'WORKFLOW_EXECUTION_FAILED',requestId:'request',key:'public-ledger-key',
    resolution:{knownNativeComplete:true,metadataRecovered:true,receiptVerified:true,finalState:'succeeded',responseResolved:false,
      factProofSha256:'a'.repeat(64),metadataRecovery:{workflowId:'wf',executionId:'execution',clusterId:'cid',workspaceId:'source'}}});
  it('retains original 503 while selecting only minimal known-complete evidence',()=>{
    const original=packet(),selected=knownCompletedOriginal(original,proof,'a'.repeat(64));
    expect(original.status).toBe(503);expect(selected.originalResponseRewritten).toBe(false);expect(selected.responseResolved).toBe(false);
    expect(selected).not.toHaveProperty('key');expect(selected).not.toHaveProperty('headers');
  });
  it('rejects an unknown original even when a completion flag has been added',()=>{
    const original=packet();original.state='response_unknown';expect(()=>knownCompletedOriginal(original,proof,'a'.repeat(64))).toThrow();
  });
  it('rejects metadata-incomplete, receipt-unverified and original-response-rewritten claims',()=>{
    for(const patch of [{metadataRecovered:false},{receiptVerified:false},{responseResolved:true}]){
      const original=packet();Object.assign(original.resolution,patch);expect(()=>knownCompletedOriginal(original,proof,'a'.repeat(64))).toThrow();
    }
  });
  it('binds exact proof digest, request ID, execution key and native completion facts',()=>{
    expect(()=>knownCompletedOriginal(packet(),proof,'b'.repeat(64))).toThrow();
    expect(()=>knownCompletedOriginal(packet(),{...proof,execution:{...proof.execution,originalRequestId:'other'}},'a'.repeat(64))).toThrow();
    expect(()=>knownCompletedOriginal(packet(),{...proof,mutation:{...proof.mutation,remoteCompleted:false}},'a'.repeat(64))).toThrow();
  });
});

describe('M9 every-component migration audit verification',()=>{
  const fingerprint=(value:unknown)=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const secrets={fingerprint,redact:(value:any)=>({...value,...(Object.hasOwn(value,'key')?{key:'[REDACTED]'}:{})})};
  const fixture=()=>{
    const before={id:'credential',key:'UnitOnlySyntheticApiKey',tags:['source-tag'],consumer:{id:'consumer'}},after={...before,tags:['target-tag']};
    return {node:{key:'key-auth:consumer:credential',type:'key-auth',id:'credential',data:before,afterTags:after.tags,inheritedOnly:false},
      component:{object_key:'key-auth:consumer:credential',type:'key-auth',kong_id:'credential',status:'succeeded',error_code:null,after_fingerprint:fingerprint(after)},
      audit:{id:'audit',entity_type:'key-auth',entity_id:'credential',result:'succeeded',action:'workspace.migrate',workspace_id:'source',
        before:secrets.redact(before),after:secrets.redact(after),json_patch:[{op:'replace',path:'/tags',value:after.tags}]}};
  };
  it('replays the redacted patch on original encrypted-source data and verifies native after HMAC',()=>{
    const f=fixture();expect(verifyMigrationComponentAudit(f.node,f.component,f.audit,'source','target',secrets)).toEqual({entityType:'key-auth',entityId:'credential',auditId:'audit',componentAfterHmacVerified:true,patchVerified:true});
  });
  it('compares stored JSON semantics across the production redactor null-prototype boundary',()=>{
    const f=fixture(),nullPrototypeRedactor={fingerprint,redact:(value:any)=>Object.assign(Object.create(null),secrets.redact(value))};
    expect(verifyMigrationComponentAudit(f.node,f.component,f.audit,'source','target',nullPrototypeRedactor).componentAfterHmacVerified).toBe(true);
  });
  it('rejects a sibling audit or changed native after fingerprint',()=>{
    const f=fixture();expect(()=>verifyMigrationComponentAudit(f.node,f.component,{...f.audit,entity_id:'other'},'source','target',secrets)).toThrow();
    expect(()=>verifyMigrationComponentAudit(f.node,{...f.component,after_fingerprint:'0'.repeat(64)},f.audit,'source','target',secrets)).toThrow();
  });
  it('cannot use a matching sealed after HMAC to hide a non-tag configuration change',()=>{
    const f=fixture(),after={...f.node.data,tags:f.node.afterTags,consumer:{id:'different'}};
    f.component.after_fingerprint=fingerprint(after);f.audit.after=secrets.redact(after);
    f.audit.json_patch.push({op:'replace',path:'/consumer',value:{id:'different'}});
    expect(()=>verifyMigrationComponentAudit(f.node,f.component,f.audit,'source','target',secrets)).toThrow();
  });
  it('rejects missing original before material, failed component status and wrong source scope',()=>{
    const f=fixture();expect(()=>verifyMigrationComponentAudit(f.node,f.component,{...f.audit,before:{}},'source','target',secrets)).toThrow();
    expect(()=>verifyMigrationComponentAudit(f.node,{...f.component,status:'failed'},f.audit,'source','target',secrets)).toThrow();
    expect(()=>verifyMigrationComponentAudit(f.node,f.component,{...f.audit,workspace_id:'other'},'source','target',secrets)).toThrow();
  });
});

describe('M9 exact business audit cluster with global management envelopes',()=>{
  const request={requestId:'request',actorId:'actor',clusterId:'cluster',category:'cluster.metadata'};
  const base={request_id:'request',actor_id:'actor',actor_type:'user',source_ip:'192.0.2.1',occurred_at:'2026-10-12T00:00:00.000Z'};
  const business={...base,cluster_id:'cluster',entity_id:'cluster',entity_type:'cluster',action:'update'};
  const envelope={...base,cluster_id:null,workspace_id:null,entity_id:'cluster',entity_type:'clusters',action:'iam.write'};
  it('accepts real cluster business action with narrowly scoped global IAM envelope',()=>{
    expect(verifyRequestAuditIdentities(request,[business,envelope],[business])).toEqual({globalManagementEnvelopes:1,historicalMissingSourceIP:[]});
  });
  it('does not allow a global row to substitute for an expected cluster business audit',()=>{
    const globalBusiness={...business,cluster_id:null};expect(()=>verifyRequestAuditIdentities(request,[globalBusiness,envelope],[globalBusiness])).toThrow();
  });
  it('rejects wrong actor, different cluster and non-management global support rows',()=>{
    expect(()=>verifyRequestAuditIdentities(request,[business,{...envelope,actor_id:'other'}],[business])).toThrow();
    expect(()=>verifyRequestAuditIdentities(request,[business,{...envelope,cluster_id:'other'}],[business])).toThrow();
    expect(()=>verifyRequestAuditIdentities(request,[business,{...envelope,action:'delete'}],[business])).toThrow();
    expect(()=>verifyRequestAuditIdentities(request,[business,{...envelope,entity_id:'other-cluster'}],[business])).toThrow();
    expect(()=>verifyRequestAuditIdentities(request,[business,{...envelope,workspace_id:'workspace'}],[business])).toThrow();
    expect(()=>verifyRequestAuditIdentities({...request,category:'native.update'},[business,envelope],[business])).toThrow();
  });
  it('records only the exact four identified pre-fix missing IP rows without repairing them',()=>{
    const original={source:'native',index:77,method:'POST',requestId:'5d688f5d-b6b4-4559-90d9-356ba7efd96c',actorId:'f5738365-97c4-44af-abdb-0262c5104376',
      clusterId:'e269f167-53e9-4895-af89-5b1b8835c6ec',startedAt:'2026-10-12T18:39:16.184Z',category:'workspace.migration',
      routePath:'/clusters/e269f167-53e9-4895-af89-5b1b8835c6ec/workspace-migrations/6a2e803f-6f5e-436e-b896-6977e8a323db/apply'};
    const rows=['migrate.requested','workspace.migrate','workspace.migrate','migrate'].map((action,index)=>({...base,id:'audit-'+index,action,request_id:original.requestId,
      actor_id:original.actorId,cluster_id:original.clusterId,entity_type:'workspace_migration',source_ip:null,occurred_at:'2026-10-12T18:39:17.000Z'}));
    const selected=verifyRequestAuditIdentities(original,rows,[rows[3]]);expect(selected.historicalMissingSourceIP).toHaveLength(4);expect(rows.every(row=>row.source_ip===null)).toBe(true);
    expect(()=>verifyRequestAuditIdentities({...original,requestId:'new'},rows.map(row=>({...row,request_id:'new'})),[rows[3]])).toThrow();
  });
  it('never generalizes the historical missing IP allowance to a new request or incomplete old row set',()=>{
    const row={...business,source_ip:null};expect(()=>verifyRequestAuditIdentities(request,[row],[row])).toThrow();
  });
});

describe('M9 public evidence matching',()=>{
  const secret='SyntheticEscaped!"Key/2026';
  it('finds literal, URI, JSON and base64 encodings without returning the secret',()=>{
    const matcher=buildSecretMatcher([{value:secret,kinds:['api-key']}]);
    for(const value of [secret,encodeURIComponent(secret),JSON.stringify(secret).slice(1,-1),Buffer.from(secret).toString('base64')]){
      const found=matcher.scan(Buffer.from('prefix '+value+' suffix'));
      expect(found.length).toBeGreaterThan(0);expect(JSON.stringify(found)).not.toContain(secret);
      expect(found.every(row=>row.byteOffset>=7&&row.occurrences>=1)).toBe(true);
    }
  });
  it('detects overlapping suffix patterns and repeated occurrences',()=>{
    const matcher=buildSecretMatcher([{value:'Syntheticabcdefgh',kinds:['password']},{value:'abcdefgh',kinds:['secret']}]);
    const found=matcher.scan(Buffer.from('Syntheticabcdefgh Syntheticabcdefgh'));
    expect(found.filter(row=>row.encodings.includes('literal')).map(row=>row.occurrences)).toEqual([2,2]);
  });
  it('does not report a similar public token prefix as a full credential',()=>{
    expect(buildSecretMatcher([{value:secret,kinds:['api-key']}]).scan(Buffer.from('SyntheticEscaped public identifier'))).toEqual([]);
  });
});

describe('M9 independent audit JSON patch replay',()=>{
  it('preserves false and zero and resolves JSON pointer escapes',()=>{
    expect(applyAuditPatch({nested:{'a/b':false,'til~de':0}},[
      {op:'replace',path:'/nested/a~1b',value:true},{op:'replace',path:'/nested/til~0de',value:9},
    ])).toEqual({nested:{'a/b':true,'til~de':9}});
  });
  it('supports root replacement and array addition/removal without modifying before',()=>{
    const before={values:[1,2]};expect(applyAuditPatch(before,[{op:'remove',path:'/values/0'},{op:'add',path:'/values/-',value:3}])).toEqual({values:[2,3]});
    expect(before).toEqual({values:[1,2]});expect(applyAuditPatch(null,[{op:'replace',path:'',value:{count:0}}])).toEqual({count:0});
  });
  it('refuses invalid pointer escapes, absent replace targets and invalid indices',()=>{
    expect(()=>applyAuditPatch({},[{op:'add',path:'/invalid~2escape',value:1}])).toThrow();
    expect(()=>applyAuditPatch({},[{op:'replace',path:'/absent',value:1}])).toThrow();
    expect(()=>applyAuditPatch([],[{op:'remove',path:'/0'}])).toThrow();
  });
  it('treats __proto__ as an own JSON field rather than changing the prototype',()=>{
    const value=applyAuditPatch({},[{op:'add',path:'/__proto__',value:{polluted:true}}]);
    expect(Object.prototype).not.toHaveProperty('polluted');expect(Object.hasOwn(value,'__proto__')).toBe(true);
  });
});
