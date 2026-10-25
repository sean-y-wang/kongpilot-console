// @ts-nocheck -- actual ESM journal exports are exercised with synthetic packets only.
import {describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {authorizeFreshBootstrap,beforeManualMutation,completeManualMutation,confirmManualIamMetadata,createManualJournal,interruptManualMutation} from './lib/m6-manual-journal.mjs';
import {beforePublicationTailMutation,publicationTailSessionCookies} from './lib/m6-manual-publication-tail.mjs';

function pendingPublication() {
  const cid=randomUUID(),wid=randomUUID(),actors=Object.fromEntries(['owner','administrator','approver'].map(role=>[role,{id:randomUUID(),username:`synthetic-${role}`,password:`Synthetic!Offline-${role}-2026`}])) as any;
  const journal=createManualJournal({clusterId:cid,workspaceId:wid,actors,content:{slug:'synthetic-manual-page',title:'Synthetic manual page',markdown:'# Synthetic'},priorKeys:[],forbiddenEntityIds:[]}),persist=vi.fn();
  for(const role of ['owner','administrator']){
    authorizeFreshBootstrap(journal,role,[],persist);
    const portal=role==='owner',body={username:actors[role].username,password:actors[role].password,...(portal?{clusterId:cid,workspaceId:wid}:{})},key=randomUUID();
    const attempt=beforeManualMutation(journal,role,{url:portal?`http://127.0.0.1:8082/api/v1/portal/auth/login?clusterId=${cid}&workspaceId=${wid}`:'http://127.0.0.1:8080/api/v1/auth/login',method:'POST',headers:{'X-Idempotency-Key':key},rawBody:JSON.stringify(body)},[],persist);
    completeManualMutation(journal,attempt,201,{data:portal?{developer:{id:actors[role].id,username:actors[role].username,clusterId:cid,workspaceId:wid,status:'active'}}:{user:{id:actors[role].id,username:actors[role].username}},meta:{requestId:randomUUID()}},persist);
  }
  const packet=(action:string)=>({url:`http://127.0.0.1:8080/api/v1/clusters/${cid}/portal/pages${action==='page-create'?'':action==='page-publish'?`/${journal.pageId}/publish`:`/${journal.pageId}`}?workspaceId=${wid}`,method:action==='page-archive'?'DELETE':'POST',headers:{'X-Idempotency-Key':randomUUID()},rawBody:JSON.stringify(action==='page-create'?journal.content:{revision:journal.pageRevision,confirmed:true,confirm_name:journal.content.title})});
  const created={id:randomUUID(),slug:journal.content.slug,title:journal.content.title,revision:2,documentRevision:null,state:'draft'},workflowId=randomUUID(),create=beforeManualMutation(journal,'administrator',packet('page-create'),[],persist);
  completeManualMutation(journal,create,201,{data:{entity:created,workflowId,receipt:{workflowId,state:'succeeded',clusterId:cid,workspaceId:wid,idempotencyKey:create.key}},meta:{requestId:randomUUID()}},persist);
  const attempt=beforeManualMutation(journal,'administrator',packet('page-publish'),[],persist),entity={id:created.id,slug:created.slug,title:created.title,revision:3,documentRevision:1,state:'published'};
  const acknowledge=(save=persist)=>completeManualMutation(journal,attempt,201,{data:{entity},meta:{requestId:randomUUID()}},save);
  const read=()=>({url:`http://127.0.0.1:8080/api/v1/clusters/${cid}/portal/operations/by-key/${attempt.key}?workspaceId=${wid}`,method:'GET',status:200,actorId:actors.administrator.id,payload:{meta:{requestId:randomUUID()},data:{kind:'iam',state:'succeeded',receipt:{id:randomUUID(),state:'succeeded',remote_completed:true,error_code:null,module:'portal',action:'write',target_id:created.id,cluster_id:cid,workspace_id:wid,safe_result:{entity:{state:entity.state,documentRevision:entity.documentRevision,revision:entity.revision,title:entity.title,slug:entity.slug,id:entity.id}}}}}});
  return {cid,wid,actors,journal,persist,packet,attempt,entity,acknowledge,read};
}

describe('independent existing-page IAM acknowledgement and original-key proof boundaries',()=>{
  it('a real entity ACK stays locked until a separate original GET proves the same reordered JSONB result',()=>{
    const f=pendingPublication(),originalPacket=JSON.stringify({key:f.attempt.key,body:f.attempt.body,rawBody:f.attempt.rawBody,query:f.attempt.query});
    expect(f.acknowledge()).toBe(false);expect(f.journal.nextIndex).toBe(3);expect(f.journal.inFlight).toBe(f.attempt.key);
    const read=f.read();expect(JSON.stringify(read.payload.data.receipt.safe_result.entity)).not.toBe(JSON.stringify(f.entity));
    expect(confirmManualIamMetadata(f.journal,f.attempt,read,f.persist)).toBe(true);
    expect(f.journal.nextIndex).toBe(4);expect(f.journal.inFlight).toBeNull();expect(f.attempt.state).toBe('response-observed-success');
    expect(f.attempt).not.toHaveProperty('workflowId');expect(f.attempt.iamOperationId).toBe(read.payload.data.receipt.id);
    expect(JSON.stringify({key:f.attempt.key,body:f.attempt.body,rawBody:f.attempt.rawBody,query:f.attempt.query})).toBe(originalPacket);
  });
  it('CREATE still requires the compound Workflow receipt instead of accepting an existing-page IAM ACK',()=>{
    const f=pendingPublication(),create=f.journal.attempts.find(a=>a.action==='page-create');
    const journal=structuredClone(f.journal);journal.attempts=journal.attempts.slice(0,3);journal.nextIndex=2;journal.pageId=null;journal.pageRevision=null;journal.inFlight=create.key;journal.phase='active';
    const original=journal.attempts[2];original.state='before-single-send';
    expect(()=>completeManualMutation(journal,original,201,{data:{entity:{...f.entity,state:'draft',revision:2,documentRevision:null}},meta:{requestId:randomUUID()}},vi.fn())).toThrow();
    expect(journal.phase).toBe('stopped-without-replay');expect(journal.nextIndex).toBe(2);expect(journal.pageId).toBeNull();
  });
  it('unknown response blocks original proof and every unused write while retaining the exact first packet',()=>{
    const f=pendingPublication(),original=JSON.stringify({key:f.attempt.key,body:f.attempt.body,rawBody:f.attempt.rawBody});
    interruptManualMutation(f.journal,f.attempt,f.persist);
    expect(()=>confirmManualIamMetadata(f.journal,f.attempt,f.read(),f.persist)).toThrow();
    expect(()=>beforeManualMutation(f.journal,'administrator',f.packet('page-archive'),[],f.persist)).toThrow();
    expect(f.journal.attempts).toHaveLength(4);expect(f.journal.nextIndex).toBe(3);expect(JSON.stringify({key:f.attempt.key,body:f.attempt.body,rawBody:f.attempt.rawBody})).toBe(original);
  });
  it('foreign actor, tenant, target, original key, changed document revision and unsealed entity additions cannot prove completion',()=>{
    const changes=[r=>{r.actorId=randomUUID();},r=>{r.url=r.url.replace(/workspaceId=[^&]+/,`workspaceId=${randomUUID()}`);},r=>{r.payload.data.receipt.cluster_id=randomUUID();},r=>{r.payload.data.receipt.target_id=randomUUID();},r=>{r.url=r.url.replace(/by-key\/[^?]+/,`by-key/${randomUUID()}`);},r=>{r.payload.data.receipt.safe_result.entity.documentRevision=2;},r=>{r.payload.data.receipt.safe_result.entity.secret='Synthetic!NeverAllowed';}];
    for(const change of changes){const f=pendingPublication();f.acknowledge();const read=f.read();change(read);expect(()=>confirmManualIamMetadata(f.journal,f.attempt,read,f.persist)).toThrow();expect(f.journal.nextIndex).toBe(3);expect(f.journal.phase).toBe('stopped-without-replay');expect(f.journal.attempts).toHaveLength(4);}
  });
  it('pending, uncertain, failed, incomplete and non-IAM receipts never release an acknowledged original packet',()=>{
    const changes=[r=>{r.payload.data.receipt.state='running';},r=>{r.payload.data.state='uncertain';},r=>{r.payload.data.receipt.state='failed';},r=>{r.payload.data.receipt.remote_completed=false;},r=>{r.payload.data.kind='workflow';},r=>{r.payload.meta.requestId=undefined;}];
    for(const change of changes){const f=pendingPublication();f.acknowledge();const read=f.read();change(read);expect(()=>confirmManualIamMetadata(f.journal,f.attempt,read,f.persist)).toThrow();expect(f.journal.nextIndex).toBe(3);expect(f.journal.inFlight).toBe(f.attempt.key);}
  });
  it('an ACK save failure prevents the next packet even though the HTTP result is already observed',()=>{
    const f=pendingPublication(),failedSave=vi.fn(()=>{throw Error('SYNTHETIC_DURABILITY_FAILURE');});
    expect(()=>f.acknowledge(failedSave)).toThrow();expect(f.journal.phase).toBe('stopped-without-replay');expect(f.journal.nextIndex).toBe(3);
    expect(()=>beforeManualMutation(f.journal,'administrator',f.packet('page-archive'),[],f.persist)).toThrow();expect(f.journal.attempts).toHaveLength(4);
  });
  it('a separate proof cannot be reused or save-failed into permission to send another packet',()=>{
    const f=pendingPublication();f.acknowledge();confirmManualIamMetadata(f.journal,f.attempt,f.read(),f.persist);
    expect(()=>confirmManualIamMetadata(f.journal,f.attempt,f.read(),f.persist)).toThrow();expect(f.journal.nextIndex).toBe(4);expect(f.journal.phase).toBe('stopped-without-replay');
    const g=pendingPublication();g.acknowledge();expect(()=>confirmManualIamMetadata(g.journal,g.attempt,g.read(),()=>{throw Error('SYNTHETIC_PROOF_SAVE_FAILURE');})).toThrow();expect(g.journal.phase).toBe('stopped-without-replay');
    expect(()=>beforeManualMutation(g.journal,'administrator',g.packet('page-archive'),[],g.persist)).toThrow();expect(g.journal.attempts).toHaveLength(4);
  });
  it('the tail excludes publish replay and a consumed third refresh, and expires original SID cookies before any packet',()=>{
    function tail(){const f=pendingPublication();f.acknowledge();confirmManualIamMetadata(f.journal,f.attempt,f.read(),f.persist);f.journal.publicationTailContinuation={sourceOnlyTrustedPreparedBoundary:true};const sid=randomUUID(),now=Date.now(),claims={sid,sub:f.actors.administrator.id,iat:Math.floor(now/1000)-10,exp:Math.floor(now/1000)+600},access=`e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.offline-signature`,cookies=[{name:'kongos_access',value:access},{name:'kongos_refresh',value:`${sid}.SyntheticOriginalRefresh`},{name:'kongos_csrf',value:'SyntheticOriginalCSRF'}];f.journal.restoredSessions={administrator:{actorId:f.actors.administrator.id,sessionId:sid,refreshAttempted:true,refreshed:true,originalCookies:structuredClone(cookies),latestCookies:structuredClone(cookies)}};return{...f,cookies,now};}
    const refresh=tail(),header=refresh.cookies.map(c=>`${c.name}=${c.value}`).join('; ');
    expect(()=>beforePublicationTailMutation(refresh.journal,'administrator',{url:'http://127.0.0.1:8080/api/v1/auth/refresh',method:'POST',headers:{'X-Idempotency-Key':randomUUID(),Cookie:header,'X-CSRF-Token':'SyntheticOriginalCSRF'},rawBody:'{}'},refresh.cookies,refresh.persist)).toThrow();
    expect(refresh.journal.phase).toBe('stopped-without-replay');expect(refresh.journal.attempts).toHaveLength(4);
    const replay=tail();expect(()=>beforePublicationTailMutation(replay.journal,'administrator',replay.packet('page-publish'),replay.cookies,replay.persist)).toThrow();expect(replay.journal.attempts).toHaveLength(4);
    const expired=tail();expect(publicationTailSessionCookies(expired.journal,'administrator',expired.now)).toEqual(expired.cookies);expect(()=>publicationTailSessionCookies(expired.journal,'administrator',expired.now+601000)).toThrow();expect(expired.journal.attempts).toHaveLength(4);
    expired.journal.restoredSessions.administrator.sessionId=randomUUID();expect(()=>publicationTailSessionCookies(expired.journal,'administrator',expired.now)).toThrow();
  });
});
