import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { M6Harness, M6_C1, M6_C2 } from './lib/m6-harness.mjs';
import { guardPublicationContinuation, originalConsoleSession, publicationContinuationCheckpoint } from './lib/m6-publication-continuation.mjs';

const directories: string[]=[];
afterEach(()=>{for(const directory of directories.splice(0))rmSync(directory,{recursive:true,force:true});vi.restoreAllMocks();});
function checkpoint(){
  const make=(cid:string,index:number)=>({cluster:{id:cid},workspace:{id:randomUUID(),code:`test-${index}`,status:'active',revision:1},slug:`test-${index}`,settings:{id:randomUUID(),revision:2},services:[] as any[],routes:[] as any[],publications:[] as any[]});
  const primary=make(M6_C1,1),secondary=make(M6_C2,2),other=make(M6_C1,3);
  for(const [fixture,names]of [[primary,['A','B','legacy']],[secondary,['C']]] as const)for(const name of names){const service={id:randomUUID(),name:`test-${name}`,host:'echo-upstream',protocol:'http',port:8081};fixture.services.push(service);fixture.routes.push({id:randomUUID(),name:`test-${name}`,service:{id:service.id},paths:[`/test/${name}`]});if(name!=='legacy')fixture.publications.push({id:randomUUID(),serviceId:service.id,revision:2,name:`Test ${name}`});}
  const key=randomUUID(),requestId=randomUUID(),actor=randomUUID(),publication=primary.publications[0];
  const attempt={key,requestId,actorId:actor,clusterId:M6_C1,workspaceId:primary.workspace.id,state:'response_observed',httpStatus:403,errorCode:'KONG_ENDPOINT_FORBIDDEN',path:`/api/v1/clusters/${M6_C1}/portal/publications/${publication.id}/publish`,query:`?workspaceId=${primary.workspace.id}`,body:{revision:2,confirmed:true,confirm_name:publication.name}};
  const reference={phase:'bootstrap',liveStartedAt:new Date().toISOString(),fixtures:[primary,secondary,other],consoleAdministrator:{user:{id:actor},cookie:'private-unit-cookie'},accounts:{'approver-only':{session:{user:{id:randomUUID()}}},'approver-c2':{session:{user:{id:randomUUID()}}}},writeAttempts:[attempt],fixtureJournal:[{id:randomUUID(),type:'plugins',name:'key-auth',clusterId:M6_C1,workspaceId:primary.workspace.id}]};
  const proof={readOnly:true,originalKey:key,requestId,clusterId:M6_C1,workspaceId:primary.workspace.id,publicationId:publication.id,operationsStatus:200,operationsKind:'not_sent',operationsState:'not_sent',publicationStatus:'draft',publicationRevision:2,noUnknowns:true,ledgerCounts:{workflows:0,iam_operations:0,native_operations:0,unresolved:0}};
  return{reference,proof};
}
function liveMock(){
  const {reference,proof}=checkpoint(),directory=mkdtempSync(join(tmpdir(),'kongos-m6-continuation-unit-'));directories.push(directory);const referencePath=join(directory,'reference.json');writeFileSync(referencePath,JSON.stringify(reference),{mode:0o600});const h=new M6Harness({referencePath,requireReference:true,liveEnabled:true});
  const request=vi.spyOn(h,'request').mockImplementation(async(_session:any,path:string,method='GET')=>{
    expect(method).toBe('GET');let data:any;
    if(path==='/auth/me')data={id:_session.user.id};
    else if(path.includes('/operations/by-key/'))data={kind:'not_sent',state:'not_sent'};
    else if(path.includes('/entities/plugins/'))data={id:reference.fixtureJournal[0].id,name:'key-auth',enabled:true,service:{id:reference.fixtures[0].services[2].id},config:{}};
    else for(const fixture of reference.fixtures){if(path.includes(`/workspaces/${fixture.workspace.id}`))data=fixture.workspace;else if(new URL(path,'http://unit.invalid').searchParams.get('workspaceId')===fixture.workspace.id){if(path.includes('/portal/settings'))data={settings:{...fixture.settings,slug:fixture.slug,published:true}};for(const type of ['services','routes'] as const)for(const row of fixture[type])if(path.includes(`/entities/${type}/${row.id}`))data={entity:row};for(const row of fixture.publications)if(path.includes(`/publications/${row.id}`))data={entity:{...row,status:'draft'}};}}
    if(!data)throw new Error('Unexpected unit-only read path');return{status:200,payload:{data},text:'{}'}as any;
  });
  const db=vi.spyOn(h,'consoleRead').mockReturnValue([{workflows:0,iam_operations:0,native_operations:0,unresolved:0}]);return{h,reference,proof,request,db};
}
describe('M6 narrowly authorized publication continuation guard (offline)',()=>{
  it('pins the existing host-private actor, original key/body and exact proved zero-ledger exception',()=>{const{reference,proof}=checkpoint();const state=publicationContinuationCheckpoint(reference,proof);expect(state.attempt.key).toBe(proof.originalKey);expect(state.first.id).toBe(proof.publicationId);expect(state.fixtures).toBe(reference.fixtures);});
  it('rejects an unknown result, mismatched actor/body/scope or a later write instead of retrying',()=>{const{reference,proof}=checkpoint();for(const change of [()=>reference.writeAttempts[0].state='response_unknown',()=>reference.writeAttempts[0].actorId=randomUUID(),()=>reference.writeAttempts[0].body.revision=3,()=>reference.writeAttempts[0].query=`?workspaceId=${randomUUID()}`,()=>reference.writeAttempts.push({...reference.writeAttempts[0],key:randomUUID()})]){const fresh=structuredClone(reference);change();expect(()=>publicationContinuationCheckpoint(reference,proof)).toThrow('incomplete or changed');Object.assign(reference,fresh);}});
  it('does not accept not_sent alone when native/IAM/workflow or unresolved evidence is missing',()=>{const{reference,proof}=checkpoint();for(const counts of [{...proof.ledgerCounts,native_operations:1},{...proof.ledgerCounts,iam_operations:1},{...proof.ledgerCounts,workflows:1},{...proof.ledgerCounts,unresolved:1},{workflows:0}])expect(()=>publicationContinuationCheckpoint(reference,{...proof,ledgerCounts:counts})).toThrow();});
  it('freshly rechecks all current identities and ledgers using GET-only requests before preserving the original key',async()=>{const{h,proof,request}=liveMock();const state=await guardPublicationContinuation(h,proof);expect(state.attempt.key).toBe(proof.originalKey);expect(request.mock.calls.every(call=>!call[2]||call[2]==='GET')).toBe(true);expect(h.referenceData.continuation.originalKey).toBe(proof.originalKey);});
  it('blocks the continuation when a current draft changes or the original session identifies a different actor',async()=>{for(const actorChanged of [false,true]){const{h,proof,request}=liveMock();const original=request.getMockImplementation()!;request.mockImplementation(async(...args:any[])=>{const result:any=await original(...args);if(actorChanged&&args[1]==='/auth/me')result.payload.data.id=randomUUID();else if(!actorChanged&&args[1].includes(`/publications/${proof.publicationId}`))result.payload.data.entity.revision=3;return result;});await expect(guardPublicationContinuation(h,proof)).rejects.toThrow();expect(h.referenceData.continuation).toBeUndefined();}});
  it('blocks a new running/uncertain operation discovered after the original static proof',async()=>{const{h,proof,db}=liveMock();db.mockReturnValue([{workflows:0,iam_operations:0,native_operations:0,unresolved:1}]);await expect(guardPublicationContinuation(h,proof)).rejects.toThrow();expect(h.referenceData.continuation).toBeUndefined();});
  it('renews only an expired original session once and proves both returned tokens keep its original SID and actor',async()=>{
    const {h,request}=liveMock(),sid=randomUUID(),token=randomUUID(),actor=randomUUID(),session={user:{id:actor},cookie:`kongos_refresh=${sid}.${token}; kongos_access=expired; kongos_csrf=${randomUUID()}`,csrf:randomUUID()};
    let me=0;const refreshedToken=Buffer.from(JSON.stringify({sid})).toString('base64url');
    request.mockImplementation(async(_session:any,path:string,method='GET')=>{
      if(path==='/auth/me')return (++me===1?{status:401,payload:{error:{code:'SESSION_EXPIRED'}}}:{status:200,payload:{data:{user:{id:actor}}}})as any;
      if(path==='/auth/csrf')return{status:200,payload:{data:{csrfToken:randomUUID()}}}as any;
      expect(path).toBe('/auth/refresh');expect(method).toBe('POST');expect(h.referenceData.originalSessionRefreshes.at(-1).previousCookie).toBe(session.cookie);
      return{status:201,payload:{data:{user:{id:actor}}},response:new Response('',{headers:{'Set-Cookie':`kongos_access=header.${refreshedToken}.signature; Path=/api`}})}as any;
    });
    await expect(originalConsoleSession(h,session)).resolves.toBe(session);expect(request.mock.calls.filter(call=>call[1]==='/auth/refresh')).toHaveLength(1);expect(me).toBe(2);
  });
  it('never refreshes a non-401 authorization failure or retries an unknown refresh response',async()=>{
    const {h,request}=liveMock(),sid=randomUUID(),session={user:{id:randomUUID()},cookie:`kongos_refresh=${sid}.${randomUUID()}`,csrf:randomUUID()};
    request.mockResolvedValue({status:403,payload:{error:{code:'PERMISSIONS_CHANGED'}}}as any);await expect(originalConsoleSession(h,session)).rejects.toThrow();expect(request).toHaveBeenCalledTimes(1);
    request.mockClear();request.mockImplementation(async(_session:any,path:string)=>{if(path==='/auth/me')return{status:401}as any;if(path==='/auth/csrf')return{status:200,payload:{data:{csrfToken:randomUUID()}}}as any;throw new TypeError('synthetic refresh connection closed');});
    await expect(originalConsoleSession(h,session)).rejects.toThrow(TypeError);expect(request.mock.calls.filter(call=>call[1]==='/auth/refresh')).toHaveLength(1);
  });
  it('rejects a refreshed cookie family that changes actor or original session identity',async()=>{
    const {h,request}=liveMock(),sid=randomUUID(),session={user:{id:randomUUID()},cookie:`kongos_refresh=${sid}.${randomUUID()}`,csrf:randomUUID()};
    request.mockImplementation(async(_session:any,path:string)=>{if(path==='/auth/me')return{status:401}as any;if(path==='/auth/csrf')return{status:200,payload:{data:{csrfToken:randomUUID()}}}as any;const other=randomUUID();return{status:201,payload:{data:{user:session.user}},response:new Response('',{headers:{'Set-Cookie':`kongos_access=header.${Buffer.from(JSON.stringify({sid:other})).toString('base64url')}.signature; Path=/api`}})}as any;});
    await expect(originalConsoleSession(h,session)).rejects.toThrow();expect(request.mock.calls.filter(call=>call[1]==='/auth/refresh')).toHaveLength(1);
  });
});
