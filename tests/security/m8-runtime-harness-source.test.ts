// @ts-nocheck -- actual ESM harness methods; only synthetic sessions and private temp files.
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {mkdtempSync, readFileSync, rmSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';

const isolation = vi.hoisted(() => ({directory: '', opens: 0, exists: 0}));
vi.mock('node:fs', async importOriginal => {
  const fs = await importOriginal();
  const local = path => {
    if (typeof path !== 'string' || !isolation.directory || !resolve(path).startsWith(isolation.directory + '/')) throw Error('ONLY_SYNTHETIC_TEMP_FILES_ALLOWED');
  };
  return {...fs, existsSync: vi.fn(() => {isolation.exists++; return false;}), openSync: (...args) => {
    const path = args[0];
    if (path !== isolation.directory) local(path);
    isolation.opens++; return fs.openSync(...args);
  }, lstatSync: path => {local(path); return fs.lstatSync(path);}, readFileSync: (...args) => {local(args[0]); return fs.readFileSync(...args);}};
});
vi.mock('node:child_process', () => ({execFileSync: vi.fn(() => {throw Error('NO_DOCKER_OR_PROCESS_EXECUTION_ALLOWED');})}));
import {M8Harness, durableJson, sha256} from './lib/m8-harness.mjs';

function claimsCookie(actorId, sid, expiresAt = Date.now() + 600000) {
  return `kongos_access=e30.${Buffer.from(JSON.stringify({sub:actorId, sid, iat:Math.floor(Date.now()/1000), exp:Math.floor(expiresAt/1000)})).toString('base64url')}.synthetic; kongos_refresh=${sid}.synthetic-refresh; kongos_csrf=SyntheticCurrentCSRF`;
}
function fixture() {
  const actorId=randomUUID(), sid=randomUUID(), file=join(isolation.directory, `${randomUUID()}.json`);
  const h=Object.create(M8Harness.prototype);
  h.state={version:1,milestone:'M8',phase:'created',requests:[],secrets:[],sessions:{},fixtures:[],providerControls:[]};
  h.base='http://127.0.0.1:8080/api/v1';h.checks=[];h.lastRequest=0;
  h.save=extra => {Object.assign(h.state,extra);durableJson(file,h.state);};
  const session={label:'synthetic-owner',user:{id:actorId,username:'synthetic-owner'},sid,expiresAt:Date.now()+600000,csrf:'SyntheticCurrentCSRF',cookie:claimsCookie(actorId,sid)};
  h.state.sessions[session.label]=session;
  return {h,file,session,actorId,sid,read:()=>JSON.parse(readFileSync(file,'utf8'))};
}
function response(data={},status=201,cookies=[],bodyFault=false) {
  const bytes=Buffer.from(JSON.stringify({success:true,data,meta:{requestId:randomUUID()}}));
  return {status,headers:{getSetCookie:()=>cookies,get:()=>null},arrayBuffer:vi.fn(async()=>{if(bodyFault)throw Error('SyntheticBodyStreamFault');return bytes;})};
}

beforeEach(()=>{vi.clearAllMocks();isolation.directory=mkdtempSync(join(tmpdir(),'m8-independent-harness-'));isolation.opens=0;isolation.exists=0;});
afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();rmSync(isolation.directory,{recursive:true,force:true});isolation.directory='';});

describe('independent M8 runtime harness source boundaries',()=>{
  it.each([
    ['/clusters/a8000000-0000-4000-8000-000000000001/configuration/plans/a8000000-0000-4000-8000-000000000002/apply',310000],
    ['/clusters/a8000000-0000-4000-8000-000000000001/snapshots',310000],
    ['/clusters/a8000000-0000-4000-8000-000000000001/workflows/a8000000-0000-4000-8000-000000000002/execute',310000],
    ['/clusters/a8000000-0000-4000-8000-000000000001/workflows/a8000000-0000-4000-8000-000000000002/approve',45000],
    ['/clusters/a8000000-0000-4000-8000-000000000001/entities/services',45000],
    ['/auth/refresh',45000],
  ])('uses fixed transport wait for %s without client-derived authority',async(path,budget)=>{
    const f=fixture(),signal=new AbortController().signal,timeout=vi.spyOn(AbortSignal,'timeout').mockReturnValue(signal);
    vi.stubGlobal('fetch',vi.fn(async(_url,init)=>{expect(init.signal).toBe(signal);return response({id:randomUUID()});}));
    try{await f.h.request(f.session,path,'POST',{synthetic:true},{renew:false});expect(timeout).toHaveBeenCalledWith(budget);
      expect(f.read().requests[0].body).toEqual({synthetic:true});expect(f.read().requests[0]).not.toHaveProperty('nativeAuthority');
    }finally{timeout.mockRestore();}
  });
  it('missing exclusive handoff fails before env/private file probing or a packet',()=>{
    vi.stubEnv('M8_DEPLOYMENT_READY','false');const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
    expect(()=>new M8Harness({resume:true,reference:{milestone:'M6'}})).toThrow('M8_EXCLUSIVE_DEPLOYMENT_HANDOFF_REQUIRED');
    expect(isolation.exists).toBe(0);expect(isolation.opens).toBe(0);expect(fetch).not.toHaveBeenCalled();
  });
  it('an explicitly supplied older-milestone reference is never adopted or saved',()=>{
    vi.stubEnv('M8_DEPLOYMENT_READY','true');vi.stubEnv('M8_RUNTIME_READY','true');
    expect(()=>new M8Harness({resume:true,reference:{version:1,milestone:'M6',requests:[],secrets:[]}})).toThrow('M8_PRIVATE_REFERENCE_INVALID');
    expect(isolation.opens).toBe(0);
  });
  it('the exact actor, SID, scope, original key and body are private-durable before fetch',async()=>{
    const f=fixture(),cid=randomUUID(),wid=randomUUID(),key=randomUUID(),body={revision:2,config:{secret:'SyntheticCredentialOnly'}};
    const fetch=vi.fn(async(url,init)=>{
      const saved=f.read(),packet=saved.requests[0];
      expect(statSync(f.file).mode&0o777).toBe(0o600);expect(saved.inFlight).toBe(0);
      expect(packet).toMatchObject({actorId:f.actorId,sessionId:f.sid,key,clusterId:cid,workspaceId:wid,state:'prepared',body});
      expect(packet.bodySha256).toBe(sha256(init.body));expect(init.headers['X-Idempotency-Key']).toBe(key);expect(init.headers['X-CSRF-Token']).toBe(f.session.csrf);
      return response({id:randomUUID()});
    });vi.stubGlobal('fetch',fetch);
    await f.h.request(f.session,`/clusters/${cid}/events/channels?workspaceId=${wid}`,'POST',body,{key});
    expect(fetch).toHaveBeenCalledTimes(1);expect(f.read().requests[0]).toMatchObject({key,state:'response_observed',status:201});
  });
  it('a save fault produces zero packets and an unknown transport locks every later write',async()=>{
    const f=fixture(),fetch=vi.fn(async()=>{throw Error('SyntheticResponseLost');});vi.stubGlobal('fetch',fetch);
    const originalSave=f.h.save;f.h.save=()=>{throw Error('SyntheticSaveFault');};
    await expect(f.h.request(f.session,'/events/channels','POST',{name:'synthetic'},{renew:false})).rejects.toThrow('SyntheticSaveFault');
    expect(fetch).not.toHaveBeenCalled();
    f.h.save=originalSave;
    await expect(f.h.request(f.session,'/events/subscriptions','POST',{}, {renew:false})).rejects.toThrow('NO_FURTHER_WRITE');
    const g=fixture(),key=randomUUID();
    await expect(g.h.request(g.session,'/events/channels','POST',{name:'synthetic'},{key,renew:false})).rejects.toThrow('M8_RESPONSE_UNKNOWN');
    const retained=g.read();expect(retained.phase).toBe('stopped-unknown');expect(retained.requests[0]).toMatchObject({key,state:'response_unknown',body:{name:'synthetic'}});
    await expect(g.h.request(g.session,'/events/subscriptions','DELETE',{revision:1},{key:randomUUID(),renew:false})).rejects.toThrow('NO_FURTHER_WRITE');
    expect(execFileSync).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);expect(g.read()).toEqual(retained);
  });
  it('concurrent callers cannot both pass an asynchronous renewal boundary and send',async()=>{
    const f=fixture();let release;const pending=new Promise(resolve=>{release=resolve;});
    const fetch=vi.fn(async()=>{await pending;return response({id:randomUUID()});});vi.stubGlobal('fetch',fetch);
    const first=f.h.request(f.session,'/events/channels','POST',{name:'first'});
    const second=f.h.request(f.session,'/events/subscriptions','POST',{name:'second'}).catch(error=>error);
    await Promise.resolve();await Promise.resolve();
    release();await first;expect(await second).toBeInstanceOf(Error);expect(fetch).toHaveBeenCalledTimes(1);expect(f.read().requests).toHaveLength(1);
  });
  it('the wire uses the frozen durable body even if the caller changes its original object',async()=>{
    const f=fixture(),body={name:'original',config:{secret:'SyntheticOriginalSecret'}},originalSave=f.h.save,originalCookie=f.session.cookie,originalCsrf=f.session.csrf;
    f.h.save=extra=>{originalSave(extra);if(extra?.inFlight===0){body.name='changed-after-save';body.config.secret='ChangedSyntheticSecret';f.session.cookie=claimsCookie(randomUUID(),randomUUID());f.session.csrf='ChangedSyntheticCSRF';}};
    const fetch=vi.fn(async(_url,init)=>{expect(JSON.parse(init.body)).toEqual(f.read().requests[0].body);expect(f.read().requests[0].bodySha256).toBe(sha256(init.body));expect(init.headers.Cookie).toBe(originalCookie);expect(init.headers['X-CSRF-Token']).toBe(originalCsrf);expect(f.read().requests[0].headers).toEqual(init.headers);return response({id:randomUUID()});});
    vi.stubGlobal('fetch',fetch);await f.h.request(f.session,'/events/channels','POST',body,{renew:false});expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('login cookies survive a rejected status and a broken body before any named session assertion',async()=>{
    for(const fault of [false,true]){
      const f=fixture(),cookies=[`kongos_access=SyntheticLoginAccess; HttpOnly`,`kongos_refresh=SyntheticLoginRefresh; HttpOnly`,`kongos_csrf=SyntheticLoginCSRF; HttpOnly`],r=response({},503,cookies,fault);
      r.arrayBuffer=vi.fn(async()=>{expect(f.read().requests[0].responseCookies).toEqual(cookies);expect(f.read().secrets).toContain('SyntheticLoginRefresh');if(fault)throw Error('SyntheticBrokenBody');return Buffer.from(JSON.stringify({error:{code:'AUTH_UNAVAILABLE'}}));});
      vi.stubGlobal('fetch',vi.fn(async()=>r));
      await expect(f.h.login('new-offline-login','offline-user','SyntheticPassword!47')).rejects.toThrow();
      expect(f.read().requests[0].responseCookies).toEqual(cookies);expect(f.read().sessions['new-offline-login']).toBeUndefined();
    }
  });
  it('normal renewal honors the actual user-only refresh DTO and original SID, then sends with current cookies',async()=>{
    const f=fixture();f.session.expiresAt=Date.now()+1000;
    const cookies=[`${claimsCookie(f.actorId,f.sid).split('; ')[0]}; HttpOnly`,'kongos_csrf=SyntheticRotatedCSRF; HttpOnly'];
    const fetch=vi.fn(async(url,init)=>{
      if(url.endsWith('/auth/refresh'))return response({user:f.session.user},201,cookies);
      expect(init.headers['X-CSRF-Token']).toBe('SyntheticRotatedCSRF');expect(init.headers.Cookie).toContain('kongos_csrf=SyntheticRotatedCSRF');return response({id:randomUUID()});
    });vi.stubGlobal('fetch',fetch);
    await f.h.request(f.session,'/events/channels','POST',{name:'after-renewal'});
    expect(fetch).toHaveBeenCalledTimes(2);expect(f.session.sid).toBe(f.sid);expect(f.read().requests.map(p=>p.path)).toEqual(['/api/v1/auth/refresh','/api/v1/events/channels']);
  });
  it('a renewal response cannot replace the original actor even when its SID is unchanged',async()=>{
    for(const change of ['actor','sid']){
      const f=fixture();f.session.expiresAt=Date.now()+1000;
      const actorId=change==='actor'?randomUUID():f.actorId,sid=change==='sid'?randomUUID():f.sid;
      const fetch=vi.fn(async()=>response({user:{...f.session.user,id:actorId}},201,[`${claimsCookie(actorId,sid).split('; ')[0]}; HttpOnly`]));vi.stubGlobal('fetch',fetch);
      await expect(f.h.request(f.session,'/events/channels','POST',{name:'must-never-send'})).rejects.toThrow();
      expect(fetch).toHaveBeenCalledTimes(1);expect(f.read().requests).toHaveLength(1);expect(f.read().requests[0].path).toBe('/api/v1/auth/refresh');
    }
  });
  it('an explicit five-minute window uses actual remaining expiry without changing the original SID',async()=>{
    const f=fixture();f.session.expiresAt=Date.now()+240000;
    const fetch=vi.fn(async()=>response({user:f.session.user},201,[`${claimsCookie(f.actorId,f.sid,Date.now()+900000).split('; ')[0]}; HttpOnly`,'kongos_csrf=SyntheticRotatedCSRF; HttpOnly']));vi.stubGlobal('fetch',fetch);
    const originalExpiry=f.session.expiresAt;await f.h.renewIfNeeded(f.session);expect(fetch).not.toHaveBeenCalled();expect(f.session.expiresAt).toBe(originalExpiry);
    await f.h.renewIfNeeded(f.session,{minimumRemainingMs:300000});expect(fetch).toHaveBeenCalledOnce();expect(f.session.sid).toBe(f.sid);expect(f.session.expiresAt).toBeGreaterThan(Date.now()+300000);
    expect(f.read().requests[0]).toMatchObject({path:'/api/v1/auth/refresh',actorId:f.actorId,sessionId:f.sid,status:201});
    await f.h.renewIfNeeded(f.session,{minimumRemainingMs:300000});expect(fetch).toHaveBeenCalledOnce();
  });
  it.each([89999,300001,Infinity,NaN,'300000',null])('invalid explicit renewal window %s fails before any packet',async minimumRemainingMs=>{
    const f=fixture(),fetch=vi.fn();vi.stubGlobal('fetch',fetch);await expect(f.h.renewIfNeeded(f.session,{minimumRemainingMs})).rejects.toThrow('M8_NORMAL_SESSION_RENEWAL_WINDOW_INVALID');expect(fetch).not.toHaveBeenCalled();expect(f.h.state.requests).toEqual([]);
  });
  it('a private initial journal is exclusive and unsupported URLs produce no packet',async()=>{
    const f=fixture(),file=join(isolation.directory,'exclusive.json');durableJson(file,{sentinel:'synthetic'},0o600,true);
    expect(()=>durableJson(file,{sentinel:'overwritten'},0o600,true)).toThrow();expect(JSON.parse(readFileSync(file,'utf8'))).toEqual({sentinel:'synthetic'});
    const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
    for(const path of ['//outside.invalid/x','/https://outside.invalid/x','/bad\\path'])await expect(f.h.request(f.session,path,'POST',{}, {renew:false})).rejects.toThrow('M8_RELATIVE_BFF_PATH_REQUIRED');
    expect(fetch).not.toHaveBeenCalled();expect(f.h.state.requests).toEqual([]);
  });
  it('one-time raw response is private-durable before a later status assertion rejects it',async()=>{
    const f=fixture(),body='_format_version: "1.1"\nconsumers: []\n',headers=new Headers({'Content-Type':'application/yaml','X-Request-Id':randomUUID()});
    headers.getSetCookie=()=>[];
    vi.stubGlobal('fetch',vi.fn(async()=>({status:201,headers,arrayBuffer:async()=>Buffer.from(body)})));
    await expect(f.h.request(f.session,'/configuration/exports/synthetic/download','POST',{revision:1},{expected:[200],raw:true,renew:false})).rejects.toThrow('expected BFF HTTP 200 received 201');
    const packet=f.read().requests[0];expect(packet.state).toBe('response_observed');expect(packet.rawResponseText).toBe(body);expect(packet.responseByteCount).toBe(Buffer.byteLength(body));expect(packet.responseSha256).toBe(sha256(body));expect(packet.responseHeaders['content-type']).toBe('application/yaml');
  });
});
