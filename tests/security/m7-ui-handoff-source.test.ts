// @ts-nocheck -- original-session handoff in RAM, no current environment/files.
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { M7_UI_ACTIONS } from './lib/m7-manual-journal.mjs';
import { M7Harness, sha256 } from './lib/m7-harness.mjs';
function fixture(renew=true){
  const areas=Object.fromEntries(['direct','approval','foreign'].map(key=>[key,{cid:randomUUID(),wid:randomUUID()}])),now=Date.now();
  const sessions=Object.fromEntries(['admin','owner','read-only'].map(label=>[label,{user:{id:randomUUID(),username:label},sid:randomUUID(),csrf:'synthetic',cookie:'',expiresAt:now+(renew?1000:900000)}]));
  const encode=session=>`kongos_access=h.${Buffer.from(JSON.stringify({sub:session.user.id,sid:session.sid,exp:Math.floor((Date.now()+900000)/1000)})).toString('base64url')}.s; kongos_csrf=SyntheticCsrfValue`;
  const cid1=areas.direct.cid,cid2=areas.approval.cid,clusters=[{id:cid1,name:'direct',environment:'test',execution_mode:'direct'},{id:cid2,name:'approval',environment:'test',execution_mode:'direct'}];
  const h={state:{phase:'producers-complete',producersComplete:true,testTag:'m7-security-abcd1234',requests:[],inFlight:null,sessions,scopes:areas,fixtures:Object.entries(areas).map(([key,a])=>({type:'workspaces',id:a.wid,cid:a.cid,name:key})),originalClusterModes:{[cid2]:{mode:'direct'}},eventOperations:[{approval:true,workflowId:randomUUID(),...areas.approval}]},
    check(v,n){if(!v)throw Error(n)},data:r=>r.data,save:vi.fn(),cookies:vi.fn(),remember:vi.fn(),updateSessionIdentity:M7Harness.prototype.updateSessionIdentity};
  h.request=vi.fn(async(session,path,method='GET',body,options={})=>{expect(options.renew).toBe(false);if(path==='/auth/refresh'){session.cookie=encode(session);return{requestId:randomUUID(),data:{user:structuredClone(session.user)}}}if(path==='/auth/me')return{data:{user:session.user}};if(path==='/clusters')return{data:{items:clusters}};throw Error('UNEXPECTED_ENDPOINT')});
  const retain=vi.fn(),source=readFileSync(new URL('./lib/m7-ui-handoff.mjs',import.meta.url),'utf8').replace(/^import .*;$/gm,'').replace(/export /g,'');
  const helper=new Function('readFileSync','M7_UI_ACTIONS','sha256','rows','retainM7History',source+'\nreturn prepareM7UiHandoff;')(()=>Buffer.from(JSON.stringify({allPassed:true,failed:0,testTag:h.state.testTag})),M7_UI_ACTIONS,sha256,v=>v.items??[],retain);
  return{h,helper,sessions,retain};
}
describe('normal original SID preparation for an exact twelve-write UI handoff',()=>{
  it('renews each insufficient original actor once, verifies current me and never logs in',async()=>{
    const f=fixture(),before=Object.fromEntries(Object.entries(f.sessions).map(([key,s])=>[key,{actor:s.user.id,sid:s.sid}])),r=await f.helper(f.h);
    expect(r.authenticationWrites).toBe(3);expect(r.loginWrites).toBe(0);expect(r.handoff.approvedActions).toEqual(M7_UI_ACTIONS);expect(f.h.state.manualUiHandoff.phase).toBe('ready');
    expect(f.h.request.mock.calls.filter(c=>c[2]==='POST').map(c=>c[1])).toEqual(Array(3).fill('/auth/refresh'));
    for(const [key,s]of Object.entries(f.sessions)){expect(s.user.id).toBe(before[key].actor);expect(s.sid).toBe(before[key].sid);expect(s.expiresAt).toBeGreaterThan(Date.now()+300000)}
    expect(f.retain).toHaveBeenCalledTimes(1);
  });
  it('does not rotate a session that already has enough remaining lifetime',async()=>{const f=fixture(false),r=await f.helper(f.h);expect(r.authenticationWrites).toBe(0);expect(f.h.request.mock.calls.every(c=>c[2]!=='POST')).toBe(true)});
  it.each(['producer-incomplete','unknown-request','prior-handoff'])('refuses %s before any authentication packet',async defect=>{
    const f=fixture();if(defect==='producer-incomplete')f.h.state.producersComplete=false;if(defect==='unknown-request')f.h.state.requests.push({state:'response_unknown'});if(defect==='prior-handoff')f.h.state.manualUiHandoff={};
    await expect(f.helper(f.h)).rejects.toThrow();expect(f.h.request).not.toHaveBeenCalled();expect(f.retain).not.toHaveBeenCalled();
  });
  it.each(['wrong-actor','wrong-subject','changed-sid','unknown-refresh'])('refuses %s and preserves prepared evidence without a ready handoff',async defect=>{
    const f=fixture(),original=f.h.request.getMockImplementation();f.h.request.mockImplementation(async(...args)=>{if(args[1]==='/auth/refresh'){if(defect==='unknown-refresh')throw Error('UNKNOWN_ORIGINAL_PACKET');const r=await original(...args);if(defect==='wrong-actor')r.data.user.id=randomUUID();if(defect==='wrong-subject'){const s=args[0];s.cookie=`kongos_access=h.${Buffer.from(JSON.stringify({sub:randomUUID(),sid:s.sid,exp:Math.floor((Date.now()+900000)/1000)})).toString('base64url')}.s; kongos_csrf=SyntheticCsrfValue`}if(defect==='changed-sid'){const s=args[0];s.cookie=`kongos_access=h.${Buffer.from(JSON.stringify({sub:s.user.id,sid:randomUUID(),exp:Math.floor((Date.now()+900000)/1000)})).toString('base64url')}.s; kongos_csrf=SyntheticCsrfValue`}return r}return original(...args)});
    await expect(f.helper(f.h)).rejects.toThrow();expect(f.h.state.uiHandoffPreparation.state).toBe('prepared');expect(f.h.state.manualUiHandoff).toBeUndefined();expect(f.h.request.mock.calls.filter(c=>c[2]==='POST')).toHaveLength(1);
  });
});
