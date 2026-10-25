// @ts-nocheck -- real helper, synthetic RAM-only current authentication.
import{describe,it,expect,vi}from'vitest';import{randomUUID}from'node:crypto';
import{prepareM8UiCurrentSessions}from'./lib/m8-ui-session-handoff.mjs';
function fixture(lifetime=900000,problem=''){
 const sessions=Object.fromEntries(['admin','owner','read-only'].map(label=>[label,{user:{id:randomUUID(),username:label},sid:randomUUID(),csrf:'original-csrf',cookie:'kongos_csrf=original-csrf',expiresAt:Date.now()+lifetime}]));
 const h={state:{sessions,requests:[],inFlight:null},check:(v,n)=>{if(!v)throw Error(n);},save:vi.fn(),data:r=>r.payload.data,remember:vi.fn(),cookies:vi.fn(),updateSessionIdentity:a=>{if(problem==='sid')a.sid=randomUUID();a.expiresAt=Date.now()+900000;},request:vi.fn(async(a,path,method)=>{
  if(method==='POST'){h.state.requests.push({actorId:a.user.id,sessionId:a.sid,path:'/api/v1/auth/refresh',method,status:201,state:'response_observed',requestId:randomUUID()});a.cookie='kongos_csrf=renewed-csrf';return{payload:{data:{user:{...a.user,id:problem==='actor'?randomUUID():a.user.id}}}};}
  return{payload:{data:{user:{...a.user},csrfToken:problem==='csrf'?'other-csrf':a.csrf}}};
 })};return h;
}
describe('M8 exact normal current-session UI handoff',()=>{
 it('keeps sufficiently live sessions and proves each actor via protected GET',async()=>{const h=fixture(),r=await prepareM8UiCurrentSessions(h);expect(r.normalAuthenticationWrites).toBe(0);expect(r.sessions).toHaveLength(3);expect(h.request.mock.calls.every(v=>v[2]==='GET')).toBe(true);});
 it('normally renews only the insufficient actor once with its real original SID',async()=>{const h=fixture();h.state.sessions.owner.expiresAt=Date.now()+1000;const sid=h.state.sessions.owner.sid,r=await prepareM8UiCurrentSessions(h);expect(r.normalAuthenticationWrites).toBe(1);expect(h.state.sessions.owner.sid).toBe(sid);expect(h.request.mock.calls.filter(v=>v[2]==='POST')).toHaveLength(1);});
 for(const failure of['actor','sid','csrf'])it(`does not complete a changed ${failure}`,async()=>{const h=fixture(1000,failure);await expect(prepareM8UiCurrentSessions(h)).rejects.toThrow();expect(h.state.uiSessionHandoff.state).toBe('running');expect(h.request.mock.calls.filter(v=>v[2]==='POST').length).toBeLessThanOrEqual(1);});
 it('cannot repeat an existing completed authentication window',async()=>{const h=fixture();h.state.uiSessionHandoff={state:'completed'};await expect(prepareM8UiCurrentSessions(h)).rejects.toThrow();expect(h.request).not.toHaveBeenCalled();});
});
