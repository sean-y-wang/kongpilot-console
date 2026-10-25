/** Normal product authentication only. The original actors remain the same;
 * an owner SID genuinely changed by the prior logout/login acceptance is the
 * current SID. No expiry, SID, cookie, or authority is manufactured here. */
export async function prepareM8UiCurrentSessions(h){
 h.check(!h.state.uiSessionHandoff&&h.state.inFlight===null,'M8 UI session maintenance is one explicitly journaled window');
 const actors={admin:h.state.sessions.admin,owner:h.state.sessions.owner,readonly:h.state.sessions['read-only']};
 h.check(Object.values(actors).every(a=>a?.user?.id&&a.sid&&Number.isFinite(a.expiresAt)),'three actual current named M8 sessions exist');
 const start=h.state.requests.length,window={version:1,state:'running',originalRequestCount:start,actors:Object.fromEntries(Object.entries(actors).map(([label,a])=>[label,{actorId:a.user.id,sessionId:a.sid,expiresAt:a.expiresAt}]))};
 h.state.uiSessionHandoff=window;h.save();const result=[];
 for(const[label,actor]of Object.entries(actors)){
  const previous={actorId:actor.user.id,username:actor.user.username,sid:actor.sid};
  if(actor.expiresAt<Date.now()+300000){
   const response=await h.request(actor,'/auth/refresh','POST',{}, {expected:[201],renew:false}),data=h.data(response);
   h.check(data.user?.id===previous.actorId&&data.user.username===previous.username,'UI normal renewal preserves the original current actor');
   actor.csrf=actor.cookie.split('; ').find(p=>p.startsWith('kongos_csrf='))?.slice(12);
   h.check(typeof actor.csrf==='string'&&actor.csrf.length>0,'UI normal renewal receives a current product CSRF cookie');
   actor.user=data.user;h.updateSessionIdentity(actor);h.cookies(actor.cookie);h.remember({csrfToken:actor.csrf});h.save();
   h.check(actor.sid===previous.sid,'UI normal renewal preserves the genuine current SID');
  }
  const me=h.data(await h.request(actor,'/auth/me','GET',undefined,{expected:[200],renew:false}));
  h.check(me.user?.id===previous.actorId&&me.user.username===previous.username&&me.csrfToken===actor.csrf&&actor.sid===previous.sid
   &&actor.expiresAt>=Date.now()+300000,'actual protected current user and original SID have at least five minutes for exclusive UI handoff');
  result.push({role:label,actorId:previous.actorId,sessionId:previous.sid,sessionExpiresAt:new Date(actor.expiresAt).toISOString(),remainingSeconds:Math.floor((actor.expiresAt-Date.now())/1000),currentUserProven:true});
 }
 const suffix=h.state.requests.slice(start);
 h.check(suffix.every(p=>p.path==='/api/v1/auth/refresh'&&p.method==='POST'&&p.status===201&&p.state==='response_observed'
  &&Object.values(window.actors).some(a=>a.actorId===p.actorId&&a.sessionId===p.sessionId)),'UI maintenance appends only actual same-SID normal authentication packets');
 Object.assign(window,{state:'completed',normalAuthenticationWrites:suffix.length,requestIds:suffix.map(p=>p.requestId),sessions:result});h.save();return window;
}
