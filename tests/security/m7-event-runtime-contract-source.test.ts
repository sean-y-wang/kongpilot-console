// @ts-nocheck -- actual acceptance ESM helpers, synthetic RAM responses only.
import { describe, expect, it, vi, afterEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eventRead, eventWrite, nineMetadataHandlers, fourProviderDelivery } from './lib/m7-event-acceptance.mjs';
import { notificationAcceptance, lateAckFenceAcceptance } from './lib/m7-notification-acceptance.mjs';
import { EVENT_WORKFLOW_HANDLERS } from '../../apps/console-api/src/modules/workflows/event-workflow';

const ok = data => ({ status: 200, payload: { data } });
const actors = Object.fromEntries(['admin','approver','owner','other','readonly'].map(label => [label, { label, user: { id: randomUUID() } }]));
const area = { cid: randomUUID(), wid: randomUUID() };
const materials = { httpBearer: 'SyntheticBearer', httpBasic: { username: 'synthetic', password: 'SyntheticPassword' } };

// The model supplies documented safe DTOs and receiver observations. It never
// invokes a harness constructor, fetch, a process, a file, or a product service.
function ram(options = {}) {
  const calls = [], receipts = new Map(), workflows = new Map(), workflowReceipts = new Map();
  const channels = new Map(), subscriptions = new Map(), deliveries = new Map(), preferences = new Map();
  const faults = {}, stats = Object.fromEntries(['event-mail','event-receiver'].map(v => [v,{auth:0,received:0,unique:0,duplicates:0,records:[]}]));
  let service, event, notification;
  const h = {
    state: { testTag: 'm7-independent', fixtures: [], eventOperations: [] }, calls, channels, subscriptions, preferences, deliveries,
    save: vi.fn(), data: r => { if (r.status >= 300) throw Error('unexpected HTTP '+r.status); return r.payload.data; },
    check: (condition, name) => { if (!condition) throw Error(name); },
    poll: async (read, predicate, name) => { const value = await read(); if (!predicate(value)) throw Error(name); return value; },
    receiver: (name,input) => {
      calls.push({receiver:name,...structuredClone(input)});
      if (input.action === 'fault') { faults[name] = input.fault; return {ok:true}; }
      return structuredClone(stats[name]);
    },
  };
  function queue(channel, replay = false) {
    const id = randomUUID(), eventId = randomUUID(), name = channel.type === 'email' ? 'event-mail' : 'event-receiver';
    const fault = faults[name] ?? {}, tls = fault.starttlsDisabled, uncertain = fault.dropAfterBody || fault.delayMs;
    const state = tls ? 'exhausted' : uncertain ? 'uncertain' : 'succeeded';
    const value = {id,name:id,eventId,revision:1,state,errorCode:tls?'EVENT_SMTP_STARTTLS_REQUIRED':null,subscriptionId:null};
    value.attempts = tls ? [{sendStarted:false,outcome:'failed'}] : fault.status===429 ? [{sendStarted:true,outcome:'failed',httpStatus:429},{sendStarted:true,outcome:'succeeded',httpStatus:200}] : [{sendStarted:true,outcome:state,httpStatus:200}];
    if (!tls || options.tlsLeak) {
      stats[name].auth += channel.type==='email'||channel.auth?.type!=='none' ? 1 : 0;
      const count = fault.status===429?2:1;
      for (let i=0;i<count;i++) stats[name].records.push({deliveryId:id,eventId,idempotencyDigest:'same-intent-'+id,bodyDigest:options.changedRetryBody&&i===1?'changed':'same-body-'+id});
      stats[name].received+=count;stats[name].unique++;stats[name].duplicates+=count-1;
    }
    if (options.latePromote && uncertain) {value.state='succeeded';value.attempts[0].outcome='succeeded';}
    deliveries.set(id,value);return {deliveryId:id,eventId,...(replay?{replayGeneration:1}:{})};
  }
  function commit(path,method,body) {
    const [collection,id,action] = path.split('/');
    if (collection==='deliveries') return {handler:'event.delivery.replay',result:{queued:queue(channels.values().next().value,true)}};
    const map = collection==='channels'?channels:subscriptions, family = collection==='channels'?'channel':'subscription';
    let value = map.get(id);
    if (!id) {value={id:randomUUID(),...structuredClone(body),revision:1,status:'active',configured:true,credentialGeneration:1,capabilities:{write:true,delete:true,restore:false,test:true}};map.set(value.id,value);}
    else {value={...value,revision:value.revision+1,...(action==='status'?{status:body.status}:action==='restore'?{status:'disabled'}:method==='DELETE'?{status:'deleted'}:body)};if(body.auth)value.credentialGeneration++;map.set(id,value);}
    const handler = `event.${family}.${action==='test'?'test':action==='status'?'status':action==='restore'?'restore':method==='DELETE'?'delete':'save'}`;
    return {handler,result:action==='test'?{queued:queue(value)}:{entity:structuredClone(value)}};
  }
  h.request = async (actor,path,method='GET',body,config={}) => {
    const url = new URL(path,'http://synthetic.invalid'), clean = url.pathname;
    const key = config.key ?? randomUUID();calls.push({actor:actor.label,path:clean,query:Object.fromEntries(url.searchParams),method,body:structuredClone(body),key,expected:config.expected});
    let value, status=200;
    const eventPath = clean.split('/events/')[1], workflowPath = clean.split('/workflows/')[1];
    if (workflowPath) {
      if(workflowPath.startsWith('receipts/by-key/'))value=structuredClone(workflowReceipts.get(workflowPath.split('/').at(-1)));
      else {
        const [id,action]=workflowPath.split('/'), wf=workflows.get(id);
        if(action==='approve') {wf.entity.state='approved';wf.entity.revision++;value={entity:structuredClone(wf.entity)};if(options.wrongApproval)value.entity.id=randomUUID();workflowReceipts.set(key,{workflowId:id,clusterId:area.cid,workspaceId:area.wid,idempotencyKey:key,state:'approved',action:'approve',decisionCompleted:true});}
        else if(action==='execute') {
          const {handler,result}=commit(wf.path,wf.method,wf.body);wf.entity.state='succeeded';wf.entity.revision++;
          Object.assign(receipts.get(wf.originalKey),{state:'succeeded',configurationCommitted:true,executionCompleted:true,result});
          value={workflowId:id,executionId:randomUUID(),clusterId:area.cid,workspaceId:area.wid,state:'succeeded',steps:[{name:handler,state:'succeeded',remoteCompleted:true}]};
          workflowReceipts.set(key,{...value,idempotencyKey:key,action:'execute'});
        } else value={entity:structuredClone(wf.entity),steps:[{kind:options.nativeStep?'native':'metadata',handler:'event.channel.save',nativeRequests:[]}]};
      }
    } else if (eventPath) {
      const [kind,id,action] = eventPath.split('/');
      if (method==='GET') {
        if(kind==='operations') {value=structuredClone(receipts.get(eventPath.split('/').at(-1)));if(options.foreignFinal)value.workspaceId=randomUUID();}
        else if(kind==='records') value={items:[event]};
        else if(kind==='deliveries'&&!id) value={items:[...deliveries.values()].filter(d=>d.eventId===url.searchParams.get('eventId')).map(d=>structuredClone(d))};
        else if(kind==='deliveries'&&action==='attempts') value={items:structuredClone(deliveries.get(id).attempts)};
        else {value={entity:structuredClone((kind==='channels'?channels:kind==='subscriptions'?subscriptions:deliveries).get(id))};if(actor===actors.readonly&&kind==='channels')value.entity.capabilities={write:false,delete:false,restore:false,test:false};}
      } else if(actor===actors.readonly) {status=403;value=null;}
      else if(kind==='deliveries'&&deliveries.get(id).state==='uncertain') {status=409;value=null;}
      else if(options.approval) {
        const workflowId=randomUUID(), handler=kind==='deliveries'?'event.delivery.replay':`event.${kind==='channels'?'channel':'subscription'}.${action??(method==='DELETE'?'delete':'save')}`;
        const entity={id:workflowId,kind:'event-metadata',clusterId:area.cid,workspaceId:area.wid,state:'pending',revision:1,planHash:'sealed-plan-'+workflowId};
        value={id:workflowId,workflowId,domain:'workflow',state:'pending',clusterId:area.cid,workspaceId:area.wid,idempotencyKey:key,handler,configurationCommitted:false,submissionCompleted:true,executionCompleted:false,entity};
        workflows.set(workflowId,{entity,path:eventPath,method,body,originalKey:key});receipts.set(key,structuredClone(value));
      } else {
        const {handler,result}=commit(eventPath,method,body);
        value={id:randomUUID(),domain:'iam',state:'succeeded',clusterId:area.cid,workspaceId:area.wid,idempotencyKey:key,handler,configurationCommitted:true,executionCompleted:true,result};receipts.set(key,structuredClone(value));
      }
    } else if(clean.includes('/entities/services')) {
      if(method==='POST'){service={id:randomUUID(),...body,retries:0};value={entity:service};}
      else if(method==='GET')value={entity:structuredClone(service)};
      else {
        service={...service,...body};value={entity:service};event={id:randomUUID(),phase:'terminal'};
        for(const sub of subscriptions.values()){const id=randomUUID();deliveries.set(id,{id,eventId:event.id,subscriptionId:options.duplicateFanout?'duplicate':sub.id,state:'succeeded'});}
        notification={id:randomUUID(),eventId:event.id,revision:1,readAt:null,dismissedAt:null};
      }
    } else if(clean==='/notifications/preferences'&&method==='POST') {
      if(actor===actors.readonly){status=403;value=null;}else {value={entity:{id:randomUUID(),...body,revision:1,status:'active'}};preferences.set(value.entity.id,value.entity);}
    } else if(clean.startsWith('/notifications/preferences/')) {
      const id=clean.split('/')[3], pref=preferences.get(id);
      if(method==='GET'){status=404;value=null;}
      else {value={entity:{...pref,...body,revision:pref.revision+1,status:clean.endsWith('/restore')?'active':method==='DELETE'?'deleted':'active'}};preferences.set(id,value.entity);}
    } else if(clean.startsWith('/notifications/operations/')){status=404;value=null;}
    else if(clean==='/notifications')value={items:[notification]};
    else if(clean.startsWith('/notifications/')) {
      if(method==='GET'){status=404;value=null;}
      else {notification={...notification,revision:notification.revision+1,...(clean.endsWith('/read')?{readAt:'2026-10-11T00:00:00Z'}:{dismissedAt:'2026-10-11T00:00:01Z'})};value=notification;}
    } else throw Error('UNEXPECTED_RAM_CONTRACT_PATH '+clean);
    if(config.expected&&!config.expected.includes(status))throw Error('unexpected HTTP '+status);
    return {status,payload:status<300?{data:structuredClone(value)}:{error:{code:status===409?'DELIVERY_UNRESOLVED':'PERMISSION_DENIED'}}};
  };
  return h;
}
afterEach(()=>vi.unstubAllGlobals());

describe('independent actual M7 acceptance helper contracts, RAM only',()=>{
  it('detail wrappers unwrap, while an original-key workflow receipt retains its namespace',async()=>{
    const id=randomUUID(),receipt={domain:'workflow',state:'pending',entity:{id}},h=ram();
    h.request=vi.fn(async(_a,path)=>ok(path.includes('/operations/')?receipt:{entity:{id}}));
    expect(await eventRead(h,actors.admin,area,`channels/${id}`)).toEqual({id});
    expect(await eventRead(h,actors.admin,area,`operations/by-key/${randomUUID()}`)).toEqual(receipt);
  });
  it('a foreign terminal receipt cannot certify completion of an original scoped write',async()=>{
    const h=ram({foreignFinal:true});
    await expect(eventWrite(h,actors.admin,actors.approver,area,'channels','POST',{name:'scope-test',type:'email'},'event.channel.save')).rejects.toThrow('original event receipt');
    expect(h.state.eventOperations).toHaveLength(0);
  });
  it('approval rejects a foreign decision and native step before execute; happy execution reads its exact original-key receipt',async()=>{
    for(const options of [{approval:true,wrongApproval:true},{approval:true,nativeStep:true}]) {
      const h=ram(options);await expect(eventWrite(h,actors.admin,actors.approver,area,'channels','POST',{name:'approval',type:'email'},'event.channel.save',true)).rejects.toThrow();
      expect(h.calls.some(v=>v.path?.endsWith('/execute'))).toBe(false);
    }
    const h=ram({approval:true});await eventWrite(h,actors.admin,actors.approver,area,'channels','POST',{name:'approval',type:'email'},'event.channel.save',true);
    const executed=h.calls.find(v=>v.path?.endsWith('/execute'));
    expect(h.calls.find(v=>v.path?.endsWith('/receipts/by-key/'+executed.key)).actor).toBe('admin');
    expect(h.calls.filter(v=>v.method==='POST'&&v.path?.endsWith('/execute'))).toHaveLength(1);
  });
  it('both modes run exactly the nine fixed handlers and STARTTLS denial precedes repair/replay; AUTH or DATA leakage stops replay',async()=>{
    for(const approval of [false,true]) {
      const h=ram({approval});await nineMetadataHandlers(h,actors,area,materials,approval);
      expect(new Set(h.state.eventOperations.map(v=>v.handler))).toEqual(new Set(Object.keys(EVENT_WORKFLOW_HANDLERS)));
      const repair=h.calls.findIndex(v=>v.fault?.starttlsDisabled===false),replay=h.calls.findIndex(v=>v.path?.endsWith('/replay'));
      expect(repair).toBeGreaterThan(0);expect(replay).toBeGreaterThan(repair);
    }
    const bad=ram({tlsLeak:true});await expect(nineMetadataHandlers(bad,actors,area,materials)).rejects.toThrow('stripped STARTTLS');
    expect(bad.calls.some(v=>v.path?.endsWith('/replay'))).toBe(false);
  });
  it('known429 retains one immutable body/key, while uncertain body delivery is denied replay',async()=>{
    const h=ram();await fourProviderDelivery(h,actors,area,materials);
    const denial=h.calls.find(v=>v.path?.endsWith('/replay'));
    expect(denial.expected).toEqual([409]);expect(h.state.eventOperations.some(v=>v.handler==='event.delivery.replay')).toBe(false);
    const bad=ram({changedRetryBody:true});await expect(fourProviderDelivery(bad,actors,area,materials)).rejects.toThrow('known429');
    expect(bad.calls.some(v=>v.fault?.dropAfterBody)).toBe(false);
  });
  it('fanout uses55 actual preference/subscription helper writes and one Native PATCH, with owner-only receipts and notifications',async()=>{
    const h=ram(),channel={id:randomUUID(),name:'fanout-channel',revision:1};h.channels.set(channel.id,channel);
    await notificationAcceptance(h,actors,area,channel);
    expect(h.preferences.size).toBe(55);expect(h.subscriptions.size).toBe(55);
    expect(h.calls.filter(v=>v.method==='PATCH'&&v.path?.includes('/entities/services/'))).toHaveLength(1);
    expect(h.calls.some(v=>v.method==='POST'&&v.path?.endsWith('/events/records'))).toBe(false);
    expect(h.calls.filter(v=>v.expected?.includes(404))).toHaveLength(6);
    expect(h.public.fanout).toEqual({sharedSubscriptions:55,successfulDeliveries:55,personalPreferences:55,deduplicatedOwnerNotifications:1});
  });
  it('55 duplicate fanout rows do not substitute for55 distinct real subscriptions',async()=>{
    const h=ram({duplicateFanout:true}),channel={id:randomUUID(),name:'fanout-channel',revision:1};h.channels.set(channel.id,channel);
    await expect(notificationAcceptance(h,actors,area,channel)).rejects.toThrow('does not duplicate');
    expect(h.calls.some(v=>v.path?.endsWith('/read'))).toBe(false);
  });
  it('a late provider acknowledgement after generation rotation must remain uncertain and exactly once',async()=>{
    const h=ram();await lateAckFenceAcceptance(h,actors,area,materials);
    expect(h.calls.filter(v=>v.method==='POST'&&v.path?.endsWith('/test'))).toHaveLength(1);
    const replays=h.calls.filter(v=>v.path?.endsWith('/replay'));
    expect(replays).toHaveLength(1);expect(replays[0].expected).toEqual([409]);
    expect(h.state.eventOperations.some(v=>v.handler==='event.delivery.replay')).toBe(false);
    const bad=ram({latePromote:true});await expect(lateAckFenceAcceptance(bad,actors,area,materials)).rejects.toThrow('expected uncertain');
  });
});
