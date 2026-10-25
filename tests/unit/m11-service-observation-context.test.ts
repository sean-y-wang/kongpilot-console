import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {serviceObservationContextFixture} from './helpers/m11-service-observation-context-fixture';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ae'.repeat(32)));
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
const denied=(code:string)=>({response:{code}});
/** Actual Context shared meter and fixed bootstrap dispatch; Approved/SQL and
 * SDK responses are controlled adapters, never real Native send evidence. */
function fixture(){
 const f=serviceObservationContextFixture(),handle=Object.freeze({}),observed:any={before:{id:f.nativeId,host:'backend.local'},serviceHostUpstream:null,serviceTargets:[]};
 const state:any={reader:undefined,consumer:undefined,handle,consumed:0};
 const read=f.context.installConfigurationServiceBeforeObserver({async read(original:any){if(original!==handle)throw Error('SOURCE_ORIGINAL_READ_HANDLE_REQUIRED');
   f.context.startConfigurationServiceObservation();await state.reader?.();return observed;}});
 f.approved.readConfigurationNativeBefore=vi.fn(async(_step:any,_input:any)=>read(handle as any));
 f.context.installConfigurationServiceDestinationObserver({async observe(ticket,result){state.consumed++;f.context.assertTicketActive(ticket);expect(result).toBe(observed);await state.consumer?.(ticket);}});
 const get=async(result:any={id:randomUUID()})=>{const ticket=await f.context.authorizeRequest(f.cluster,'GET','/upstreams/backend.local',undefined,{});await f.context.authorizeResponse(ticket,result);return ticket;};
 return{...f,sourceState:f.state,state,read,get};
}
describe('fixed Service relation/destination one invocation budget',()=>{
 it('dispatches only through the once-installed fixed consumer with the original packet',async()=>{
  const f=fixture();f.state.reader=async()=>{await f.get();};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).resolves.toBe(true);});
  expect(f.state.consumed).toBe(1);expect(f.approved.readConfigurationNativeBefore).toHaveBeenCalledOnce();
  expect(()=>f.context.startConfigurationServiceObservation()).toThrow();
 });
 it('rejects duplicate bootstrap readers and consumers',()=>{
  const f=fixture();expect(()=>f.context.installConfigurationServiceBeforeObserver({read:async()=>({before:null})})).toThrow();
  expect(()=>f.context.installConfigurationServiceDestinationObserver({observe:async()=>undefined})).toThrow();
 });
 it('rejects a copied packet ticket and never calls the observer',async()=>{
  const f=fixture();await f.packet(async()=>{await expect(f.context.protectScheduledConfigurationServiceDestination({} as any)).rejects.toMatchObject(denied('KONG_EXECUTION_TICKET_INVALID'));});expect(f.state.consumed).toBe(0);
 });
 it('covers the direct verifier reader entry without the primary Context adapter',async()=>{
  const f=fixture();f.state.reader=async()=>{await f.get();};
  await f.packet(async()=>{await expect(f.read(f.state.handle)).resolves.toMatchObject({serviceHostUpstream:null});});
  expect(f.state.consumed).toBe(0);
 });
 it('requires the fixed provider to start a finite original round',async()=>{
  const f=serviceObservationContextFixture(),read=f.context.installConfigurationServiceBeforeObserver({read:async()=>({before:null})});
  await f.packet(async()=>{await expect(read({} as any)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_NOT_STARTED'));});
 });
 it('shares eight SDK attempt charges across named lookup, five pages and retries',async()=>{
  const f=fixture();f.state.reader=async()=>{const ticket=await f.context.authorizeRequest(f.cluster,'GET','/upstreams/backend.local',undefined,{});
   f.context.chargeRetry(ticket);f.context.chargeRetry(ticket);await f.context.authorizeResponse(ticket,{id:randomUUID()});
   for(let i=0;i<5;i++)await f.get({data:Array.from({length:100},()=>({id:randomUUID()})),next:i===4?null:'next'});
  };await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).resolves.toBe(true);});
 });
 it('does not reset eight attempts when a new child read or retry begins',async()=>{
  const f=fixture();f.state.reader=async()=>{for(let i=0;i<8;i++)await f.get();await f.get();};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_CALL_BUDGET'));});expect(f.state.consumed).toBe(0);
 });
 it('charges actual retry events in the same eight-attempt meter',async()=>{
  const f=fixture();f.state.reader=async()=>{const ticket=await f.context.authorizeRequest(f.cluster,'GET','/upstreams/backend.local',undefined,{});for(let i=0;i<8;i++)f.context.chargeRetry(ticket);};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_CALL_BUDGET'));});
 });
 it.each([['pages',6,1],['rows',1,501]] as const)('keeps the original %s cap',async(_name,pages,rows)=>{
  const f=fixture();f.state.reader=async()=>{for(let i=0;i<pages;i++)await f.get({data:Array.from({length:rows},()=>({id:randomUUID()})),next:null});};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_RECORD_BUDGET'));});expect(f.state.consumed).toBe(0);
 });
 it('keeps the same ten-second deadline through SDK return and asynchronous DNS consumer',async()=>{
  const f=fixture();let now=100;vi.spyOn(globalThis.performance,'now').mockImplementation(()=>now);f.state.reader=async()=>{await f.get();};
  f.state.consumer=async()=>{await Promise.resolve();now+=10001;};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_EXPIRED'));});
 });
 it('checks the distinct outer return continuation after the ALS callback resolves',async()=>{
  const f=fixture();let now=100,checks=0;vi.spyOn(globalThis.performance,'now').mockImplementation(()=>now);
  const actual=f.context.assertConfigurationServiceObservation.bind(f.context);
  vi.spyOn(f.context,'assertConfigurationServiceObservation').mockImplementation(()=>{actual();if(++checks===2)queueMicrotask(()=>{now+=10001;});});
  await f.packet(async()=>{await expect(f.read(f.state.handle)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_EXPIRED'));});
 });
 it('does not let the fixed reader restart the absolute deadline',async()=>{
  const f=fixture();f.state.reader=async()=>{f.context.startConfigurationServiceObservation();};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_OBSERVATION_ALREADY_STARTED'));});
 });
 it('rechecks the actual Namespace lease after a DNS await',async()=>{
  const f=fixture();f.state.reader=async()=>{await f.get();};f.state.consumer=async()=>{await Promise.resolve();f.sourceState.live=false;};
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toThrow('ORIGINAL_NAMESPACE_LEASE_REVOKED');});
 });
 it('revokes a completed budget so a later genuine fresh pass starts independently',async()=>{
  const f=fixture();f.state.reader=async()=>{await f.get();};await f.packet(async(ticket:any)=>{await f.context.protectScheduledConfigurationServiceDestination(ticket);await f.context.protectScheduledConfigurationServiceDestination(ticket);});
  expect(f.state.consumed).toBe(2);
 });
 it('cannot turn copied or expired read handles into a new observation',async()=>{
  const f=fixture();await f.packet(async()=>{await expect(f.read({} as any)).rejects.toThrow('SOURCE_ORIGINAL_READ_HANDLE_REQUIRED');});expect(f.state.consumed).toBe(0);
 });
});
