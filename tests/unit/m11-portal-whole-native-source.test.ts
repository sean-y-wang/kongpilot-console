import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {writeFileSync} from 'node:fs';
import * as transport from '../../apps/console-api/src/infrastructure/kong/outbound';
import {portalWholeNativeSourceFixture} from './helpers/m11-portal-whole-native-source-fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cb'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T11:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
/** Clock control measures topology only. It does not prove the five-minute
 * authority/performance envelope, real PostgreSQL, real Kong or commercial use. */
it.each(['complete','new-round-after-31-seconds','binding-MIN-expired']as const)('measures the complete original Portal pipeline: %s',async scenario=>{
 const clock=performance.now(),monotonic=vi.spyOn(performance,'now').mockReturnValue(clock);
 const f=await portalWholeNativeSourceFixture(),wire:any[]=[],nativeMeters:any[]=[],checkpoints:any[]=[],budgetFailures:any[]=[],phases:any[]=[],responseFailures:any[]=[];
 let advanced=false;
 if(scenario==='binding-MIN-expired'){
  const query=f.db.query.getMockImplementation()!,expiresAt=new Date(Date.now()+5000).toISOString();
  f.db.query.mockImplementation(async(sql:string,args:any[]=[])=>{const rows=await query(sql,args);
   return sql.includes('FROM iam_effective_grants')&&sql.includes('binding_current')?rows.map((row:any)=>({...row,binding:{...row.binding,expires_at:expiresAt},binding_expires_at:expiresAt})):rows;
  });
 }
 if(scenario!=='complete'){
  const execute=f.db.exec.getMockImplementation()!,advanceAt=f.plan.steps[scenario==='binding-MIN-expired'?0:1].id;
  f.db.exec.mockImplementation(async(sql:string,args:any[]=[])=>{const value=await execute(sql,args);
   if(!advanced&&sql.startsWith("UPDATE workflow_steps SET state='running'")&&args[0]===advanceAt){advanced=true;monotonic.mockReturnValue(clock+(scenario==='binding-MIN-expired'?5001:31001));}
   return value;
  });
 }
 const authorizeResponse=f.context.authorizeResponse.bind(f.context);vi.spyOn(f.context,'authorizeResponse').mockImplementation(async(...args:any[])=>{try{return await (authorizeResponse as any)(...args);}catch(error:any){responseFailures.push({code:error?.getResponse?.()?.code??error?.message,status:error?.getStatus?.(),frame:{kind:f.context.peek()?.kind,purpose:f.context.peek()?.purpose},preparation:f.context.scheduledPortalPreparationPhase()?.purpose??null,meter:f.namespaceUsage(),stack:error?.stack});throw error;}});
 const budget=(f.context as any).budgetExceeded.bind(f.context);
 vi.spyOn(f.context as any,'budgetExceeded').mockImplementation((frame:any,kind:any,limit:any,current:any)=>{budgetFailures.push({frame:{kind:frame.kind,purpose:frame.purpose??null,module:frame.module,action:frame.action},kind,limit,current,namespaceMeter:f.namespaceUsage(),stack:new Error('SOURCE_ORIGINAL_BUDGET_LOCATION').stack});return budget(frame,kind,limit,current);});
 const nsVerify=f.namespaces.verifyHandle.bind(f.namespaces);vi.spyOn(f.namespaces,'verifyHandle').mockImplementation((handle:any,phase:any)=>{checkpoints.push({event:'Namespace.verifyHandle',phase,frame:f.context.peek()?.kind??null,preparation:f.context.scheduledPortalPreparationPhase()?.purpose??null,meter:f.namespaceUsage()});return nsVerify(handle,phase);});
 for(const name of ['authorizeRequest','beforeNativeSend']as const){const original=(f.nativePolicy as any)[name].bind(f.nativePolicy);vi.spyOn(f.nativePolicy as any,name).mockImplementation((...args:any[])=>{if(args[2]!=='GET')checkpoints.push({event:'NativePolicy.'+name,method:args[2],path:args[3],meter:f.namespaceUsage()});return original(...args);});}
 vi.spyOn(transport,'outboundJson').mockImplementation(async(_base,path,method,body,_query,_auth,_timeout,beforeSend,prepareSend)=>{
  await prepareSend?.();beforeSend?.();let response:any,status=200;
  if(method==='POST'){
   const index=f.plan.steps.findIndex((step:any)=>step.nativeRequests[0]?.canonicalPath===path);if(index<0||index>2)throw Error('SOURCE_UNPLANNED_NATIVE_PATH');
   const expected=f.plan.steps[index].nativeRequests[0];if(f.secrets.fingerprint(body)!==expected.bodyHmac)throw Error('SOURCE_NATIVE_BODY_MISMATCH');
   nativeMeters.push({index,path,meter:f.namespaceUsage(),finalPhase:f.context.scheduledPortalFinalNativePhase()?.stage??null});
   response={...structuredClone(body as object),...(index?{consumer:{id:f.plan.generated!.consumerId}}:{})};status=201;f.source.nativeSent=true;if(index===0)f.source.liveConsumer=response;else if(index===1)f.source.liveAcl=response;else f.source.liveKey=response;
  }else if(method!=='GET')throw Error('SOURCE_UNPLANNED_NATIVE_METHOD');
  else if(path.startsWith('/schemas/')){const m=await f.compiler.portalMaterial(f.plan,f.db);response=path==='/schemas/consumers'?m.publicationProof.schemas.consumers:path==='/schemas/acls'?m.publicationProof.schemas.acls:m.publicationProof.schemas.keyAuth;}
  else if(path===`/services/${f.service.id}`)response=f.service;
  else if(path.startsWith('/plugins/')){const m=await f.compiler.portalMaterial(f.plan,f.db);response=path===`/plugins/${m.publicationProof.aclPluginId}`?m.publicationProof.aclPlugin:path===`/plugins/${m.publicationProof.keyAuthPluginId}`?m.publicationProof.keyAuthPlugin:null;if(!response){status=404;response={message:'Not found'};}}
  else if(path===`/consumers/${f.plan.generated.consumerId}`){if(f.source.liveConsumer)response=f.source.liveConsumer;else{status=404;response={message:'Not found'};}}
  else if(path===`/consumers/${f.plan.generated.consumerId}/acls/${f.plan.generated.aclId}`){if(f.source.liveAcl)response=f.source.liveAcl;else{status=404;response={message:'Not found'};}}
  else if(path===`/consumers/${f.plan.generated.consumerId}/key-auth/${f.plan.generated.credentialId}`){if(f.source.liveKey)response=f.source.liveKey;else{status=404;response={message:'Not found'};}}
  else if(path==='/services')response={data:[f.service],next:null};
  else if(path==='/plugins'){const m=await f.compiler.portalMaterial(f.plan,f.db);response={data:[m.publicationProof.aclPlugin,m.publicationProof.keyAuthPlugin],next:null};}
  else if(path==='/consumers')response={data:f.source.liveConsumer?[f.source.liveConsumer]:[],next:null};
  else if(path===`/consumers/${f.plan.generated.consumerId}/acls`)response={data:f.source.liveAcl?[f.source.liveAcl]:[],next:null};
  else if(path===`/consumers/${f.plan.generated.consumerId}/key-auth`)response={data:f.source.liveKey?[f.source.liveKey]:[],next:null};
  else if(path.split('/').length===2)response={data:[],next:null};
  else{status=404;response={message:'Not found'};}
  const prep=f.context.scheduledPortalPreparationPhase();if(prep)phases.push({purpose:prep.purpose,path,method});
  wire.push({method,path,actorId:f.context.current().actor?.id,namespace:f.context.hasWorkflowScheduledNamespace()});
  return{status,body:response,bytes:Buffer.byteLength(JSON.stringify(response)),jsonParsed:true};
 });
 let error:any;try{await f.run();}catch(e){error=e;}
 const trace={sourceOnly:true,testClock:'Date and performance fixed for topology only; five-minute deadline, real PostgreSQL/Kong and commercial readiness are NOT accepted.',
  actual:'Actual same-source Authority/Namespace/Context/Material/Runtime/canonical Approval/Candidates/Validation/Authorization/Identity/Approved/NativePolicy/PortalBoundary/Kong SDK/WorkflowBusinessExecution/WorkflowRegistry/PortalCredentials/PortalNative/CredentialStore/EntityService. SQL, lease, outbound and MutationService persistence/lifecycle are explicit controlled Source adapters.',
  scenario,advanced,namespaceMeter:f.namespaceUsage(),budgetFailures,responseFailures,checkpoints,executionState:f.execution()?.state,scheduleState:f.stored.progress.state,grantState:f.tables.portal_application_grants[0].state,credentialState:f.tables.portal_credentials[0].state,
  auditResults:f.audits.filter((a:any)=>a.action==='workflow.execute').map((a:any)=>({result:a.result,after:a.after})),nativeMeters,total:wire.length,insideNamespace:wire.filter(r=>r.namespace).length,nativeCount:wire.filter(r=>r.method==='POST').length,
  credentialRefs:f.credentialRefs.map((r:any)=>({kind:r.credential_type,state:r.state})),dispatchError:f.source.dispatchError,error:error?.getResponse?.()??(error?{message:error.message,stack:error.stack}:null),roots:f.state.rootReads,phases,wire};
 const output=process.env.KP_SOURCE_TRACE_PATH??'/tmp/kp-portal-whole-native-source.trace.json';writeFileSync(scenario==='complete'?output:output.replace(/\.json$/,'.'+scenario+'.json'),JSON.stringify(trace,null,2));
 if(scenario==='binding-MIN-expired'){
  expect(advanced).toBe(true);expect(wire.filter(r=>r.method==='POST')).toHaveLength(0);
  expect(f.tables.portal_application_grants[0].state).toBe('pending');expect(f.tables.portal_credentials[0].state).toBe('pending');
  expect(error).toBeUndefined();expect(f.execution()?.state).toBe('failed');expect(f.stored.progress.state).toBe('failed');
  expect(trace.auditResults).toContainEqual({result:'failed',after:{code:'WORKFLOW_SCHEDULE_NAMESPACE_GRANT_EXPIRED',state:'failed'}});return;
 }
 if(error)throw error;if(scenario==='new-round-after-31-seconds')expect(advanced).toBe(true);
 expect(wire.filter(r=>r.method==='POST')).toHaveLength(3);expect(f.execution()?.state).toBe('succeeded');expect(f.stored.progress.state).toBe('succeeded');
 expect(f.tables.portal_application_grants[0].state).toBe('active');expect(f.tables.portal_credentials[0].state).toBe('active');expect(f.credentialRefs).toHaveLength(2);
 expect(f.namespaceUsage()?.calls).toBeLessThanOrEqual(500);expect(budgetFailures).toHaveLength(0);
},180000);
