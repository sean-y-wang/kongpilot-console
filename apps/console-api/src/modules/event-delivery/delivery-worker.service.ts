import{Inject,Injectable,Logger,OnModuleDestroy,OnModuleInit}from'@nestjs/common';
import{randomUUID}from'node:crypto';
import{DeliveryRepositoryService}from'../event-core/delivery-repository.service';
import{EVENT_ACCESS,EventAccess}from'../event-core/event-access';
import{DELIVERY_CLAIM_LIMIT,DELIVERY_CONCURRENCY,DELIVERY_HEARTBEAT_MS,DELIVERY_LEASE_MS,DeliveryClaim,DeliveryOutcome}from'../event-core/event.types';
import{DeliveryPolicyService}from'./delivery-policy.service';
import{HttpDeliveryTransport}from'./http-delivery.transport';
import{SmtpDeliveryTransport}from'./smtp-delivery.transport';
import{DeliveryChannelInput,DeliverySendFence}from'./delivery.types';
import{safeDeliveryEnvelope}from'./delivery.providers';
import{deliveryAwait}from'./delivery-deadline';

export const DELIVERY_WORKER_OPTIONS=Symbol('DELIVERY_WORKER_OPTIONS');
export interface DeliveryWorkerOptions{enabled:boolean;pollMs?:number}
@Injectable()
export class DeliveryWorkerService implements OnModuleInit,OnModuleDestroy{
 private readonly owner=randomUUID();private readonly logger=new Logger(DeliveryWorkerService.name);
 private stopped=false;private running=false;private timer?:NodeJS.Timeout;private readonly active=new Set<AbortController>();
 constructor(private readonly repository:DeliveryRepositoryService,@Inject(EVENT_ACCESS)private readonly access:EventAccess,
  private readonly policy:DeliveryPolicyService,private readonly http:HttpDeliveryTransport,private readonly smtp:SmtpDeliveryTransport,
  @Inject(DELIVERY_WORKER_OPTIONS)private readonly options:DeliveryWorkerOptions){}
 onModuleInit(){if(!this.options.enabled)return;this.timer=setInterval(()=>void this.runOnce().catch(()=>this.logger.error({code:'EVENT_DELIVERY_POLL_FAILED'})),Math.max(250,Math.min(5000,this.options.pollMs??1000)));this.timer.unref();}
 onModuleDestroy(){this.stopped=true;if(this.timer)clearInterval(this.timer);for(const controller of this.active)controller.abort();}
 async runOnce():Promise<number>{
  if(this.stopped||this.running)return 0;this.running=true;
  try{
   await this.repository.recoverExpiredIntents({limit:DELIVERY_CLAIM_LIMIT});if(this.stopped)return 0;
   // Claim only the available execution slots. A batch of twenty queued claims
   // could expire before two SMTP slots reached its final item.
   const claims=await this.repository.claimDue({owner:this.owner,limit:DELIVERY_CONCURRENCY,leaseMs:DELIVERY_LEASE_MS});let position=0,completed=0;
   await Promise.all(Array.from({length:Math.min(DELIVERY_CONCURRENCY,claims.length)},async()=>{
    for(;;){const index=position++;if(index>=claims.length||this.stopped)return;if(await this.deliver(claims[index]))completed++;}
   }));return completed;
  }finally{this.running=false;}
 }
 private async deliver(claim:DeliveryClaim):Promise<boolean>{
  const started=Date.now(),controller=new AbortController();this.active.add(controller);
  let closed=false,proofReady=false,sendStarted=false,intent=false,heartbeatBusy=false,authorityRevoked=false;
  const close=(authority=false)=>{closed=true;authorityRevoked ||= authority;controller.abort();};
  const check=()=>{if(closed||this.stopped||controller.signal.aborted||!proofReady||Date.parse(claim.leaseUntil)<=Date.now())throw new Error('EVENT_DELIVERY_FENCE_CLOSED');};
  const current=async()=>{
   if(closed||this.stopped||controller.signal.aborted)throw new Error('EVENT_DELIVERY_FENCE_CLOSED');
   try{
    await deliveryAwait(this.repository.assertLeaseCurrent(claim),controller.signal);if(closed||this.stopped)throw new Error('EVENT_DELIVERY_FENCE_CLOSED');
    const proof=await deliveryAwait(this.access.assertDeliveryCurrent(claim),controller.signal);
    if(closed||this.stopped||controller.signal.aborted||proof.channelRevision!==claim.channelRevision||proof.subscriptionRevision!==claim.subscriptionRevision||proof.credentialGeneration!==claim.credentialGeneration)throw new Error('EVENT_DELIVERY_FENCE_CLOSED');
    await deliveryAwait(this.repository.assertLeaseCurrent(claim),controller.signal);proofReady=true;check();
   }catch(error){close(isAuthorityFailure(error));throw error;}
  };
  const fence:DeliverySendFence={prepareSend:current,beforeSend:check,signal:controller.signal,onSendStarted:()=>{check();sendStarted=true;}};
  const heartbeat=setInterval(()=>{if(heartbeatBusy||closed)return;heartbeatBusy=true;
   void(async()=>{try{const renewed=await this.repository.renewLease(claim,DELIVERY_LEASE_MS);if(!renewed||closed||this.stopped){close();return;}await current();}catch(error){close(isAuthorityFailure(error));}finally{heartbeatBusy=false;}})();
  },DELIVERY_HEARTBEAT_MS);heartbeat.unref();
  try{
   // Await the committed DB result even if shutdown occurs concurrently; the
   // durable intent must be completed or recovered, never mistaken for none.
   await current();await this.repository.commitSendIntent(claim);intent=true;
   await current();const materials=await deliveryAwait(this.repository.loadChannelSecrets(claim),controller.signal);await current();
   const input:DeliveryChannelInput={type:materials.type,endpoint:'url'in materials.endpoint?materials.endpoint.url:{recipients:[...materials.endpoint.recipients]},auth:materials.auth,options:{}};
   const channel=await deliveryAwait(this.policy.validateChannelConfig(input),controller.signal);await current();
   const envelope=safeDeliveryEnvelope({version:1,eventId:claim.eventId,deliveryId:claim.deliveryId,clusterId:claim.clusterId,workspaceId:claim.workspaceId,
    occurredAt:claim.occurredAt,eventType:claim.payloadSafe.eventType,phase:claim.payloadSafe.phase,result:claim.payloadSafe.result,summary:claim.payloadSafe.summary,sourceId:claim.sourceId});
   const outcome=channel.type==='email'?await this.smtp.send(channel,envelope,fence):await this.http.send(channel,envelope,claim.idempotencyKey,fence);
   const final:DeliveryOutcome=authorityRevoked?{outcome:sendStarted?'uncertain':'failed',sendStarted,durationMs:Date.now()-started,errorCode:'EVENT_DELIVERY_AUTHORITY_REVOKED',retryable:false}:outcome;
   return await this.repository.finalize(claim,final);
  }catch(error){
   if(!intent){if(isAuthorityFailure(error)||authorityRevoked){await this.repository.pauseAuthority(claim,'EVENT_DELIVERY_AUTHORITY_REVOKED');return true;}return false;}
   return await this.repository.finalize(claim,{outcome:sendStarted?'uncertain':'failed',sendStarted,durationMs:Date.now()-started,
    errorCode:authorityRevoked?'EVENT_DELIVERY_AUTHORITY_REVOKED':closed?'EVENT_DELIVERY_FENCE_CLOSED':'EVENT_DELIVERY_PRE_SEND_REJECTED',retryable:false});
  }finally{clearInterval(heartbeat);close();this.active.delete(controller);}
 }
}
function isAuthorityFailure(error:unknown):boolean{
 if(!error||typeof error!=='object')return false;const value=error as{getStatus?:()=>number;response?:{code?:string};message?:string};
 return value.getStatus?.()===403||value.response?.code==='EVENT_DELIVERY_AUTHORITY_REVOKED'||value.message==='EVENT_DELIVERY_AUTHORITY_REVOKED';
}
