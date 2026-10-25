import{Injectable}from'@nestjs/common';
import{Agent,request}from'node:https';
import{connect,TLSSocket}from'node:tls';
import{DeliveryPolicyService}from'./delivery-policy.service';
import{boundedRetryAfter,httpProviderBody,providerAcknowledged}from'./delivery.providers';
import{DeliveryEnvelope,DeliverySendFence,TransportDeliveryOutcome,ValidatedDeliveryChannel}from'./delivery.types';
import{deliveryAwait}from'./delivery-deadline';

@Injectable()
export class HttpDeliveryTransport{
 constructor(private readonly policy:DeliveryPolicyService){}
 async send(channel:ValidatedDeliveryChannel,envelope:DeliveryEnvelope,key:string,fence:DeliverySendFence):Promise<TransportDeliveryOutcome>{
  const started=Date.now();let sendStarted=false,socket:TLSSocket|undefined,agent:Agent|undefined;
  const controller=new AbortController(),abort=()=>controller.abort();fence.signal.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,5000),check=()=>{if(fence.signal.aborted||controller.signal.aborted||Date.now()-started>=5000)throw new Error('EVENT_DELIVERY_ABORTED');fence.beforeSend();};
  const fail=(code:string,retryable=true):TransportDeliveryOutcome=>({outcome:sendStarted?'uncertain':'failed',sendStarted,durationMs:Date.now()-started,errorCode:code,retryable});
  try{
   if(channel.type==='email'||!('url'in channel.endpoint)||typeof key!=='string'||!/^[a-zA-Z0-9_.:-]{8,128}$/.test(key))return fail('EVENT_DELIVERY_PAYLOAD_INVALID',false);
   const url=this.policy.httpUrl(channel.endpoint.url),body=httpProviderBody(channel.type,envelope,channel.auth);
   const target=await deliveryAwait(this.policy.resolveDestination(url.hostname,Number(url.port||443)),controller.signal);check();
   await deliveryAwait(fence.prepareSend(),controller.signal);check();
   socket=await deliveryAwait(new Promise<TLSSocket>((resolve,reject)=>{
    check();const value=connect({host:target.pinned.address,port:target.port,servername:target.hostname,ca:this.policy.httpsCa(),rejectUnauthorized:true,minVersion:'TLSv1.2'});
    const stop=()=>value.destroy(new Error('EVENT_DELIVERY_ABORTED'));controller.signal.addEventListener('abort',stop,{once:true});
    value.once('error',()=>{controller.signal.removeEventListener('abort',stop);reject(new Error('EVENT_DELIVERY_TLS_FAILED'));});
    value.once('secureConnect',()=>{controller.signal.removeEventListener('abort',stop);if(!value.authorized){value.destroy();reject(new Error('EVENT_DELIVERY_TLS_FAILED'));}else resolve(value);});
   }),controller.signal);
   check();await deliveryAwait(fence.prepareSend(),controller.signal);check();
   const headers:Record<string,string>={'content-type':'application/json','content-length':String(body.length),'user-agent':'KongPilot-EventDelivery/1','idempotency-key':key,'x-kongos-event-id':envelope.eventId,'connection':'close'};
   if(channel.auth.type==='bearer')headers.authorization='Bearer '+channel.auth.token;
   if(channel.auth.type==='basic')headers.authorization='Basic '+Buffer.from(channel.auth.username+':'+channel.auth.password,'utf8').toString('base64');
   const readySocket=socket;agent=new Agent({keepAlive:false,maxSockets:1});agent.createConnection=()=>readySocket;
   return await new Promise<TransportDeliveryOutcome>(resolve=>{
    let finished=false;const done=(outcome:TransportDeliveryOutcome)=>{if(finished)return;finished=true;controller.signal.removeEventListener('abort',stop);resolve(outcome);};
    const stop=()=>{req.destroy();done(fail('EVENT_DELIVERY_TIMEOUT'));};
    check();const req=request(url,{method:'POST',headers,agent,maxHeaderSize:8192},response=>{
     const status=response.statusCode??0,encoding=response.headers['content-encoding'];
     if(encoding&&encoding!=='identity'){response.destroy();done(fail('EVENT_DELIVERY_RESPONSE_ENCODING',false));return;}
     if(Number(response.headers['content-length']??0)>8192){response.destroy();done(fail('EVENT_DELIVERY_RESPONSE_TOO_LARGE',false));return;}
     const chunks:Buffer[]=[];let size=0;
     response.on('data',(chunk:Buffer)=>{size+=chunk.length;if(size>8192){response.destroy();done(fail('EVENT_DELIVERY_RESPONSE_TOO_LARGE',false));}else chunks.push(chunk);});
     response.once('error',()=>done(fail('EVENT_DELIVERY_RESPONSE_FAILED')));
     response.once('end',()=>{
      if(status<100||status>599){done(fail('EVENT_DELIVERY_RESPONSE_INVALID'));return;}
      const ack=providerAcknowledged(channel.type as 'webhook'|'slack'|'feishu',status,Buffer.concat(chunks).toString('utf8'));
      done({outcome:ack?'succeeded':'failed',sendStarted,httpStatus:status,durationMs:Date.now()-started,
       ...(ack?{}:{errorCode:status>=300&&status<400?'EVENT_DELIVERY_REDIRECT_DENIED':'EVENT_DELIVERY_PROVIDER_REJECTED'}),
       retryable:!ack&&(status===429||status>=500),...(status===429?{retryAfterMs:boundedRetryAfter(typeof response.headers['retry-after']==='string'?response.headers['retry-after']:undefined)}:{})});
     });
    });
    req.once('error',()=>done(fail('EVENT_DELIVERY_NETWORK_FAILED')));controller.signal.addEventListener('abort',stop,{once:true});
    // The HTTP headers/body are emitted only in this synchronous socket callback
    // after the post-TLS current proof, not automatically during TLS handshaking.
    req.once('socket',()=>{try{check();fence.onSendStarted();sendStarted=true;req.end(body);}catch{req.destroy();done(fail('EVENT_DELIVERY_FENCE_CLOSED',false));}});
    if(controller.signal.aborted)stop();
   });
  }catch(error){const code=error instanceof Error&&['EVENT_DELIVERY_PAYLOAD_INVALID','EVENT_DELIVERY_PAYLOAD_TOO_LARGE','EVENT_DELIVERY_TLS_FAILED'].includes(error.message)?error.message:'EVENT_DELIVERY_PRE_SEND_REJECTED';return fail(code,false);}
  finally{clearTimeout(timer);fence.signal.removeEventListener('abort',abort);agent?.destroy();socket?.destroy();}
 }
}
