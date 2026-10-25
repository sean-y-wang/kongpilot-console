import{Injectable}from'@nestjs/common';
import{createConnection,Socket}from'node:net';
import{connect as tlsConnect,TLSSocket}from'node:tls';
import{DeliveryPolicyService}from'./delivery-policy.service';
import{smtpMessage}from'./delivery.providers';
import{DeliveryEnvelope,DeliverySendFence,TransportDeliveryOutcome,ValidatedDeliveryChannel}from'./delivery.types';
import{deliveryAwait}from'./delivery-deadline';

interface Reply{code:number;lines:readonly string[]}
class SmtpReplies{
 private buffer='';private lines:string[]=[];private code=0;private size=0;private waiting?:{resolve:(reply:Reply)=>void;reject:(error:Error)=>void};private ready:Reply[]=[];private failed=false;
 constructor(private readonly socket:Socket|TLSSocket){socket.on('data',this.data);socket.on('error',this.error);socket.on('close',this.error);}
 private error=()=>{this.failed=true;this.waiting?.reject(new Error('EVENT_SMTP_NETWORK_FAILED'));this.waiting=undefined;};
 private data=(bytes:Buffer)=>{
  this.buffer+=bytes.toString('latin1');if(this.buffer.length+this.size>8192){this.error();this.socket.destroy();return;}
  for(;;){const end=this.buffer.indexOf('\r\n');if(end<0)return;const line=this.buffer.slice(0,end);this.buffer=this.buffer.slice(end+2);
   const match=/^([0-9]{3})([- ])(.*)$/.exec(line);if(!match||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(line)){this.error();this.socket.destroy();return;}
   const code=Number(match[1]);if(this.code&&this.code!==code){this.error();this.socket.destroy();return;}
   this.code=code;this.lines.push(match[3]);this.size+=line.length+2;if(this.lines.length>32||this.size>8192){this.error();this.socket.destroy();return;}
   if(match[2]===' '){const reply={code,lines:Object.freeze([...this.lines])};this.lines=[];this.code=0;this.size=0;
    if(this.waiting){const wait=this.waiting;this.waiting=undefined;wait.resolve(reply);}else{this.ready.push(reply);if(this.ready.length>4){this.error();this.socket.destroy();return;}}
   }
  }
 };
 read():Promise<Reply>{if(this.failed)return Promise.reject(new Error('EVENT_SMTP_NETWORK_FAILED'));const ready=this.ready.shift();if(ready)return Promise.resolve(ready);
  if(this.waiting)return Promise.reject(new Error('EVENT_SMTP_PROTOCOL_INVALID'));return new Promise((resolve,reject)=>{this.waiting={resolve,reject};});}
 detach(){this.socket.removeListener('data',this.data);this.socket.removeListener('error',this.error);this.socket.removeListener('close',this.error);this.buffer='';this.ready=[];this.lines=[];}
}

@Injectable()
export class SmtpDeliveryTransport{
 constructor(private readonly policy:DeliveryPolicyService){}
 async send(channel:ValidatedDeliveryChannel,envelope:DeliveryEnvelope,fence:DeliverySendFence):Promise<TransportDeliveryOutcome>{
  const started=Date.now();let sendStarted=false,socket:Socket|TLSSocket|undefined,replies:SmtpReplies|undefined;
  const controller=new AbortController(),abort=()=>{controller.abort();socket?.destroy();};fence.signal.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,15000),check=()=>{if(fence.signal.aborted||controller.signal.aborted||Date.now()-started>=15000)throw new Error('EVENT_DELIVERY_ABORTED');fence.beforeSend();};
  const fresh=async()=>{await deliveryAwait(fence.prepareSend(),controller.signal);check();};
  const read=async()=>{const reply=await deliveryAwait(replies!.read(),controller.signal);check();return reply;};
  const command=async(value:string,startsSend=false)=>{await fresh();check();if(startsSend){fence.onSendStarted();sendStarted=true;}socket!.write(value+'\r\n');return read();};
  const fail=(errorCode:string,retryable=false):TransportDeliveryOutcome=>({outcome:sendStarted?'uncertain':'failed',sendStarted,durationMs:Date.now()-started,errorCode,retryable});
  const expect=(reply:Reply,codes:readonly number[])=>{if(!codes.includes(reply.code))throw new Error(reply.code>=400&&reply.code<500?'EVENT_SMTP_TEMPORARY_REJECTED':'EVENT_SMTP_PROVIDER_REJECTED');};
  try{
   if(channel.type!=='email'||!('recipients'in channel.endpoint)||channel.auth.type!=='none')return fail('EVENT_DELIVERY_PAYLOAD_INVALID');
   const config=this.policy.smtpConfig(),message=smtpMessage(envelope,config.from,channel.endpoint.recipients);
   if(!/^[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[A-Za-z0-9.-]+$/.test(config.from))return fail('EVENT_SMTP_CONFIG_INVALID');
   const destination=await deliveryAwait(this.policy.resolveDestination(config.host,config.port),controller.signal);check();await fresh();
   const secure=async(existing?:Socket)=>{
    check();const value=tlsConnect({...existing?{socket:existing}:{host:destination.pinned.address,port:destination.port},servername:config.servername,
     ca:config.ca,rejectUnauthorized:true,minVersion:'TLSv1.2'});socket=value;
    await deliveryAwait(new Promise<void>((resolve,reject)=>{value.once('secureConnect',()=>value.authorized?resolve():reject(new Error('EVENT_SMTP_TLS_FAILED')));value.once('error',()=>reject(new Error('EVENT_SMTP_TLS_FAILED')));}),controller.signal);
    check();if(!value.authorized)throw new Error('EVENT_SMTP_TLS_FAILED');return value;
   };
   if(config.mode==='implicit-tls'){socket=await secure();replies=new SmtpReplies(socket);expect(await read(),[220]);}
   else{
    check();socket=createConnection({host:destination.pinned.address,port:destination.port});replies=new SmtpReplies(socket);
    await deliveryAwait(new Promise<void>((resolve,reject)=>{socket!.once('connect',resolve);socket!.once('error',()=>reject(new Error('EVENT_SMTP_NETWORK_FAILED')));}),controller.signal);check();
    expect(await read(),[220]);const initial=await command('EHLO kongos.local');expect(initial,[250]);
    if(!initial.lines.some(line=>/^STARTTLS(?:\s|$)/i.test(line)))return fail('EVENT_SMTP_STARTTLS_REQUIRED');
    await fresh();expect(await command('STARTTLS'),[220]);replies.detach();await fresh();socket=await secure(socket);replies=new SmtpReplies(socket);
   }
   // The current proof is re-read after TLS and before any credentials leave.
   await fresh();const capabilities=await command('EHLO kongos.local');expect(capabilities,[250]);
   if(config.username){
    if(!capabilities.lines.some(line=>/^AUTH(?:=|\s).*\bPLAIN\b/i.test(line)))return fail('EVENT_SMTP_AUTH_UNSUPPORTED');
    expect(await command('AUTH PLAIN '+Buffer.from('\0'+config.username+'\0'+config.password,'utf8').toString('base64'),true),[235]);
   }
   expect(await command('MAIL FROM:<'+config.from+'>',true),[250]);
   for(const recipient of channel.endpoint.recipients){await fresh();expect(await command('RCPT TO:<'+recipient+'>'),[250,251,252]);}
   await fresh();expect(await command('DATA'),[354]);
   // A revocation while waiting for 354 must stop the actual message body.
   await fresh();check();fence.onSendStarted();sendStarted=true;socket.write(message);expect(await read(),[250]);
   return{outcome:'succeeded',sendStarted,durationMs:Date.now()-started,retryable:false};
  }catch(error){
   const code=error instanceof Error&&['EVENT_SMTP_TLS_FAILED','EVENT_SMTP_TEMPORARY_REJECTED','EVENT_SMTP_PROVIDER_REJECTED','EVENT_SMTP_NETWORK_FAILED'].includes(error.message)?error.message:'EVENT_SMTP_PRE_SEND_REJECTED';
   return fail(code,code==='EVENT_SMTP_TEMPORARY_REJECTED'||code==='EVENT_SMTP_NETWORK_FAILED'||sendStarted&&controller.signal.aborted);
  }finally{clearTimeout(timer);fence.signal.removeEventListener('abort',abort);replies?.detach();socket?.destroy();}
 }
}
