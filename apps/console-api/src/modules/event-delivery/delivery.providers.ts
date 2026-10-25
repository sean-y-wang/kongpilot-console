import{createHmac}from'node:crypto';
import{DeliveryChannelAuth,DeliveryEnvelope,DeliveryProviderType}from'./delivery.types';

const uuid=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
export function safeDeliveryEnvelope(input:DeliveryEnvelope):Readonly<DeliveryEnvelope>{
 if(!input||![input.eventId,input.deliveryId,input.clusterId,input.workspaceId].every(uuid)||input.version!==1
  ||typeof input.eventType!=='string'||!/^[a-z][a-z0-9_.:-]{0,95}$/.test(input.eventType)
  ||!['requested','node','aggregate','terminal','observation'].includes(input.phase)
  ||!['success','succeeded','failure','failed','pending','uncertain','denied','cancelled','unknown','observed'].includes(input.result)
  ||!Number.isFinite(Date.parse(input.occurredAt))||input.sourceId!==undefined&&!uuid(input.sourceId))throw new Error('EVENT_DELIVERY_PAYLOAD_INVALID');
 // The provider has no raw config/labels/template entrypoint. Summaries are
 // fixed server text, including for a trusted payload with additional keys.
 return Object.freeze({version:1,eventId:input.eventId,deliveryId:input.deliveryId,clusterId:input.clusterId,workspaceId:input.workspaceId,
  occurredAt:new Date(input.occurredAt).toISOString(),eventType:input.eventType,phase:input.phase,result:input.result,
  summary:'KongPilot 网关事件通知',...(input.sourceId?{sourceId:input.sourceId}:{})});
}
export function httpProviderBody(type:Exclude<DeliveryProviderType,'email'>,event:DeliveryEnvelope,auth:DeliveryChannelAuth,now=Date.now()):Buffer{
 const safe=safeDeliveryEnvelope(event);let value:unknown=safe;
 if(type==='slack')value={text:'KongPilot 网关事件通知\n'+JSON.stringify(safe)};
 if(type==='feishu'){
  const content={msg_type:'text',content:{text:'KongPilot 网关事件通知\n'+JSON.stringify(safe)}};
  if(auth.type==='feishu-signature'){const timestamp=String(Math.floor(now/1000));value={...content,timestamp,sign:createHmac('sha256',timestamp+'\n'+auth.secret).update('').digest('base64')};}
  else value=content;
 }
 const bytes=Buffer.from(JSON.stringify(value),'utf8');if(bytes.length>8192)throw new Error('EVENT_DELIVERY_PAYLOAD_TOO_LARGE');return bytes;
}
export function providerAcknowledged(type:Exclude<DeliveryProviderType,'email'>,status:number,body:string):boolean{
 if(type==='webhook')return status>=200&&status<300;
 if(status!==200)return false;if(type==='slack')return body.trim()==='ok';
 try{const result=JSON.parse(body);return!!result&&typeof result==='object'&&(result.code===0||result.StatusCode===0);}catch{return false;}
}
export function boundedRetryAfter(value:string|undefined,now=Date.now()):number|undefined{
 if(!value||value.length>128)return undefined;
 const millis=/^[0-9]{1,8}$/.test(value)?Number(value)*1000:Date.parse(value)-now;
 return Number.isFinite(millis)?Math.min(3600000,Math.max(1000,millis)):undefined;
}
export function smtpMessage(event:DeliveryEnvelope,from:string,recipients:readonly string[]):Buffer{
 const safe=safeDeliveryEnvelope(event),subject=Buffer.from('KongPilot 网关事件通知').toString('base64');
 const text=JSON.stringify(safe,null,2).replace(/\r?\n/g,'\r\n').replace(/(^|\r\n)\./g,'$1..');
 const value=`From: <${from}>\r\nTo: ${recipients.map(v=>'<'+v+'>').join(', ')}\r\nSubject: =?UTF-8?B?${subject}?=\r\nMessage-ID: <${safe.deliveryId}@kongos.local>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${text}\r\n.\r\n`;
 const bytes=Buffer.from(value,'utf8');if(bytes.length>8192)throw new Error('EVENT_DELIVERY_PAYLOAD_TOO_LARGE');return bytes;
}
