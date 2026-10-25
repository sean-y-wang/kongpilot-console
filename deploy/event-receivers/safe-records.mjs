import{createHash,timingSafeEqual}from'node:crypto';
export const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export const digest=value=>createHash('sha256').update(value).digest('hex');
export function equalDigest(value,expected){return typeof expected==='string'&&/^[a-f0-9]{64}$/.test(expected)&&timingSafeEqual(Buffer.from(digest(value),'hex'),Buffer.from(expected,'hex'));}
export function safeEnvelope(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||![value.eventId,value.deliveryId,value.clusterId,value.workspaceId].every(v=>typeof v==='string'&&UUID.test(v)))return null;
 return{eventId:value.eventId,deliveryId:value.deliveryId,clusterId:value.clusterId,workspaceId:value.workspaceId};
}
export function bodyIdentity(bytes){
 try{const value=JSON.parse(bytes.toString('utf8'));let envelope=value;
  if(typeof value?.text==='string')envelope=JSON.parse(value.text.slice(value.text.indexOf('\n')+1));
  if(value?.msg_type==='text'&&typeof value.content?.text==='string')envelope=JSON.parse(value.content.text.slice(value.content.text.indexOf('\n')+1));
  return safeEnvelope(envelope);
 }catch{return null;}
}
export function createSafeRecords(){
 const rows=[],keys=new Set();let received=0,unique=0,duplicates=0,auth=0,rejected=0;
 return{auth:()=>auth++,reject:()=>rejected++,record:(bytes,identity,key)=>{
  received++;const keyHash=digest(key);if(keys.has(keyHash))duplicates++;else{keys.add(keyHash);unique++;if(keys.size>1000)keys.delete(keys.values().next().value);}
  const row={at:new Date().toISOString(),bodyDigest:digest(bytes),idempotencyDigest:keyHash,...identity};rows.push(row);if(rows.length>1000)rows.shift();return row;
 },snapshot:()=>({received,unique,duplicates,auth,rejected,records:rows.map(row=>({...row}))})};
}
export function validFault(input){
 if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(key=>!['status','delayMs','dropAfterBody','times','starttlsDisabled'].includes(key)))throw new Error('RECEIVER_CONTROL_INVALID');
 const fault={status:input.status??200,delayMs:input.delayMs??0,dropAfterBody:input.dropAfterBody??false,times:input.times??1,starttlsDisabled:input.starttlsDisabled??false};
 if(![200,429,503].includes(fault.status)||!Number.isInteger(fault.delayMs)||fault.delayMs<0||fault.delayMs>14000||typeof fault.dropAfterBody!=='boolean'||typeof fault.starttlsDisabled!=='boolean'||!Number.isInteger(fault.times)||fault.times<0||fault.times>100)throw new Error('RECEIVER_CONTROL_INVALID');return Object.freeze(fault);
}
export function createFaultState(){let value=validFault({times:0});return{set:input=>value=validFault(input),take:()=>{const result=value;if(value.times>0)value=Object.freeze({...value,times:value.times-1});else return validFault({times:0});return result;},peek:()=>value};}
