import { BadRequestException, ConflictException } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { encodeTag } from '../../infrastructure/kong/tags';
import { ENTITIES } from '../../infrastructure/kong/policy';
import { CREDENTIAL_KINDS, pageSize } from '../entities/entities.types';

const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
export function eventId(value:unknown):string {if(typeof value!=='string'||!uuid.test(value))throw new BadRequestException({code:'INVALID_EVENT_ID'});return value.toLowerCase();}
export function eventKey(value:unknown):string {if(typeof value!=='string'||!/^[A-Za-z\d_.:-]{8,128}$/.test(value))throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY'});return value;}
export function eventObject(value:unknown,fields:readonly string[],max=65536):Record<string,unknown> {
  const invalid=()=>new BadRequestException({code:'INVALID_EVENT_BODY'});
  const safeObject=(node:object):boolean=>Object.getPrototypeOf(node)===Object.prototype||Object.getPrototypeOf(node)===null;
  // Express 5 parses query parameters into a dictionary without a prototype.
  // Both dictionary forms have only own data; inherited or class objects fail.
  if(!value||typeof value!=='object'||Array.isArray(value)||!safeObject(value))throw invalid();
  const visit=(node:unknown,depth=0):void=>{if(depth>24)throw invalid();if(node&&typeof node==='object'){
    if(!Array.isArray(node)&&!safeObject(node))throw invalid();
    for(const[key,child]of Object.entries(node)){if(['__proto__','prototype','constructor'].includes(key))throw invalid();visit(child,depth+1);}
  }};
  visit(value);if(Buffer.byteLength(JSON.stringify(value))>max||Object.keys(value).some(key=>!fields.includes(key)))throw invalid();return structuredClone(value) as Record<string,unknown>;
}
export function eventRevision(value:unknown):number {if(typeof value!=='number'||!Number.isInteger(value)||value<1||value>=2147483647)throw new BadRequestException({code:'INVALID_EVENT_REVISION'});return value;}
export function eventText(value:unknown,max=128):string {if(typeof value!=='string'||!value.trim()||value.length>max||/[\u0000-\u001f\u007f]/.test(value))throw new BadRequestException({code:'INVALID_EVENT_TEXT'});return value.trim();}
export function eventStatus(value:unknown):'active'|'disabled' {if(value!=='active'&&value!=='disabled')throw new BadRequestException({code:'INVALID_EVENT_STATUS'});return value;}
export function eventConfirm(value:Record<string,unknown>,name:string):void {eventRevision(value.revision);if(value.confirmed!==true||value.confirm_name!==name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'请二次确认并输入对象名称'});}
export function eventCas(count:number):void {if(count!==1)throw new ConflictException({code:'EVENT_REVISION_CONFLICT',message:'对象已改变，请核验原回执并刷新'});}
export const EVENT_NATIVE_TYPES=[...ENTITIES,'targets',...CREDENTIAL_KINDS] as const;
export function eventNativeType(value:unknown):string|null {if(value==null)return null;if(typeof value!=='string'||!(EVENT_NATIVE_TYPES as readonly string[]).includes(value))throw new BadRequestException({code:'INVALID_EVENT_NATIVE_TYPE'});return value;}
export function eventStrings(value:unknown,max:number,validate:(value:unknown)=>string):string[] {if(!Array.isArray(value)||value.length>max)throw new BadRequestException({code:'INVALID_EVENT_FILTER'});return [...new Set(value.map(validate))].sort();}
export function eventTags(value:unknown):string[] {return eventStrings(value,256,tag=>{const logical=eventText(tag,128);if(logical.startsWith('workspace:')||logical.startsWith('kos-ws-'))throw new BadRequestException({code:'EVENT_RESERVED_WORKSPACE_TAG'});return encodeTag(logical);});}
export interface EventCursorPosition {id:string;createdAt:string;lowerBound?:string}
export class EventCursor {
  private sign(value:string):Buffer {const secret=process.env.CURSOR_SIGNING_KEY||process.env.APP_SECRET;if(!secret||secret.length<32)throw new Error('Event cursor signing key unavailable');return createHmac('sha256',secret).update(value).digest();}
  encode(binding:string,position:EventCursorPosition):string {eventId(position.id);this.time(position.createdAt);if(position.lowerBound)this.time(position.lowerBound);const data=Buffer.from(JSON.stringify({version:1,binding,position,expiresAt:Date.now()+900000})).toString('base64url');return data+'.'+this.sign(data).toString('base64url');}
  private time(value:string):void {if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(value)||!Number.isFinite(Date.parse(value)))throw new Error('Invalid event timestamp');}
  decode(value:unknown,binding:string):EventCursorPosition|null {if(value===undefined)return null;try{if(typeof value!=='string'||value.length>4096)throw new Error();const[data,signature,extra]=value.split('.'),supplied=Buffer.from(signature,'base64url'),expected=this.sign(data);if(extra||supplied.length!==expected.length||!timingSafeEqual(supplied,expected))throw new Error();const decoded=JSON.parse(Buffer.from(data,'base64url').toString());if(decoded.version!==1||decoded.binding!==binding||!Number.isSafeInteger(decoded.expiresAt)||decoded.expiresAt<=Date.now())throw new Error();eventId(decoded.position.id);this.time(decoded.position.createdAt);if(decoded.position.lowerBound)this.time(decoded.position.lowerBound);return decoded.position;}catch{throw new BadRequestException({code:'INVALID_EVENT_CURSOR'});}}
}
export { pageSize as eventPageSize };
