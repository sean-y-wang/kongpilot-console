import {BadRequestException,ForbiddenException} from '@nestjs/common';
import {DECK_CREDENTIAL_PATHS,DECK_ENTITIES,type DeckPacket,type DeckSessionIssue} from './deck.types';

export const DECK_UUID=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const invalid=()=>new BadRequestException({code:'DECK_PACKET_INVALID',message:'固定 decK 协议包不符合要求'});
function plain(value:unknown):value is Record<string,unknown>{return!!value&&typeof value==='object'&&!Array.isArray(value)&&(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null);}
export function deckObject(value:unknown,maxBytes=2*1024*1024):Record<string,unknown>{
 if(!plain(value))throw invalid();let nodes=0;const seen=new WeakSet<object>();
 const visit=(item:unknown,depth:number):void=>{if(++nodes>50000||depth>32)throw invalid();if(item===null||typeof item==='boolean')return;if(typeof item==='number'){if(!Number.isFinite(item))throw invalid();return;}if(typeof item==='string'){if(/\[REDACTED(?::|\])/i.test(item))throw invalid();return;}if(typeof item!=='object'||!item||seen.has(item))throw invalid();seen.add(item);if(!Array.isArray(item)&&!plain(item))throw invalid();for(const[key,child]of Object.entries(item)){if(['__proto__','prototype','constructor'].includes(key))throw invalid();visit(child,depth+1);}};
 visit(value,0);if(Buffer.byteLength(JSON.stringify(value))>maxBytes)throw invalid();return value;
}
export function deckQuery(value:unknown):{size:number;offset?:string;tags?:string}{
 if(!plain(value)||Object.keys(value).some(key=>!['size','offset','tags'].includes(key)))throw invalid();
 if(value.size!==undefined&&(typeof value.size!=='string'||!/^\d{1,4}$/.test(value.size)))throw invalid();
 const size=value.size===undefined?1000:Number(value.size);if(size<1||size>1000)throw invalid();
 if(value.offset!==undefined&&(typeof value.offset!=='string'||!value.offset||value.offset.length>16384||/\s/.test(value.offset)))throw invalid();
 if(value.tags!==undefined&&(typeof value.tags!=='string'||value.tags.length>2048||/[\r\n\0]/.test(value.tags)||value.tags.includes(',')&&value.tags.includes('/')))throw invalid();
 return{size,...(value.offset?{offset:value.offset as string}:{}),...(value.tags?{tags:value.tags as string}:{})};
}
function freezePayload(value:unknown):void{if(value&&typeof value==='object'){for(const child of Object.values(value))freezePayload(child);Object.freeze(value);}}
export function deckPacket(method:string,path:string,query:unknown,body:unknown,bodyHmac?:(value:unknown)=>string):DeckPacket{
 if(!['GET','POST','PUT','PATCH','DELETE'].includes(method)||typeof path!=='string'||path.length>512||!path.startsWith('/')||path!=='/'&&path.endsWith('/')||/[?#%\\\s]/.test(path)||path.includes('//'))throw invalid();
 const parts=path.slice(1).split('/'),credentialKinds=new Set(Object.values(DECK_CREDENTIAL_PATHS));
 let kind:DeckPacket['kind'],type:string,id:string|undefined,parentId:string|undefined,collection:boolean;
 if(path==='/'){kind='root';type='root';collection=false;if(method!=='GET')throw invalid();}
 // decK 1.2.4 probes this optional enterprise collection once. The BFF
 // answers unavailable locally; it must never become a native Kong packet.
 else if(path==='/mtls-auths'&&method==='GET'){kind='unsupported-discovery';type='mtls-auth';collection=true;}
 else if(parts.length===1&&Object.hasOwn(DECK_CREDENTIAL_PATHS,parts[0])){kind='global-credential';type=DECK_CREDENTIAL_PATHS[parts[0] as keyof typeof DECK_CREDENTIAL_PATHS];collection=true;if(method!=='GET')throw invalid();}
 else if(parts[0]==='consumers'&&parts.length>=3&&parts.length<=4&&DECK_UUID.test(parts[1])&&credentialKinds.has(parts[2] as any)){kind='credential';type=parts[2];parentId=parts[1];id=parts[3];collection=!id;}
 else if(parts[0]==='upstreams'&&parts.length>=3&&parts.length<=4&&DECK_UUID.test(parts[1])&&parts[2]==='targets'){kind='targets';type='targets';parentId=parts[1];id=parts[3];collection=!id;}
 else if((DECK_ENTITIES as readonly string[]).includes(parts[0])&&parts.length<=2){kind='entity';type=parts[0];id=parts[1];collection=!id;}
 else throw invalid();
 if(id&&!DECK_UUID.test(id))throw invalid();
 const parsed=deckQuery(query);if((!collection||method!=='GET')&&Object.keys(query as object).length)throw invalid();
 if(kind==='unsupported-discovery'&&Object.keys(query as object).some(key=>key!=='size'))throw invalid();
 if(method==='POST'&&!collection||['PUT','PATCH','DELETE'].includes(method)&&collection)throw invalid();
 if(kind==='targets'&&['PUT','PATCH'].includes(method))throw invalid();
 let payload:Record<string,unknown>|undefined;
 if(['POST','PUT','PATCH'].includes(method)){payload=JSON.parse(JSON.stringify(deckObject(body))) as Record<string,unknown>;freezePayload(payload);if(payload.id!==undefined&&(!DECK_UUID.test(String(payload.id))||id!==undefined&&payload.id!==id))throw invalid();if(parentId){const foreign=payload[kind==='credential'?'consumer':'upstream'];if(foreign!==undefined&&(typeof foreign==='string'?foreign!==parentId:!plain(foreign)||foreign.id!==parentId||Object.keys(foreign).some(key=>key!=='id')))throw invalid();}}
 else if(body!==undefined&&body!==null&&(!plain(body)||Object.keys(body).length))throw invalid();
 return Object.freeze({method:method as DeckPacket['method'],path,kind,type,id,parentId,collection,query:Object.freeze(parsed),...(payload?{body:payload,bodyHmac:bodyHmac?.(payload)}:{})});
}
export function deckSessionIssue(value:unknown):DeckSessionIssue{const row=deckObject(value,4096);if(Object.keys(row).some(key=>!['jobId','purpose','planId','planRevision','planHash'].includes(key))||!DECK_UUID.test(String(row.jobId))||!['read','write'].includes(String(row.purpose)))throw invalid();if(row.purpose==='write'&&(!DECK_UUID.test(String(row.planId))||!Number.isSafeInteger(row.planRevision)||Number(row.planRevision)<1||typeof row.planHash!=='string'||! /^[a-f\d]{64}$/.test(row.planHash)))throw invalid();if(row.purpose==='read'&&['planId','planRevision','planHash'].some(key=>row[key]!==undefined))throw invalid();return row as unknown as DeckSessionIssue;}
export function deckAuthorization(rawHeaders:readonly string[]):string{
 const values=[];for(let i=0;i<rawHeaders.length;i+=2)if(rawHeaders[i].toLowerCase()==='authorization')values.push(rawHeaders[i+1]);
 if(values.length!==1||!/^KongOS-Deck [A-Za-z\d_-]{43}$/.test(values[0]))throw new ForbiddenException({code:'DECK_SESSION_REQUIRED',message:'需要有效的专用 decK 会话'});
 return values[0].slice('KongOS-Deck '.length);
}
