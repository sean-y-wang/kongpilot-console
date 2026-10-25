import {BadRequestException,ForbiddenException,Inject,Injectable,ServiceUnavailableException} from '@nestjs/common';
import {SecretService} from '../../infrastructure/secret.service';
import {DECK_UUID,deckPacket} from './deck-protocol';
import {DeckSessionService,type AuthenticatedDeckSession} from './deck-session.service';
import {CONFIGURATION_DECK_ACCESS,type DeckAuthority,type DeckConfigurationAccess,type DeckCredential,type DeckPacket} from './deck.types';

interface ScanState{consumerCursor?:string;consumerDone:boolean;consumers:string[];index:number;childCursor?:string;}
interface Cursor{version:1;binding:string;expires:number;coreCursor?:string;scan?:ScanState;}
const invalid=()=>new BadRequestException({code:'DECK_CURSOR_INVALID',message:'decK 分页游标无效或不属于当前会话查询'});
const incomplete=()=>new ServiceUnavailableException({code:'DECK_READ_INCOMPLETE',message:'decK 配置读取未完成；不能将部分配置作为同步基线'});
@Injectable()
export class DeckAdapterService{
 constructor(@Inject(DeckSessionService)private readonly sessions:DeckSessionService,@Inject(SecretService)private readonly secrets:SecretService,@Inject(CONFIGURATION_DECK_ACCESS)private readonly access:DeckConfigurationAccess){}
 private binding(authority:DeckAuthority,packet:DeckPacket):string{return this.secrets.fingerprint({sessionId:authority.locator.id,actorId:authority.user.id,originSessionId:authority.sessionId,clusterId:authority.locator.clusterId,workspaceId:authority.locator.workspaceId,transportScope:authority.locator.transportScope,jobId:authority.locator.jobId,purpose:authority.locator.purpose,permissionVersion:authority.locator.permissionVersion,credentialEpoch:authority.locator.credentialEpoch,planHash:authority.locator.planHash??null,planRevision:authority.locator.planRevision??null,path:packet.path,size:packet.query.size,tags:packet.query.tags??null});}
 private cursor(authority:DeckAuthority,packet:DeckPacket):Cursor|null{
  if(!packet.query.offset)return null;
  try{
   if(!packet.query.offset.startsWith('dc1.'))throw invalid();
   const state=this.secrets.decrypt<Cursor>(packet.query.offset.slice(4),`deck-cursor:${authority.locator.id}`);
   if(!state||state.version!==1||state.binding!==this.binding(authority,packet)||!Number.isFinite(state.expires)||state.expires<=Date.now()||state.expires>Date.parse(authority.locator.expiresAt)||Object.keys(state).some(k=>!['version','binding','expires','coreCursor','scan'].includes(k)))throw invalid();
   if(state.coreCursor!==undefined&&(typeof state.coreCursor!=='string'||!state.coreCursor||state.coreCursor.length>16384))throw invalid();
   if(state.coreCursor!==undefined&&state.scan!==undefined)throw invalid();
   if(state.scan){const s=state.scan;if(Object.keys(s).some(k=>!['consumerCursor','consumerDone','consumers','index','childCursor'].includes(k))||typeof s.consumerDone!=='boolean'||!Array.isArray(s.consumers)||s.consumers.length>100||s.consumers.some(id=>!DECK_UUID.test(id))||new Set(s.consumers).size!==s.consumers.length||!Number.isSafeInteger(s.index)||s.index<0||s.index>s.consumers.length||[s.consumerCursor,s.childCursor].some(c=>c!==undefined&&(typeof c!=='string'||c.length>16384)))throw invalid();}
   return state;
  }catch{throw invalid();}
 }
 private encode(authority:DeckAuthority,packet:DeckPacket,state:{coreCursor?:string;scan?:ScanState}):string{
  const token='dc1.'+this.secrets.encrypt({version:1,binding:this.binding(authority,packet),expires:Math.min(Date.now()+120000,Date.parse(authority.locator.expiresAt)),...state},`deck-cursor:${authority.locator.id}`);
  if(token.length>16384)throw incomplete();return token;
 }
 private shape(row:Record<string,unknown>):Record<string,unknown>{const result={...row};delete result.console_scope_notice;delete result.effective_workspace_id;return result;}
 private pageValid(items:unknown,next:unknown):asserts items is Record<string,unknown>[] {
  if(!Array.isArray(items)||items.length>100||items.some(item=>!item||typeof item!=='object'||Array.isArray(item)||(Object.getPrototypeOf(item)!==Object.prototype&&Object.getPrototypeOf(item)!==null)||!DECK_UUID.test(String(item.id)))||new Set(items.map(item=>item.id)).size!==items.length||next!==null&&(typeof next!=='string'||!next||next.length>16384))throw incomplete();
 }
 private async globalCredentials(authority:DeckAuthority,packet:DeckPacket,cursor:Cursor|null){
  if(cursor?.coreCursor||cursor&&!cursor.scan)throw invalid();
  const scan:ScanState=cursor?.scan?structuredClone(cursor.scan):{consumerDone:false,consumers:[],index:0};
  for(let calls=0;calls<10;calls++){
   if(scan.index>=scan.consumers.length){
    if(scan.consumerDone)return{data:[],offset:null,next:null};
    const page=await this.access.readDeckCollection(authority,{type:'consumers',size:100,cursor:scan.consumerCursor,tags:packet.query.tags});this.pageValid(page.items,page.nextCursor);
    if(scan.consumerCursor&&page.nextCursor===scan.consumerCursor)throw incomplete();
    scan.consumers=page.items.map(item=>String(item.id));scan.index=0;scan.childCursor=undefined;scan.consumerDone=page.nextCursor===null;scan.consumerCursor=page.nextCursor??undefined;
    if(!scan.consumers.length)continue;
   }
   const parent=scan.consumers[scan.index],previous=scan.childCursor;
   const page=await this.access.readDeckCollection(authority,{type:packet.type as DeckCredential,parentId:parent,size:100,cursor:scan.childCursor});this.pageValid(page.items,page.nextCursor);
   if(previous&&page.nextCursor===previous)throw incomplete();
   const data=page.items.map(row=>{if(row.consumer&&(!row.consumer||typeof row.consumer!=='object'||(row.consumer as any).id!==parent))throw incomplete();return this.shape({...row,consumer:{id:parent}});});
   if(page.nextCursor)scan.childCursor=page.nextCursor;else{scan.index++;scan.childCursor=undefined;}
   const finished=scan.consumerDone&&scan.index>=scan.consumers.length;
   if(data.length){const offset=finished?null:this.encode(authority,packet,{scan});return{data,offset,next:null};}
  }
  // Empty bounded pages remain resumable. Never infer global credential zero
  // from an empty Consumer/credential subpage, or collect the whole graph.
  return{data:[],offset:this.encode(authority,packet,{scan}),next:null};
 }
 async dispatch(session:AuthenticatedDeckSession,method:string,path:string,query:unknown,body:unknown):Promise<{status:number;body?:unknown}>{
  const packet=deckPacket(method,path,query,body,value=>this.secrets.fingerprint({domain:'deck-cli-packet:v1',body:value}));
  const authority=await this.sessions.current(session,'request');let result:{status:number;body?:unknown};
  if(packet.kind==='unsupported-discovery'){
   // Current session/epoch/grants are still checked on request and response.
   // No Root native read, credential scan, CRUD or Kong API is delegated.
   result={status:404,body:{message:'DECK_CAPABILITY_UNAVAILABLE'}};
  }else if(packet.method!=='GET'){
   if(authority.locator.purpose!=='write')throw new ForbiddenException({code:'DECK_READ_SESSION_WRITE_FORBIDDEN',message:'只读 decK 会话不能执行同步'});
   const completed=await this.access.executeDeckPacket(authority,packet);if(![200,201,204].includes(completed.status)||packet.method==='DELETE'&&completed.status!==204||packet.method!=='DELETE'&&(completed.status===204||!completed.entity))throw incomplete();if(completed.entity){this.pageValid([completed.entity],null);if(packet.id&&completed.entity.id!==packet.id)throw incomplete();}result={status:completed.status,body:completed.status===204?undefined:this.shape(completed.entity!)};
  }else if(packet.kind==='root'){
   const root=await this.access.readDeckRoot(authority);if(!/^1\.5\.\d+$/.test(root.version))throw incomplete();result={status:200,body:{version:root.version}};
  }else if(packet.kind==='global-credential')result={status:200,body:await this.globalCredentials(authority,packet,this.cursor(authority,packet))};
  else if(packet.collection){
   const state=this.cursor(authority,packet);if(state?.scan)throw invalid();
   const page=await this.access.readDeckCollection(authority,{type:packet.type as any,parentId:packet.parentId,size:100,cursor:state?.coreCursor,tags:packet.query.tags});this.pageValid(page.items,page.nextCursor);
   if(state?.coreCursor&&page.nextCursor===state.coreCursor)throw incomplete();
   result={status:200,body:{data:page.items.map(row=>this.shape(row)),offset:page.nextCursor?this.encode(authority,packet,{coreCursor:page.nextCursor}):null,next:null}};
  }else{const entity=await this.access.readDeckEntity(authority,{type:packet.type,id:packet.id!,parentId:packet.parentId});this.pageValid([entity],null);if(entity.id!==packet.id)throw incomplete();result={status:200,body:this.shape(entity)};}
  if(result.body!==undefined&&Buffer.byteLength(JSON.stringify(result.body))>4*1024*1024)throw incomplete();
  await this.sessions.current(session,'response');return result;
 }
}
