import {ForbiddenException,Inject,Injectable} from '@nestjs/common';
import {createHash} from 'node:crypto';
import {DECK_UUID,deckAuthorization,deckSessionIssue} from './deck-protocol';
import {CONFIGURATION_DECK_ACCESS,CONFIGURATION_DECK_REPOSITORY,type DeckAuthority,type DeckConfigurationAccess,type DeckSessionLocator,type DeckSessionRepository} from './deck.types';
import type {AuthUser} from '../../common/auth';

const denied=()=>new ForbiddenException({code:'DECK_SESSION_INVALID',message:'decK 会话无效、已过期或授权已变更'});
export type AuthenticatedDeckSession=Readonly<{readonly __deckSession:never}>;
interface PrivateSession{authority:DeckAuthority;token:string;}
type ConsoleActor={user:AuthUser;sessionId:string;clusterId:string;workspaceId?:string;requestId:string};
function locatorValid(value:DeckSessionLocator):boolean{return!!value&&[value.id,value.clusterId,value.workspaceId,value.actorId,value.sessionId,value.jobId].every(id=>typeof id==='string'&&DECK_UUID.test(id))&&['read','write'].includes(value.purpose)&&typeof value.transportScope==='string'&&/^[a-f\d]{64}$/.test(value.transportScope)&&typeof value.permissionVersion==='string'&&value.permissionVersion.length>0&&value.permissionVersion.length<=256&&Number.isSafeInteger(value.credentialEpoch)&&value.credentialEpoch>0&&Number.isSafeInteger(value.revision)&&value.revision>0&&Date.parse(value.expiresAt)>Date.now()&&(value.purpose!=='write'||!!value.planId&&DECK_UUID.test(value.planId)&&Number.isSafeInteger(value.planRevision)&&Number(value.planRevision)>0&&/^[a-f\d]{64}$/.test(value.planHash??''));}
function identity(value:DeckSessionLocator):string{return JSON.stringify([value.id,value.clusterId,value.workspaceId,value.transportScope,value.actorId,value.sessionId,value.jobId,value.purpose,String(value.credentialEpoch),value.permissionVersion,value.planId??null,value.planRevision??null,value.planHash??null,value.expiresAt]);}
@Injectable()
export class DeckSessionService{
 private readonly sessions=new WeakMap<object,PrivateSession>();
 constructor(@Inject(CONFIGURATION_DECK_REPOSITORY)private readonly repository:DeckSessionRepository,@Inject(CONFIGURATION_DECK_ACCESS)private readonly access:DeckConfigurationAccess){}
 private state(session:AuthenticatedDeckSession):PrivateSession{const found=this.sessions.get(session);if(!found)throw denied();return found;}
 private verifyAuthority(authority:DeckAuthority,locator:DeckSessionLocator){if(!authority?.handle||!authority.user||authority.user.id!==locator.actorId||authority.sessionId!==locator.sessionId||!locatorValid(authority.locator)||identity(authority.locator)!==identity(locator))throw denied();}
 async authenticate(id:string,rawHeaders:readonly string[]):Promise<AuthenticatedDeckSession>{
  if(!DECK_UUID.test(id))throw denied();const token=deckAuthorization(rawHeaders),tokenHash=createHash('sha256').update(token,'utf8').digest('hex');
  const located=await this.repository.locateDeckSession({id,tokenHash});if(!located||!locatorValid(located)||located.id!==id)throw denied();
  const authority=await this.access.acquireDeckSession(located);this.verifyAuthority(authority,located);
  const current=await this.repository.readDeckSession(authority.handle,{id,token,purpose:located.purpose});if(!locatorValid(current)||identity(current)!==identity(located))throw denied();
  await this.access.assertDeckCurrent(authority,'request');if(!locatorValid(authority.locator))throw denied();
  const proof=Object.freeze({}) as AuthenticatedDeckSession;this.sessions.set(proof,{authority,token});return proof;
 }
 authority(session:AuthenticatedDeckSession):DeckAuthority{return this.state(session).authority;}
 async current(session:AuthenticatedDeckSession,phase:'request'|'response'):Promise<DeckAuthority>{
  const{authority,token}=this.state(session);if(!locatorValid(authority.locator))throw denied();
  const current=await this.repository.readDeckSession(authority.handle,{id:authority.locator.id,token,purpose:authority.locator.purpose});
  if(!locatorValid(current)||identity(current)!==identity(authority.locator))throw denied();
  await this.access.assertDeckCurrent(authority,phase);if(!locatorValid(authority.locator))throw denied();return authority;
 }
 async issue(body:unknown,actor:ConsoleActor){
  if(!actor?.user||!DECK_UUID.test(actor.sessionId)||!DECK_UUID.test(actor.clusterId)||actor.workspaceId!==undefined&&!DECK_UUID.test(actor.workspaceId))throw denied();
  const input=deckSessionIssue(body),authority=await this.access.authorizeDeckSessionIssue(input,actor);
  if(!authority?.handle||authority.user.id!==actor.user.id||authority.sessionId!==actor.sessionId||authority.clusterId!==actor.clusterId||authority.jobId!==input.jobId||authority.purpose!==input.purpose||!Number.isFinite(Date.parse(authority.expiresAt))||Date.parse(authority.expiresAt)<=Date.now())throw denied();
  await this.access.assertDeckCurrent(authority,'request');
  const expiresAt=new Date(Math.min(Date.now()+5*60*1000,Date.parse(authority.expiresAt))).toISOString();
  const issued=await this.repository.issueDeckSession(authority.handle,{...input,expiresAt,credentialEpoch:authority.credentialEpoch});
  if(!DECK_UUID.test(issued.id)||! /^[A-Za-z\d_-]{43}$/.test(issued.token)||Date.parse(issued.expiresAt)>Date.parse(expiresAt)||Date.parse(issued.expiresAt)<=Date.now())throw denied();
  await this.access.assertDeckCurrent(authority,'response');
  return{id:issued.id,revision:1,basePath:`/api/v1/deck/${issued.id}`,purpose:input.purpose,authorizationScheme:'KongOS-Deck',tokenSecret:issued.token,expiresAt:issued.expiresAt};
 }
 async revoke(id:string,revision:number,actor:ConsoleActor){
  if(!DECK_UUID.test(id)||!Number.isSafeInteger(revision)||revision<1)throw denied();
  const authority=await this.access.authorizeDeckSessionRevoke(actor,id);if(authority.locator.id!==id||authority.locator.clusterId!==actor.clusterId)throw denied();
  return this.repository.revokeDeckSession(authority.handle,id,revision);
 }
}
