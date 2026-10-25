import { BadRequestException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { createHash,createPublicKey,randomBytes,timingSafeEqual } from 'node:crypto';
import { Client } from 'ldapts';
import jwt from 'jsonwebtoken';
import { RedisService } from '../../../infrastructure/redis.service';
import { providerAddress,providerJson,providerUrl } from './provider-http';

interface BaseProvider {id:string;name:string;type:'ldap'|'oidc';group_roles:Record<string,string[]>;}
interface LdapProvider extends BaseProvider {type:'ldap';url:string;bind_dn:string;bind_password:string;base_dn:string;username_attribute:string;subject_attribute:string;groups_attribute:string;}
interface OidcProvider extends BaseProvider {type:'oidc';issuer:string;authorization_url:string;token_url:string;jwks_url:string;client_id:string;client_secret:string;callback_uri:string;groups_claim:string;}
export type IdentityProvider=LdapProvider|OidcProvider;
export interface VerifiedExternalIdentity {provider:IdentityProvider;providerKey:string;subject:string;groups:string[];roleIds:string[];}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const fail=()=>new UnauthorizedException({code:'EXTERNAL_AUTH_FAILED',message:'外部认证失败，请重新登录'});
export function escapeLdapFilter(value:string):string{return value.replace(/[\0()*\\]/g,ch=>`\\${ch.charCodeAt(0).toString(16).padStart(2,'0')}`);}
function exact(value:any,keys:string[]){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!keys.includes(k)))throw new BadRequestException({code:'AUTH_PROVIDER_CONFIG_INVALID',message:'认证提供方配置字段无效'});}
function text(value:any,max=1024):string{if(typeof value!=='string'||!value.length||value.length>max||/[\x00-\x1f]/.test(value))throw new BadRequestException('认证提供方配置无效');return value;}
export function configuredProviders():IdentityProvider[]{
 const raw=process.env.AUTH_PROVIDERS_JSON;if(!raw)return [];if(Buffer.byteLength(raw)>65536)throw new BadRequestException('认证提供方配置过大');
 let values:any;try{values=JSON.parse(raw);}catch{throw new BadRequestException('认证提供方 JSON 配置无效');}
 if(!Array.isArray(values)||values.length>16)throw new BadRequestException('认证提供方数量无效');const ids=new Set<string>();
 return values.map(input=>{
  const base=['id','name','type','group_roles'];
  exact(input,input.type==='ldap'?[...base,'url','bind_dn','bind_password','base_dn','username_attribute','subject_attribute','groups_attribute']:[...base,'issuer','authorization_url','token_url','jwks_url','client_id','client_secret','callback_uri','groups_claim']);
  if(!/^[a-z][a-z0-9_-]{0,31}$/.test(input.id)||ids.has(input.id)||!['ldap','oidc'].includes(input.type))throw new BadRequestException('认证提供方标识无效');ids.add(input.id);text(input.name,128);
  const mapping=input.group_roles??{};if(!mapping||typeof mapping!=='object'||Array.isArray(mapping)||Object.keys(mapping).length>100)throw new BadRequestException('提供方角色映射无效');
  for(const [group,roles] of Object.entries(mapping)){text(group);if(['__proto__','constructor','prototype'].includes(group)||!Array.isArray(roles)||roles.length>32||roles.some(role=>typeof role!=='string'||!UUID.test(role)))throw new BadRequestException('提供方角色映射无效');}
  if(input.type==='ldap'){
   providerUrl(input.url,'ldaps:');text(input.bind_dn);text(input.bind_password,4096);text(input.base_dn);
   for(const attr of ['username_attribute','subject_attribute','groups_attribute'])if(!/^[a-zA-Z][a-zA-Z0-9.-]{0,63}$/.test(input[attr]))throw new BadRequestException('LDAP 属性配置无效');
  }else{
   for(const value of [input.issuer,input.authorization_url,input.token_url,input.jwks_url])providerUrl(value);
   text(input.client_id,256);text(input.client_secret,4096);
   let callback:URL;try{callback=new URL(input.callback_uri);}catch{throw new BadRequestException('OIDC 回调地址无效');}
   const insecureDev=process.env.NODE_ENV!=='production'&&process.env.AUTH_ALLOW_INSECURE_CALLBACK_FOR_DEV==='true';
   if(callback.protocol!=='https:'&&!(insecureDev&&callback.protocol==='http:')||callback.username||callback.password||callback.search||callback.hash||callback.pathname!==`/api/v1/auth/oidc/${input.id}/callback`)throw new BadRequestException('OIDC 回调地址须使用固定控制台 TLS 路径');
   const origins=(process.env.PUBLIC_ORIGINS??'').split(',').filter(Boolean);if(!origins.includes(callback.origin))throw new BadRequestException('OIDC 回调来源未登记 PUBLIC_ORIGINS');
   if(!/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(input.groups_claim))throw new BadRequestException('OIDC 组声明配置无效');
  }
  return {...input,group_roles:mapping} as IdentityProvider;
 });
}
function identity(provider:IdentityProvider,subject:string,groups:string[]):VerifiedExternalIdentity{
 if(!subject||subject.length>1024||groups.length>100||groups.some(g=>typeof g!=='string'||g.length>1024))throw fail();
 const roleIds=[...new Set(groups.flatMap(group=>Object.hasOwn(provider.group_roles,group)?provider.group_roles[group]:[]))];if(roleIds.length>64)throw fail();
 const source=provider.type==='oidc'?provider.issuer:`${provider.url}|${provider.base_dn}|${provider.subject_attribute}`;
 return {provider,providerKey:`${provider.id}:${hash(source)}`,subject,groups,roleIds};
}
export class IdentityProviders {
 constructor(private readonly redis:RedisService){}
 catalog(){return configuredProviders().map(({id,name,type})=>({id,name,type}));}
 private provider(id:string,type:'ldap'|'oidc'):IdentityProvider{
  const provider=configuredProviders().find(p=>p.id===id&&p.type===type);if(!provider)throw new ServiceUnavailableException({code:'AUTH_PROVIDER_UNAVAILABLE',message:'此认证提供方尚未配置'});return provider;
 }
 async ldap(id:string,username:string,password:string):Promise<VerifiedExternalIdentity>{
  const provider=this.provider(id,'ldap') as LdapProvider;
  if(typeof username!=='string'||!username.length||username.length>128||typeof password!=='string'||!password.length||Buffer.byteLength(password)>4096||password.includes('\0'))throw fail();
  const url=providerUrl(provider.url,'ldaps:'),address=await providerAddress(url),host=url.hostname.replace(/^\[|\]$/g,'');url.hostname=address.family===6?`[${address.address}]`:address.address;
  const client=new Client({url:url.toString(),timeout:5000,connectTimeout:5000,tlsOptions:{servername:host,rejectUnauthorized:true}});
  try{
   await client.bind(provider.bind_dn,provider.bind_password);
   const result=await client.search(provider.base_dn,{scope:'sub',filter:`(${provider.username_attribute}=${escapeLdapFilter(username)})`,attributes:[provider.subject_attribute,provider.groups_attribute],sizeLimit:2,timeLimit:5});
   if(result.searchEntries.length!==1)throw fail();const entry=result.searchEntries[0];
   const subjects=entry[provider.subject_attribute];const subject=Array.isArray(subjects)?subjects.length===1?subjects[0]:undefined:subjects;
   if(typeof subject!=='string'||!entry.dn)throw fail();
   await client.bind(entry.dn,password);
   const rawGroups=entry[provider.groups_attribute]??[],groups=Array.isArray(rawGroups)?rawGroups:[rawGroups];if(groups.some(group=>typeof group!=='string'))throw fail();
   return identity(provider,subject,groups as string[]);
  }catch{throw fail();}finally{await client.unbind().catch(()=>undefined);}
 }
 async start(id:string,redirect='/'){
  const provider=this.provider(id,'oidc') as OidcProvider;
  if(!['/','/overview','/profile'].includes(redirect))throw new BadRequestException('登录后跳转地址不允许');
  const state=randomBytes(32).toString('base64url'),nonce=randomBytes(32).toString('base64url'),verifier=randomBytes(48).toString('base64url'),correlation=randomBytes(32).toString('base64url');
  const stored={provider:id,nonce,verifier,redirect,correlationHash:hash(correlation),createdAt:Date.now()};
  if(await this.redis.client.set(`auth:oidc:state:${hash(state)}`,JSON.stringify(stored),'EX',300,'NX')!=='OK')throw new ServiceUnavailableException({code:'AUTH_STATE_UNAVAILABLE',message:'无法建立安全登录状态'});
  const url=new URL(provider.authorization_url);for(const [key,value] of Object.entries({response_type:'code',client_id:provider.client_id,redirect_uri:provider.callback_uri,scope:'openid profile',state,nonce,code_challenge:hash(verifier),code_challenge_method:'S256'}))url.searchParams.set(key,key==='code_challenge'?createHash('sha256').update(verifier).digest('base64url'):value);
  return {authorizationUrl:url.toString(),correlation,callbackSecure:new URL(provider.callback_uri).protocol==='https:'};
 }
 async callback(id:string,code:string,state:string,correlation:string):Promise<{identity:VerifiedExternalIdentity;redirect:string}>{
  const provider=this.provider(id,'oidc') as OidcProvider;
  if(typeof code!=='string'||!code.length||code.length>4096||typeof state!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(state)||typeof correlation!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(correlation))throw fail();
  const raw=await this.redis.client.getdel(`auth:oidc:state:${hash(state)}`);if(!raw)throw fail();let stored:any;
  try{stored=JSON.parse(raw);const supplied=Buffer.from(hash(correlation)),expected=Buffer.from(stored.correlationHash);if(stored.provider!==id||supplied.length!==expected.length||!timingSafeEqual(supplied,expected)||Date.now()-stored.createdAt>300000||!['/','/overview','/profile'].includes(stored.redirect))throw new Error();}catch{throw fail();}
  const form=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:provider.callback_uri,code_verifier:stored.verifier});
  const token=await providerJson(provider.token_url,'POST',form,`Basic ${Buffer.from(`${encodeURIComponent(provider.client_id)}:${encodeURIComponent(provider.client_secret)}`).toString('base64')}`);
  if(typeof token.id_token!=='string'||token.id_token.length>16384)throw fail();
  const decoded=jwt.decode(token.id_token,{complete:true});if(!decoded||typeof decoded.payload==='string'||!['RS256','PS256','ES256'].includes(decoded.header.alg)||typeof decoded.header.kid!=='string'||decoded.header.kid.length>256)throw fail();
  const jwks=await providerJson(provider.jwks_url);if(!Array.isArray(jwks.keys)||jwks.keys.length>32)throw fail();
  const matches=jwks.keys.filter((key:any)=>key.kid===decoded.header.kid&&(!key.use||key.use==='sig')&&(!key.key_ops||Array.isArray(key.key_ops)&&key.key_ops.includes('verify'))&&(!key.alg||key.alg===decoded.header.alg));if(matches.length!==1)throw fail();
  let claims:jwt.JwtPayload;try{
   const jwk=matches[0];if(jwk.kty==='RSA'){if(typeof jwk.n!=='string'||jwk.n.length>1400||typeof jwk.e!=='string'||jwk.e.length>12)throw new Error();}
   else if(jwk.kty==='EC'){if(jwk.crv!=='P-256'||typeof jwk.x!=='string'||jwk.x.length!==43||typeof jwk.y!=='string'||jwk.y.length!==43)throw new Error();}else throw new Error();
   const key=createPublicKey({key:matches[0],format:'jwk'});
   if(decoded.header.alg==='ES256'&&(key.asymmetricKeyType!=='ec'||key.asymmetricKeyDetails?.namedCurve!=='prime256v1')||decoded.header.alg!=='ES256'&&(key.asymmetricKeyType!=='rsa'||Number(key.asymmetricKeyDetails?.modulusLength)<2048||Number(key.asymmetricKeyDetails?.modulusLength)>8192))throw new Error();
   const verified=jwt.verify(token.id_token,key,{algorithms:[decoded.header.alg as jwt.Algorithm],issuer:provider.issuer,audience:provider.client_id,clockTolerance:30});if(typeof verified==='string')throw new Error();claims=verified;
   if(typeof claims.exp!=='number'||typeof claims.iat!=='number'||claims.iat>Date.now()/1000+30||claims.nonce!==stored.nonce||typeof claims.sub!=='string'||!claims.sub||Array.isArray(claims.aud)&&claims.aud.length>1&&claims.azp!==provider.client_id||claims.azp!==undefined&&claims.azp!==provider.client_id)throw new Error();
  }catch{throw fail();}
  const groups=claims[provider.groups_claim]??[];if(!Array.isArray(groups)||groups.some(value=>typeof value!=='string'))throw fail();
  return {identity:identity(provider,claims.sub!,groups),redirect:stored.redirect};
 }
}
