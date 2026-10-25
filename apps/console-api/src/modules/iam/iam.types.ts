import { BadRequestException } from '@nestjs/common';
import { createHmac,timingSafeEqual } from 'node:crypto';
import { objectBody,pageSize,type EntityActor } from '../entities/entities.types';
import type { EffectiveGrant } from '../../common/authorization.types';

export type IamActor=EntityActor;
export type IamScope={cluster_id:string|null;workspace_id:string|null};
export interface IamPageQuery {size?:number|string;cursor?:string;search?:string;status?:string;clusterId?:string;workspaceId?:string}
export interface IamPage<T=any> {items:T[];nextCursor:string|null;size:number;total:null}
export interface IamPermission extends EffectiveGrant {id:string;role_id:string;status:string;revision:number}
export const USER_COLUMNS='id,username,display_name,email,locale,timezone,status,auth_source,super_admin,revision,force_password_change,created_at,updated_at,deleted_at,retention_until';
export const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
export function iamId(value:unknown):string{
  if(typeof value!=='string'||!uuid.test(value))throw new BadRequestException({code:'INVALID_IAM_ID',message:'身份资源 ID 无效'});return value;
}
export function iamBody(input:unknown,keys:readonly string[]):Record<string,any>{
  const body=objectBody(input);if(Object.keys(body).some(key=>!keys.includes(key)))throw new BadRequestException({code:'INVALID_IAM_FIELD',message:'身份配置包含不允许修改的字段'});return body;
}
export function iamRevision(value:any):number{
  if(!Number.isInteger(value)||value<1||value>=2147483647)throw new BadRequestException({code:'INVALID_IAM_REVISION',message:'请提供有效的身份配置版本号'});return value;
}
export function iamText(value:unknown,name:string,max=128,required=false):string|undefined{
  if(value===undefined&&!required)return undefined;
  if(typeof value!=='string'||value.length>max||required&&!value.trim())throw new BadRequestException({code:'INVALID_IAM_INPUT',message:`${name} 格式无效`});return value.trim();
}
export function iamConfirm(body:any,name:string):void{
  iamRevision(body.revision);if(body.confirmed!==true||body.confirm_name!==name)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:`请二次确认并输入 ${name}`});
}
export function retentionDays():number{
  const days=Number(process.env.RECYCLE_RETENTION_DAYS??30);if(!Number.isInteger(days)||days<1||days>3650)throw new BadRequestException('回收保留期无效');return days;
}
export function publicUser(row:any):any{
  return Object.fromEntries(USER_COLUMNS.split(',').map(key=>[key,row[key]??null]));
}
export function pagination(query:IamPageQuery,binding:string):{size:number;prior:{id:string;created_at:string}|null;next:(row:any)=>string}{
  const size=pageSize(query.size),secret=process.env.APP_SECRET;
  if(!secret||secret.length<32)throw new Error('APP_SECRET must contain at least 32 characters');
  let prior:{id:string;created_at:string}|null=null;
  if(query.cursor){try{
    if(typeof query.cursor!=='string'||query.cursor.length>4096)throw new Error();
    const [encoded,signature,extra]=query.cursor.split('.');if(!encoded||!signature||extra)throw new Error();
    const actual=Buffer.from(signature,'base64url'),expected=createHmac('sha256',secret).update(encoded).digest();
    if(actual.length!==expected.length||!timingSafeEqual(actual,expected))throw new Error();
    const data=JSON.parse(Buffer.from(encoded,'base64url').toString());
    if(data.binding!==binding||data.expires<Date.now()||!uuid.test(data.id)||!Number.isFinite(Date.parse(data.created_at)))throw new Error();prior=data;
  }catch{throw new BadRequestException({code:'INVALID_CURSOR',message:'身份分页游标无效、过期或权限已变化'});}}
  return {size,prior,next:(row:any)=>{const value=Buffer.from(JSON.stringify({binding,id:row.id,created_at:new Date(row.created_at).toISOString(),expires:Date.now()+900000})).toString('base64url');
    return `${value}.${createHmac('sha256',secret).update(value).digest('base64url')}`;}};
}
