import { BadRequestException } from '@nestjs/common';
import bcrypt from 'bcryptjs';

/** Runtime IAM and bootstrap share this policy; bcrypt input is never truncated. */
export function validatePassword(password:unknown):asserts password is string {
  if(typeof password!=='string'||Array.from(password).length<12||Buffer.byteLength(password,'utf8')>72||
    !/[A-Z]/.test(password)||!/[a-z]/.test(password)||!/[0-9]/.test(password)||!/[\p{P}\p{S}]/u.test(password)||password.includes('\0')) {
    throw new BadRequestException({code:'PASSWORD_POLICY',message:'密码至少 12 个字符、最多 72 个 UTF-8 字节，且包含大写字母、小写字母、数字及符号'});
  }
}
export function passwordWorkFactor():number {
  const rounds=Number(process.env.PASSWORD_BCRYPT_ROUNDS??12);
  if(!Number.isInteger(rounds)||rounds<10||rounds>14)throw new Error('PASSWORD_BCRYPT_ROUNDS must be between 10 and 14');
  return rounds;
}
export async function hashPolicyPassword(password:unknown,options:{username?:string;previousHash?:string}={}):Promise<string> {
  validatePassword(password);
  if(options.previousHash&&await bcrypt.compare(password,options.previousHash))throw new BadRequestException({code:'PASSWORD_UNCHANGED',message:'新密码不能与当前密码相同'});
  return bcrypt.hash(password,passwordWorkFactor());
}
