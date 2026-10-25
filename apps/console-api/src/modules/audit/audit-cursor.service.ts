import { Injectable } from '@nestjs/common';
import { SecretService } from '../../infrastructure/secret.service';
import { auditInvalid } from './audit.types';

export interface AuditCursorBinding {actorId:string;permissionVersion:string;scope:unknown;filter:unknown;size?:number}
@Injectable()
export class AuditCursorService {
  constructor(private readonly secrets:SecretService){}
  seal(kind:'list'|'integrity',binding:AuditCursorBinding,state:unknown):string {
    // Encryption also hides unfiltered chain bounds from restricted readers.
    return this.secrets.encrypt({version:1,kind,binding:this.secrets.fingerprint(binding),state,expires:Date.now()+30*60*1000},`audit-cursor:${kind}`);
  }
  open<T>(kind:'list'|'integrity',binding:AuditCursorBinding,token:string):T {
    try{
      if(typeof token!=='string'||token.length>24576)throw new Error();
      const data=this.secrets.decrypt<{version:number;kind:string;binding:string;state:T;expires:number}>(token,`audit-cursor:${kind}`);
      if(data.version!==1||data.kind!==kind||data.binding!==this.secrets.fingerprint(binding)
        ||!Number.isFinite(data.expires)||data.expires<Date.now())throw new Error();
      return data.state;
    }catch{throw auditInvalid('审计游标无效、已过期或属于其他身份及范围');}
  }
}
