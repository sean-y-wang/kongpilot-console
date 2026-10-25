import { BadRequestException,ConflictException,ForbiddenException,HttpException,Injectable,NotFoundException,OnModuleDestroy,OnModuleInit } from '@nestjs/common';
import { createHash,randomUUID } from 'node:crypto';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson,SecretService } from '../../infrastructure/secret.service';
import { HistoricalEventAccessService } from '../authorization/historical-event-access.service';
import { AuditService } from './audit.service';
import { AuditQueryService,type AuditCapturedQuery } from './audit-query.service';
import { AUDIT_EXPORT_MAX_BYTES,AUDIT_EXPORT_MAX_ROWS,type AuditScope,type AuditSafeView,auditQuery,auditUuid,auditInvalid } from './audit.types';

export type AuditExportState='queued'|'running'|'succeeded'|'incomplete'|'failed'|'cancelled'|'expired';
export interface AuditExportView {
  id:string;state:AuditExportState;format:'ndjson'|'csv';rowCount:number;bytesCount:number;complete:boolean;
  reasonCodes:string[];createdAt:string;expiresAt:string;capabilities:{download:boolean};
}
export interface AuditExportReceipt {domain:'audit-export';jobId:string;durable:true;job:AuditExportView}
interface ExportRow {
  id:string;actor_id:string;cluster_id:string|null;workspace_id:string|null;idempotency_key:string;request_hash:string;
  format:'ndjson'|'csv';filter_safe:unknown;upper_bounds:AuditCapturedQuery;permission_version:string;
  state:AuditExportState;revision:number;row_count:number;bytes_count:number;digest:string|null;output_secret:string|null;
  lease_owner_hash:string|null;lease_generation:number;lease_until:Date|string|null;error_code:string|null;
  expires_at:Date|string;created_at:Date|string;
}
const keyPattern=/^[A-Za-z\d_.:-]{1,128}$/;
function exportContext(row:Pick<ExportRow,'id'|'actor_id'|'cluster_id'|'workspace_id'|'request_hash'>):string {
  return `audit-export:${row.id}:${row.actor_id}:${row.cluster_id??'global'}:${row.workspace_id??'global'}:${row.request_hash}:output`;
}
export function auditCsvCell(value:unknown):string {
  let text=typeof value==='string'?value:value===null||value===undefined?'':canonicalJson(value);
  // A spreadsheet may trim whitespace and controls before interpreting a formula.
  if(/^[\s\u0000-\u001f]*[=+@-]/.test(text)||/^[\t\r\n]/.test(text))text=`'${text}`;
  return `"${text.replace(/"/g,'""')}"`;
}
const csvFields=['id','occurredAt','actorId','actorType','sourceIp','clusterId','workspaceId','entityType','entityId','action','result','requestId','workflowId','before','after','jsonPatch'] as const;
function exportLine(view:AuditSafeView,format:'ndjson'|'csv'):string {
  return format==='ndjson'?`${canonicalJson(view)}\n`:`${csvFields.map(field=>auditCsvCell(view[field])).join(',')}\r\n`;
}

/** Owner-only DB ledger and bounded encrypted output; it never executes Kong writes. */
@Injectable()
export class AuditExportService implements OnModuleInit,OnModuleDestroy {
  private timer?:ReturnType<typeof setInterval>;private busy=false;private stopping=false;
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly access:HistoricalEventAccessService,
    private readonly queries:AuditQueryService,private readonly audit:AuditService){}
  onModuleInit():void {
    this.timer=setInterval(()=>{void this.tick().catch(()=>undefined);},2000);this.timer.unref();
  }
  onModuleDestroy():void {this.stopping=true;if(this.timer)clearInterval(this.timer);}
  private view(row:ExportRow,download:boolean):AuditExportView {
    return {id:row.id,state:row.state,format:row.format,rowCount:Number(row.row_count),bytesCount:Number(row.bytes_count),
      complete:row.state==='succeeded',reasonCodes:row.error_code?[row.error_code]:[],createdAt:new Date(row.created_at).toISOString(),
      expiresAt:new Date(row.expires_at).toISOString(),capabilities:{download}};
  }
  private jobScope(row:ExportRow):AuditScope {
    return {clusterId:row.cluster_id,workspaceId:row.workspace_id,mode:row.cluster_id===null?'global':row.workspace_id?'workspace':'cluster'};
  }
  private async current(user:AuthUser,scope:AuditScope,row:ExportRow):Promise<string>{
    if(row.actor_id!==user.id||row.cluster_id!==scope.clusterId||row.workspace_id!==scope.workspaceId)
      throw new NotFoundException({code:'AUDIT_EXPORT_NOT_FOUND',message:'导出任务不存在'});
    return (await this.access.assertAuditScope(user,this.jobScope(row))).version;
  }
  async create(user:AuthUser,clusterId:string|null,body:unknown,key:string,request:{requestId?:string;ip?:string}):Promise<AuditExportReceipt>{
    if(typeof key!=='string'||!keyPattern.test(key))throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY',message:'导出需要原始幂等键'});
    if(!body||typeof body!=='object'||Array.isArray(body))throw auditInvalid();
    const {format='ndjson',confirmed,...filters}=body as Record<string,unknown>;
    if(!['ndjson','csv'].includes(String(format))||confirmed!==true||filters.cursor!==undefined||filters.size!==undefined)throw auditInvalid('请确认导出，并选择 ndjson 或 csv 格式');
    const query=auditQuery(clusterId,{...filters,size:100});
    const requestHash=this.secrets.fingerprint({actorId:user.id,clusterId:query.clusterId,workspaceId:query.workspaceId,mode:query.mode,format,filter:query.filter});
    const captured=await this.queries.capture(user,query);
    const row=await this.db.transaction(async tx=>{
      await tx.exec('SELECT pg_advisory_xact_lock(hashtext($1))',[`kongos:audit-export:${user.id}:${key}`]);
      const old=await tx.one<ExportRow>('SELECT * FROM audit_export_jobs WHERE actor_id=$1 AND idempotency_key=$2',[user.id,key]);
      if(old){if(old.request_hash!==requestHash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'原键已经用于另一导出请求'});return old;}
      await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
      await this.access.assertVersion(user,captured.permissionVersion);
      const id=randomUUID();
      const created=await tx.one<ExportRow>(`INSERT INTO audit_export_jobs(id,actor_id,cluster_id,workspace_id,idempotency_key,request_hash,
        format,filter_safe,upper_bounds,permission_version,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,now()+interval '24 hours') RETURNING *`,
        [id,user.id,query.clusterId,query.workspaceId,key,requestHash,format,JSON.stringify(query.filter),JSON.stringify(captured),captured.permissionVersion]);
      if(!created)throw new Error('Audit export request was not created');
      await this.audit.append({actorId:user.id,clusterId:query.clusterId,workspaceId:query.workspaceId,entityType:'audit_exports',entityId:id,
        action:'audit.export.created',after:{format,filter:query.filter},result:'success',requestId:request.requestId,ip:request.ip},tx);
      return created;
    });
    const version=await this.current(user,query,row);
    await this.access.assertVersion(user,version);
    return {domain:'audit-export',jobId:row.id,durable:true,job:this.view(row,this.downloadAllowed(row,version))};
  }
  private downloadAllowed(row:ExportRow,version:string):boolean {
    return ['succeeded','incomplete'].includes(row.state)&&!!row.output_secret&&row.permission_version===version&&new Date(row.expires_at).getTime()>Date.now();
  }
  async get(user:AuthUser,scope:AuditScope,idOrKey:string,byKey=false):Promise<AuditExportView>{
    if(byKey){if(!keyPattern.test(idOrKey))throw auditInvalid();}else auditUuid(idOrKey);
    const row=await this.db.one<ExportRow>(`SELECT * FROM audit_export_jobs WHERE actor_id=$1 AND ${byKey?'idempotency_key':'id'}=$2`,[user.id,idOrKey]);
    if(!row)throw new NotFoundException({code:'AUDIT_EXPORT_NOT_FOUND',message:'导出任务不存在'});
    const version=await this.current(user,scope,row);const view=this.view(row,this.downloadAllowed(row,version));
    await this.access.assertVersion(user,version);return view;
  }
  async receipt(user:AuthUser,scope:AuditScope,key:string):Promise<AuditExportReceipt>{
    const job=await this.get(user,scope,key,true);return {domain:'audit-export',jobId:job.id,durable:true,job};
  }
  async download(user:AuthUser,scope:AuditScope,id:string):Promise<{buffer:Buffer;filename:string;contentType:string}>{
    auditUuid(id);const row=await this.db.one<ExportRow>('SELECT * FROM audit_export_jobs WHERE actor_id=$1 AND id=$2',[user.id,id]);
    if(!row)throw new NotFoundException({code:'AUDIT_EXPORT_NOT_FOUND',message:'导出任务不存在'});
    const version=await this.current(user,scope,row);
    if(!this.downloadAllowed(row,version))throw new ForbiddenException({code:'AUDIT_EXPORT_UNAVAILABLE',message:'文件未完成、已到期或当前授权已变化'});
    const content=this.secrets.decrypt<unknown>(row.output_secret!,exportContext(row));
    if(typeof content!=='string')throw new Error('Audit export output invalid');
    const buffer=Buffer.from(content,'utf8');
    if(buffer.length!==Number(row.bytes_count)||buffer.length>AUDIT_EXPORT_MAX_BYTES
      ||createHash('sha256').update(buffer).digest('hex')!==row.digest)throw new Error('Audit export output invalid');
    await this.access.assertVersion(user,version);
    return {buffer,filename:`audit-${row.id}.${row.format}`,contentType:row.format==='ndjson'?'application/x-ndjson; charset=utf-8':'text/csv; charset=utf-8'};
  }
  async tick():Promise<void>{
    if(this.busy||this.stopping)return;this.busy=true;
    try{
      await this.db.exec(`UPDATE audit_export_jobs SET state='expired',output_secret=NULL,revision=revision+1,
        lease_owner_hash=NULL,lease_until=NULL,updated_at=now() WHERE expires_at<=now() AND state<>'expired'`);
      const owner=this.secrets.fingerprint({purpose:'audit-export-worker',nonce:randomUUID()});
      const row=await this.db.transaction(async tx=>{
        const candidate=await tx.one<ExportRow>(`SELECT * FROM audit_export_jobs WHERE expires_at>now()
          AND (state='queued' OR state='running' AND lease_until<=now()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`);
        if(!candidate)return null;
        return tx.one<ExportRow>(`UPDATE audit_export_jobs SET state='running',lease_owner_hash=$2,
          lease_generation=lease_generation+1,lease_until=now()+interval '60 seconds',revision=revision+1,updated_at=now()
          WHERE id=$1 RETURNING *`,[candidate.id,owner]);
      });
      if(row)await this.generate(row);
    }finally{this.busy=false;}
  }
  private async generate(row:ExportRow):Promise<void>{
    const captured=structuredClone(row.upper_bounds);const parts:string[]=[];
    let bytes=0,count=0,scanned=0,complete=false,limitReached=false,sealedPlainBytes=2;
    const materialPlainBudget=Math.floor((50331648-128)*3/4);
    if(row.format==='csv'){const header=`${csvFields.map(auditCsvCell).join(',')}\r\n`;parts.push(header);bytes=Buffer.byteLength(header);sealedPlainBytes+=Buffer.byteLength(canonicalJson(header))-2;}
    try{
      const user=await this.access.loadBackgroundActor(row.actor_id);
      if(captured.permissionVersion!==row.permission_version)throw new ForbiddenException();
      while(!this.stopping&&count<AUDIT_EXPORT_MAX_ROWS&&scanned<AUDIT_EXPORT_MAX_ROWS&&bytes<AUDIT_EXPORT_MAX_BYTES){
        await this.access.assertVersion(user,row.permission_version);
        const renewed=await this.db.exec(`UPDATE audit_export_jobs SET lease_until=now()+interval '60 seconds',
          revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND lease_owner_hash=$2 AND lease_generation=$3
          AND lease_until>now() AND expires_at>now()`,[row.id,row.lease_owner_hash,row.lease_generation]);
        if(!renewed)return;
        const {page,state,scannedRows}=await this.queries.capturedPage(user,captured);captured.state=state;scanned+=scannedRows;
        for(const view of page.items){
          const line=exportLine(view,row.format),lineBytes=Buffer.byteLength(line);
          const plainBytes=Buffer.byteLength(canonicalJson(line))-2;
          if(count>=AUDIT_EXPORT_MAX_ROWS||bytes+lineBytes>AUDIT_EXPORT_MAX_BYTES||sealedPlainBytes+plainBytes>materialPlainBudget){limitReached=true;break;}
          parts.push(line);bytes+=lineBytes;sealedPlainBytes+=plainBytes;count++;
        }
        if(limitReached)break;
        if(!page.nextCursor){complete=true;break;}
        if(count>=AUDIT_EXPORT_MAX_ROWS||bytes>=AUDIT_EXPORT_MAX_BYTES)break;
        // A page may be empty after current row-level filtering; continue its durable keyset.
      }
      if(this.stopping)return;
      await this.access.assertVersion(user,row.permission_version);
      const output=parts.join(''),digest=createHash('sha256').update(output,'utf8').digest('hex');
      await this.db.transaction(async tx=>{
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        await this.access.assertVersion(user,row.permission_version);
        const published=await tx.exec(`UPDATE audit_export_jobs SET state=$4,row_count=$5,bytes_count=$6,digest=$7,output_secret=$8,
          error_code=$9,lease_owner_hash=NULL,lease_until=NULL,revision=revision+1,updated_at=now()
          WHERE id=$1 AND state='running' AND lease_owner_hash=$2 AND lease_generation=$3 AND lease_until>now() AND expires_at>now()`,
          [row.id,row.lease_owner_hash,row.lease_generation,complete?'succeeded':'incomplete',count,bytes,digest,
            this.secrets.encrypt(output,exportContext(row)),complete?null:'AUDIT_EXPORT_LIMIT_REACHED']);
        if(published)await this.audit.append({actorId:row.actor_id,clusterId:row.cluster_id,workspaceId:row.workspace_id,
          entityType:'audit_exports',entityId:row.id,action:'audit.export.completed',after:{rowCount:count,bytesCount:bytes,complete},result:'success'},tx);
      });
    }catch(error){
      const denied=error instanceof HttpException&&[401,403].includes(error.getStatus());
      await this.db.exec(`UPDATE audit_export_jobs SET state=$4,error_code=$5,lease_owner_hash=NULL,lease_until=NULL,
        revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND lease_owner_hash=$2 AND lease_generation=$3`,
        [row.id,row.lease_owner_hash,row.lease_generation,denied?'cancelled':'failed',denied?'AUDIT_PERMISSION_CHANGED':'AUDIT_EXPORT_FAILED']);
    }
  }
}
