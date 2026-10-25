import { BadRequestException,ConflictException,Injectable,NotFoundException,UnauthorizedException } from '@nestjs/common';
import { createHash,randomUUID,timingSafeEqual } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService } from '../audit/audit.service';
import { METRICS_AUDIENCE,METRICS_PURPOSES,type MetricsAudience,type MetricsCredentialIdentity,type MetricsEnrollment,type MetricsPurpose } from './metrics.types';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export function metricsTokenDigest(token:string):string{return createHash('sha256').update(token,'utf8').digest('hex');}
function equalDigest(a:string,b:string):boolean {
  return /^[a-f0-9]{64}$/.test(a)&&/^[a-f0-9]{64}$/.test(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}
@Injectable()
export class MetricsCredentialsService {
  private readonly identities=new WeakSet<object>();
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly audit:AuditService){}
  private denied():UnauthorizedException{return new UnauthorizedException({code:'METRICS_CREDENTIAL_INVALID',message:'采集凭证无效'});}
  async currentGeneration(clusterId:string):Promise<{clusterId:string;generation:number;enrolled:boolean}>{
    if(!uuid.test(clusterId))throw new BadRequestException({code:'INVALID_CLUSTER_ID',message:'集群 ID 无效'});
    const row=await this.db.one<any>(`SELECT c.id,s.credential_generation FROM clusters c LEFT JOIN metrics_settings s ON s.cluster_id=c.id
      WHERE c.id=$1 AND c.deleted_at IS NULL`,[clusterId]);
    if(!row)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
    const generation=Number(row.credential_generation??0);return {clusterId,generation,enrolled:generation>0};
  }
  /** Called by the trusted post-bootstrap CLI, never exposed as an HTTP enrolment endpoint. */
  async trustedEnroll(input:MetricsEnrollment,context:{actorId?:string;requestId?:string}={}):Promise<any>{
    if(!input||!uuid.test(input.clusterId)||!Number.isSafeInteger(input.generation)||input.generation<1||input.generation>2147483647
      ||!Array.isArray(input.credentials)||input.credentials.length!==4)throw new BadRequestException({code:'INVALID_METRICS_ENROLLMENT',message:'采集凭证登记参数无效'});
    const entries=input.credentials.map(item=>{
      if(!item||!METRICS_PURPOSES.includes(item.purpose)||METRICS_AUDIENCE[item.purpose]!==item.audience
        ||typeof item.token!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(item.token))throw new BadRequestException({code:'INVALID_METRICS_ENROLLMENT',message:'采集凭证必须使用独立高熵令牌和正确用途'});
      return {...item,fingerprint:metricsTokenDigest(item.token)};
    });
    if(new Set(entries.map(item=>item.purpose)).size!==4||new Set(entries.map(item=>item.fingerprint)).size!==4)
      throw new BadRequestException({code:'METRICS_CREDENTIALS_NOT_DISTINCT',message:'四种用途必须使用不同的采集凭证'});
    return this.db.transaction(async tx=>{
      await tx.exec('SELECT pg_advisory_xact_lock(hashtext($1))',[`kongos:metrics-credentials:${input.clusterId}`]);
      const cluster=await tx.one('SELECT id FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[input.clusterId]);
      if(!cluster)throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
      await tx.exec('INSERT INTO metrics_settings(cluster_id) VALUES($1) ON CONFLICT DO NOTHING',[input.clusterId]);
      const settings=await tx.one<any>('SELECT credential_generation FROM metrics_settings WHERE cluster_id=$1 FOR UPDATE',[input.clusterId]);
      const current=Number(settings.credential_generation),old=await tx.query<any>("SELECT * FROM metrics_credentials WHERE cluster_id=$1 AND status='active' ORDER BY purpose",[input.clusterId]);
      const safe=(rows:any[])=>rows.map(row=>({id:row.id,purpose:row.purpose,audience:row.audience,generation:Number(row.generation),fingerprint:row.token_fingerprint}));
      if(input.generation===current){
        if(old.length!==4||entries.some(item=>!old.some(row=>row.purpose===item.purpose&&row.audience===item.audience&&equalDigest(row.token_fingerprint,item.fingerprint))))
          throw new ConflictException({code:'METRICS_ENROLLMENT_CONFLICT',message:'当前凭证代次已登记不同内容，轮换必须递增代次'});
        return {clusterId:input.clusterId,generation:current,enrolled:true,credentials:safe(old)};
      }
      if(input.generation!==current+1)throw new ConflictException({code:'METRICS_GENERATION_CONFLICT',message:'采集凭证代次必须连续递增'});
      await tx.exec("UPDATE metrics_credentials SET status='revoked',revoked_at=now(),retention_until=now()+interval '30 days' WHERE cluster_id=$1 AND status='active'",[input.clusterId]);
      const rows=[];
      for(const entry of entries){
        const id=randomUUID();await tx.exec(`INSERT INTO metrics_credentials(id,cluster_id,purpose,audience,generation,token_secret,token_fingerprint)
          VALUES($1,$2,$3,$4,$5,$6,$7)`,[id,input.clusterId,entry.purpose,entry.audience,input.generation,
          this.secrets.encrypt(entry.token,`metrics-credential:${id}:${input.clusterId}:${entry.purpose}:${input.generation}`),entry.fingerprint]);
        rows.push({id,purpose:entry.purpose,audience:entry.audience,generation:input.generation,token_fingerprint:entry.fingerprint});
      }
      await tx.exec('UPDATE metrics_settings SET credential_generation=$2,revision=revision+1,catalog_revision=catalog_revision+1,updated_at=now() WHERE cluster_id=$1',[input.clusterId,input.generation]);
      await this.audit.append({actorId:context.actorId,actorType:context.actorId?'user':'system',clusterId:input.clusterId,
        entityType:'monitoring',action:current?'credentials.rotate':'credentials.enroll',requestId:context.requestId,
        before:{generation:current,credentials:safe(old)},after:{generation:input.generation,credentials:safe(rows)}},tx);
      return {clusterId:input.clusterId,generation:input.generation,enrolled:true,credentials:safe(rows)};
    });
  }
  async validate(token:string,clusterId:string,purpose:MetricsPurpose,audience:MetricsAudience):Promise<Readonly<MetricsCredentialIdentity>>{
    if(typeof token!=='string'||!uuid.test(clusterId)||!METRICS_PURPOSES.includes(purpose)||METRICS_AUDIENCE[purpose]!==audience
      ||token.length<43||token.length>128)throw this.denied();
    const row=await this.db.one<any>(`SELECT k.id,k.cluster_id,k.purpose,k.audience,k.generation,k.token_fingerprint
      FROM metrics_credentials k JOIN metrics_settings s ON s.cluster_id=k.cluster_id JOIN clusters c ON c.id=k.cluster_id
      WHERE k.cluster_id=$1 AND k.purpose=$2 AND k.audience=$3 AND k.status='active'
        AND k.generation=s.credential_generation AND c.deleted_at IS NULL`,[clusterId,purpose,audience]);
    // Perform a digest comparison for unknown credentials as well.
    const matches=equalDigest(metricsTokenDigest(token),row?.token_fingerprint??'0'.repeat(64));
    if(!row||!matches)throw this.denied();
    const identity=Object.freeze({id:row.id,clusterId:row.cluster_id,purpose:row.purpose,audience:row.audience,generation:Number(row.generation)}) as Readonly<MetricsCredentialIdentity>;
    this.identities.add(identity);return identity;
  }
  /** Alias retained for internal listeners that call credential verification `verify`. */
  verify(token:string,cid:string,purpose:MetricsPurpose,audience:MetricsAudience){return this.validate(token,cid,purpose,audience);}
  async assertCurrent(identity:Readonly<MetricsCredentialIdentity>):Promise<void>{
    if(!identity||!this.identities.has(identity))throw this.denied();
    const row=await this.db.one(`SELECT k.id FROM metrics_credentials k JOIN metrics_settings s ON s.cluster_id=k.cluster_id
      JOIN clusters c ON c.id=k.cluster_id WHERE k.id=$1 AND k.cluster_id=$2 AND k.purpose=$3 AND k.audience=$4
      AND k.generation=$5 AND k.generation=s.credential_generation AND k.status='active' AND c.deleted_at IS NULL`,
      [identity.id,identity.clusterId,identity.purpose,identity.audience,identity.generation]);
    if(!row)throw this.denied();
  }
  /** Only trusted, fresh platform-authorized setup may receive this secret. */
  async getActiveIngestCredential(clusterId:string):Promise<{generation:number;token:string;fingerprint:string}>{
    if(!uuid.test(clusterId))throw this.denied();
    const row=await this.db.one<any>(`SELECT k.* FROM metrics_credentials k JOIN metrics_settings s ON s.cluster_id=k.cluster_id
      JOIN clusters c ON c.id=k.cluster_id WHERE k.cluster_id=$1 AND k.purpose='collector_ingest' AND k.audience='collector'
      AND k.status='active' AND k.generation=s.credential_generation AND c.deleted_at IS NULL`,[clusterId]);
    if(!row)throw this.denied();
    return {generation:Number(row.generation),token:this.secrets.decrypt<string>(row.token_secret,
      `metrics-credential:${row.id}:${clusterId}:collector_ingest:${row.generation}`),fingerprint:row.token_fingerprint};
  }
  async verifyManagedIngestUrl(clusterId:string,input:string):Promise<{valid:boolean;generation?:number;fingerprint?:string}>{
    let url:URL;try{url=new URL(input);}catch{return {valid:false};}
    if(url.protocol!=='http:'||url.hostname!=='telemetry-collector'||url.port!=='9093'||url.pathname!==`/ingest/${clusterId}`
      ||url.search||url.hash||url.username!=='kongos'||!url.password)return {valid:false};
    let token:string;try{token=decodeURIComponent(url.password);}catch{return {valid:false};}
    try{const identity=await this.validate(token,clusterId,'collector_ingest','collector');await this.assertCurrent(identity);
      return {valid:true,generation:identity.generation,fingerprint:metricsTokenDigest(token)};
    }catch(error){if(error instanceof UnauthorizedException)return {valid:false};throw error;}
  }
}
