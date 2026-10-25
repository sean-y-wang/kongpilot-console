import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { PortalCursor, portalId, portalObject, portalText } from './portal-input';
import { pageSize } from '../entities/entities.types';
import { decodePublicationProof } from './portal-proof';
import { portalScope } from '../portal-auth/portal-auth.types';

export const PORTAL_CATALOG_SCAN_LIMITS = Object.freeze({ rows: 500, batches: 10, batchSize: 50, bytes: 32 * 1024 * 1024, batchBytes: 8 * 1024 * 1024 });
type CatalogPosition = { createdAt: string; id: string };
const catalogTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

/** Public readers only expose explicitly published, terminal successful metadata. */
@Injectable()
export class PortalPublicService {
  private readonly cursors=new PortalCursor();
  constructor(private readonly db:DbService,private readonly secrets:SecretService){}
  async tenants(query:Record<string,unknown>):Promise<any>{portalObject(query,['size','cursor','search']);const size=pageSize(query.size),search=portalText(query.search??'',128,false),binding=this.secrets.fingerprint({kind:'portal-tenants',size,search}),offset=this.cursors.decode(query.cursor,binding)?.offset??0;this.offset(offset);
    const rows=await this.db.query<any>(`SELECT s.id,s.cluster_id,s.workspace_id,s.slug,s.name,s.description,s.branding,s.registration_enabled,s.revision FROM portal_settings s JOIN clusters c ON c.id=s.cluster_id JOIN workspaces w ON w.id=s.workspace_id WHERE s.status='active' AND s.published=true AND c.deleted_at IS NULL AND c.status<>'disabled' AND w.status='active' AND ($1='' OR s.name ILIKE '%'||$1||'%') ORDER BY s.created_at DESC,s.id DESC LIMIT $2 OFFSET $3`,[search,size,offset]);return{items:rows.map(row=>({id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,slug:row.slug,name:row.name,description:row.description,branding:row.branding,registrationEnabled:row.registration_enabled,revision:row.revision})),size,total:null,nextCursor:rows.length===size?this.cursors.encode(binding,{offset:offset+size}):null};
  }
  async tenant(slug:string):Promise<any>{if(!/^[a-z0-9][a-z0-9-]{0,79}$/.test(slug))throw new BadRequestException({code:'INVALID_PORTAL_SLUG'});const row=await this.db.one<any>(`SELECT s.* FROM portal_settings s JOIN clusters c ON c.id=s.cluster_id JOIN workspaces w ON w.id=s.workspace_id WHERE s.slug=$1 AND s.status='active' AND s.published=true AND c.deleted_at IS NULL AND c.status<>'disabled' AND w.status='active'`,[slug]);if(!row)throw new NotFoundException({code:'PORTAL_NOT_FOUND'});return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,slug:row.slug,name:row.name,description:row.description,branding:row.branding,registrationEnabled:row.registration_enabled,revision:row.revision};}
  private offset(value:any){if(!Number.isInteger(value)||value<0||value>1000000)throw new BadRequestException({code:'INVALID_CURSOR'});}
  private async published(query:any):Promise<{clusterId:string;workspaceId:string}>{const scope=portalScope(query);if(!await this.db.one(`SELECT s.id FROM portal_settings s JOIN clusters c ON c.id=s.cluster_id JOIN workspaces w ON w.id=s.workspace_id WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.status='active' AND s.published AND c.deleted_at IS NULL AND c.status<>'disabled' AND w.status='active'`,[scope.clusterId,scope.workspaceId]))throw new NotFoundException({code:'PORTAL_NOT_FOUND'});return scope;}
  private publicationView(row:any){const proof=decodePublicationProof(row.publication_proof,this.secrets),info=proof.publicationInfo??{name:row.published_name,slug:row.slug,description:row.published_description,category:null},keyNames=proof.keyAuthPlugin?.config?.key_names;
    if(!Array.isArray(keyNames)||!keyNames.length||keyNames.some(name=>typeof name!=='string'||name.length>128))throw new NotFoundException({code:'PORTAL_PUBLICATION_NOT_FOUND'});
    return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,name:info.name,slug:info.slug,description:info.description,category:info.category,revision:row.revision,documentRevision:row.published_revision,status:'published',auth:{type:'key-auth',credentialScope:'application_publication',accessScope:'whole_service',keyNames}};}
  private catalogPosition(value:unknown):CatalogPosition|null {
    if(value===null)return null;
    if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='createdAt,id')throw new BadRequestException({code:'INVALID_CURSOR'});
    const position=value as CatalogPosition;
    if(typeof position.createdAt!=='string'||!catalogTimestamp.test(position.createdAt)||!Number.isFinite(Date.parse(position.createdAt)))throw new BadRequestException({code:'INVALID_CURSOR'});
    try{return{createdAt:position.createdAt,id:portalId(position.id)};}catch{throw new BadRequestException({code:'INVALID_CURSOR'});}
  }
  private catalogCandidates(scope:{clusterId:string;workspaceId:string},after:CatalogPosition|null,limit:number,bytes:number):Promise<any[]> {
    // Read only a prefix that fits the byte budget. The first oversized row is
    // returned without ciphertext so exhaustion cannot masquerade as EOF.
    return this.db.query<any>(`WITH candidates AS (
      SELECT p.id,p.cluster_id,p.workspace_id,p.slug,p.revision,p.published_revision,p.created_at,
        to_char(p.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_created_at,
        r.title AS published_name,r.description AS published_description,to_jsonb(proof) AS proof_row,
        (octet_length(proof.publication_proof_secret)+octet_length(r.title)+octet_length(r.description)+2048)::bigint AS row_bytes
      FROM portal_publications p
      JOIN portal_publication_revisions r ON r.cluster_id=p.cluster_id AND r.workspace_id=p.workspace_id AND r.publication_id=p.id AND r.revision=p.published_revision
      JOIN portal_publication_proofs proof ON proof.cluster_id=p.cluster_id AND proof.workspace_id=p.workspace_id AND proof.publication_id=p.id AND proof.publication_revision=p.published_revision AND proof.transport_scope=p.transport_scope
      JOIN workflow_executions e ON e.cluster_id=proof.cluster_id AND e.workspace_id=proof.workspace_id AND e.id=proof.workflow_execution_id AND e.workflow_id=proof.workflow_id AND e.plan_revision=proof.workflow_plan_revision AND e.plan_hash=proof.workflow_plan_hash
      JOIN workflows w ON w.cluster_id=proof.cluster_id AND w.workspace_id=proof.workspace_id AND w.id=proof.workflow_id AND w.kind='portal-publication' AND w.subject_type='portal_publications' AND w.subject_id=p.id
      WHERE p.cluster_id=$1 AND p.workspace_id=$2 AND p.state='published' AND e.state='succeeded' AND w.state='succeeded'
        AND ($3::timestamptz IS NULL OR (p.created_at,p.id)<($3::timestamptz,$4::uuid))
      ORDER BY p.created_at DESC,p.id DESC LIMIT $5
    ), measured AS (
      SELECT *,row_number() OVER(ORDER BY created_at DESC,id DESC) AS candidate_order,count(*) OVER() AS candidate_count,
        sum(row_bytes) OVER(ORDER BY created_at DESC,id DESC) AS prefix_bytes FROM candidates
    ) SELECT id,cluster_id,workspace_id,slug,revision,published_revision,cursor_created_at,published_name,published_description,row_bytes,candidate_count,
      prefix_bytes>$6 AS byte_exhausted,CASE WHEN prefix_bytes<=$6 THEN proof_row ELSE NULL END AS publication_proof
      FROM measured WHERE candidate_order<$5 AND (prefix_bytes<=$6 OR candidate_order=1)
      ORDER BY created_at DESC,id DESC`,[scope.clusterId,scope.workspaceId,after?.createdAt??null,after?.id??null,limit+1,bytes]);
  }
  async publications(query:Record<string,unknown>):Promise<any>{
    portalObject(query,['clusterId','workspaceId','size','cursor','search','category']);
    const scope=await this.published(query),size=pageSize(query.size),search=portalText(query.search??'',128,false),category=query.category===undefined?null:portalText(query.category,128);
    const filtered=category!==null||search!=='',binding=this.secrets.fingerprint({kind:'publications',version:2,scope,size,search,category});
    let position=this.catalogPosition(this.cursors.decode(query.cursor,binding));
    const items:any[]=[],maxBatches=filtered?PORTAL_CATALOG_SCAN_LIMITS.batches:1;
    let searchedRows=0,usedBytes=0,hasMore=false,scanIncomplete=false;
    for(let batch=0;batch<maxBatches;batch++){
      const limit=filtered?Math.min(PORTAL_CATALOG_SCAN_LIMITS.batchSize,PORTAL_CATALOG_SCAN_LIMITS.rows-searchedRows):size;
      const remainingBytes=PORTAL_CATALOG_SCAN_LIMITS.bytes-usedBytes;
      if(limit<=0||remainingBytes<=0){scanIncomplete=hasMore;break;}
      const rows=await this.catalogCandidates(scope,position,limit,Math.min(filtered?PORTAL_CATALOG_SCAN_LIMITS.batchBytes:PORTAL_CATALOG_SCAN_LIMITS.bytes,remainingBytes));
      if(!rows.length){hasMore=false;break;}
      const candidateCount=Number(rows[0].candidate_count);
      if(!Number.isInteger(candidateCount)||candidateCount<rows.length||candidateCount>limit+1)throw new ConflictException({code:'PORTAL_CATALOG_RESPONSE_INVALID'});
      let consumed=0;
      for(const row of rows){
        if(row.byte_exhausted===true){
          if(searchedRows===0)throw new ConflictException({code:'PORTAL_CATALOG_PROOF_LIMIT'});
          scanIncomplete=true;hasMore=true;break;
        }
        const bytes=Number(row.row_bytes);
        if(!Number.isSafeInteger(bytes)||bytes<=0||usedBytes+bytes>PORTAL_CATALOG_SCAN_LIMITS.bytes)throw new ConflictException({code:'PORTAL_CATALOG_RESPONSE_INVALID'});
        const view=this.publicationView(row);
        if(typeof view.name!=='string'||view.name.length>128||view.category!==null&&(typeof view.category!=='string'||view.category.length>128))throw new ConflictException({code:'PORTAL_PUBLICATION_PROOF_INVALID'});
        position=this.catalogPosition({createdAt:row.cursor_created_at,id:row.id});
        usedBytes+=bytes;searchedRows++;consumed++;
        if((category===null||view.category===category)&&(!search||view.name.toLowerCase().includes(search.toLowerCase())))items.push(view);
        if(items.length===size)break;
      }
      hasMore=scanIncomplete||consumed<candidateCount;
      if(items.length===size||scanIncomplete||!hasMore)break;
      if(batch===maxBatches-1||searchedRows===PORTAL_CATALOG_SCAN_LIMITS.rows)scanIncomplete=true;
    }
    await this.published(query);
    return{items,size,total:null,nextCursor:hasMore&&position?this.cursors.encode(binding,position):null,scanIncomplete,searchedRows};
  }
  async publication(id:string,query:Record<string,unknown>,document=false):Promise<any>{portalObject(query,['clusterId','workspaceId']);const scope=await this.published(query),row=await this.db.one<any>(`SELECT p.*,r.openapi_document,r.title AS published_name,r.description AS published_description,to_jsonb(proof) AS publication_proof FROM portal_publications p JOIN portal_publication_revisions r ON r.publication_id=p.id AND r.revision=p.published_revision JOIN portal_publication_proofs proof ON proof.publication_id=p.id AND proof.publication_revision=p.published_revision JOIN workflow_executions e ON e.id=proof.workflow_execution_id JOIN workflows w ON w.id=proof.workflow_id WHERE p.id=$1 AND p.cluster_id=$2 AND p.workspace_id=$3 AND p.state='published' AND e.state='succeeded' AND w.state='succeeded'`,[portalId(id),scope.clusterId,scope.workspaceId]);if(!row)throw new NotFoundException({code:'PORTAL_PUBLICATION_NOT_FOUND'});await this.published(query);return document?{document:row.openapi_document,publicationId:row.id,revision:row.published_revision}:{entity:this.publicationView(row)};}
  async pages(query:Record<string,unknown>):Promise<any>{portalObject(query,['clusterId','workspaceId','size','cursor']);const scope=await this.published(query),size=pageSize(query.size),binding=this.secrets.fingerprint({kind:'pages',scope,size}),offset=this.cursors.decode(query.cursor,binding)?.offset??0;this.offset(offset);const rows=await this.db.query<any>(`SELECT p.*,r.title AS published_title FROM portal_content p JOIN portal_content_revisions r ON r.content_id=p.id AND r.revision=p.published_revision LEFT JOIN workflows w ON w.id=p.workflow_id WHERE p.cluster_id=$1 AND p.workspace_id=$2 AND p.state='published' AND p.published_revision IS NOT NULL AND (p.workflow_id IS NULL OR w.state='succeeded') ORDER BY p.created_at DESC,p.id DESC LIMIT $3 OFFSET $4`,[scope.clusterId,scope.workspaceId,size,offset]);await this.published(query);return{items:rows.map(row=>({id:row.id,slug:row.slug,title:row.published_title,revision:row.revision,documentRevision:row.published_revision,state:'published'})),size,total:null,nextCursor:rows.length===size?this.cursors.encode(binding,{offset:offset+size}):null};}
  async page(slug:string,query:Record<string,unknown>):Promise<any>{portalObject(query,['clusterId','workspaceId']);if(!/^[a-z0-9][a-z0-9-]{0,79}$/.test(slug))throw new BadRequestException({code:'INVALID_PORTAL_SLUG'});const scope=await this.published(query),row=await this.db.one<any>(`SELECT p.*,r.markdown,r.title AS published_title FROM portal_content p JOIN portal_content_revisions r ON r.content_id=p.id AND r.revision=p.published_revision LEFT JOIN workflows w ON w.id=p.workflow_id WHERE p.slug=$1 AND p.cluster_id=$2 AND p.workspace_id=$3 AND p.state='published' AND (p.workflow_id IS NULL OR w.state='succeeded')`,[slug,scope.clusterId,scope.workspaceId]);if(!row)throw new NotFoundException({code:'PORTAL_PAGE_NOT_FOUND'});await this.published(query);return{entity:{id:row.id,slug:row.slug,title:row.published_title,revision:row.revision,documentRevision:row.published_revision,state:'published'},markdown:row.markdown};}
}
