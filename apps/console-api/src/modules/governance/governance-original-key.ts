import { ConflictException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import { governanceKey } from './governance-input';

export type GovernanceOriginalDomain='analysis'|'fix'|'promotion'|'metadata';
export function governanceOriginalLock(actorId:string,key:string):string{return `governance-original:${actorId}:${governanceKey(key)}`;}
/** One fixed namespace for governance registrations, including IAM-backed
 * metadata. Existing records remain authoritative; this performs no replay. */
export async function assertGovernanceOriginalDomain(db:DbService,actorId:string,key:string,expected:GovernanceOriginalDomain):Promise<void>{
 const records=await db.query<{domain:GovernanceOriginalDomain}>(`SELECT 'analysis'::text AS domain FROM governance_runs WHERE actor_id=$1 AND idempotency_key=$2
  UNION ALL SELECT 'fix'::text FROM governance_fix_requests WHERE actor_id=$1 AND idempotency_key=$2
  UNION ALL SELECT 'promotion'::text FROM governance_promotions WHERE actor_id=$1 AND idempotency_key=$2
  UNION ALL SELECT 'metadata'::text FROM governance_metadata_requests WHERE actor_id=$1 AND idempotency_key=$2
  UNION ALL SELECT 'metadata'::text FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2`,[actorId,governanceKey(key)]);
 if(records.length>1||records.some(row=>row.domain!==expected))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'原请求键已绑定其他治理操作，请核验原回执'});
}
