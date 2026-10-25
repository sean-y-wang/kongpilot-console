import { BadGatewayException, BadRequestException, ConflictException } from '@nestjs/common';
import type { KongService } from '../../infrastructure/kong/kong.service';
import { CREDENTIAL_KINDS, type CredentialKind } from '../entities/entities.types';
import type { GraphNode } from '../recycle-bin/graph-capturer.service';

export interface CredentialClosureBudget { pages:number; records:number; bytes?:number }
export interface CredentialClosureLimits { maxPages:number; maxRecords:number }
export interface CredentialClosureSummary { consumers:number; credentials:number; pages:number; records:number }
export type CredentialClosureNode = Pick<GraphNode,'type'|'id'|'data'>;

const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const kinds=new Set<string>(CREDENTIAL_KINDS);
const hardLimits={maxPages:100,maxRecords:10000};
function changed():never {
  throw new ConflictException({code:'MIGRATION_CHILDREN_CHANGED',message:'Consumer 的凭证集合或所属关系在计划生成后发生变化，尚未执行迁移写入'});
}
function limit():never {
  throw new ConflictException({code:'WORKSPACE_MIGRATION_CAPTURE_LIMIT',message:'凭证闭包检查的分页或记录预算已耗尽，请缩小迁移范围，尚未执行迁移写入'});
}
function invalidPlan():never {
  throw new BadGatewayException({code:'MIGRATION_PLAN_INVALID',message:'迁移计划包含无效的 Consumer 凭证归属'});
}
function invalidResponse():never {
  throw new BadGatewayException({code:'KONG_INVALID_MIGRATION_CHILDREN',message:'网关凭证集合响应无效，无法核验迁移闭包'});
}
function parentId(value:unknown):string|undefined {
  if(typeof value==='string')return uuid.test(value)?value:undefined;
  if(value&&typeof value==='object'){
    const id=(value as {id?:unknown}).id;
    return typeof id==='string'&&uuid.test(id)?id:undefined;
  }
  return undefined;
}

/**
 * Revalidates the full credential closure of Consumers being moved. Call under the
 * same cluster mutation lock before any PATCH, and again before reconciliation.
 * Only IDs and Consumer relations are inspected; credential material is not read,
 * copied, restored, logged, or included in the result. Pagination counts are shared
 * with the caller's aggregate budget; bytes are deliberately left untouched.
 */
export async function assertMigrationConsumerCredentialClosure(
  kong:Pick<KongService,'list'>,clusterId:string,plannedNodes:readonly CredentialClosureNode[],
  budget:CredentialClosureBudget,limits:CredentialClosureLimits=hardLimits,
):Promise<CredentialClosureSummary>{
  if(!Array.isArray(plannedNodes)||plannedNodes.length>hardLimits.maxRecords)invalidPlan();
  if(!Number.isInteger(budget.pages)||budget.pages<0||!Number.isInteger(budget.records)||budget.records<0
    ||!Number.isInteger(limits.maxPages)||limits.maxPages<1||limits.maxPages>hardLimits.maxPages
    ||!Number.isInteger(limits.maxRecords)||limits.maxRecords<1||limits.maxRecords>hardLimits.maxRecords){
    throw new BadRequestException({code:'INVALID_MIGRATION_CHILDREN_BUDGET',message:'凭证闭包检查预算无效'});
  }
  const consumers=new Map<string,Map<CredentialKind,Set<string>>>();
  for(const node of plannedNodes){
    if(node.type!=='consumers')continue;
    if(typeof node.id!=='string'||!uuid.test(node.id)||consumers.has(node.id))invalidPlan();
    consumers.set(node.id,new Map(CREDENTIAL_KINDS.map(kind=>[kind,new Set<string>()])));
  }
  for(const node of plannedNodes){
    if(!kinds.has(node.type))continue;
    const owner=parentId(node.data?.consumer);
    if(typeof node.id!=='string'||!uuid.test(node.id)||!owner)invalidPlan();
    const expected=consumers.get(owner)?.get(node.type as CredentialKind);
    // Independently selected credentials whose Consumer is a shared reference are
    // checked by the caller's fresh-object validation, rather than moving its closure.
    if(!expected)continue;
    if(expected.has(node.id))invalidPlan();
    expected.add(node.id);
  }
  const initialPages=budget.pages,initialRecords=budget.records;
  let credentials=0;
  for(const [consumerId,byKind] of consumers){
    for(const kind of CREDENTIAL_KINDS){
      const expected=byKind.get(kind)!,seen=new Set<string>(),cursors=new Set<string>();
      // Native signed cursors bind the query size. Keep it stable for this
      // collection rather than changing it as the aggregate budget decreases.
      const size=Math.min(100,limits.maxRecords-budget.records);
      let cursor:string|undefined;
      do{
        if(budget.pages>=limits.maxPages||size<1||budget.records+size>limits.maxRecords)limit();
        // Charge a transport attempt even if the call fails; budgets never refund.
        budget.pages++;
        const page=await kong.list(clusterId,`/consumers/${consumerId}/${kind}`,{size},cursor,'workspace-migration-credential-closure');
        if(!page||!Array.isArray(page.items)||page.items.length>size
          ||page.nextCursor!==null&&(typeof page.nextCursor!=='string'||!page.nextCursor||page.nextCursor.length>8192))invalidResponse();
        budget.records+=page.items.length;
        if(budget.records>limits.maxRecords)limit();
        for(const credential of page.items){
          if(!credential||typeof credential.id!=='string'||!uuid.test(credential.id))invalidResponse();
          if(parentId(credential.consumer)!==consumerId||!expected.has(credential.id)||seen.has(credential.id))changed();
          seen.add(credential.id);
        }
        if(page.nextCursor&&cursors.has(page.nextCursor)){
          throw new ConflictException({code:'WORKSPACE_MIGRATION_PAGINATION_LOOP',message:'凭证闭包检查收到重复分页游标，尚未执行迁移写入'});
        }
        if(page.nextCursor)cursors.add(page.nextCursor);
        cursor=page.nextCursor??undefined;
      }while(cursor);
      if(seen.size!==expected.size)changed();
      credentials+=seen.size;
    }
  }
  return {consumers:consumers.size,credentials,pages:budget.pages-initialPages,records:budget.records-initialRecords};
}
