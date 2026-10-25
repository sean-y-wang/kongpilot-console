import { BadGatewayException, BadRequestException, ConflictException } from '@nestjs/common';
import type { KongService } from './kong.service';
import type { SecretService } from '../secret.service';
import { immutableJson } from './immutable-json';
import type { TargetLookupBudget } from './effective-target';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const record=(v:any):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const invalid=()=>new BadGatewayException({code:'TARGET_DISABLED_READBACK_INVALID',message:'零权重 Target 历史或有效集合与原响应不一致，请核验原操作，勿重复提交'});
const changed=()=>new ConflictException({code:'TARGET_DISABLED_READBACK_CHANGED',message:'零权重 Target 回读期间历史或有效集合发生变化，请核验原操作，勿重复提交'});
const exhausted=()=>new ConflictException({code:'TARGET_DISABLED_READBACK_LIMIT',message:'零权重 Target 核验超过有界分页或数据预算，请核验原操作，勿重复提交'});
const ceilings={maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,pageSize:100};
export interface DisabledTargetReadbackOptions {maxPages?:number;maxRecords?:number;maxBytes?:number;pageSize?:number;}
export interface DisabledTargetReadbackObservation{
 /** A real GET history row, or null when Kong's native DAO removed the whole
  * disabled address history. Never substitute the POST body for a GET row. */
 observedTarget:any|null;knownOriginalResponse:any;historyRetention:'retained'|'native-pruned';
 originalResultHmac:string;observedHistoryHmac:string|null;historyAddressAbsent:boolean;currentEffectiveAbsent:true;
 historySnapshotHmac:string;effectiveSnapshotHmac:string;budget:TargetLookupBudget;
}
const tags=(v:unknown):string[]|null=>v==null?[]:Array.isArray(v)&&v.every(t=>typeof t==='string'&&!!t)&&new Set(v).size===v.length?[...v].sort():null;

/** Future-operation readback only. The fixed Mutation caller already holds the
 * genuine current actor/operation/read scope and an observed native result.
 * This supplies no permit, Native201 receipt, repair, replay or outcome rewrite.
 * Kong1.5 zero-weight rows are excluded from effective /targets. DAO
 * clean_history() may remove every row for the disabled address, including
 * the new zero row, when >90% of upstream history can be cleaned. This is
 * native retention behavior, not another Console request or a GET201 receipt.
 * Both retained and pruned cases require two stable complete collection EOFs. */
export async function disabledTargetReadback(kong:Pick<KongService,'list'>,secrets:Pick<SecretService,'fingerprint'>,
  input:Readonly<{clusterId:string;upstreamId:string;approvedBody:unknown;nativeResult:unknown}>,options:DisabledTargetReadbackOptions={}):Promise<DisabledTargetReadbackObservation>{
  const frozen=immutableJson(input),result=frozen.nativeResult,body=frozen.approvedBody;
  if(!uuid.test(frozen.clusterId??'')||!uuid.test(frozen.upstreamId??'')||!record(result)||!record(body)||!uuid.test(result.id??'')
    ||result.upstream?.id!==frozen.upstreamId||body.id!==undefined&&body.id!==result.id||body.weight!==0||result.weight!==0
    ||typeof body.target!=='string'||!body.target||body.target.length>1024||result.target!==body.target
    ||!Number.isFinite(result.created_at)||result.created_at<=0||Object.keys(body).some(k=>!['id','target','weight','tags'].includes(k))
    ||tags(body.tags)===null||tags(result.tags)===null||secrets.fingerprint(tags(body.tags))!==secrets.fingerprint(tags(result.tags)))throw invalid();
  const resultHmac=secrets.fingerprint(result),bodyHmac=secrets.fingerprint(body),limits={...ceilings};
  for(const key of Object.keys(ceilings)as Array<keyof typeof ceilings>){const value=options[key]??ceilings[key];
    if(!Number.isInteger(value)||value<0||value>ceilings[key]||key==='pageSize'&&value===0)throw new BadRequestException({code:'TARGET_DISABLED_READBACK_BUDGET_INVALID'});limits[key]=value;}
  if(!limits.maxPages||!limits.maxRecords||!limits.maxBytes)throw exhausted();
  const size=Math.min(limits.pageSize,limits.maxRecords),budget:TargetLookupBudget={pages:0,records:0,bytes:0};
  const base=`/upstreams/${frozen.upstreamId}/targets`;
  const collection=async(history:boolean,phase:number):Promise<any[]>=>{
    const rows:any[]=[],seenIds=new Set<string>(),seenAddresses=new Set<string>(),seenTimes=new Set<string>(),seenCursors=new Set<string>();let cursor:string|undefined;
    do{
      if(budget.pages>=limits.maxPages||budget.records+size>limits.maxRecords)throw exhausted();
      const page=await kong.list(frozen.clusterId,history?`${base}/all`:base,{size},cursor,`disabled-target-readback:${frozen.upstreamId}:${result.id}:${phase}`);
      if(!Array.isArray(page?.items)||page.items.length>size||page.size!==size||page.console_permission_projection
        ||page.nextCursor!==null&&(typeof page.nextCursor!=='string'||!page.nextCursor))throw invalid();
      budget.pages++;budget.records+=page.items.length;budget.bytes+=Buffer.byteLength(JSON.stringify(page.items));if(budget.bytes>limits.maxBytes)throw exhausted();
      for(const row of page.items){if(!record(row)||!uuid.test(row.id??'')||seenIds.has(row.id.toLowerCase())||typeof row.target!=='string'||!row.target||row.target.length>1024
        ||row.upstream?.id!==frozen.upstreamId||!Number.isInteger(row.weight)||row.weight<(history?0:1)||row.weight>1000||!Number.isFinite(row.created_at)||row.created_at<=0
        ||tags(row.tags)===null||!history&&seenAddresses.has(row.target))throw invalid();
        const time=JSON.stringify([row.target,row.created_at]);if(history&&seenTimes.has(time))throw changed();
        seenIds.add(row.id.toLowerCase());seenAddresses.add(row.target);seenTimes.add(time);rows.push(row);}
      if(page.nextCursor){if(seenCursors.has(page.nextCursor))throw invalid();seenCursors.add(page.nextCursor);}cursor=page.nextCursor??undefined;
    }while(cursor);
    return rows;
  };
  const verifyHistory=(rows:any[]):'retained'|'native-pruned'=>{
    const sameId=rows.filter(row=>row.id.toLowerCase()===result.id.toLowerCase()),sameAddress=rows.filter(row=>row.target===result.target);
    // No same-address rows is a distinct current absence observation. The
    // authentic POST result remains an original response; it is never forged
    // into a history row. A reused UUID at a foreign address still blocks.
    if(!sameAddress.length){if(sameId.length)throw invalid();return'native-pruned';}
    if(sameId.length!==1||secrets.fingerprint(sameId[0])!==resultHmac||!sameAddress.length)throw invalid();
    const latest=Math.max(...sameAddress.map(row=>row.created_at)),latestRows=sameAddress.filter(row=>row.created_at===latest);
    // A timestamp tie has no reliable current UUID; never choose by UUID,
    // page position or the mere presence of the original POST response.
    if(latestRows.length!==1||latestRows[0].id!==result.id||latest!==result.created_at)throw changed();return'retained';
  };
  const history1=await collection(true,1),retention1=verifyHistory(history1);
  const verifyEffective=(rows:any[])=>{if(rows.some(row=>row.target===result.target||row.id.toLowerCase()===result.id.toLowerCase()))throw changed();};
  const effective1=await collection(false,2);verifyEffective(effective1);
  const history2=await collection(true,3),retention2=verifyHistory(history2);
  const effective2=await collection(false,4);verifyEffective(effective2);
  const fingerprint=(rows:any[])=>secrets.fingerprint([...rows].sort((a,b)=>a.id.localeCompare(b.id)));
  if(retention1!==retention2||fingerprint(history1)!==fingerprint(history2)||fingerprint(effective1)!==fingerprint(effective2)
    ||secrets.fingerprint(frozen.nativeResult)!==resultHmac||secrets.fingerprint(frozen.approvedBody)!==bodyHmac)throw changed();
  const observedTarget=retention2==='retained'?history2.find(row=>row.id===result.id)!:null;
  return immutableJson({observedTarget,knownOriginalResponse:result,historyRetention:retention2,originalResultHmac:resultHmac,
    observedHistoryHmac:observedTarget?secrets.fingerprint(observedTarget):null,historyAddressAbsent:retention2==='native-pruned',currentEffectiveAbsent:true,
    historySnapshotHmac:fingerprint(history2),effectiveSnapshotHmac:fingerprint(effective2),budget});
}
