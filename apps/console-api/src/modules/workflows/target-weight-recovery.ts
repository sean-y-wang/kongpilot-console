import {ConflictException} from '@nestjs/common';
import type {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {decodeTag} from '../../infrastructure/kong/tags';
import type {EntityChangeOperation} from '../entities/entity-change.types';
import type {EntityChangeBaselineObject} from './entity-change-execution-facts.types';

const changed=(code='ENTITY_CHANGE_RECOVERY_TARGET_CHANGED')=>new ConflictException({code,message:'Target 当前有效配置与原成功回执不一致，请重新核验；不会重发旧操作'});
const object=(value:any)=>!!value&&typeof value==='object'&&!Array.isArray(value);
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const tags=(value:any)=>value==null?[]:Array.isArray(value)&&value.every(tag=>typeof tag==='string')?[...value].sort():null;
/** Pure recovery intent builder. The caller must separately verify original
 * private baseline/actual 201 receipt, current grants, stable bounded current
 * EOF (including disabled-history observation), and zero unknown outcomes.
 * It provides no receipt, permit, replay or authorization to reuse an ID. */
export function targetWeightRecoveryOperation(original:Readonly<EntityChangeBaselineObject>,
  packet:Readonly<{nativeId:string;originalNativeId:string;parentId:string;mutationAction:string;nativeStatus:number}>,
  nativeResult:unknown,approvedBody:unknown,currentTarget:unknown|null,secrets:Pick<SecretService,'fingerprint'>):EntityChangeOperation{
  const before=original.before as any,restore=original.restorePayload as any,result=nativeResult as any,body=approvedBody as any,current=currentTarget as any;
  if(!original.affected||!original.present||original.nativeType!=='targets'||original.recovery!=='complete'||!object(restore)||!object(before)
    ||!uuid.test(packet.nativeId)||!uuid.test(packet.originalNativeId)||!uuid.test(packet.parentId)||packet.nativeId===packet.originalNativeId
    ||packet.mutationAction!=='update'||packet.nativeStatus!==201||original.nativeId!==packet.originalNativeId||original.parentId!==packet.parentId
    ||before.id!==packet.originalNativeId||restore.id!==packet.originalNativeId||before.upstream?.id!==packet.parentId
    ||typeof before.target!=='string'||!before.target||restore.target!==before.target||!Number.isInteger(restore.weight)||restore.weight<1||restore.weight>1000
    ||restore.weight!==before.weight||tags(before.tags)===null||tags(restore.tags)===null||secrets.fingerprint(tags(restore.tags))!==secrets.fingerprint(tags(before.tags))
    ||!object(body)||!object(result)||body.id!==packet.nativeId||result.id!==packet.nativeId||body.target!==before.target||result.target!==before.target
    ||result.upstream?.id!==packet.parentId||!Number.isInteger(body.weight)||body.weight<0||body.weight>1000||result.weight!==body.weight
    ||tags(body.tags)===null||tags(result.tags)===null||secrets.fingerprint(tags(body.tags))!==secrets.fingerprint(tags(result.tags)))throw changed('ENTITY_CHANGE_RECOVERY_TARGET_RECEIPT_INVALID');
  if(body.weight===0){if(current!==null)throw changed();}
  else if(!object(current)||current.id!==packet.nativeId||secrets.fingerprint(current)!==secrets.fingerprint(result))throw changed();
  const originalTags=tags(restore.tags);if(originalTags===null)throw changed('ENTITY_CHANGE_RECOVERY_TARGET_BASELINE_INVALID');
  const restoredBody={target:restore.target,weight:restore.weight,tags:originalTags.map(decodeTag).filter(tag=>!tag.startsWith('workspace:'))};
  // Kong 1.5 appends a fresh physical UUID. A native-pruned zero tombstone
  // means current-before is genuine absence, therefore this NEW intent uses
  // create. The historic original UUID remains only in the baseline/link.
  return immutableJson(current===null?{kind:'target',action:'create',upstreamId:packet.parentId,body:restoredBody}
    :{kind:'target',action:'weight',upstreamId:packet.parentId,targetId:current.id,body:restoredBody}) as EntityChangeOperation;
}
