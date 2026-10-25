import { canonicalId, scopeQuery } from '../api/workspace-scope';
import type { ApiError } from '../api/client';
export function isToolboxKind(value:unknown):value is 'toolbox'|'drafts'{return value==='toolbox'||value==='drafts';}
export function toolboxReceiptPath(recovery:NonNullable<ApiError['recovery']>):string{
  const cid=canonicalId(recovery.clusterId),wid=canonicalId(recovery.workspaceId),key=canonicalId(recovery.idempotencyKey);
  if(!cid||!wid||!key||!isToolboxKind(recovery.kind)||recovery.domain!==undefined)throw new Error('原操作范围或幂等键无效');
  return scopeQuery(`/clusters/${cid}/${recovery.kind==='toolbox'?'toolbox/operations':'drafts/operations'}/by-key/${key}`,cid,wid);
}
export function toolboxReceiptComplete(value:any,recovery:NonNullable<ApiError['recovery']>,actorId?:string):boolean{
  if(!value||!actorId||value.actorId!==actorId||value.clusterId!==recovery.clusterId||value.workspaceId!==recovery.workspaceId||value.idempotencyKey!==recovery.idempotencyKey||!canonicalId(value.id)||value.state!=='succeeded')return false;
  return recovery.kind==='toolbox'?value.kind==='cache-invalidate'&&value.remoteStarted===true&&value.remoteCompleted===true:recovery.kind==='drafts'&&value.kind==='draft-metadata'&&value.metadataCommitted===true&&value.remoteStarted===false&&value.remoteCompleted===false;
}
