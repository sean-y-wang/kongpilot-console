import{sha256}from'./m8-harness.mjs';
export const M8_TERMINAL_CAPTURE_ARCHIVE=Object.freeze({snapshotId:'e4eb9135-719f-4bfa-a2aa-66d07a3addaf',jobId:'a109c9ef-2363-4596-bd77-fe8e62efed91',
 cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',actorId:'b5f796fa-9515-47de-9123-89a903a48224',
 proofPath:'artifacts/M8/own-snapshot-lifecycle-readonly-diagnosis.json',proofSha256:'48d0deebaff52ee0baa9d662b35a780e3d5884a65a4df644180be4a1cdbb23ee',
 prefix98:'2467d175f01c85c818d2d462cbe11f78af3724c66851f9a80d126f40259767aa'});
export function assertM8KnownTerminalCaptureCleanup(row,selection,actor,reference,proofBytes){
 const c=M8_TERMINAL_CAPTURE_ARCHIVE;
 if(sha256(proofBytes)!==c.proofSha256||sha256(JSON.stringify(reference.requests.slice(0,98)))!==c.prefix98)throw Error('M8_EXACT_TERMINAL_CAPTURE_PROVENANCE_REQUIRED');
 const proof=JSON.parse(proofBytes),item=proof.sql?.scopes?.find(s=>s.clusterId===c.cid&&s.workspaceId===c.wid)?.items?.find(s=>s.id===c.snapshotId);
 if(proof.actual!==true||proof.sql?.ok!==true||proof.sql.nonOwnerReadOnly!==true||proof.originalRequestsCount!==98||proof.originalRequestsSha256!==c.prefix98)throw Error('M8_EXACT_TERMINAL_CAPTURE_PROVENANCE_REQUIRED');
 return assertM8KnownTerminalCaptureRow(row,selection,actor,item);
}
// This checks only safe structure. The cleanup executor always calls the
// wrapper above, which independently verifies the immutable actual proof.
export function assertM8KnownTerminalCaptureRow(row,selection,actor,item){
 const c=M8_TERMINAL_CAPTURE_ARCHIVE;
 if(row.id!==c.snapshotId||row.clusterId!==c.cid||row.workspaceId!==c.wid||row.state!=='capturing'||row.currentVersion!==null||row.revision!==1||row.capabilities?.delete!==true
  ||row.completeness!==null||row.objectCount!==0||row.pageCount!==0||row.recordCount!==0||row.byteCount!==0
  ||selection.area.cid!==c.cid||selection.area.wid!==c.wid||selection.kind!=='workspace'||selection.roots.length!==0||row.scopeKind!=='workspace'||row.rootIds?.length!==0||actor.user.id!==c.actorId
  ||item?.state!=='capturing'||item.revision!==1||item.currentVersion!==null||!item.sameOwner||item.versions.length!==0||item.jobs.length!==1||item.materials.length!==1
  ||item.jobs[0].id!==c.jobId||item.jobs[0].kind!=='capture'||item.jobs[0].state!=='failed'||item.jobs[0].error_code!=='CONFIGURATION_SCHEMA_FIELD_MISMATCH'
  ||!item.jobs[0].same_owner||!item.jobs[0].same_transport||!item.jobs[0].progress_matches||item.jobs[0].scope_kind!=='workspace'||item.jobs[0].root_ids.length!==0
  ||item.materials[0].job_id!==c.jobId||item.materials[0].state!=='available'||item.materials[0].has_wrapped_secret!==true||item.materials[0].artifact_kind!=='snapshot')
  throw Error('M8_ONLY_EXACT_FAILED_UNSEALED_CAPTURE_MAY_SOFT_ARCHIVE');
 return{snapshotId:c.snapshotId,jobId:c.jobId,cid:c.cid,wid:c.wid,proofPath:c.proofPath,proofSha256:c.proofSha256,terminalJobState:'failed',unsealed:true,restoreAllowed:false,purgeUsed:false};
}
