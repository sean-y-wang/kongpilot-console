import { sha256 } from './m8-harness.mjs';

export const M8_EXPORT_COMMIT_CHECKPOINT = Object.freeze({
  packetCount:61, prefixSha256:'923ba60cbd0dc61133236f1eabe91752e9f5bd92be625199f60f31ea8f18037c',
  packetSha256:'ff9b13f3ccecb46f3d2e58457128952a7fb8dcb58c9e0769013d9d4e4f731f1f',
  failurePath:'artifacts/M8/security-live-schema-tls-continuation.json', failureSha256:'c4d319c3341c3683edf72c8c21097fed5f7ccd83ad48da65d8cc1eb92fa81ab0',
  proofPath:'artifacts/M8/original-export-console-readonly-diagnostic.json', proofSha256:'dc450cc3051284d5fa1cbd8ed032f1aa544ba3488ef3af08c78fe2688acad761',
  key:'aa7cf753-4fc4-4172-a746-f7dd2c6d63b9', requestId:'b069d2c8-9537-4838-a3d5-795dc9c170af',
  cid:'dff45535-ed8d-4851-b7a6-6376feac7f59', wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',
  actorId:'b5f796fa-9515-47de-9123-89a903a48224', sessionId:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',
  snapshotId:'2fb9b46e-afb3-442d-b06d-e9112603e00f', captureJobId:'e44dcbdb-793b-4ffc-bae1-aeb8038c1c7e',
  jobId:'b31f3e5d-5a8a-49a2-9a08-983273514fc3', exportId:'94f13606-93c8-4718-9345-ce34da42da88',
  confirmationName:'m8-security-9f6e2a3e verified-TLS baseline', bodySha256:'db885019dbfd1ed64f3f55821ab35c51028b93d4554985d825d1cc4ee3bbb0ae',
  authClosurePath:'artifacts/M8/original-export-normal-session-maintenance-readonly-closure.json',authClosureSha256:'6079be64c5fd17a52b2ee7a38e9b1417a8c277e994eafb684d2aa96a6b9c33d0',
  maintainedPrefixSha256:'ae7846a6526f83cd04d026d36948e573916c93041204b59d4c12c769f6fc7c3d',authPacketSha256:'2d249f136802c2b5fcfb2fba626351fd21b7296a7b27d13bbc3a2e1ea6a42f92',
});
function requireTrue(value) { if(!value) throw Error('M8_EXACT_COMMITTED_EXPORT_CHECKPOINT_REQUIRED'); }
/** This is a single historical transport failure with a subsequently proven
 * committed export. It does not classify arbitrary HTTP500/absent receipts. */
export function assertOriginalM8ExportPacket(packet) {
  const c=M8_EXPORT_COMMIT_CHECKPOINT;
  requireTrue(packet?.index===60&&packet.key===c.key&&packet.requestId===c.requestId
    &&packet.method==='POST'&&packet.path===`/api/v1/clusters/${c.cid}/snapshots/${c.snapshotId}/export`
    &&packet.query===`?workspaceId=${c.wid}`&&packet.clusterId===c.cid&&packet.workspaceId===c.wid
    &&packet.actorId===c.actorId&&packet.sessionId===c.sessionId&&packet.state==='response_observed'
    &&packet.status===500&&packet.errorCode==='INTERNAL_ERROR'&&packet.responseData===null
    &&packet.bodySha256===c.bodySha256&&sha256(JSON.stringify(packet.body))===c.bodySha256
    &&packet.body.mode==='deployment'&&packet.body.confirmed===true&&packet.body.confirm_name===c.confirmationName
    &&Object.keys(packet.body).length===3&&packet.headers?.['X-Idempotency-Key']===c.key
    &&typeof packet.headers.Cookie==='string'&&packet.headers.Cookie.includes('kongos_access=')
    &&typeof packet.headers['X-CSRF-Token']==='string'&&packet.headers['X-CSRF-Token'].length>0);
  return packet;
}
export function assertM8CommittedExportCheckpoint(r, failureBytes, proofBytes, authClosureBytes) {
  const c=M8_EXPORT_COMMIT_CHECKPOINT,original=r?.requests?.[60];
  requireTrue(sha256(failureBytes)===c.failureSha256&&sha256(proofBytes)===c.proofSha256
    &&authClosureBytes&&sha256(authClosureBytes)===c.authClosureSha256);
  const failure=JSON.parse(failureBytes),proof=JSON.parse(proofBytes),authClosure=JSON.parse(authClosureBytes),authPacket=r.requests[61];
  requireTrue(r.version===1&&r.milestone==='M8'&&r.testTag==='m8-security-9f6e2a3e'
    &&r.phase==='stopped-known-original-export-expired'&&r.inFlight==null&&!r.exportCommitContinuation&&!r.baseline
    &&r.schemaTlsContinuation?.state==='started'&&r.oauthTlsProof?.state==='completed'
    &&r.requests.length===62&&sha256(JSON.stringify(r.requests))===c.maintainedPrefixSha256
    &&sha256(JSON.stringify(r.requests.slice(0,c.packetCount)))===c.prefixSha256
    &&sha256(JSON.stringify(original))===c.packetSha256&&failure.allPassed===false&&failure.failed===1&&failure.unknownWrites===0
    &&r.sessions.admin.user.id===c.actorId&&r.sessions.admin.sid===c.sessionId
    &&r.scopes.direct.cid===c.cid&&r.scopes.direct.wid===c.wid
    &&!r.requests.some(p=>['prepared','response_unknown'].includes(p.state))
    &&!(r.proxyChecks??[]).some(p=>p.method==='POST'&&['prepared','response_unknown'].includes(p.state))
    &&!(r.cliIntents??[]).some(p=>['prepared','response_unknown'].includes(p.state)));
  requireTrue(authClosure.allPassed===true&&authClosure.authWrites===1&&authClosure.newAuthWritesInClosure===0
    &&authClosure.businessWrites===0&&authClosure.nativeAdminRequests===0&&authClosure.sameActor===true&&authClosure.sameSID===true
    &&r.exportAuthMaintenance?.state==='completed'&&r.exportAuthMaintenance.reportSha256===c.authClosureSha256
    &&sha256(JSON.stringify(authPacket))===c.authPacketSha256&&authPacket.path==='/api/v1/auth/refresh'&&authPacket.status===201
    &&authPacket.actorId===c.actorId&&authPacket.sessionId===c.sessionId&&authPacket.state==='response_observed'
    &&r.originalExpiredExportReceipt?.expired===true&&r.originalExpiredExportReceipt.downloadAllowed===false);
  // The immutable diagnostic is an observation, never a substitute for the
  // current protected original-key receipt read performed by the caller.
  const proven=proof.sql?.rows?.[0];
  requireTrue(proof.consoleSelectOnly===true&&proof.originalRequestJournalUnchanged===true
    &&proof.businessWrites===0&&proof.authenticationWrites===0&&proof.nativeAdminRequests===0
    &&proof.sql?.allPassed===true&&proof.sql.consoleNonownerReadOnly===true&&proof.sql.rows.length===1
    &&proven.id===c.jobId&&proven.kind==='export'&&proven.state==='succeeded'&&proven.error_code===null
    &&proven.cluster_matches===true&&proven.workspace_matches===true&&proven.actor_matches===true&&proven.original_sid_matches===true
    &&proven.export_id===c.exportId&&proof.sql.counts.exports===1&&proof.sql.counts.export_materials===1&&proof.sql.counts.available_export_materials===1);
  assertOriginalM8ExportPacket(original);
  return c;
}
export function assertM8HistoricalCommittedExportReceipt(receipt, actor, area) {
  const c=M8_EXPORT_COMMIT_CHECKPOINT;
  requireTrue(actor.user.id===c.actorId&&area.cid===c.cid&&area.wid===c.wid
    &&receipt?.domain==='configuration'&&receipt.durable===true&&receipt.idempotencyKey===c.key
    &&receipt.id===c.jobId&&receipt.jobId===c.jobId&&receipt.kind==='export'&&receipt.state==='succeeded'
    &&receipt.actorId===c.actorId&&receipt.clusterId===c.cid&&receipt.workspaceId===c.wid
    &&receipt.originalScope?.clusterId===c.cid&&receipt.originalScope?.workspaceId===c.wid
    &&receipt.exportId===c.exportId&&receipt.sourceSnapshotId===c.snapshotId&&receipt.mode==='deployment'
    &&Number.isInteger(receipt.exportRevision)&&receipt.exportRevision>0&&typeof receipt.capabilities?.download==='boolean');
  return receipt;
}
export function assertM8RecoveredExportReceipt(receipt, actor, area) {
  assertM8HistoricalCommittedExportReceipt(receipt,actor,area);
  requireTrue(actor.sid===M8_EXPORT_COMMIT_CHECKPOINT.sessionId&&receipt.capabilities.download===true);
  return receipt;
}
/** Later audit closure may include this committed write separately from the
 * HTTP-success denominator, while preserving the original failed packet. */
export function isM8ProvenCommittedExportPacket(r,packet,index) {
  const c=M8_EXPORT_COMMIT_CHECKPOINT,marker=r.exportCommitContinuation;
  if(index!==60||!marker?.recoveredReceipt)return false;
  requireTrue(marker.originalPrefixCount===c.packetCount&&marker.originalPrefixSha256===c.prefixSha256
    &&marker.originalPacketSha256===c.packetSha256&&marker.originalFailureSha256===c.failureSha256
    &&marker.committedExportReadonlyProofSha256===c.proofSha256&&marker.originalHTTPStatus===500&&marker.exportPOSTReplayed===false
    &&sha256(JSON.stringify(r.requests.slice(0,c.packetCount)))===c.prefixSha256&&sha256(JSON.stringify(packet))===c.packetSha256);
  assertOriginalM8ExportPacket(packet);
  const operations=r.configurationOperations.filter(v=>v.key===c.key);
  requireTrue(operations.length===1&&operations[0].state==='succeeded'&&operations[0].recoveryReadOnly===true&&operations[0].originalHTTPFailureRetained===true);
  assertM8HistoricalCommittedExportReceipt(operations[0].receipt,{user:{id:c.actorId},sid:c.sessionId},{cid:c.cid,wid:c.wid});
  return true;
}
