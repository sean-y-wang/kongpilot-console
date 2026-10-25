import{readFileSync,renameSync,existsSync}from'node:fs';
import{ProductionHarness,productionDigest}from'./lib/production-http-harness.mjs';
import{PRODUCTION_UI_REFERENCE,PRODUCTION_UI_JOURNAL,readProductionUiReference,durableProductionJson}from'./lib/production-ui-storage.mjs';
import{validateProductionHandoff}from'./lib/production-ui-journal.mjs';

const jbytes=readFileSync(PRODUCTION_UI_JOURNAL),j=JSON.parse(jbytes),rbytes=readFileSync('artifacts/production/ui-lifecycle.json'),r=JSON.parse(rbytes),historyPath='/tmp/kongos-production-ui-original-handoff.json',historyBytes=readFileSync(historyPath),reference=readProductionUiReference();
if(productionDigest(jbytes)!=='f25ce87d7151d9b7430749d042a9db8be80f20d35f852bd96f4907040ae6ff38'||productionDigest(rbytes)!=='853aaf667778517a932fae84c1fe0ad9c45825b28bbf3a7299d3738f80beb9d0'
 ||productionDigest(historyBytes)!=='b13737d0b2ce4eee274aa53845609624624ace2740d14561f297ea2017a6a5db'||j.attempts.length!==0||j.reviews.length!==0||j.nextIndex!==0||j.inFlight!==null||j.armed!==null
 ||r.successfulUiWrites!==0||r.unknownUiWrites!==0||r.failed!==1||r.screenshots.length!==0||j.actorId!==reference.session.user.id||j.sessionId!==reference.session.sid)throw Error('PRODUCTION_EXACT_ZERO_TRANSPORT_PREFLIGHT_ONLY');
const h=new ProductionHarness({resume:true}),actor=h.state.sessions.bootstrap;if(actor.sid!==j.sessionId||actor.user.id!==j.actorId)throw Error('PRODUCTION_SAME_ORIGINAL_SESSION_ONLY');
const marker={version:1,zeroPriorBusinessTransports:true,zeroPriorReadonlyPostReviews:true,originalJournalSha256:productionDigest(jbytes),originalReportSha256:productionDigest(rbytes),originalHandoffSha256:productionDigest(historyBytes),sameScopeAndActor:true};
durableProductionJson('/tmp/kongos-production-ui-unused-preflight-full-reference.json',reference,true);
await h.refresh(actor);
const oldReport=JSON.parse(readFileSync(reference.uiHandoff.securityReportPath)),path='artifacts/production/production-ui-handoff-unused-preflight.json',report={...oldReport,performedAt:new Date().toISOString(),sessionExpiresAt:actor.expiresAt,...marker,normalSessionRenewalVerified:true};durableProductionJson(path,report,true,0o644);const bytes=readFileSync(path);
const next={...reference,session:structuredClone(actor),requests:structuredClone(h.state.requests),secrets:[...new Set([...reference.secrets,...h.state.secrets])],zeroUiPreflightContinuation:marker,uiHandoff:{...reference.uiHandoff,securityReportPath:path,securityReportSha256:productionDigest(bytes)}};validateProductionHandoff(next,report,bytes);
for(const p of['/tmp/kongos-production-ui-zero-preflight-original-journal.json','/tmp/kongos-production-ui-zero-preflight-original-handoff.json'])if(existsSync(p))throw Error('PRODUCTION_PREFLIGHT_HISTORY_ALREADY_EXISTS');
renameSync(PRODUCTION_UI_JOURNAL,'/tmp/kongos-production-ui-zero-preflight-original-journal.json');renameSync(historyPath,'/tmp/kongos-production-ui-zero-preflight-original-handoff.json');durableProductionJson(PRODUCTION_UI_REFERENCE,next);h.state.uiPreparation.zeroTransportIconPreflightContinuation=marker;h.save();console.log(JSON.stringify({originalZeroTransportFailureRetained:true,normalOriginalSidRenewed:true,freshUnused178UiActionsReady:true}));
