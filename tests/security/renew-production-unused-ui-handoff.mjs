import{existsSync,readFileSync}from'node:fs';
import{ProductionHarness,productionDigest}from'./lib/production-http-harness.mjs';
import{readProductionUiReference,durableProductionJson,PRODUCTION_UI_REFERENCE,PRODUCTION_UI_JOURNAL}from'./lib/production-ui-storage.mjs';
import{validateProductionHandoff}from'./lib/production-ui-journal.mjs';

if(existsSync(PRODUCTION_UI_JOURNAL)||existsSync('/tmp/kongos-production-ui-original-handoff.json')||existsSync('artifacts/production/ui-lifecycle.json'))throw Error('PRODUCTION_ZERO_UI_TRANSPORT_ONLY');
const original=readProductionUiReference(),oldBytes=readFileSync(PRODUCTION_UI_REFERENCE),h=new ProductionHarness({resume:true}),actor=h.state.sessions.bootstrap;
if(original.session.sid!==actor.sid||original.session.user.id!==actor.user.id||original.requests.some(p=>p.state!=='response_observed'))throw Error('PRODUCTION_ORIGINAL_SESSION_REQUIRED');
durableProductionJson('/tmp/kongos-production-ui-before-first-transport-session.json',original,true);
await h.refresh(actor);
const oldReportBytes=readFileSync(original.uiHandoff.securityReportPath),oldReport=JSON.parse(oldReportBytes),path='artifacts/production/production-ui-handoff-unused-session.json';
const report={...oldReport,performedAt:new Date().toISOString(),sessionExpiresAt:actor.expiresAt,originalHandoffSha256:productionDigest(oldReportBytes),originalReferenceSha256:productionDigest(oldBytes),zeroPriorUiTransports:true,actualNormalSameSidRenewal:true};
durableProductionJson(path,report,true,0o644);const bytes=readFileSync(path),reference={...original,session:structuredClone(actor),requests:structuredClone(h.state.requests),secrets:[...new Set([...original.secrets,...h.state.secrets])],uiHandoff:{...original.uiHandoff,securityReportPath:path,securityReportSha256:productionDigest(bytes)}};
validateProductionHandoff(reference,report,bytes);durableProductionJson(PRODUCTION_UI_REFERENCE,reference);h.state.uiPreparation.normalZeroUiTransportSessionRenewal={path,sha256:productionDigest(bytes),originalHandoffRetained:true};h.save();console.log(JSON.stringify({zeroPriorUiTransports:true,actualSameSidRenewal:true,originalHandoffRetained:true}));
