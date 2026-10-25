import{readFileSync}from'node:fs';
import{M6Harness}from'./lib/m6-harness.mjs';
import{guardCredentialContinuation}from'./lib/m6-credential-continuation.mjs';
import{finishM6CredentialFlow}from'./live-m6.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_CREDENTIAL_CONTINUATION_READY!=='true')throw new Error('M6 patched runtime and explicit credential continuation handoff required');
const h=new M6Harness({requireReference:true});let failure;
try{
  const previous=JSON.parse(readFileSync('artifacts/M6/security-live-pre-fix-isolated-publication-proof.json','utf8'));
  h.check(previous.testTag===h.tag&&previous.passed===194&&previous.failed===1&&previous.lastHttpRequest?.path==='/requests'&&previous.lastHttpRequest.status===409,'CredentialContinuation/Evidence','the preserved actual 194-check run is this exact fixture checkpoint');
  h.checks.unshift(...previous.checks.filter(row=>row.passed));
  for(const key of['isolatedTransition','boundaryRefusalProof','portalTestClusters','retainedMonitoringFamilies'])if(previous[key])h.public[key]=previous[key];
  const diagnostic=JSON.parse(readFileSync('artifacts/M6/isolated-publication-request-proof.json','utf8'));
  const context=await guardCredentialContinuation(h,diagnostic);
  h.public.credentialContinuation={previousFailureEvidence:'security-live-pre-fix-isolated-publication-proof.json',previousPassingChecks:194,oldRequestKeyStillFailed:true,newRequestKeyExplicitlySavedBeforePost:true,bootstrapRegisterProbePublishRepeated:false};
  await finishM6CredentialFlow(h,context);
}catch(error){failure=error;}
process.exitCode=await h.finish(failure);
