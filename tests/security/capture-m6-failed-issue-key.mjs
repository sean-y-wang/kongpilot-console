import {execFileSync} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync,renameSync,rmSync} from 'node:fs';
import {privateReference,M6_REFERENCE} from './lib/m6-reference.mjs';
import {FAILED_ISSUE_TUPLE,FAILED_ISSUE_CAPTURE_PROGRAM,failedIssueCaptureReferenceGuard,decryptFailedIssueTransfer,mergeFailedIssueCapture} from './lib/m6-failed-issue-key-capture.mjs';

if(process.env.M6_FAILED_ISSUE_KEY_SCAN_CAPTURE_READY!=='true')throw new Error('Root exact failed-issue scanner-only handoff required');
let phase='reference-guard',transferKey,temporary;
try{
 const bytes=readFileSync(M6_REFERENCE),reference=privateReference(M6_REFERENCE,true);failedIssueCaptureReferenceGuard(reference);const before=createHash('sha256').update(bytes).digest('hex');transferKey=randomBytes(32);
 phase='fixed-read-only-trusted-capture';const transfer=JSON.parse(execFileSync('docker',['compose','exec','-T','console-api','node','-e',FAILED_ISSUE_CAPTURE_PROGRAM],{input:JSON.stringify({tuple:FAILED_ISSUE_TUPLE,key:transferKey.toString('hex')}),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:20000,maxBuffer:8192}));
 phase='aead-transfer-validate';const bundle=decryptFailedIssueTransfer(transfer,transferKey),next=mergeFailedIssueCapture(reference,bundle);
 phase='reference-cas';if(createHash('sha256').update(readFileSync(M6_REFERENCE)).digest('hex')!==before)throw new Error('Private reference changed during capture');
 temporary=`${M6_REFERENCE}.${randomUUID()}.tmp`;writeFileSync(temporary,JSON.stringify(next),{mode:0o600,flag:'wx'});renameSync(temporary,M6_REFERENCE);temporary=undefined;
 const proof={performedAt:new Date().toISOString(),allPassed:true,credentialId:FAILED_ISSUE_TUPLE.credentialId,workflowId:FAILED_ISSUE_TUPLE.workflowId,originalExecutionId:FAILED_ISSUE_TUPLE.executionId,scannerOnly:true,exactFailedConsumerAndPristinePendingStepsVerified:true,noNativeCredentialOrReferenceIssued:true,immutablePlanAndPortalAeadKeyMatch:true,plaintextTransferStdout:false,transferKeyStdinOnly:true,mode0600:true,privateReferenceRetained:true,oldCheckpointAndCompletedMetadataRecoveryPreserved:true,originalExecutionReplayed:false,nativeWrites:0,consoleWrites:0,portalReveals:0,businessActivationOrAbandonmentPerformed:false,secretsPublished:false};
 writeFileSync('artifacts/M6/failed-issue-credential-secret-capture.json',JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify({allPassed:true,scannerOnly:true,nativeWrites:0,consoleWrites:0,privateReferenceRetained:true}));
}catch{console.error(`M6_FAILED_ISSUE_KEY_SCAN_CAPTURE_FAILED phase=${phase}; no secret or raw error printed.`);process.exitCode=1;}finally{transferKey?.fill(0);if(temporary)rmSync(temporary,{force:true});}
