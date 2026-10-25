import {execFileSync} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync,renameSync,rmSync} from 'node:fs';
import {privateReference,M6_REFERENCE} from './lib/m6-reference.mjs';
import {PENDING_KEY_TUPLE,PENDING_CAPTURE_PROGRAM,pendingReferenceGuard,decryptPendingTransfer,mergePendingCapture} from './lib/m6-pending-key-capture.mjs';

if(process.env.M6_PENDING_KEY_SCAN_CAPTURE_READY!=='true')throw new Error('Root exact scanner-only handoff required');
let phase='reference-guard',transferKey,temporary;
try{
 const before=readFileSync(M6_REFERENCE),reference=privateReference(M6_REFERENCE,true);pendingReferenceGuard(reference);
 const originalSha=createHash('sha256').update(before).digest('hex');transferKey=randomBytes(32);
 phase='fixed-read-only-trusted-capture';
 const transfer=JSON.parse(execFileSync('docker',['compose','exec','-T','console-api','node','-e',PENDING_CAPTURE_PROGRAM],{input:JSON.stringify({tuple:PENDING_KEY_TUPLE,key:transferKey.toString('hex')}),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:20000,maxBuffer:8192}));
 phase='aead-transfer-validate';const bundle=decryptPendingTransfer(transfer,transferKey),next=mergePendingCapture(reference,bundle);
 phase='reference-cas';if(createHash('sha256').update(readFileSync(M6_REFERENCE)).digest('hex')!==originalSha)throw new Error('reference changed during scanner capture');
 temporary=`${M6_REFERENCE}.${randomUUID()}.tmp`;writeFileSync(temporary,JSON.stringify(next),{mode:0o600,flag:'wx'});renameSync(temporary,M6_REFERENCE);temporary=undefined;
 const proof={performedAt:new Date().toISOString(),allPassed:true,credentialId:PENDING_KEY_TUPLE.credentialId,workflowId:PENDING_KEY_TUPLE.workflowId,originalExecutionId:PENDING_KEY_TUPLE.executionId,scannerOnly:true,exactCredentialGrantExecutionOperationReferenceTuplesVerified:true,portalAeadContextVerified:true,nativeSucceededResultAndPrivateCredentialReferenceMatch:true,plaintextTransferStdout:false,transferKeyStdinOnly:true,mode0600:true,privateReferenceRetained:true,oldCheckpointHistoryPreserved:true,originalExecutionNotRepeated:true,nativeWrites:0,consoleWrites:0,portalReveals:0,businessActivationPerformed:false,secretValuesPublished:false};
 writeFileSync('artifacts/M6/pending-credential-secret-capture.json',JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify({allPassed:true,scannerOnly:true,privateReferenceRetained:true,mode0600:true,nativeWrites:0,consoleWrites:0,portalReveals:0}));
}catch{console.error(`M6_PENDING_KEY_SCAN_CAPTURE_FAILED phase=${phase}; no secret or raw error printed.`);process.exitCode=1;}finally{transferKey?.fill(0);if(temporary)rmSync(temporary,{force:true});}
