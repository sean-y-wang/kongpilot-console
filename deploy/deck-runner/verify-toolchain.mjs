import {runDeck} from './runner.mjs';
let result;
try {
 const run=await runDeck({command:'validate',stateYaml:'_format_version: "1.1"\nservices: []\n'},{timeoutMs:10000});
 try {result={version:'1.2.4',commit:'8e68931',binarySha256:run.safe.toolBinarySha256,command:'validate',networkRequired:false,credentialRequired:false,exitCode:run.safe.exitCode,allPassed:run.safe.exitCode===0&&!run.safe.timedOut&&!run.safe.outputLimitReached};}
 finally {run.dispose();}
} catch {result={version:'1.2.4',command:'validate',allPassed:false,errorCode:'DECK_TOOLCHAIN_VERIFICATION_FAILED'};}
process.stdout.write(JSON.stringify(result)+'\n');
if(!result.allPassed)process.exitCode=1;
