import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {portalRepairRunOptions} from './verify-nullable-portal-repair-continuity.mjs';

function workflowRecoverySwaggerChecks(document,kind){
  const isAbandonment=kind==='abandon-rejected-issue',schemaName=isAbandonment?'RejectedIssueAbandonment':'IssueMetadataRecovery';
  const matches=Object.entries(document?.paths??{}).filter(([path,item])=>new RegExp('/clusters/\\{[^}]+\\}/workflows/\\{[^}]+\\}/'+kind+'$').test(path)&&item?.post);
  const operation=matches.length===1?matches[0][1].post:null,schema=document?.components?.schemas?.[schemaName],parameters=operation?.parameters??[];
  const parameter=(name,where)=>parameters.find(row=>row?.name===name&&row?.in===where);
  const key=parameter('X-Idempotency-Key','header'),workspace=parameter('workspaceId','query'),cookie=document?.components?.securitySchemes?.cookie;
  return [
    {name:`exactly one ${kind} POST declared`,passed:matches.length===1},
    {name:`required JSON body references ${schemaName}`,passed:operation?.requestBody?.required===true&&operation.requestBody.content?.['application/json']?.schema?.$ref===`#/components/schemas/${schemaName}`},
    {name:'recovery schema is a closed object with original execution tuple',passed:schema?.type==='object'&&schema.additionalProperties===false&&JSON.stringify([...(schema.required??[])].sort())===JSON.stringify(['confirmed','confirm_name','executionId','planHash','revision'].sort())},
    {name:'original execution UUID and positive plan revision documented',passed:schema?.properties?.executionId?.format==='uuid'&&schema?.properties?.revision?.type==='integer'&&schema.properties.revision.minimum===1},
    {name:'plan fingerprint and typed double confirmation documented',passed:schema?.properties?.planHash?.pattern==='^[a-f0-9]{64}$'&&JSON.stringify(schema?.properties?.confirmed?.enum)==='[true]'&&JSON.stringify(schema?.properties?.confirm_name?.enum)==='["portal-credential-issue"]'},
    {name:'original X-Idempotency-Key is mandatory with bounded string schema',passed:key?.required===true&&key?.schema?.type==='string'&&key.schema.minLength===8&&key.schema.maxLength===128&&typeof key.description==='string'&&key.description.includes('原执行')},
    {name:'workspaceId is a mandatory UUID query parameter',passed:workspace?.required===true&&workspace?.schema?.type==='string'&&workspace.schema.format==='uuid'},
    {name:'recovery POST uses Console cookie identity exclusively',passed:JSON.stringify(operation?.security)==='[{"cookie":[]}]'&&cookie?.type==='apiKey'&&cookie.in==='cookie'&&cookie.name==='kongos_access'},
  ];
}

export function issueMetadataRecoverySwaggerChecks(document){return workflowRecoverySwaggerChecks(document,'reconcile-metadata');}
export function rejectedIssueAbandonmentSwaggerChecks(document){return workflowRecoverySwaggerChecks(document,'abandon-rejected-issue');}

export async function metadataRecoveryOpenapiMain(args=process.argv.slice(2)){
  if((args.length!==1&&args.length!==2)||(args.length===2&&args[1]!=='--with-abandonment'))throw new Error('METADATA_OPENAPI_ARGUMENTS_INVALID');
  const options=portalRepairRunOptions(['--before',args[0]]),directory=resolve('artifacts/M6'),output=resolve(directory,`${options.label}-openapi-verification.json`);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);let result;
  try{
    const response=await fetch('http://127.0.0.1:8080/api/docs-json',{method:'GET',redirect:'error',signal:controller.signal});
    if(response.status!==200||!response.headers.get('content-type')?.includes('application/json'))throw new Error('METADATA_OPENAPI_RESPONSE_INVALID');
    const reader=response.body.getReader(),chunks=[];let size=0;
    try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>4*1024*1024)throw new Error('METADATA_OPENAPI_RESPONSE_TOO_LARGE');chunks.push(value);}}finally{await reader.cancel();}
    const document=JSON.parse(Buffer.concat(chunks).toString('utf8')),checks=[...issueMetadataRecoverySwaggerChecks(document),...(args[1]==='--with-abandonment'?rejectedIssueAbandonmentSwaggerChecks(document):[])];
    result={stage:'M6',label:options.label,kind:'readonly-runtime-openapi-metadata-recovery-contract',performedAt:new Date().toISOString(),checks,allPassed:checks.every(row=>row.passed),credentialsSent:false,businessRecoveryInvoked:false};
  }finally{clearTimeout(timer);}
  mkdirSync(directory,{recursive:true});writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({checks:result.checks.length,allPassed:result.allPassed,credentialsSent:false,businessRecoveryInvoked:false}));
  if(!result.allPassed)process.exitCode=1;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))metadataRecoveryOpenapiMain().catch(()=>{console.error('METADATA_RECOVERY_OPENAPI_VERIFICATION_FAILED; no raw document or errors printed.');process.exitCode=1;});
