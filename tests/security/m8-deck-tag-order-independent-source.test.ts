import {describe,it,expect} from 'vitest';
import {createServer} from 'node:http';
import {randomBytes,randomUUID} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {stringify} from 'yaml';
import {runDeck,DECK_BINARY_SHA256} from '../../deploy/deck-runner/runner.mjs';
import {compileTransferDag} from '../../apps/console-api/src/modules/config-transfer/transfer-dag';
import {canonicalJson} from '../../apps/console-api/src/infrastructure/secret.service';
import {sha256} from './lib/m8-harness.mjs';

// Root-authorized new synthetic loopback protocol observation only. No actual
// deployment env/private packet/YAML, Kong, database, BFF or Docker is used.
describe('independent fixed decK1.2.4 tagged-Service SDK ordering SOURCE proof',()=>{
 it('compares the official SDK full body with the actual compiler workspace-last seal',async()=>{
  const id=randomUUID(),sid=randomUUID(),cid=randomUUID(),wid=randomUUID(),token=randomBytes(32).toString('base64url');
  const workspaceTag=`kos-ws-${wid}`,tags=[workspaceTag,'zz-source-synthetic','aa-source-synthetic'];
  const original={id,name:`synthetic-tag-order-${randomUUID()}`,host:`synthetic-${randomUUID()}.example.invalid`,port:80,protocol:'http',retries:0,connect_timeout:60000,read_timeout:60000,write_timeout:60000,tags};
  const desired={...original,retries:3,tags:[...tags]},objectKey=`services:${id}`;
  const before={objectKey,entityType:'services',nativeId:id,objectWorkspaceId:wid,payload:original,beforeHmac:'b'.repeat(64),affected:true,referenceOnly:false,dependencies:[],recovery:{state:'complete',blockerCodes:[]}};
  const plan=compileTransferDag({scope:{transportScope:'workspace',clusterId:cid,workspaceId:wid,kind:'workspace',rootIds:[]},mode:'merge',blockerCodes:[],recoveryComplete:true,
   baseline:{objects:[before],schemas:{entities:{services:{fields:[{tags:{type:'set',elements:{type:'string'}}}]}},plugins:{},enabledPlugins:[]},schemaHmac:'c'.repeat(64),permissionVersion:'d'.repeat(64),clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1'},
   changes:[{objectKey,entityType:'services',nativeId:id,action:'update',before,after:{...before,payload:desired},effectivePayload:desired,writePayload:{retries:3},dependencies:[],blockerCodes:[],patch:[{op:'replace',path:'/retries',value:3}],clearMap:[]}]},
   {fingerprint:(value:unknown)=>sha256(canonicalJson(value)),redact:(value:unknown)=>structuredClone(value),sourceManifestHmac:'e'.repeat(64),baselineManifestHmac:'f'.repeat(64),expiresAt:new Date(Date.now()+300000).toISOString(),stepIds:{[objectKey]:randomUUID()}} as any);
  const sealed=plan.steps[0].deckWirePayload!;expect(sealed.tags).toEqual([tags[1],tags[2],tags[0]]);expect(plan.steps[0].deckWireSetFields).toEqual(['tags']);expect(plan.steps[0].nativeRequests[0].body).toEqual({retries:3});
  let current={...original},unexpected=0;const unexpectedRoutes:string[]=[],writes:Array<{method:string;body:Record<string,unknown>}>=[];
  const server=createServer(async(req,res)=>{
   res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
   if(req.headers.authorization!==`KongOS-Deck ${token}`){unexpected++;res.writeHead(403);res.end('{}');return;}
   const path=new URL(req.url!,'http://127.0.0.1').pathname,prefix=`/api/v1/deck/${sid}`;
   if(!path.startsWith(prefix)){unexpected++;res.writeHead(404);res.end('{}');return;}
   const native=path.slice(prefix.length)||'/';
   if(req.method==='GET'){
    if(native==='/'){res.end(JSON.stringify({version:'1.5.1'}));return;}
    if(native==='/mtls-auths'){res.writeHead(404);res.end('{}');return;}
    if(native===`/services/${id}`){res.end(JSON.stringify(current));return;}
    if(/^\/[a-z0-9_-]+$/.test(native)){res.end(JSON.stringify({data:native==='/services'?[current]:[],next:null}));return;}
    unexpected++;unexpectedRoutes.push(`${req.method} ${native.replaceAll(id,'{synthetic-id}')}`);res.writeHead(404);res.end('{}');return;
   }
   if(req.method==='PUT'&&native===`/services/${id}`){
    const chunks:Buffer[]=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>65536){unexpected++;res.writeHead(413);res.end('{}');return;}chunks.push(Buffer.from(chunk));}
    const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));writes.push({method:'PUT',body});current={...body,id} as typeof original;res.end(JSON.stringify(current));return;
   }
   unexpected++;unexpectedRoutes.push(`${req.method} ${native.replaceAll(id,'{synthetic-id}')}`);res.writeHead(405);res.end('{}');
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
   const origin=`http://127.0.0.1:${(server.address() as {port:number}).port}`;
   const result=await runDeck({command:'sync',sessionId:sid,tokenSecret:token,stateYaml:stringify({_format_version:'1.1',services:[desired]})},
    {binaryPath:'/tmp/kongos-deck124-cli/deck',origin,allowLocalTestBff:true,timeoutMs:15000,environment:{PATH:'/usr/bin:/bin'}});
   try{
    expect(result.safe).toMatchObject({exitCode:0,toolVersion:'1.2.4',toolCommit:'8e68931',toolBinarySha256:DECK_BINARY_SHA256,possibleUnknown:false,consoleJobSuccessProved:false});
    expect(unexpectedRoutes).toEqual([]);expect(unexpected).toBe(0);expect(writes).toHaveLength(1);const body=writes[0].body,actualTags=body.tags as string[];
    const sameSet=(a:string[],b:string[])=>canonicalJson([...a].sort())===canonicalJson([...b].sort());
    const mismatches=Object.keys(body).filter(key=>canonicalJson(body[key])!==canonicalJson(sealed[key])).map(key=>`/${key}`).sort();
    const observation={version:1,milestone:'M8',sourceOnly:true,actualRuntimeAcceptance:false,allPassed:true,
     tool:{version:result.safe.toolVersion,commit:result.safe.toolCommit,binarySha256:result.safe.toolBinarySha256},
     syntheticObservation:{method:'PUT',pathPattern:'/services/{fresh-synthetic-id}',writeCount:writes.length,bodyFields:Object.keys(body).sort(),
      sourceWorkspaceTagFirst:true,compilerWorkspaceTagLast:(sealed.tags as string[]).at(-1)===workspaceTag,
      tagSetEqualsInput:sameSet(actualTags,tags),tagSetEqualsSealed:sameSet(actualTags,sealed.tags as string[]),tagOrderEqualsInput:canonicalJson(actualTags)===canonicalJson(tags),
      tagOrderEqualsSealed:canonicalJson(actualTags)===canonicalJson(sealed.tags),tagOrderSortedLexically:canonicalJson(actualTags)===canonicalJson([...tags].sort()),
      mismatchFieldPaths:mismatches,plannedDeltaMatches:body.retries===3,nativeDeltaUnchanged:canonicalJson(plan.steps[0].nativeRequests[0].body)===canonicalJson({retries:3}),
      wireBodyCanonicalEqualsSeal:canonicalJson(body)===canonicalJson(sealed),cliExitCode:result.safe.exitCode,consoleJobSuccessProved:false},
     deploymentPrivateRead:false,actualConsoleRequests:0,actualNativeWrites:0,actualCliIntents:0,actualOriginalPacketReplay:false};
    expect(observation.syntheticObservation.tagSetEqualsSealed).toBe(true);expect(observation.syntheticObservation.mismatchFieldPaths).toEqual(['/tags']);
    expect(observation.syntheticObservation.tagOrderEqualsSealed).toBe(false);expect(observation.syntheticObservation.tagOrderEqualsInput).toBe(true);expect(observation.syntheticObservation.tagOrderSortedLexically).toBe(false);
    if(process.env.M8_TAG_ORDER_SOURCE_PROOF_RECORD==='true')writeFileSync('artifacts/M8/deck-tag-order-schema-set-source-proof.json',JSON.stringify(observation,null,2)+'\n',{mode:0o644,flag:'wx'});
   }finally{result.dispose();}
  }finally{await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
 },20000);
});
