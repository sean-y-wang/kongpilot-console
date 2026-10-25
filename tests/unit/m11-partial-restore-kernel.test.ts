import 'reflect-metadata';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {ForbiddenException,HttpException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {EntityChangeExecutionService} from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import {entityBaselineAad,entityPacketFactAad} from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import {partialBasicCustodyHmac} from '../../apps/console-api/src/modules/recycle-bin/partial-recycle-restore';

/** Actual Kernel.execute and private original handles/ALS are exercised. SQL,
 * historical verifier, graph capture and transport observers are controlled
 * adapters. These are source regressions, never real SQL025/Kong evidence. */
function fixture(){
  const secrets=new SecretService(),context=new KongExecutionContextService(),now=Date.now(),cid=randomUUID(),wid=randomUUID(),owner=randomUUID(),sid=randomUUID();
  const consumer=randomUUID(),entryId=randomUUID(),oldSourceId=randomUUID(),baselineId=randomUUID(),pinId=randomUUID(),workflowId=randomUUID(),intentId=randomUUID();
  const user:any={id:owner,username:'controlled-partial-owner',superAdmin:false},actor:any={user,workspaceId:wid,idempotencyKey:'unit-partial-original'},pv=`${owner}:1:1`;
  const h=(v:any)=>secrets.fingerprint(v),expiresAt=new Date(now+240000).toISOString(),types=['consumers','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
  const rawInput:any={password:'unit-password-only'},nodes:any[]=types.map((type,index)=>{const id=index?randomUUID():consumer;
    const data:any={id,...(index?{consumer:{id:consumer}}:{username:'unit-consumer',tags:['workspace:unit']}),...(type==='basic-auth'?{username:'unit-basic',password:createHash('sha1').update(rawInput.password+consumer).digest('hex')}:{})};
    const restoreData={...data,...(type==='basic-auth'?{password:rawInput.password}:{})};
    return{key:`${type}:${id}`,type,id,path:index?`/consumers/${consumer}/${type}/${id}`:`/consumers/${id}`,data,restoreData,affected:true,dependencies:index?[`consumers:${consumer}`]:[],restorable:true};});
  const graph:any={purpose:'recycle',complete:true,rootKey:nodes[0].key,capturedAt:new Date(now-20000).toISOString(),nodes};
  const remembered={credential:nodes[2].data,rawInput},basic=partialBasicCustodyHmac(nodes[2],nodes[2].data,remembered,consumer,secrets);
  const history:any={version:1,clusterId:cid,workspaceId:wid,entryId,graphHmac:h(graph),nodeManifestHmac:h('archive-node-manifest'),sourceId:oldSourceId,intentId:randomUUID(),intentRevision:1,
    baselineId:randomUUID(),pinId:randomUUID(),workflowId:randomUUID(),workflowExecutionId:randomUUID(),materialHmac:h('old-material'),changeDigest:h('old-change'),packetManifestHmac:h('old-packets'),
    terminalMetadataAudit:{id:randomUUID(),eventHash:h('audit'),proofHmac:h('old-proof'),outcomeEventId:randomUUID(),outcomeFactHmac:h('failed-known-no-send'),requestHmac:h('old-request')},
    presentNodes:nodes.slice(0,5).map((n,i)=>({nodeKey:n.key,nativeType:n.type,nativeId:n.id,parentId:i?consumer:null,credentialKind:i?n.type:null,packetKey:`old-${i+1}`,attemptId:randomUUID(),operationId:randomUUID(),operationKey:`old-${i+1}`,resultHmac:h(n.data),outcomeFactHmac:h(`old-outcome-${i+1}`)})),
    remainingNodes:nodes.slice(5).map((n,i)=>({nodeKey:n.key,nativeType:n.type,nativeId:n.id,parentId:consumer,credentialKind:n.type,packetKey:`old-${i+6}`,classification:i?'unattempted':'failed-known-not-sent',attemptId:i?null:randomUUID(),operationId:i?null:randomUUID(),outcomeFactHmac:i?null:h('old-failed-outcome')}))};
  history.coverageHmac=h(history);
  const selection:any={version:1,history,presentNodes:nodes.slice(0,5).map(n=>({nodeKey:n.key,beforeHmac:h(n.data),...(n.type==='basic-auth'?{basicCustodyHmac:basic}:{})})),remainingNodeKeys:nodes.slice(5).map(n=>n.key)};
  selection.selectionHmac=h(selection);
  const packets:any[]=nodes.slice(5).map((n,i)=>({key:`new-${i+1}`,order:i+1,dependencies:[],method:'POST',canonicalPath:`/consumers/${consumer}/${n.type}`,nativeType:n.type,nativeId:n.id,parentId:consumer,credentialKind:n.type,
    mutationAction:'restore',permissionAction:'write',body:n.restoreData,before:null,bodyHmac:h(n.restoreData),beforeHmac:h(null)}));
  const obligation:any={kind:'recycle-restore',entryId,graph,graphHmac:h(graph),packetKeys:packets.map(p=>p.key),partialRestore:selection,
    sealedEntry:{clusterId:cid,workspaceId:wid,entryId,state:'partially_restored',expiresAt:new Date(now+86400000).toISOString(),payloadHmac:h(graph),nodeManifestHmac:history.nodeManifestHmac,restoreMaterialHmac:h(nodes.map(n=>({key:n.key,restoreData:n.restoreData})))}};
  const scope={transportScope:h('transport'),clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',adapter:'kong-1.5'};
  const initial:any={version:1,clusterId:cid,workspaceId:wid,requesterId:owner,scope,request:{kind:'recycle',action:'restore',entryId,confirmed:true,confirm_name:'unit-consumer'},packets,
    metadataObligations:[obligation,...packets.map(p=>({kind:'credential-remember',packetKey:p.key,consumerId:consumer,credentialKind:p.nativeType,rawInput:p.body}))]};
  const prepared={...initial,changeDigest:h(initial)},envelope:any={version:1,intentId,revision:1,clusterId:cid,workspaceId:wid,requesterId:owner,credentialEpoch:'1',executionMode:'approval',expiresAt,prepared,packetManifestHmac:h('normalized-packets')};
  const metadata={intentId,intentRevision:1,materialHmac:h(envelope),changeDigest:prepared.changeDigest,packetManifestHmac:envelope.packetManifestHmac};
  const plan:any={version:1,workflowId,planRevision:1,kind:'native-change',clusterId:cid,workspaceId:wid,executionMode:'approval',approvalRequired:true,subject:{type:'entity_change_intents',id:intentId},
    requester:{type:'console',id:owner},scope,issuedAt:new Date(now).toISOString(),expiresAt,definition:{id:randomUUID(),version:1,policyHash:h('policy')},prerequisites:[],
    steps:[{id:randomUUID(),key:'entity',order:1,kind:'metadata',handler:'entity.change',entityType:'entity_change_intents',entityId:intentId,permissionAction:'write',dependencies:[],nativeRequests:[],metadata,metadataRevision:1,metadataPayloadHmac:h(metadata),metadataBeforeHmac:h(null)}]};
  const workflow:any={id:workflowId,state:'approved',revision:1,plan_hash:h(plan),approved_by:randomUUID()};
  const legacy=nodes.map((n,i)=>({entry_id:entryId,node_key:n.key,entity_type:n.type,original_id:n.id,affected:true,delete_state:'deleted',restore_state:i<5?'restored':i===5?'failed':'pending',restored_id:i<5?n.id:null,dependencies:n.dependencies}));
  const state:any={source:null,execution:null,baseline:null,pin:null,objects:[],attempts:[],events:[],mutations:[],receipts:[],legacy,sent:[],revoked:false,permissionChanged:false,leaseExpired:false,foreignUnknown:false,
    live:new Map(nodes.slice(0,5).map(n=>[n.path,structuredClone(n.data)])),original:null,bridge:null,checkpoints:[],failHistory:false,tamper:'',onPrepare:null,onOutcome:null,onRecapture:null,beforePacket:null,hideBindingMutation:false};
  const db:any={one:vi.fn(async(sql:string,v:any[]=[])=>{
    if(sql.includes('AS unresolved'))return{unresolved:state.foreignUnknown};
    if(sql.includes('FROM entity_change_execution_sources'))return state.source;
    if(sql.includes('FROM entity_change_baselines'))return state.baseline;
    if(sql.includes('FROM entity_change_baseline_pins'))return state.pin;
    if(sql.includes('FROM entity_change_recycle_archives'))return{source_id:randomUUID(),graph_hmac:h(graph)};
    if(sql.includes('FROM workflow_executions')&&sql.includes('JOIN workflows'))return{state:state.execution?.state,workflow_state:workflow.state};
    if(sql.includes('FROM workflow_executions'))return state.execution;
    if(sql.includes('FROM mutation_operations'))return state.mutations.find((m:any)=>m.id===v[0])??null;
    if(sql.includes('FROM entity_change_packet_events'))return state.events.find((e:any)=>e.attempt_id===v[0]&&e.event_kind==='outcome')??null;
    if(sql.includes('FROM auth_sessions'))return state.revoked?null:{expires_at:expiresAt,credential_epoch:'1',user_epoch:'1'};
    if(sql.includes('FROM iam_epoch'))return{version:1};
    if(sql.includes('FROM clusters'))return{revision:1,execution_mode:'approval'};
    if(sql.includes('FROM workspaces'))return{revision:1,status:'active'};
    if(sql.includes('FROM workflows'))return workflow;
    throw new Error(`Unexpected controlled read ${sql.slice(0,70)}`);
  }),query:vi.fn(async(sql:string)=>{
    if(sql.includes('FROM entity_change_baseline_objects'))return structuredClone(state.objects);
    if(sql.includes('FROM entity_change_packet_attempts'))return structuredClone(state.attempts);
    if(sql.includes('FROM entity_change_packet_events'))return structuredClone(state.events);
    if(sql.includes('FROM entity_change_recycle_receipts'))return structuredClone(state.receipts);
    if(sql.includes('FROM mutation_operations'))return structuredClone(state.hideBindingMutation?[]:state.mutations);
    if(sql.includes('FROM recycle_nodes'))return structuredClone(state.legacy);
    throw new Error('Unexpected controlled query');
  }),exec:vi.fn(async(sql:string,v:any[]=[])=>{
    if(sql.startsWith('INSERT INTO entity_change_execution_sources')){const fields=['id','cluster_id','workspace_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','workflow_id','workflow_plan_revision','workflow_plan_hash','workflow_execution_id','execution_actor_id','credential_epoch','session_id','permission_version_hmac','issued_at','expires_at'];state.source=Object.fromEntries(fields.map((k,i)=>[k,v[i]]));}
    else if(sql.startsWith('INSERT INTO workflow_executions'))state.execution={id:v[0],state:'executing'};
    else if(sql.startsWith("UPDATE workflows SET state='executing'"))workflow.state='executing';
    else if(sql.startsWith("UPDATE workflows SET state='succeeded'"))workflow.state='succeeded';
    else if(sql.startsWith('UPDATE workflows SET state=$2'))workflow.state=v[1];
    else if(sql.startsWith("UPDATE workflow_executions SET state='succeeded'"))state.execution.state='succeeded';
    else if(sql.startsWith('UPDATE workflow_executions SET state=$2'))state.execution.state=v[1];
    return 1;
  }),transaction:vi.fn(async(fn:any)=>fn(db))};
  const redis:any={withLock:vi.fn(async(_k:string,fn:any)=>fn()),assertLeaseActive:vi.fn(()=>{if(state.leaseExpired)throw new ForbiddenException({code:'CONTROLLED_LEASE_EXPIRED'});}),
    assertLeaseOwnership:vi.fn(async()=>{if(state.leaseExpired)throw new ForbiddenException({code:'CONTROLLED_LEASE_EXPIRED'});})};
  const authz:any={snapshot:vi.fn(async()=>({})),permissionVersion:vi.fn(async()=>state.permissionChanged?'changed':pv)},kong:any={transportScope:vi.fn(async()=>scope.transportScope),request:vi.fn(async(_cid:string,method:string,path:string)=>{
    expect(method).toBe('GET');if(!state.live.has(path))throw new HttpException({code:'KONG_NOT_FOUND'},404);return structuredClone(state.live.get(path));})};
  const origins:any={verifyFrozenRestoreCoverage:vi.fn(async(input:any,expected:any,current:string)=>{expect(input.entryId).toBe(entryId);expect(expected).toEqual(history);expect(current).toBe(state.source.id);
    if(state.failHistory)throw new ForbiddenException({code:'CONTROLLED_HISTORY_INVALID'});})};
  const graphs:any={capture:vi.fn(async()=>({purpose:'baseline',complete:true,rootKey:nodes[0].key,nodes:nodes.filter(n=>state.live.has(n.path)).map(n=>({...n,key:n.type==='consumers'?n.key:`${n.type}:${consumer}:${n.id}`,data:structuredClone(state.live.get(n.path))}))}))};
  const custody:any={get:vi.fn(async()=>state.tamper==='custody'?{credential:remembered.credential,rawInput:{password:'wrong'}}:structuredClone(remembered))};
  let factsDelegate:any;
  const event=(fact:any)=>({id:randomUUID(),cluster_id:cid,workspace_id:wid,source_id:fact.binding.sourceId,baseline_id:baselineId,pin_id:pinId,workflow_execution_id:state.execution.id,
    attempt_id:fact.binding.attemptId,event_kind:fact.kind,observed_at:fact.observedAt,outcome:fact.kind==='outcome'?fact.outcome:null,native_status:fact.nativeStatus??null,error_code:fact.errorCode??null,
    fact_hmac:h(fact),fact_ciphertext:secrets.encrypt(fact,entityPacketFactAad(cid,wid,fact.binding.attemptId,fact.kind))});
  const facts:any={installFixedDelegate:(d:any)=>factsDelegate=d,persistReady:vi.fn(async(sourceId:string,_capture:any,proof:object)=>{
    const source={id:state.source.id,clusterId:cid,workspaceId:wid,intentId,intentRevision:1,materialHmac:h(envelope),changeDigest:prepared.changeDigest,packetManifestHmac:envelope.packetManifestHmac,workflowId,workflowPlanRevision:1,workflowPlanHash:h(plan),workflowExecutionId:state.execution.id,executionActorId:owner,credentialEpoch:'1',sessionId:sid,permissionVersionHmac:h(pv),issuedAt:state.source.issued_at,expiresAt:state.source.expires_at};
    const objects=nodes.map((n,i)=>({key:i?`${n.type}:${consumer}:${n.id}`:n.key,nativeType:n.type,nativeId:n.id,...(i?{parentId:consumer,credentialKind:n.type}:{}),affected:i>=5,present:i<5,dependencies:n.dependencies,before:i<5?n.data:null,
      schemaMaterial:{fixture:'schema'},recovery:i<5?'reference':'absent',trustedProvenance:i<5?{kind:'closed-restore-current-present',nodeKey:n.key,historyCoverageHmac:history.coverageHmac,priorSourceId:oldSourceId,priorAttemptId:history.presentNodes[i].attemptId,
        priorOperationId:history.presentNodes[i].operationId,priorResultHmac:h(n.data),beforeHmac:h(n.data),...(i===2?{basicCustodyHmac:basic}:{})}:{kind:'native-get-404'}}));
    const capture:any={version:1,observedFrom:new Date(now).toISOString(),observedUntil:new Date(now).toISOString(),objects,graphs:[await graphs.capture()],blockerCodes:[],nonreversiblePacketKeys:[]};
    const normalized=objects.map(o=>({key:o.key,nativeType:o.nativeType,nativeId:o.nativeId,parentId:o.parentId??null,credentialKind:o.credentialKind??null,affected:o.affected,present:o.present,dependencies:o.dependencies,beforeHmac:h(o.before),restoreHmac:null,schemaHmac:h(o.schemaMaterial),provenanceHmac:h(o.trustedProvenance),recovery:o.recovery}));
    const baselineEnvelope={version:1,baselineId,source,capture},bH=h(baselineEnvelope),cH=h(capture),oH=h(normalized);
    state.baseline={id:baselineId,source_id:sourceId,cluster_id:cid,workspace_id:wid,readiness:'ready',workflow_execution_id:state.execution.id,baseline_hmac:bH,capture_hmac:cH,object_manifest_hmac:oH,object_manifest:normalized,object_count:7,graph_count:1,material_ciphertext:secrets.encrypt(baselineEnvelope,entityBaselineAad(cid,wid,baselineId))};
    state.objects=normalized.map((o,i)=>({baseline_id:baselineId,cluster_id:cid,workspace_id:wid,object_order:i+1,object_manifest_hmac:oH,object_key:o.key,native_type:o.nativeType,native_id:o.nativeId,parent_id:o.parentId,credential_kind:o.credentialKind,affected:o.affected,present:o.present,dependencies:o.dependencies,before_hmac:o.beforeHmac,restore_hmac:o.restoreHmac,schema_hmac:o.schemaHmac,provenance_hmac:o.provenanceHmac,recovery:o.recovery}));
    const protectedUntil=new Date(now+86400000).toISOString();state.pin={id:pinId,baseline_id:baselineId,source_id:sourceId,workflow_execution_id:state.execution.id,cluster_id:cid,workspace_id:wid,baseline_hmac:bH,object_manifest_hmac:oH,protected_until:protectedUntil};
    await factsDelegate.verifySource(sourceId,'capture',db);
    return{sourceId,baselineId,pinId,baselineHmac:bH,captureHmac:cH,objectManifestHmac:oH,objectCount:7,graphCount:1,protectedUntil};
  }),assertReadyForPacket:vi.fn(async()=>({capture:{},packet:{}})),appendAttempt:vi.fn(async(binding:any,proof:object)=>{
    await factsDelegate.verifyPacketFact(binding,null,proof,db);const p=packets.find(p=>p.key===binding.packetKey)!;
    state.attempts.push({id:binding.attemptId,source_id:binding.sourceId,baseline_id:baselineId,pin_id:pinId,cluster_id:cid,workspace_id:wid,workflow_execution_id:state.execution.id,packet_key:p.key,packet_order:p.order,
      native_type:p.nativeType,native_id:p.nativeId,parent_id:p.parentId,credential_kind:p.credentialKind,body_hmac:p.bodyHmac,before_hmac:p.beforeHmac,path_hmac:h(p.canonicalPath),
      intent_id:intentId,intent_revision:1,material_hmac:h(envelope),change_digest:prepared.changeDigest,packet_manifest_hmac:envelope.packetManifestHmac,method:p.method,permission_action:p.permissionAction,mutation_action:p.mutationAction,original_native_id:null});
  }),appendSendIntent:vi.fn(async(fact:any,proof:object)=>{await factsDelegate.verifyPacketFact(fact.binding,fact,proof,db);state.events.push(event(fact));}),
    appendOutcome:vi.fn(async(fact:any,proof:object)=>{await factsDelegate.verifySource(fact.binding.sourceId,'outcome',db);await factsDelegate.verifyPacketFact(fact.binding,fact,proof,db);state.events.push(event(fact));})};
  const capturer:any={capture:vi.fn(async()=>({})),assertUnchanged:vi.fn(async()=>state.onRecapture?.())},boundary:any={assertPacket:vi.fn(async()=>undefined),assertCurrentRecycleSubject:vi.fn(async()=>performance.now()+5000),
    // Explicit current-domain adapter for this historical SQL/Kernel suite.
    // The whole-execution suite exercises the actual opaque SDK producer.
    resolveCurrentRecycleWitness:()=>{const inspected=state.bridge.packet(context.requireEntityChangePacketFrame(context.current()));
      const current=[...state.live.entries()].map(([path,data]:any)=>{const n=nodes.find(n=>n.path===path),type=n?.type??path.split('/')[3],id=n?.id??data.id;return{key:n?.key??`${type}:${id}`,type,originalId:id,parentId:type==='consumers'?null:consumer,affected:true,data:structuredClone(data)};});
      return{descriptor:{source:inspected.source,prepared,obligation,packets,packet:inspected.packet,nodeKey:nodes.find(n=>n.id===inspected.packet.nativeId)!.key,completed:[]},nodes:current,absent:nodes.filter(n=>!state.live.has(n.path)).map(n=>n.key),phase:'before-native',wholeGraphObserved:true,observationHmac:h(current),monotonicDeadline:performance.now()+5000};}
  },writer:any={installExecutionDelegate:vi.fn()};
  const plans:any={load:vi.fn(async()=>({plan,row:{...workflow}})),revalidateEntityChange:vi.fn(async()=>undefined)},intents:any={executionMaterial:vi.fn(async()=>envelope)};
  const approval:any={verifyApprovalSet:vi.fn(async()=>({format:2,setId:randomUUID(),setHmac:h('three-real-adapter-votes'),reviewers:[]}))},audit:any={append:vi.fn(async()=>undefined)};
  let kernel:EntityChangeExecutionService;
  const recycle:any={installKernelBridge:(bridge:any)=>state.bridge=bridge,onModuleInit:()=>undefined,supports:()=>true,release:()=>undefined,verification:()=>undefined,bindPacketOperation:async()=>undefined,
    prepare:vi.fn(async(handle:object)=>{state.original=handle;await state.onPrepare?.();await state.bridge.verifyPartialRestoreCurrent(handle,'capture');}),
    execute:vi.fn(async(handle:object)=>context.runEntityChangePacket(handle,async()=>{
      const inspection=state.bridge.packet(handle),p=inspection.packet,input:any={clusterId:cid,workspaceId:wid,actor:user,entityType:'credentials',action:'restore',parentId:consumer,credentialKind:p.nativeType,idempotencyKey:inspection.operationKey,before:null,payload:p.body};
      await state.beforePacket?.(p);
      await state.bridge.verifyPartialRestoreCurrent(state.original,'packet');
      const binding=await kernel.mutationBinding(handle,input),operationId=randomUUID();
      const mutation:any={id:operationId,state:'running',cluster_id:cid,workspace_id:wid,actor_id:owner,workflow_id:workflowId,entity_type:'credentials',entity_id:p.nativeId,parent_id:consumer,credential_kind:p.nativeType,action:'restore',idempotency_key:inspection.operationKey,
        entity_change_source_id:inspection.source.id,entity_change_baseline_id:baselineId,entity_change_attempt_id:inspection.binding.attemptId,entity_change_packet_key:p.key,remote_started:false,remote_completed:false,result_secret:null,workflow_step_id:null,configuration_step_id:null,
        before_secret:secrets.encrypt(null,`mutation:${operationId}:before`),payload_secret:secrets.encrypt(p.body,`mutation:${operationId}:payload`),transport_scope:scope.transportScope};
      state.mutations.push(mutation);
      const bindingTx:any={...db,query:async(sql:string,v:any[])=>sql.includes('FROM mutation_operations')?structuredClone(state.mutations):db.query(sql,v)};
      state.hideBindingMutation=true;
      try{await kernel.bindOperation(handle,input,binding,operationId,bindingTx);}finally{state.hideBindingMutation=false;}
      await state.bridge.verifyPartialRestoreCurrent(state.original,'before-send');mutation.remote_started=true;
      const native:any={frame:context.current(),operationId,clusterId:cid,workspaceId:wid,transportScope:scope.transportScope,method:'POST',canonicalPath:p.canonicalPath,parentId:consumer,credentialKind:p.nativeType,query:{},body:p.body,before:null,mutationAction:'restore'};
      // Controlled current-domain adapter only; the production Coordinator's partial branch remains closed pending same-use fresh witness integration.
      await state.bridge.assertCurrentGraphParties(state.original,{} as any);await kernel.beforeNativeSend(handle,native);
      // The second DNS/prepare guard sees the same unsent reservation.
      await state.bridge.verifyPartialRestoreCurrent(state.original,'before-send');// Controlled current-domain adapter only; the production Coordinator's partial branch remains closed pending same-use fresh witness integration.
      await state.bridge.assertCurrentGraphParties(state.original,{} as any);await kernel.beforeNativeSend(handle,native);
      kernel.spendTransport(handle,native);const raw={...p.body};state.sent.push(p.key);state.live.set(`${p.canonicalPath}/${p.nativeId}`,raw);
      kernel.observeTransportResponse(handle,native,201,raw);await kernel.assertNative(handle,{...native,result:raw},'response');
      mutation.state='succeeded';mutation.remote_completed=true;mutation.result_secret=secrets.encrypt(raw,`mutation:${operationId}:result`);
      await state.onOutcome?.(p);
      await state.bridge.verifyPartialRestoreCurrent(state.original,'outcome',db);await state.bridge.appendKnownOutcome(handle,undefined,db);
      await state.bridge.verifyPartialRestoreCurrent(state.original,'outcome',db);
      const node=nodes.find(n=>n.type===p.nativeType)!;state.receipts.push({attempt_id:inspection.binding.attemptId,cluster_id:cid,workspace_id:wid,source_id:inspection.source.id,baseline_id:baselineId,pin_id:pinId,workflow_execution_id:state.execution.id,entry_id:entryId,node_key:node.key,
        packet_key:p.key,operation_id:operationId,operation_key:inspection.operationKey,native_id:p.nativeId,direction:'restore',result_hmac:h(raw),verification_hmac:null,created_at:new Date().toISOString()});
      await state.bridge.verifyPartialRestoreCurrent(state.original,'outcome',db);
      const projected=state.legacy.find((n:any)=>n.node_key===node.key);projected.restore_state='restored';projected.restored_id=node.id;
    }))};
  kernel=new EntityChangeExecutionService(db,redis,secrets,context,kong,authz,audit,plans,approval,intents,facts,capturer,writer,boundary,recycle,undefined,undefined,origins,graphs,custody);
  kernel.onModuleInit();
  const invoke=()=>context.runHttp({},async()=>{context.bindHttpActor(user,sid);return context.runActor({actor:user,clusterId:cid,workspaceId:wid,module:'workflows',action:'write'},()=>kernel.execute(plan,{revision:1,planHash:h(plan),confirmed:true,confirm_name:'native-change'},actor));});
  return{kernel,state,invoke,db,origins,kong,graphs,custody,workflow,selection,prepared,actor,packets,graph,secrets,context,redis,authz,approval,cid,wid,entryId};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cd'.repeat(32));vi.stubEnv('APP_SECRET','controlled-partial-source-unit-secret-32');});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});
describe('M11 genuine partial-restore Root bridge (controlled source adapters)',()=>{
  it('runs only new HMAC/ACL packets through repeated guards and truthful outcomes; original five are references',async()=>{
    const f=fixture();try{await f.invoke();}catch(error){throw new Error(JSON.stringify((error as HttpException).getResponse()));}expect(f.state.sent).toEqual(['new-1','new-2']);expect(f.state.receipts).toHaveLength(2);expect(f.state.events.filter((e:any)=>e.event_kind==='send-intent')).toHaveLength(2);
    expect(f.state.events.filter((e:any)=>e.event_kind==='outcome')).toHaveLength(2);expect(f.origins.verifyFrozenRestoreCoverage.mock.calls.length).toBeGreaterThan(10);
    expect(f.workflow.state).toBe('succeeded');expect(f.state.live.size).toBe(7);expect(f.kong.request.mock.calls.every((c:any[])=>c[1]==='GET')).toBe(true);
    expect(f.approval.verifyApprovalSet).toHaveBeenCalled();expect(f.redis.assertLeaseOwnership).toHaveBeenCalled();
  });
  it('rejects copied execution handles before SQL, history checks or current Kong observations',async()=>{
    const f=fixture();for(const handle of [{},{approved:true,partialRestore:f.selection},[],Object.create({sourceId:'copied'})])await expect(f.state.bridge.verifyPartialRestoreCurrent(handle,'capture')).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_EXECUTION_PROOF_INVALID'}});
    expect(f.db.one).not.toHaveBeenCalled();expect(f.origins.verifyFrozenRestoreCoverage).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('uses only the privately registered binding transaction for the still-uncommitted first operation',async()=>{
    const f=fixture();let checked=0;
    f.state.onRecapture=async()=>{expect(f.state.hideBindingMutation).toBe(true);expect(await f.db.query('SELECT * FROM mutation_operations',[])).toEqual([]);
      const source=await f.state.bridge.activeRestoreRevalidation({clusterId:f.cid,workspaceId:f.wid,entryId:f.entryId,actor:f.actor,subjectAction:'read'});
      expect(source).toBe(f.state.source.id);checked++;};
    await f.invoke();expect(checked).toBe(1);expect(f.state.sent).toEqual(['new-1','new-2']);
  });
  it.each(['receipt','unknown','projection'])('rejects forged own %s progress before allocating the second transport',async kind=>{
    const f=fixture();f.state.beforePacket=(p:any)=>{if(p.order!==2)return;if(kind==='receipt')f.state.receipts[0].result_hmac='0'.repeat(64);
      else if(kind==='unknown')f.state.events.find((e:any)=>e.event_kind==='outcome').outcome='sent-unknown';else f.state.legacy.find((n:any)=>n.entity_type==='hmac-auth').restore_state='failed';};
    await expect(f.invoke()).rejects.toBeDefined();expect(f.state.sent).toEqual(['new-1']);expect(f.state.receipts).toHaveLength(1);expect(f.workflow.state).toBe('partial');
  });
  it.each(['foreign','history','custody','baseline'])('stops %s invalidity before either new packet emits',async kind=>{
    const f=fixture();f.state.onPrepare=()=>{if(kind==='foreign')f.state.foreignUnknown=true;else if(kind==='history')f.state.failHistory=true;else if(kind==='custody')f.state.tamper='custody';else f.state.objects[0].before_hmac='0'.repeat(64);};
    await expect(f.invoke()).rejects.toBeDefined();expect(f.state.sent).toEqual([]);expect(f.state.receipts).toEqual([]);expect(f.workflow.state).toBe('failed');
  });
  it.each(['session','grant','lease'])('preserves an already observed result after %s revocation and forbids the next send',async kind=>{
    const f=fixture();f.state.onOutcome=(p:any)=>{if(p.order!==1)return;if(kind==='session')f.state.revoked=true;else if(kind==='grant')f.state.permissionChanged=true;else f.state.leaseExpired=true;};
    await expect(f.invoke()).rejects.toBeDefined();expect(f.state.sent).toEqual(['new-1']);expect(f.state.receipts).toHaveLength(1);
    expect(f.state.events.filter((e:any)=>e.event_kind==='outcome'&&e.outcome==='succeeded')).toHaveLength(1);expect(f.workflow.state).toBe('partial');
  });
  it('records the genuine first response after both source and ALS deadlines pass without reopening a context',async()=>{
    vi.useFakeTimers();const f=fixture();f.state.onOutcome=(p:any)=>{if(p.order===1)vi.setSystemTime(Date.now()+300001);};
    await expect(f.invoke()).rejects.toBeDefined();expect(f.state.sent).toEqual(['new-1']);expect(f.state.receipts).toHaveLength(1);
    expect(f.state.events.filter((e:any)=>e.event_kind==='outcome'&&e.outcome==='succeeded')).toHaveLength(1);expect(f.workflow.state).toBe('partial');
  });
  it('rejects changed prior raw configuration and extra current descendants instead of shrinking the graph',async()=>{
    for(const extra of [false,true]){const f=fixture();f.state.onPrepare=()=>{if(extra)f.graphs.capture.mockImplementation(async()=>({...f.graph, purpose:'baseline',nodes:[...f.graph.nodes.slice(0,5),{...f.graph.nodes[5],id:randomUUID()}]}));else{const first=[...f.state.live.keys()][0];f.state.live.set(first,{...f.state.live.get(first),username:'changed'});}};
      await expect(f.invoke()).rejects.toBeDefined();expect(f.state.sent).toEqual([]);}
  });
});
