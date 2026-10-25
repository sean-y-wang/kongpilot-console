import{describe,it,expect,beforeEach,afterEach,vi}from'vitest';
import{configurationApprovedFixture as fixture,id}from'./m8-configuration-approved-fixture';
import{snapshotAad}from'../../apps/console-api/src/modules/workflows/workflow.types';
describe('M8 true V2 approval capability',()=>{
  beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-secret-with-at-least-thirty-two-characters');});afterEach(()=>vi.unstubAllEnvs());
  it('mints only private proof/step/binding and binds full SQL reciprocal tuple',async()=>{const f=await fixture();await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,async()=>{
    const binding=await f.context.approvedMutationBinding(f.mutation);expect(binding).toMatchObject({version:2,configurationJobId:f.jobId,configurationExecutionId:f.executionId,configurationStepId:f.jobStepId});
    f.operations.set(id(19),f.op(binding));await f.context.bindApprovedOperation(f.mutation,binding!,id(19),f.db);expect(f.rows[0].operation_id).toBe(id(19));
  })));});
  it('accepts genuine PostgreSQL bigint-text user/session epochs against int4 configuration epoch',async()=>{
    const f=await fixture();f.session.credential_epoch='1';f.session.user_epoch='1';
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).resolves.toBeUndefined();
  });
  it.each(['userChanged','sessionChanged','jobChanged','zero','leadingZero','space','exponent','float','overflow','unsafeNumber','boolean','object','missing'])('rejects %s DB epoch before V2 capability mint',async(which)=>{
    const f=await fixture();f.session.credential_epoch='1';f.session.user_epoch='1';
    if(which==='userChanged')f.session.user_epoch='2';if(which==='sessionChanged')f.session.credential_epoch='2';if(which==='jobChanged')f.job.credential_epoch=2;
    const bad:any={zero:'0',leadingZero:'01',space:' 1',exponent:'1e0',float:1.5,overflow:'2147483648',unsafeNumber:Number.MAX_SAFE_INTEGER+1,boolean:true,object:{valueOf:()=>1},missing:undefined};
    if(Object.hasOwn(bad,which))f.session.credential_epoch=bad[which];
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_SESSION_INVALID'}});
    expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects fabricated execution and copied proof outside active private mint',async()=>{const f=await fixture();await f.run(async()=>{await expect(f.verifier.verifyExecution({}as any)).rejects.toThrow();await expect(f.verifier.verifyStep({executionId:f.executionId}as any,f.jobStepId)).rejects.toThrow();});});
  it.each(['claim','session','actor','mode','physical','permission','lease','approver','approval','wrapper','baseline','material','encryptedStep','rowBody','rowPacket','dependency','nativeBudget'])("rejects %s tampering before issuing capability",async(which)=>{const f=await fixture();
    if(which==='claim')f.claim.claimHash='0'.repeat(64);if(which==='session')f.session.credential_epoch=2;if(which==='actor')f.claim.actorId=id(88);if(which==='mode')f.cluster.execution_mode='direct';if(which==='physical')f.cluster.transport_scope='0'.repeat(64);
    if(which==='permission')f.authz.permissionVersion.mockResolvedValue('changed');if(which==='lease')f.job.lease_until=new Date(0);if(which==='approver')f.approval.status='disabled';if(which==='approval')f.stage.state='active';
    if(which==='wrapper')f.wrapperVersion.plan_hash='0'.repeat(64);if(which==='baseline')f.baseline.manifest_hmac='0'.repeat(64);if(which==='material')f.material.state='destroyed';if(which==='encryptedStep')f.objects[0].payload_ciphertext=f.version.manifest_ciphertext;
    if(which==='rowBody')f.objects[0].body_hmac='0'.repeat(64);if(which==='rowPacket')f.objects[0].native_requests[0].path_hmac='0'.repeat(64);if(which==='dependency'){f.step.dependencies=[f.step.stepId];await f.seal();}if(which==='nativeBudget')f.version.native_packet_count=501;
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toThrow();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['actor','cid','wid','body','before','entity','key','parent','action'])("rejects logical %s mutation mismatch before INSERT binding",async(which)=>{const f=await fixture();await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,async()=>{
    const input={...f.mutation};if(which==='actor')input.actor={...f.actor,id:id(88)};if(which==='cid')input.clusterId=id(88);if(which==='wid')input.workspaceId=id(88);if(which==='body')input.payload={...input.payload,host:'foreign'};if(which==='before')input.before={id:f.nativeId};if(which==='entity')input.entityId=null;if(which==='key')input.idempotencyKey='foreign-original-key';if(which==='parent')input.parentId=id(88);if(which==='action')input.action='delete';await expect(f.context.approvedMutationBinding(input)).rejects.toThrow();
  })));});
  it('rejects copied V2 binding and wrong reciprocal operation; original binding remains private',async()=>{const f=await fixture();await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,async()=>{
    const binding=await f.context.approvedMutationBinding(f.mutation);f.operations.set(id(19),f.op(binding));await expect(f.context.bindApprovedOperation(f.mutation,{...binding!},id(19),f.db)).rejects.toThrow();f.operations.get(id(19)).configuration_step_id=id(88);await expect(f.context.bindApprovedOperation(f.mutation,binding!,id(19),f.db)).rejects.toThrow();expect(f.rows[0].operation_id).toBeNull();
  })));});
  it('cannot use configuration cap to mutate Portal historical authentication boundary',async()=>{const f=await fixture();await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,async()=>{
    await expect(f.verifier.assertNativeWrite({clusterId:f.cid,workspaceId:f.wid,transportScope:f.job.transport_scope,operationId:id(19),method:'POST',canonicalPath:'/consumers',body:{},before:null,mutationAction:'create'})).rejects.toThrow();
  })));});
  it('keeps execution anchor while proving another exact object workspace for a native step',async()=>{const f=await fixture(),objectWid=id(44);f.step.objectWorkspaceId=objectWid;f.rows[0].object_workspace_id=objectWid;await f.seal();f.mutation.workspaceId=objectWid;
    await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,()=>f.context.runActor({actor:f.actor,clusterId:f.cid,workspaceId:objectWid},async()=>{
      const binding=await f.context.approvedMutationBinding(f.mutation);expect(binding).toMatchObject({version:2,configurationJobId:f.jobId});
      await expect(f.context.approvedMutationBinding({...f.mutation,workspaceId:f.wid})).rejects.toThrow();
    }))));
  });
  it('checks actual-before at send and rejects created response IDs, changed grants and foreign native tuples',async()=>{const f=await fixture();await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,async()=>{
    const binding=await f.context.approvedMutationBinding(f.mutation);f.operations.set(id(19),f.op(binding));await f.context.bindApprovedOperation(f.mutation,binding!,id(19),f.db);
    f.operations.get(id(19)).remote_started=true;
    const input:any={clusterId:f.cid,workspaceId:f.wid,transportScope:f.job.transport_scope,operationId:id(19),method:'POST',canonicalPath:'/services',body:f.step.body,before:null,mutationAction:'create',frame:f.context.current(),cluster:f.cluster,query:{}};
    const proof=f.context.currentApprovedStep();await expect(f.verifier.assertNative(proof,input,'before-send')).resolves.toBeUndefined();
    await expect(f.verifier.assertNative(proof,{...input,query:{offset:'foreign'}},'authorize')).rejects.toThrow();
    await expect(f.verifier.assertNative(proof,{...input,result:{id:id(88)}},'response')).rejects.toThrow();
    f.kong.request.mockResolvedValue({id:f.nativeId,host:'external-change'});await expect(f.verifier.assertNative(proof,input,'before-send')).rejects.toMatchObject({response:{code:'CONFIGURATION_CURRENT_BEFORE_CHANGED'}});
    f.job.lease_generation=2;await expect(f.verifier.assertNative(proof,input,'response')).rejects.toThrow();
  })));});
  it('rejects a forged normalized actual object workspace despite correctly sealed plan',async()=>{const f=await fixture();f.objects[0].object_workspace_id=id(88);await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toThrow();});
  it.each(['alreadySucceeded','merelyApproved','wrapperPending','foreignWrapper','duplicateWrapper','nativeWrapper','wrapperPayload','wrapperRevision','executionId','executionActor','executionState','executionVersion','snapshotPending','snapshotExpired','snapshotHash','snapshotForeign','snapshotNative'])('rejects %s without the original running M6 metadata-only execution',async(which)=>{
    const f=await fixture();
    if(which==='alreadySucceeded')f.workflow.state='succeeded';if(which==='merelyApproved')f.workflow.state='approved';
    if(which==='wrapperPending')f.wrapperRows[0].state='pending';if(which==='foreignWrapper')f.wrapperRows[0].workflow_id=id(88);
    if(which==='duplicateWrapper')f.wrapperRows.push({...f.wrapperRows[0],id:id(88)});if(which==='nativeWrapper')f.wrapperRows[0].native_requests=[{method:'POST',path_hash:'a'.repeat(64)}];
    if(which==='wrapperPayload')f.wrapperRows[0].metadata_payload_hmac='0'.repeat(64);if(which==='wrapperRevision')f.wrapperRows[0].metadata_revision=2;
    if(which==='executionId')f.claim.workflowExecutionId=id(88);if(which==='executionActor')f.wrapperExecution.execution_actor_id=id(88);
    if(which==='executionState')f.wrapperExecution.state='succeeded';if(which==='executionVersion')f.wrapperExecution.plan_revision=2;
    if(which==='snapshotPending')f.wrapperExecution.snapshot_state='pending';if(which==='snapshotExpired')f.wrapperExecution.expires_at=new Date(0);
    if(which==='snapshotHash')f.wrapperExecution.snapshot_hash='0'.repeat(64);
    if(which==='snapshotForeign'||which==='snapshotNative'){
      const snapshot={...f.wrapperSnapshot,executionId:which==='snapshotForeign'?id(88):f.wrapperExecution.id,objects:which==='snapshotNative'?[{type:'services',id:f.nativeId}]:[]};
      f.wrapperExecution.snapshot_hash=f.secrets.fingerprint(snapshot);f.wrapperExecution.snapshot_secret=f.secrets.encrypt(snapshot,snapshotAad(f.cid,f.wid,f.workflow.id,f.wrapperExecution.id));
    }
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toThrow();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('proves target append against original before and fresh allocated ID, with no duplicate native intent after ACK',async()=>{
    const f=await fixture(),allocated=id(55),parent=id(56),before={id:f.nativeId,target:'upstream.internal:80',weight:50,upstream:{id:parent}},body={id:allocated,target:'upstream.internal:80',weight:100};
    Object.assign(f.step,{entityType:'targets',mutationAction:'update',nativeId:f.nativeId,allocatedNativeId:allocated,parentType:'upstreams',parentId:parent,objectKey:`targets:${parent}:${f.nativeId}`,body,before,bodyHmac:f.secrets.fingerprint(body),beforeHmac:f.secrets.fingerprint(before),nativeRequests:[{method:'POST',canonicalPath:`/upstreams/${parent}/targets`,body,bodyHmac:f.secrets.fingerprint(body),beforeHmac:f.secrets.fingerprint(before)}]});
    f.rows[0].before_hmac=f.step.beforeHmac;await f.seal();Object.assign(f.mutation,{entityType:'targets',action:'update',parentId:parent,payload:body,before});
    await f.run(()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,async()=>{
      const binding=await f.context.approvedMutationBinding(f.mutation),op={...f.op(binding),entity_type:'targets',action:'update',parent_id:parent,payload_secret:f.secrets.encrypt(body,`mutation:${id(19)}:payload`),before_secret:f.secrets.encrypt(before,`mutation:${id(19)}:before`)};
      f.operations.set(id(19),op);await f.context.bindApprovedOperation(f.mutation,binding!,id(19),f.db);
      op.remote_started=true;
      const input:any={clusterId:f.cid,workspaceId:f.wid,transportScope:f.job.transport_scope,operationId:id(19),method:'POST',canonicalPath:`/upstreams/${parent}/targets`,body,before,mutationAction:'update',parentId:parent,frame:f.context.current(),cluster:f.cluster,query:{}},proof=f.context.currentApprovedStep();
      f.kong.request.mockImplementation(async(_cid:any,_method:any,path:any)=>{if(path.endsWith(`/${f.nativeId}`))return before;const e:any=new Error('absent');e.status=404;throw e;});
      await expect(f.verifier.assertNative(proof,input,'before-send')).resolves.toBeUndefined();expect(f.kong.request.mock.calls.map(c=>c[2])).toEqual([`${input.canonicalPath}/${f.nativeId}`,`${input.canonicalPath}/${allocated}`]);
      f.kong.request.mockResolvedValue(before);await expect(f.verifier.assertNative(proof,input,'before-send')).rejects.toMatchObject({response:{code:'CONFIGURATION_TARGET_APPEND_ID_OCCUPIED'}});
      await expect(f.verifier.assertNative(proof,{...input,result:{id:allocated}},'response')).resolves.toBeUndefined();
      await expect(f.verifier.assertNative(proof,{...input,result:{id:f.nativeId}},'response')).rejects.toThrow();
      Object.assign(op,{remote_completed:true,entity_id:allocated});await expect(f.verifier.assertNative(proof,input,'authorize')).rejects.toThrow();
    })));
  });
  it('rejects sealed POST request with a different created ID before authority mint',async()=>{const f=await fixture();f.step.nativeRequests[0].body={...f.step.body,id:id(88)};f.step.nativeRequests[0].bodyHmac=f.secrets.fingerprint(f.step.nativeRequests[0].body);await f.seal();await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toThrow();});
});
