import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityRecycleOriginReaderService } from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-origin-reader.service';
import { auditCanonicalRecord } from '../../apps/console-api/src/modules/audit/audit-integrity.service';
import { certifyTerminalRecycleMetadata } from '../../apps/console-api/src/modules/workflows/entity-change-terminal-metadata-proof';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { decodeEntityExecutionSource } from '../../apps/console-api/src/modules/workflows/entity-change-source-codec';
import { entityChangeIntentAad, normalizedEntityChangePackets } from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import { entityBaselineAad, entityPacketFactAad } from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import { PARTIAL_RECYCLE_FACTS_MIGRATION, partialRestoreObservationAad } from '../../apps/console-api/src/modules/recycle-bin/partial-recycle-restore';
import { terminalMetadataFixture } from './helpers/terminal-metadata-fixture';

/** Isolated SELECT-only historical coverage tests. Real AEAD/HMAC, production
 * terminal certificate and audit hashing run against synthetic rows. Calling
 * the private reader isolates this new historical half; readClosedOrigin still
 * validates the complete original DELETE archive first. No SQL is executed,
 * Kong or private ledger contacted, runtime authority issued or wire inferred. */
async function originalFixture(parentAwareGraphKeys = false) {
  const f = terminalMetadataFixture({ parentAwareGraphKeys }); f.closeProjection();
  const certificate = await certifyTerminalRecycleMetadata(f.input);
  const rows = f.rows, source = f.source, envelope = f.envelope, plan = f.plan;
  const common = { cluster_id: source.clusterId, workspace_id: source.workspaceId };
  const tuple = { ...common, intent_id: source.intentId, intent_revision: source.intentRevision, material_hmac: source.materialHmac,
    change_digest: source.changeDigest, packet_manifest_hmac: source.packetManifestHmac };
  rows.entity_change_intents = [{ ...common, id: source.intentId, requester_id: source.executionActorId, credential_epoch: source.credentialEpoch,
    issued_at: envelope.issuedAt, expires_at: envelope.expiresAt }];
  Object.assign(rows.entity_change_intent_versions[0], { requester_id: source.executionActorId, credential_epoch: source.credentialEpoch,
    issued_at: envelope.issuedAt, expires_at: envelope.expiresAt, safe_review: envelope.review, execution_mode: envelope.executionMode,
    definition_id: envelope.definition.id, definition_version: envelope.definition.version, policy_hash: envelope.definition.policyHash });
  rows.workflows = [{ ...common, id: source.workflowId, state: 'partial', kind: 'native-change', subject_type: 'entity_change_intents', subject_id: source.intentId,
    requester_type: 'console', requester_user_id: source.executionActorId, plan_revision: source.workflowPlanRevision, plan_hash: source.workflowPlanHash }];
  Object.assign(rows.workflow_executions[0], { execution_actor_id: source.executionActorId, plan_revision: source.workflowPlanRevision, plan_hash: source.workflowPlanHash });
  rows.workflow_versions = [{ ...common, workflow_id: source.workflowId, plan_revision: source.workflowPlanRevision, plan_hash: source.workflowPlanHash,
    payload_secret: f.secrets.encrypt(plan, planAad(source.clusterId, source.workspaceId, source.workflowId, source.workflowPlanRevision)) }];
  rows.entity_change_submissions = [{ ...tuple, workflow_id: source.workflowId, actor_id: source.executionActorId,
    workflow_plan_revision: source.workflowPlanRevision, workflow_plan_hash: source.workflowPlanHash }];
  const after = { executionId: source.workflowExecutionId, sourceId: source.id, entryId: f.entryId, operationId: certificate.failedOperationId,
    outcomeEventId: certificate.outcomeEventId, outcomeFactHmac: certificate.outcomeFactHmac, proofHmac: certificate.proofHmac,
    requestHmac: f.secrets.fingerprint('synthetic-original-metadata-request'), workflowState: 'partial', executionState: 'partial', operationState: 'failed',
    entryState: 'partially_restored', nodeRestoreState: 'failed', nativeSuccesses: 5, knownNotSent: 1, unattempted: 1, nativeRequestsSent: 0, metadataReconciled: true };
  const audit: any = { ...common, id: randomUUID(), chain_scope: `cluster:${source.clusterId}`, sequence: '1', actor_id: source.executionActorId,
    actor_type: 'user', source_ip: '127.0.0.1', entity_type: 'workflows', entity_id: source.workflowId, workflow_id: source.workflowId,
    action: 'workflow.execute.terminal-metadata-reconciled', result: 'failed', request_id: 'synthetic-original-request', prev_hash: 'GENESIS',
    before: { operationState: 'uncertain', entryState: 'restoring', nodeRestoreState: 'pending' }, after, json_patch: [],
    occurred_at: new Date().toISOString(), event_hash: '0'.repeat(64), millisecond_precision: true };
  const rehashAudit = () => { audit.event_hash = createHash('sha256').update(canonicalJson(auditCanonicalRecord(audit))).digest('hex'); };
  rehashAudit(); rows.audit_events = [audit];
  const select = (sql: string, params: any[]) => {
    if (!/^SELECT\s/i.test(sql) || /FOR\s+(UPDATE|SHARE)/i.test(sql)) throw new Error('Synthetic coverage adapter permits SELECT only');
    if (sql.startsWith('SELECT EXISTS(')) return [f.foreign];
    if (sql.includes('FROM schema_migrations'))return structuredClone(rows.schema_migrations ?? []);
    if (sql.includes('FROM entity_change_recycle_restore_present_facts'))return structuredClone((rows.entity_change_recycle_restore_present_facts ?? []).filter(r=>r.source_id===params[0]&&r.entry_id===params[1]));
    if (sql.includes('FROM recycle_nodes'))return structuredClone(rows.recycle_nodes.filter(r=>r.entry_id===params[0]));
    const table = /\bFROM\s+(\w+)/i.exec(sql)?.[1]; if (!table || !rows[table]) throw new Error('Unexpected synthetic coverage SELECT');
    if(table==='entity_change_recycle_nodes')return structuredClone(rows[table].filter(r=>r.entry_id===params[0]).sort((a,b)=>a.node_order-b.node_order));
    if(table==='recycle_entries')return structuredClone(rows[table].filter(r=>r.cluster_id===params[0]&&r.workspace_id===params[1]&&r.id===params[2]));
    if(table==='entity_change_recycle_archives')return structuredClone(rows[table].filter(r=>r.cluster_id===params[0]&&r.workspace_id===params[1]&&r.entry_id===params[2]));
    if (sql.startsWith('SELECT DISTINCT source_id')) {
      const ids = rows[table].filter(r => r.cluster_id === params[0] && r.workspace_id === params[1] && r.entry_id === params[2]
        && r.direction === 'restore' && r.source_id !== params[3]).map(r => r.source_id);
      return [...new Set(ids)].map(source_id => ({ source_id }));
    }
    let selected = rows[table];
    if (table === 'entity_change_baseline_pins') selected = selected.filter(r => r.id === params[0] && r.baseline_id === params[1]);
    else if (table === 'entity_change_baseline_objects') selected = selected.filter(r => r.baseline_id === params[0]).sort((a, b) => a.object_order - b.object_order);
    else {
      selected = selected.filter(r => r.cluster_id === params[0] && r.workspace_id === params[1]);
      if (['entity_change_execution_sources', 'entity_change_intents', 'entity_change_baselines', 'workflows', 'workflow_executions'].includes(table)) selected = selected.filter(r => r.id === params[2]);
      else if (table === 'workflow_versions') selected = selected.filter(r => r.workflow_id === params[2] && r.plan_revision === params[3]);
      else if (table === 'entity_change_submissions') selected = selected.filter(r => r.workflow_id === params[2]);
      else if (table === 'entity_change_intent_versions' || table === 'entity_change_intent_packets') selected = selected.filter(r => r.intent_id === params[2] && r.intent_revision === params[3]);
      else if (table === 'audit_events') selected = selected.filter(r => r.workflow_id === params[2] && (params.length===6?r.actor_id===params[3]&&r.after.sourceId===params[4]&&r.after.entryId===params[5]:r.after.sourceId===params[3]&&r.after.entryId===params[4]));
      else if (table === 'mutation_operations') selected = selected.filter(r => r.entity_change_source_id === params[2]);
      else selected = selected.filter(r => r.source_id === params[2] && (params.length < 4 || r.entry_id === params[3]));
    }
    return structuredClone(selected.sort((a, b) => (a.packet_order ?? 0) - (b.packet_order ?? 0)));
  };
  const db: any = { one: vi.fn(async (sql: string, params: any[] = []) => select(sql, params)[0] ?? null), query: vi.fn(async (sql: string, params: any[] = []) => select(sql, params)),
    exec: vi.fn(async () => { throw new Error('No SQL exec permitted'); }), transaction: vi.fn(async (fn: any) => fn(db)) };
  const reader = new EntityRecycleOriginReaderService(db, f.secrets), delegate = { assertCurrentScope: vi.fn(async () => undefined), assertFrozenSubject: vi.fn(async () => undefined) };
  reader.installFixedDelegate(delegate);
  const input = { clusterId: source.clusterId, workspaceId: source.workspaceId, entryId: f.entryId, actor: f.actor, subjectAction: 'write' as const };
  const read = (active: string | null = null) => (reader as any).closedRestoreCoverage(input, rows.entity_change_recycle_archives[0], f.graph, rows.recycle_entries[0], rows.recycle_nodes, db, active);
  const noWrites = () => { expect(db.exec).not.toHaveBeenCalled(); expect(f.txMock.exec).not.toHaveBeenCalled(); };
  return { ...f, db, reader, delegate, input, read, audit, rehashAudit, certificate, noWrites };
}

/** All rows below are synthetic and signed locally. This exercises SELECT-only
 * authentication, not an applied migration, real Root permit or native call. */
async function fixture(){
  const f=await originalFixture(),history=await f.read(),h=(value:any)=>f.secrets.fingerprint(value),rows=f.rows;
  rows.schema_migrations=[PARTIAL_RECYCLE_FACTS_MIGRATION];rows.entity_change_recycle_restore_present_facts=[];
  const add=async(closed=true)=>{
    const sourceId=randomUUID(),intentId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID(),baselineId=randomUUID(),pinId=randomUUID(),operationId=randomUUID(),attemptId=randomUUID();
    const packets=f.packets.slice(5).map((p:any,i:number)=>({...structuredClone(p),key:`remaining-${sourceId}-${i}`,order:i+1,dependencies:[]}));
    const selection:any={version:1,history,presentNodes:history.presentNodes.map((p:any)=>({nodeKey:p.nodeKey,beforeHmac:p.resultHmac,...(p.nativeType==='basic-auth'?{basicCustodyHmac:h('synthetic sealed Basic custody')}:{})})),remainingNodeKeys:history.remainingNodes.map((p:any)=>p.nodeKey)};
    selection.selectionHmac=h(selection);
    const oldObligation=f.envelope.prepared.metadataObligations.find((o:any)=>o.kind==='recycle-restore'),obligation={...structuredClone(oldObligation),partialRestore:selection,packetKeys:packets.map((p:any)=>p.key),sealedEntry:{...oldObligation.sealedEntry,state:'partially_restored'}};
    const material:any={...structuredClone(f.envelope.prepared),packets,metadataObligations:[...packets.map((p:any)=>({kind:'credential-remember',packetKey:p.key,consumerId:f.consumerId,credentialKind:p.nativeType,rawInput:p.body})),obligation]};
    delete material.changeDigest;material.changeDigest=h(material);
    const manifest=normalizedEntityChangePackets(material,f.secrets),envelope={...structuredClone(f.envelope),intentId,prepared:material,packetManifestHmac:h(manifest),review:{version:1,changeDigest:material.changeDigest}};
    const metadata={intentId,intentRevision:1,materialHmac:h(envelope),changeDigest:material.changeDigest,packetManifestHmac:h(manifest)};
    const plan={...structuredClone(f.plan),workflowId,subject:{type:'entity_change_intents',id:intentId},steps:[{...structuredClone(f.plan.steps[0]),id:randomUUID(),entityId:intentId,metadata,metadataPayloadHmac:h(metadata)}]};
    const tuple={cluster_id:f.source.clusterId,workspace_id:f.source.workspaceId,intent_id:intentId,intent_revision:1,material_hmac:h(envelope),change_digest:material.changeDigest,packet_manifest_hmac:h(manifest)};
    const sourceRow={...structuredClone(f.sourceRow),...tuple,id:sourceId,workflow_id:workflowId,workflow_execution_id:executionId,workflow_plan_hash:h(plan)},source=decodeEntityExecutionSource(sourceRow);
    rows.entity_change_execution_sources.push(sourceRow);
    rows.entity_change_intents.push({...tuple,id:intentId,requester_id:source.executionActorId,credential_epoch:'1',issued_at:envelope.issuedAt,expires_at:envelope.expiresAt});
    rows.entity_change_intent_versions.push({...tuple,requester_id:source.executionActorId,credential_epoch:'1',issued_at:envelope.issuedAt,expires_at:envelope.expiresAt,safe_review:envelope.review,execution_mode:envelope.executionMode,
      definition_id:envelope.definition.id,definition_version:envelope.definition.version,policy_hash:envelope.definition.policyHash,packet_count:2,packet_manifest:manifest,envelope_ciphertext:f.secrets.encrypt(envelope,entityChangeIntentAad(source.clusterId,source.workspaceId,intentId,1))});
    const intentPackets=manifest.map((p:any)=>({...tuple,packet_key:p.key,packet_order:p.order,dependencies:p.dependencies,method:p.method,path_hmac:p.pathHmac,native_type:p.nativeType,native_id:p.nativeId,parent_id:p.parentId,credential_kind:p.credentialKind,original_native_id:p.originalNativeId,
      mutation_action:p.mutationAction,permission_action:p.permissionAction,body_hmac:p.bodyHmac,before_hmac:p.beforeHmac}));rows.entity_change_intent_packets.push(...intentPackets);
    const common={cluster_id:source.clusterId,workspace_id:source.workspaceId},completed=new Date().toISOString();
    rows.workflows.push({...common,id:workflowId,state:'failed',kind:'native-change',subject_type:'entity_change_intents',subject_id:intentId,requester_type:'console',requester_user_id:source.executionActorId,plan_revision:1,plan_hash:h(plan)});
    rows.workflow_executions.push({...common,id:executionId,workflow_id:workflowId,state:'failed',plan_revision:1,plan_hash:h(plan),execution_actor_id:source.executionActorId,completed_at:completed});
    rows.workflow_versions.push({...common,workflow_id:workflowId,plan_revision:1,plan_hash:h(plan),payload_secret:f.secrets.encrypt(plan,planAad(source.clusterId,source.workspaceId,workflowId,1))});
    rows.entity_change_submissions.push({...tuple,workflow_id:workflowId,actor_id:source.executionActorId,workflow_plan_revision:1,workflow_plan_hash:h(plan)});
    const captureObjects=f.graph.nodes.map((n:any,i:number)=>{const prior=history.presentNodes.find((p:any)=>p.nodeKey===n.key),selected=selection.presentNodes.find((p:any)=>p.nodeKey===n.key),provenance=i<5?
      {kind:'closed-restore-current-present',nodeKey:n.key,historyCoverageHmac:history.coverageHmac,priorSourceId:history.sourceId,priorAttemptId:prior.attemptId,priorOperationId:prior.operationId,priorResultHmac:prior.resultHmac,beforeHmac:selected.beforeHmac,...(selected.basicCustodyHmac?{basicCustodyHmac:selected.basicCustodyHmac}:{})}:{kind:'native-get-404'};
      return{key:i?`${n.type}:${f.consumerId}:${n.id}`:n.key,nativeType:n.type,nativeId:n.id,...(i?{parentId:f.consumerId,credentialKind:n.type}:{}),affected:i>=5,present:i<5,dependencies:n.dependencies,before:i<5?n.data:null,schemaMaterial:{fixture:'signed schema'},trustedProvenance:provenance,recovery:i<5?'reference':'absent'};});
    const objects=[captureObjects[0],...captureObjects.slice(1).sort((a:any,b:any)=>a.key.localeCompare(b.key))],graph={...structuredClone(f.graph),purpose:'baseline',nodes:f.graph.nodes.slice(0,5).map((n:any,i:number)=>({...structuredClone(n),key:i?`${n.type}:${f.consumerId}:${n.id}`:n.key}))};
    const capture={version:1,observedFrom:f.baseline.observed_from,observedUntil:f.baseline.observed_until,objects,graphs:[graph],blockerCodes:[],nonreversiblePacketKeys:[]},bEnvelope={version:1,baselineId,source,capture};
    const normalized=objects.map((o:any)=>({key:o.key,nativeType:o.nativeType,nativeId:o.nativeId,parentId:o.parentId??null,credentialKind:o.credentialKind??null,affected:o.affected,present:o.present,dependencies:o.dependencies,beforeHmac:h(o.before),restoreHmac:null,schemaHmac:h(o.schemaMaterial),provenanceHmac:h(o.trustedProvenance),recovery:o.recovery}));
    const binding={...common,source_id:sourceId,baseline_id:baselineId,pin_id:pinId,workflow_execution_id:executionId};
    const baseline={...structuredClone(f.baseline),...tuple,id:baselineId,source_id:sourceId,workflow_id:workflowId,workflow_execution_id:executionId,workflow_plan_hash:h(plan),baseline_hmac:h(bEnvelope),capture_hmac:h(capture),object_manifest_hmac:h(normalized),object_manifest:normalized,graph_count:1,material_ciphertext:f.secrets.encrypt(bEnvelope,entityBaselineAad(source.clusterId,source.workspaceId,baselineId))};rows.entity_change_baselines.push(baseline);
    rows.entity_change_baseline_pins.push({...binding,id:pinId,baseline_hmac:baseline.baseline_hmac,object_manifest_hmac:baseline.object_manifest_hmac,pin_version:1,protected_until:obligation.sealedEntry.expiresAt});
    rows.entity_change_baseline_objects.push(...normalized.map((o:any,i:number)=>({...binding,object_manifest_hmac:baseline.object_manifest_hmac,object_order:i+1,object_key:o.key,native_type:o.nativeType,native_id:o.nativeId,parent_id:o.parentId,credential_kind:o.credentialKind,affected:o.affected,present:o.present,dependencies:o.dependencies,before_hmac:o.beforeHmac,restore_hmac:null,schema_hmac:o.schemaHmac,provenance_hmac:o.provenanceHmac,recovery:o.recovery})));
    for(const prior of history.presentNodes){const node=f.graph.nodes.find((n:any)=>n.key===prior.nodeKey),object=objects.find((o:any)=>o.nativeId===node.id),selected=selection.presentNodes.find((p:any)=>p.nodeKey===node.key),fact={version:1,kind:'closed-restore-current-present',sourceId,baselineId,pinId,clusterId:source.clusterId,workspaceId:source.workspaceId,workflowExecutionId:executionId,entryId:f.entryId,nodeKey:node.key,baselineObjectKey:object.key,priorHistory:prior,closedSourceHmac:history.coverageHmac,currentBefore:object.before,provenance:object.trustedProvenance,observedAt:capture.observedUntil};
      rows.entity_change_recycle_restore_present_facts.push({...binding,entry_id:f.entryId,node_key:node.key,direction:'restore',baseline_object_key:object.key,object_manifest_hmac:baseline.object_manifest_hmac,native_type:node.type,native_id:node.id,parent_id:node.type==='consumers'?null:f.consumerId,credential_kind:node.type==='consumers'?null:node.type,prior_attempt_id:prior.attemptId,prior_operation_id:prior.operationId,prior_source_id:history.sourceId,prior_packet_key:prior.packetKey,observed_before_hmac:selected.beforeHmac,prior_result_hmac:prior.resultHmac,closed_source_hmac:history.coverageHmac,basic_custody_hmac:selected.basicCustodyHmac??null,fact_hmac:h(fact),fact_ciphertext:f.secrets.encrypt(fact,partialRestoreObservationAad(source.clusterId,source.workspaceId,sourceId,f.entryId,node.key)),observed_at:fact.observedAt,created_at:completed});}
    rows.entity_change_recycle_packets.push(...intentPackets.map((p:any,i:number)=>{const {dependencies,...rest}=p;return{...rest,...binding,entry_id:f.entryId,node_key:f.graph.nodes[i+5].key,direction:'restore',created_at:capture.observedUntil};}));
    const {dependencies,...first}=intentPackets[0];rows.entity_change_packet_attempts.push({...first,...binding,id:attemptId,created_at:f.rows.entity_change_packet_attempts[0].created_at});
    const oldMutation=f.rows.mutation_operations[5],mutation={...structuredClone(oldMutation),...common,id:operationId,workflow_id:workflowId,idempotency_key:`entity-${executionId}-1`,state:'failed',before_secret:f.secrets.encrypt(null,`mutation:${operationId}:before`),payload_secret:f.secrets.encrypt(packets[0].body,`mutation:${operationId}:payload`),error_code:'ENTITY_RECYCLE_PARTIAL_CURRENT_CHANGED',entity_change_source_id:sourceId,entity_change_baseline_id:baselineId,entity_change_attempt_id:attemptId,entity_change_packet_key:packets[0].key};rows.mutation_operations.push(mutation);
    const fact={version:1,kind:'outcome',binding:{sourceId,baselineId,pinId,packetKey:packets[0].key,attemptId},observedAt:f.rows.entity_change_packet_events[1].observed_at,outcome:'failed-known-not-sent',errorCode:mutation.error_code,evidence:{operationId,mutationState:'failed',remoteCompleted:false,responseHmac:null,metadataComplete:false}};
    const event={...binding,id:randomUUID(),attempt_id:attemptId,event_kind:'outcome',outcome:fact.outcome,native_status:null,error_code:fact.errorCode,fact_hmac:h(fact),fact_ciphertext:f.secrets.encrypt(fact,entityPacketFactAad(source.clusterId,source.workspaceId,attemptId,'outcome')),observed_at:fact.observedAt,created_at:completed};rows.entity_change_packet_events.push(event);
    const certify=()=>f.reader.certifyKnownNoSendPartialSource(f.input,sourceId,f.db),certificate=await certify();
    let audit:any;
    if(closed){audit={...structuredClone(f.audit),id:randomUUID(),entity_id:workflowId,workflow_id:workflowId,before:{operationState:'failed',entryState:'restoring',nodeRestoreState:'pending'},after:{shape:'partial-no-send',executionId,sourceId,entryId:f.entryId,operationId,outcomeEventId:event.id,outcomeFactHmac:event.fact_hmac,proofHmac:certificate.proofHmac,requestHmac:h('synthetic independent metadata request'),workflowState:'failed',executionState:'failed',operationState:'failed',entryState:'partially_restored',nodeRestoreState:'failed',coveredPresent:5,nativeSuccesses:0,knownNotSent:1,unattempted:1,nativeRequestsSent:0,metadataReconciled:true},occurred_at:new Date().toISOString()};audit.event_hash=createHash('sha256').update(canonicalJson(auditCanonicalRecord(audit))).digest('hex');rows.audit_events.push(audit);}
    return{sourceId,source,sourceRow,workflowId,executionId,intentId,baseline,selection,envelope,mutation,event,attemptId,operationId,packets,audit,certify,certificate};
  };
  return{...f,history,add};
}

const invalid={response:{code:'RECYCLE_ENTITY_ORIGIN_INVALID'}};
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ad'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());
describe('SELECT-only failed two-packet zero-send restore footprints',()=>{
  it.each([1,2,3])('authenticates %i independently closed zero-send sources while keeping the unique five-success history seal',async count=>{
    const f=await fixture();for(let i=0;i<count;i++)await f.add();const before=structuredClone(f.rows),coverage=await f.read();
    expect(coverage).toEqual(f.history);expect(coverage.presentNodes).toHaveLength(5);expect(coverage.remainingNodes).toHaveLength(2);expect(f.rows).toEqual(before);f.noWrites();
  });
  it('certifies pre-metadata evidence without treating a missing closure audit as closed for a new intent',async()=>{
    const f=await fixture(),z=await f.add(false);f.rows.recycle_entries[0].state='restoring';f.rows.recycle_nodes[5].restore_state='pending';
    const certificate=await z.certify();expect(certificate.alreadyClosed).toBe(false);expect(certificate.proofHmac).toBe(z.certificate.proofHmac);
    await expect(f.read()).rejects.toMatchObject(invalid);f.rows.recycle_entries[0].state='partially_restored';f.rows.recycle_nodes[5].restore_state='failed';
    await expect(f.read()).rejects.toMatchObject(invalid);f.noWrites();
  });
  it('authenticates the real failed-node before state without inventing a pending transition',async()=>{
    const f=await fixture(),z=await f.add(),proof=z.audit.after.proofHmac;
    z.audit.before.nodeRestoreState='failed';z.audit.event_hash=createHash('sha256').update(canonicalJson(auditCanonicalRecord(z.audit))).digest('hex');
    const before=structuredClone(f.rows);expect(await f.read()).toEqual(f.history);
    expect(z.audit.before).toEqual({operationState:'failed',entryState:'restoring',nodeRestoreState:'failed'});
    expect(z.audit.after).toMatchObject({shape:'partial-no-send',proofHmac:proof,coveredPresent:5,nativeSuccesses:0,knownNotSent:1,unattempted:1,nativeRequestsSent:0});
    expect(f.rows).toEqual(before);f.noWrites();
  });
  it.each([
    ['restored node',(z:any)=>{z.audit.before.nodeRestoreState='restored';}],
    ['uncertain node',(z:any)=>{z.audit.before.nodeRestoreState='uncertain';}],
    ['wrong entry state',(z:any)=>{z.audit.before.entryState='partially_restored';}],
    ['wrong operation state',(z:any)=>{z.audit.before.operationState='uncertain';}],
    ['extra before field',(z:any)=>{z.audit.before.nativeRequestsSent=0;}],
    ['borrowed full-seven recipe',(z:any)=>{delete z.audit.after.shape;z.audit.after.nativeSuccesses=5;}],
  ])('rejects a rehashed audit outside the two-source closure recipe: %s',async(_name,modify)=>{
    const f=await fixture(),z=await f.add();modify(z);z.audit.event_hash=createHash('sha256').update(canonicalJson(auditCanonicalRecord(z.audit))).digest('hex');
    await expect(f.read()).rejects.toMatchObject(invalid);f.noWrites();
  });
  it.each([
    ['send reservation',(f:any,z:any)=>f.rows.entity_change_packet_events.push({...z.event,id:randomUUID(),event_kind:'send-intent'})],
    ['uncertain mutation',(_f:any,z:any)=>{z.mutation.state='uncertain';}],
    ['remote completed',(_f:any,z:any)=>{z.mutation.remote_completed=true;}],
    ['invented result',(f:any,z:any)=>{z.mutation.result_secret=f.secrets.encrypt({},`mutation:${z.mutation.id}:result`);}],
    ['missing outcome',(f:any,z:any)=>{f.rows.entity_change_packet_events=f.rows.entity_change_packet_events.filter((e:any)=>e.source_id!==z.sourceId);}],
    ['sent unknown',(_f:any,z:any)=>{z.event.outcome='sent-unknown';}],
    ['native status',(_f:any,z:any)=>{z.event.native_status=201;}],
    ['ACL attempt',(f:any,z:any)=>f.rows.entity_change_packet_attempts.push({...f.rows.entity_change_packet_attempts.find((a:any)=>a.id===z.attemptId),id:randomUUID(),packet_key:z.packets[1].key})],
    ['fake receipt',(f:any,z:any)=>f.rows.entity_change_recycle_receipts.push({...f.rows.entity_change_recycle_receipts[0],source_id:z.sourceId,attempt_id:z.attemptId})],
    ['missing observation',(f:any,z:any)=>{f.rows.entity_change_recycle_restore_present_facts=f.rows.entity_change_recycle_restore_present_facts.filter((o:any)=>!(o.source_id===z.sourceId&&o.native_type==='basic-auth'));}],
    ['missing 025 ledger',(f:any)=>{f.rows.schema_migrations=[];}],
    ['changed observation HMA',(f:any,z:any)=>{f.rows.entity_change_recycle_restore_present_facts.find((o:any)=>o.source_id===z.sourceId).fact_hmac='0'.repeat(64);}],
    ['wrong observation source AEAD',(f:any,z:any)=>{const o=f.rows.entity_change_recycle_restore_present_facts.find((o:any)=>o.source_id===z.sourceId);o.fact_ciphertext=f.secrets.encrypt({},partialRestoreObservationAad(f.source.clusterId,f.source.workspaceId,randomUUID(),f.entryId,o.node_key));}],
    ['missing baseline object',(f:any,z:any)=>{f.rows.entity_change_baseline_objects=f.rows.entity_change_baseline_objects.filter((o:any)=>!(o.baseline_id===z.baseline.id&&o.native_type==='acls'));}],
    ['workflow still executing',(f:any,z:any)=>{f.rows.workflows.find((w:any)=>w.id===z.workflowId).state='executing';}],
    ['missing completion',(f:any,z:any)=>{f.rows.workflow_executions.find((e:any)=>e.id===z.executionId).completed_at=null;}],
    ['missing closure audit',(f:any,z:any)=>{f.rows.audit_events=f.rows.audit_events.filter((a:any)=>a.id!==z.audit.id);}],
    ['wrong closure proof',(_f:any,z:any)=>{z.audit.after.proofHmac='0'.repeat(64);}],
    ['wrong closure proof with valid content SHA',(_f:any,z:any)=>{z.audit.after.proofHmac='0'.repeat(64);z.audit.event_hash=createHash('sha256').update(canonicalJson(auditCanonicalRecord(z.audit))).digest('hex');}],
    ['wrong closure actor with valid content SHA',(_f:any,z:any)=>{z.audit.actor_id=randomUUID();z.audit.event_hash=createHash('sha256').update(canonicalJson(auditCanonicalRecord(z.audit))).digest('hex');}],
    ['foreign unknown',(f:any)=>{f.foreign.unresolved=true;}],
  ])('never excludes an invalid failed footprint: %s',async(_name,mutate)=>{
    const f=await fixture(),z=await f.add();mutate(f,z);await expect(f.read()).rejects.toBeDefined();f.noWrites();
  });
  it('revalidates old and closed zero-send immutable history after own new progress without ignoring foreign unknown',async()=>{
    const f=await fixture();await f.add();f.rows.recycle_entries[0].state='restored';f.rows.recycle_entries[0].restored_at=new Date().toISOString();
    for(let i=5;i<7;i++){f.rows.recycle_nodes[i].restore_state='restored';f.rows.recycle_nodes[i].restored_id=f.graph.nodes[i].id;}
    const own=randomUUID();await expect(f.reader.verifyFrozenRestoreCoverage(f.input,f.history,own,f.db)).resolves.toBeUndefined();
    f.foreign.unresolved=true;await expect(f.reader.verifyFrozenRestoreCoverage(f.input,f.history,own,f.db)).rejects.toMatchObject(invalid);f.noWrites();
  });
  it('requires the original seven-packet restore source to remain unique',async()=>{
    const f=await fixture(),duplicate=randomUUID();f.rows.entity_change_execution_sources.push({...f.sourceRow,id:duplicate});
    f.rows.entity_change_recycle_packets.push(...f.rows.entity_change_recycle_packets.filter((p:any)=>p.source_id===f.source.id).map((p:any)=>({...p,source_id:duplicate})));
    await expect(f.read()).rejects.toMatchObject(invalid);f.noWrites();
  });
  it('refuses caller-shaped no-wire evidence even when its synthetic event AEAD and HMA are valid',async()=>{
    const f=await fixture(),z=await f.add(),fact:any=f.secrets.decrypt(z.event.fact_ciphertext,entityPacketFactAad(f.source.clusterId,f.source.workspaceId,z.attemptId,'outcome'));
    fact.evidence.wireSpent=false;z.event.fact_hmac=f.secrets.fingerprint(fact);z.event.fact_ciphertext=f.secrets.encrypt(fact,entityPacketFactAad(f.source.clusterId,f.source.workspaceId,z.attemptId,'outcome'));
    await expect(z.certify()).rejects.toBeDefined();await expect(f.read()).rejects.toBeDefined();f.noWrites();
  });
});
