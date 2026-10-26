import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { WorkflowCandidatesService } from './workflow-candidates.service';
import { assertWorkflowCandidateFeasibility, normalizeWorkflowApprovalPolicy } from './workflow-approval-policy';
import type { WorkflowApprovalCheckpoint, WorkflowApprovalPolicyV2, WorkflowApprovalSet, WorkflowCandidateManifest, WorkflowReviewerPolicy,
  WorkflowScheduledApprovalFactsReader, WorkflowScheduledApprovalFactsVerifier, WorkflowScheduledConfigurationCanonicalSqlPolicy } from './workflow-approval.types';
import type { WorkflowKind, WorkflowPlanV1 } from './workflow.types';

/** Immutable approval facts and current reviewer eligibility. This service
 * neither installs execution contexts nor creates native write authority. */
/** SQL052 platform override; evaluated inside the caller's transaction. */
export async function selfApprovalPermitted(tx: DbService, userId: string): Promise<boolean> {
  const row = await tx.one<{ ok: boolean }>('SELECT m11_self_approval_permitted($1) AS ok', [userId]);
  return row?.ok === true;
}

@Injectable()
export class WorkflowApprovalAuthorityService {
  private readonly policies = new Map<WorkflowKind, WorkflowReviewerPolicy>();
  private scheduledFactsInstalled = false;
  private scheduledConfigurationFactsInstalled = false;
  private scheduledConfigurationOriginSqlInstalled = false;
  private scheduledPortalInspectionSqlInstalled = false;
  private scheduledConfigurationSql?: Readonly<WorkflowScheduledConfigurationCanonicalSqlPolicy>;
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly candidates: WorkflowCandidatesService) {}
  installReviewerPolicy(kind: WorkflowKind, policy: WorkflowReviewerPolicy): void {
    if (this.policies.has(kind) || !policy || typeof policy.verifyCurrent !== 'function' || Object.keys(policy).some(key => key !== 'verifyCurrent')) throw new ConflictException({ code: 'WORKFLOW_REVIEWER_POLICY_ALREADY_INSTALLED' });
    this.policies.set(kind, Object.freeze(policy));
  }
  /** The returned closure stays in the fixed Authority, rather than exposing
   * a public facts-only API or caller-selectable verification mode. Format 1
   * deliberately retains its existing full reviewer policy. */
  installScheduledEligibilityFactsReader(verifier: WorkflowScheduledApprovalFactsVerifier): WorkflowScheduledApprovalFactsReader {
    if (this.scheduledFactsInstalled || !verifier || typeof verifier.enter !== 'function' || typeof verifier.leave !== 'function'
      || Object.keys(verifier).some(key => !['enter', 'leave'].includes(key))) throw new ConflictException({ code: 'WORKFLOW_SCHEDULE_APPROVAL_FACTS_ALREADY_INSTALLED' });
    const fixed = Object.freeze({ enter: verifier.enter.bind(verifier), leave: verifier.leave.bind(verifier) });
    this.scheduledFactsInstalled = true;
    return Object.freeze(async (original: object, plan: WorkflowPlanV1, input: Readonly<{ checkpoint: WorkflowApprovalCheckpoint }>, tx: DbService) => {
      await fixed.enter(original, plan, input.checkpoint, tx);
      try { return await this.verifySet(plan, input, tx, 'scheduled-facts'); }
      finally { await fixed.leave(original, plan, input.checkpoint, tx); }
    });
  }
  installScheduledConfigurationCanonicalSqlPolicy(policy: WorkflowScheduledConfigurationCanonicalSqlPolicy): void {
    if (this.scheduledConfigurationSql || !policy || typeof policy.verifyCurrent !== 'function' || Object.keys(policy).some(key => key !== 'verifyCurrent'))
      throw new ConflictException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_SQL_POLICY_ALREADY_INSTALLED' });
    this.scheduledConfigurationSql = Object.freeze({ verifyCurrent: policy.verifyCurrent.bind(policy) });
  }
  /** This separate private closure is consumed only by Authority's original
   * Namespace invocation. Ordinary verification and the background reader keep
   * their existing complete behavior. No caller-selectable facts flag exists. */
  installScheduledConfigurationEligibilityFactsReader(verifier: WorkflowScheduledApprovalFactsVerifier): WorkflowScheduledApprovalFactsReader {
    if (this.scheduledConfigurationFactsInstalled || !verifier || typeof verifier.enter !== 'function' || typeof verifier.leave !== 'function'
      || Object.keys(verifier).some(key => !['enter', 'leave'].includes(key))) throw new ConflictException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ALREADY_INSTALLED' });
    const fixed = Object.freeze({ enter: verifier.enter.bind(verifier), leave: verifier.leave.bind(verifier) });
    this.scheduledConfigurationFactsInstalled = true;
    return Object.freeze(async (original: object, plan: WorkflowPlanV1, input: Readonly<{ checkpoint: WorkflowApprovalCheckpoint }>, tx: DbService) => {
      await fixed.enter(original, plan, input.checkpoint, tx);
      try { return await this.verifySet(plan, input, tx, 'namespace-configuration-sql'); }
      finally { await fixed.leave(original, plan, input.checkpoint, tx); }
    });
  }
  /** A separate bootstrap-only reader for Origin's closed checkpoint witness.
   * Its fixed Authority gate requires its own exact original frame/token/tx;
   * it cannot enter the ordinary Namespace or background facts readers. */
  installScheduledConfigurationOriginSqlReader(verifier: WorkflowScheduledApprovalFactsVerifier): WorkflowScheduledApprovalFactsReader {
    if (this.scheduledConfigurationOriginSqlInstalled || !verifier || typeof verifier.enter !== 'function' || typeof verifier.leave !== 'function'
      || Object.keys(verifier).some(key => !['enter', 'leave'].includes(key))) throw new ConflictException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_ALREADY_INSTALLED' });
    const fixed = Object.freeze({ enter: verifier.enter.bind(verifier), leave: verifier.leave.bind(verifier) });
    this.scheduledConfigurationOriginSqlInstalled = true;
    return Object.freeze(async (original: object, plan: WorkflowPlanV1, input: Readonly<{ checkpoint: WorkflowApprovalCheckpoint }>, tx: DbService) => {
      await fixed.enter(original, plan, input.checkpoint, tx);
      try { return await this.verifySet(plan, input, tx, 'namespace-configuration-sql', 2); }
      finally { await fixed.leave(original, plan, input.checkpoint, tx); }
    });
  }
  /** Portal-only SQL closing for one genuinely completed Namespace inspection.
   * No API can select this facts mode; the fixed Authority consumes its own
   * one-shot original token and still compares every current grant snapshot. */
  installScheduledPortalInspectionSqlReader(verifier:WorkflowScheduledApprovalFactsVerifier):WorkflowScheduledApprovalFactsReader{
    if(this.scheduledPortalInspectionSqlInstalled||!verifier||typeof verifier.enter!=='function'||typeof verifier.leave!=='function'
      ||Object.keys(verifier).some(key=>!['enter','leave'].includes(key)))throw new ConflictException({code:'WORKFLOW_SCHEDULE_PORTAL_INSPECTION_SQL_ALREADY_INSTALLED'});
    const fixed=Object.freeze({enter:verifier.enter.bind(verifier),leave:verifier.leave.bind(verifier)});this.scheduledPortalInspectionSqlInstalled=true;
    return Object.freeze(async(original:object,plan:WorkflowPlanV1,input:Readonly<{checkpoint:WorkflowApprovalCheckpoint}>,tx:DbService)=>{
      if(plan.kind!=='portal-credential-issue'||!('scheduling'in plan))throw new ForbiddenException({code:'WORKFLOW_SCHEDULE_PORTAL_INSPECTION_ORIGINAL_REQUIRED'});
      await fixed.enter(original,plan,input.checkpoint,tx);
      try{return await this.verifySet(plan,input,tx,'scheduled-facts',2);}
      finally{await fixed.leave(original,plan,input.checkpoint,tx);}
    });
  }
  private async reviewer(plan: WorkflowPlanV1, reviewerId: string, tx: DbService, checkpoint: WorkflowApprovalCheckpoint, required = true): Promise<void> {
    const policy = this.policies.get(plan.kind);
    if (!policy) { if (required) throw new ConflictException({ code: 'WORKFLOW_REVIEWER_POLICY_UNAVAILABLE' }); return; }
    await policy.verifyCurrent(reviewerId, plan, tx, checkpoint);
  }
  private async definition(plan: WorkflowPlanV1, tx: DbService): Promise<{ row: any; format: 1 | 2; policy: WorkflowApprovalPolicyV2 | null }> {
    const row = await tx.one<any>(`SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4`, [plan.clusterId, plan.workspaceId, plan.definition.id, plan.definition.version]);
    if (!row || row.policy_hash !== plan.definition.policyHash || this.secrets.fingerprint(row.policy) !== row.policy_hash || ![1, 2].includes(Number(row.approval_format))) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_POLICY_INVALID' });
    const format = Number(row.approval_format) as 1 | 2;
    if (format === 1) {
      if (row.mode !== 'single' || row.allow_self_approval !== false) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_POLICY_INVALID' });
      return { row, format, policy: null };
    }
    const policy = normalizeWorkflowApprovalPolicy(row.policy, plan.kind);
    if (this.secrets.fingerprint(policy) !== row.policy_hash || row.allow_self_approval !== false) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_POLICY_INVALID' });
    return { row, format, policy };
  }
  async formatForDefinition(plan: WorkflowPlanV1, tx: DbService = this.db): Promise<1 | 2> { return (await this.definition(plan, tx)).format; }
  async freezeSubmission(plan: WorkflowPlanV1, tx: DbService): Promise<{ approvalFormat: 1 | 2; candidateVersion: number | null; candidateManifestHmac: string | null }> {
    await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    const { format, policy } = await this.definition(plan, tx);
    if (format === 1 || !plan.approvalRequired) return { approvalFormat: format, candidateVersion: null, candidateManifestHmac: null };
    const hash = this.secrets.fingerprint(plan);
    const stages: WorkflowCandidateManifest['stages'][number][] = [];
    for (const stage of policy!.stages) {
      const candidates = await this.candidates.resolve(plan, stage.selector, id => this.reviewer(plan, id, tx, 'vote'), tx);
      stages.push(Object.freeze({ level: stage.level, mode: stage.mode, threshold: stage.mode === 'all' ? candidates.length : stage.threshold!, candidates: Object.freeze(candidates) }));
    }
    assertWorkflowCandidateFeasibility(stages, policy!.distinctAcrossStages);
    const manifest: WorkflowCandidateManifest = { version: 1, clusterId: plan.clusterId, workspaceId: plan.workspaceId, workflowId: plan.workflowId, planRevision: plan.planRevision, planHash: hash, definitionId: plan.definition.id, definitionVersion: plan.definition.version, policyHash: plan.definition.policyHash, candidateVersion: 1, stages };
    const hmac = this.secrets.fingerprint(manifest);
    await tx.exec(`INSERT INTO workflow_candidate_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,definition_id,definition_version,policy_hash,manifest_hmac,manifest) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10::jsonb)`, [plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision, hash, plan.definition.id, plan.definition.version, plan.definition.policyHash, hmac, JSON.stringify(manifest)]);
    for (const stage of stages) {
      await tx.exec(`INSERT INTO workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,required_approvals,state,activated_at,approval_format,stage_mode,candidate_version,candidate_manifest_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $6=1 THEN now() ELSE NULL END,2,$9,1,$10)`, [plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision, hash, stage.level, stage.threshold, stage.level === 1 ? 'active' : 'pending', stage.mode, hmac]);
      for (const candidate of stage.candidates) await tx.exec(`INSERT INTO workflow_candidates(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac,level,user_id,credential_epoch,provenance) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10::jsonb)`, [plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision, hash, hmac, stage.level, candidate.userId, candidate.credentialEpoch, JSON.stringify(candidate.provenance)]);
    }
    await tx.exec(`UPDATE workflows SET candidate_version=1,candidate_manifest_hmac=$2 WHERE id=$1 AND approval_format=2 AND candidate_version IS NULL`, [plan.workflowId, hmac]);
    return { approvalFormat: 2, candidateVersion: 1, candidateManifestHmac: hmac };
  }
  private async facts(plan: WorkflowPlanV1, tx: DbService): Promise<{ row: any; version: any; format: 1 | 2; policy: WorkflowApprovalPolicyV2 | null; stages: any[]; decisions: any[]; manifest: WorkflowCandidateManifest | null }> {
    const row = await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [plan.workflowId, plan.clusterId, plan.workspaceId]);
    const version = await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4', [plan.workflowId, plan.clusterId, plan.workspaceId, plan.planRevision]);
    const { format, policy } = await this.definition(plan, tx), hash = this.secrets.fingerprint(plan);
    if (!row || !version || row.plan_revision !== plan.planRevision || row.plan_hash !== hash || version.plan_hash !== hash || row.definition_id !== plan.definition.id || row.definition_version !== plan.definition.version
      || row.approval_required !== plan.approvalRequired || version.approval_required !== plan.approvalRequired || Number(row.approval_format) !== format || Number(version.approval_format) !== format) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_BINDING_INVALID' });
    const stages = await tx.query<any>('SELECT * FROM workflow_stages WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level', [plan.workflowId, plan.clusterId, plan.workspaceId, plan.planRevision]);
    const decisions = await tx.query<any>('SELECT * FROM workflow_approvals WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 ORDER BY level,approver_id,id', [plan.workflowId, plan.clusterId, plan.workspaceId, plan.planRevision]);
    if (!plan.approvalRequired) {
      if (stages.length || decisions.length || row.approved_by !== null || row.approval_set_id !== null) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_BINDING_INVALID' });
      return { row, version, format, policy, stages, decisions, manifest: null };
    }
    if (format === 1) return { row, version, format, policy, stages, decisions, manifest: null };
    const candidateVersion = await tx.one<any>('SELECT * FROM workflow_candidate_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5', [plan.workflowId, plan.clusterId, plan.workspaceId, plan.planRevision, row.candidate_version]);
    const manifest = candidateVersion?.manifest as WorkflowCandidateManifest | undefined;
    if (!manifest || this.secrets.fingerprint(manifest) !== candidateVersion.manifest_hmac || candidateVersion.manifest_hmac !== row.candidate_manifest_hmac
      || manifest.version !== 1 || manifest.clusterId !== plan.clusterId || manifest.workspaceId !== plan.workspaceId || manifest.workflowId !== plan.workflowId || manifest.planRevision !== plan.planRevision || manifest.planHash !== hash
      || manifest.definitionId !== plan.definition.id || manifest.definitionVersion !== plan.definition.version || manifest.policyHash !== plan.definition.policyHash || manifest.candidateVersion !== row.candidate_version || stages.length !== policy!.stages.length || manifest.stages.length !== stages.length) throw new ConflictException({ code: 'WORKFLOW_CANDIDATE_MANIFEST_INVALID' });
    const candidates = await tx.query<any>('SELECT * FROM workflow_candidates WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND candidate_version=$5 ORDER BY level,user_id', [plan.workflowId, plan.clusterId, plan.workspaceId, plan.planRevision, row.candidate_version]);
    const expected = manifest.stages.flatMap(stage => stage.candidates.map(candidate => ({ level: stage.level, ...candidate })));
    if (candidates.length !== expected.length || candidates.some((candidate, index) => candidate.plan_hash !== hash || candidate.manifest_hmac !== row.candidate_manifest_hmac || candidate.level !== expected[index].level || candidate.user_id !== expected[index].userId || String(candidate.credential_epoch) !== expected[index].credentialEpoch || this.secrets.fingerprint(candidate.provenance) !== this.secrets.fingerprint(expected[index].provenance))) throw new ConflictException({ code: 'WORKFLOW_CANDIDATE_MANIFEST_INVALID' });
    for (const [index, stage] of stages.entries()) {
      const frozen = manifest.stages[index], definitionStage = policy!.stages[index];
      if (stage.level !== index + 1 || stage.plan_hash !== hash || stage.approval_format !== 2 || stage.candidate_version !== row.candidate_version || stage.candidate_manifest_hmac !== row.candidate_manifest_hmac
        || stage.stage_mode !== frozen.mode || frozen.mode !== definitionStage.mode || stage.required_approvals !== frozen.threshold || frozen.threshold !== (definitionStage.mode === 'all' ? frozen.candidates.length : definitionStage.threshold)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_STAGE_INVALID' });
    }
    assertWorkflowCandidateFeasibility(manifest.stages, policy!.distinctAcrossStages);
    return { row, version, format, policy, stages, decisions, manifest };
  }
  async assertCanVote(plan: WorkflowPlanV1, input: { reviewerId: string; level: number; stageRevision: number; candidateVersion: number; decision?: 'approve' | 'reject' }, tx: DbService): Promise<void> {
    const facts = await this.facts(plan, tx);
    if (facts.format !== 2 || !plan.approvalRequired || facts.row.state !== 'pending' || input.candidateVersion !== facts.row.candidate_version || Date.parse(facts.row.expires_at) <= Date.now()) throw new ConflictException({ code: 'WORKFLOW_NOT_APPROVABLE' });
    const stage = facts.stages.find(stage => stage.level === input.level);
    if (!stage || stage.state !== 'active' || stage.revision !== input.stageRevision || facts.stages.some(previous => previous.level < stage.level && previous.state !== 'approved')) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_STAGE_CHANGED' });
    const frozen = facts.manifest!.stages.find(stage => stage.level === input.level)!, candidate = frozen.candidates.find(candidate => candidate.userId === input.reviewerId);
    const self = plan.requester.type === 'console' && input.reviewerId === plan.requester.id;
    // Super-admin self-approval (SQL052): the requester is never a frozen candidate; the platform override replaces candidacy.
    if (self && (input.decision === 'reject' || !await selfApprovalPermitted(tx, input.reviewerId))) throw new ForbiddenException({ code: 'WORKFLOW_SELF_APPROVAL_FORBIDDEN' });
    if (!self && !candidate) throw new ForbiddenException({ code: 'WORKFLOW_APPROVAL_CANDIDATE_REQUIRED' });
    if (facts.decisions.some(vote => vote.approver_id === input.reviewerId && (vote.level === input.level || facts.policy!.distinctAcrossStages))) throw new ConflictException({ code: 'WORKFLOW_APPROVER_ALREADY_DECIDED' });
    if (!self) await this.candidates.assertCurrent(plan, candidate!, tx); await this.reviewer(plan, input.reviewerId, tx, 'vote');
    await this.validateDecisions(plan, facts, tx, 'vote', input.decision !== 'reject');
  }
  async assertVoteFeasible(plan: WorkflowPlanV1, reviewerId: string, level: number, tx: DbService): Promise<void> {
    const facts = await this.facts(plan, tx);
    if (facts.format === 2 && facts.policy!.distinctAcrossStages) {
      const used = new Set<string>(facts.decisions.filter(vote => vote.decision === 'approve').map(vote => vote.approver_id));
      used.add(reviewerId);
      const remaining = facts.manifest!.stages.filter(stage => stage.level >= level).map(stage => ({ ...stage, threshold: stage.threshold - facts.decisions.filter(vote => vote.level === stage.level && vote.decision === 'approve').length - (stage.level === level ? 1 : 0) })).filter(stage => stage.threshold > 0);
      if (remaining.length) assertWorkflowCandidateFeasibility(remaining, true, used);
    }
  }
  private async validateDecisions(plan: WorkflowPlanV1, facts: Awaited<ReturnType<WorkflowApprovalAuthorityService['facts']>>, tx: DbService, checkpoint: WorkflowApprovalCheckpoint, current = true, reviewerPolicy: boolean | 'namespace-configuration-sql' = true): Promise<void> {
    const used = new Set<string>();
    for (const vote of facts.decisions) {
      const stage = facts.manifest!.stages.find(stage => stage.level === vote.level), candidate = stage?.candidates.find(candidate => candidate.userId === vote.approver_id);
      const self = vote.is_self_approval === true;
      const selfValid = self && plan.requester.type === 'console' && vote.approver_id === plan.requester.id && vote.decision === 'approve';
      if (!stage || (self ? !selfValid : !candidate) || vote.plan_hash !== facts.row.plan_hash || vote.candidate_version !== facts.row.candidate_version || vote.candidate_manifest_hmac !== facts.row.candidate_manifest_hmac
        || !self && plan.requester.type === 'console' && vote.approver_id === plan.requester.id || facts.policy!.distinctAcrossStages && used.has(vote.approver_id)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_FACT_INVALID' });
      // Re-check the override on every current checkpoint (seal / execute): switching it off or demoting the super-admin blocks execution.
      if (self && current && !await selfApprovalPermitted(tx, vote.approver_id)) throw new ConflictException({ code: 'WORKFLOW_SELF_APPROVAL_REVOKED' });
      used.add(vote.approver_id); if (current) { if (!self) await this.candidates.assertCurrent(plan, candidate!, tx);
        if (reviewerPolicy === 'namespace-configuration-sql') await this.scheduledConfigurationSql!.verifyCurrent(vote.approver_id, plan, tx);
        else if (reviewerPolicy) await this.reviewer(plan, vote.approver_id, tx, checkpoint); }
    }
  }
  async sealApprovalSet(plan: WorkflowPlanV1, tx: DbService): Promise<WorkflowApprovalSet> {
    const facts = await this.facts(plan, tx);
    if (facts.format !== 2 || !plan.approvalRequired) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_INVALID' });
    await this.validateDecisions(plan, facts, tx, 'seal');
    if (facts.decisions.some(vote => vote.decision !== 'approve') || facts.stages.some(stage => stage.state !== 'approved' || facts.decisions.filter(vote => vote.level === stage.level).length !== stage.required_approvals)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_INCOMPLETE' });
    const reviewers = facts.decisions.map(vote => Object.freeze({ approvalId: vote.id, userId: vote.approver_id, level: vote.level, candidateVersion: vote.candidate_version, ...(vote.is_self_approval === true ? { selfApproval: true as const } : {}) }));
    const setId = randomUUID(), material = { version: 1, clusterId: plan.clusterId, workspaceId: plan.workspaceId, workflowId: plan.workflowId, planRevision: plan.planRevision, planHash: facts.row.plan_hash, policyHash: plan.definition.policyHash, candidateVersion: facts.row.candidate_version, candidateManifestHmac: facts.row.candidate_manifest_hmac, reviewers }, setHmac = this.secrets.fingerprint(material);
    await tx.exec(`INSERT INTO workflow_approval_sets(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,policy_hash,candidate_version,candidate_manifest_hmac,set_hmac,manifest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, [setId, plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision, facts.row.plan_hash, plan.definition.policyHash, facts.row.candidate_version, facts.row.candidate_manifest_hmac, setHmac, JSON.stringify(material)]);
    for (const reviewer of reviewers) await tx.exec(`INSERT INTO workflow_approval_set_members(cluster_id,workspace_id,set_id,set_hmac,workflow_id,plan_revision,plan_hash,approval_id,level,user_id,candidate_version,candidate_manifest_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [plan.clusterId, plan.workspaceId, setId, setHmac, plan.workflowId, plan.planRevision, facts.row.plan_hash, reviewer.approvalId, reviewer.level, reviewer.userId, reviewer.candidateVersion, facts.row.candidate_manifest_hmac]);
    const changed = await tx.exec('UPDATE workflows SET approval_set_id=$2,approval_set_hmac=$3 WHERE id=$1 AND approval_set_id IS NULL AND approval_format=2', [plan.workflowId, setId, setHmac]);
    if (changed !== 1) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_CHANGED' });
    return Object.freeze({ format: 2, policyHash: plan.definition.policyHash, setId, setHmac, reviewers: Object.freeze(reviewers) });
  }
  async verifyApprovalSet(plan: WorkflowPlanV1, input: { executionId?: string; checkpoint: WorkflowApprovalCheckpoint }, tx: DbService = this.db): Promise<WorkflowApprovalSet> {
    return this.verifySet(plan, input, tx, 'full');
  }
  private async verifySet(plan: WorkflowPlanV1, input: { executionId?: string; checkpoint: WorkflowApprovalCheckpoint }, tx: DbService,
    mode: 'full' | 'scheduled-facts' | 'namespace-configuration-sql', requiredFormat?: 2): Promise<WorkflowApprovalSet> {
    if (mode === 'scheduled-facts' && (!('scheduling' in plan) || !['configuration_v2', 'portal-credential-issue', 'entity-annotation', 'control-metadata', 'configuration-metadata', 'governance-metadata', 'workflow-policy-metadata', 'iam-metadata', 'portal-metadata', 'portal-developer-review', 'event-metadata'].includes(plan.kind)))
      throw new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_APPROVAL_FACTS_ORIGINAL_REQUIRED' });
    if (mode === 'namespace-configuration-sql' && (!('scheduling' in plan) || plan.kind !== 'configuration_v2'))
      throw new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED' });
    const epochBefore = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    const facts = await this.facts(plan, tx);
    // Only the fixed Origin reader supplies literal 2. A forged/downgraded
    // SQL format must fail before the legacy format-1 full-policy fallback.
    if (requiredFormat !== undefined && facts.format !== requiredFormat)
      throw new ConflictException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_FORMAT_INVALID' });
    const empty = Object.freeze({ format: facts.format, policyHash: plan.definition.policyHash, setId: null, setHmac: null, reviewers: Object.freeze([]) });
    if (!plan.approvalRequired) return empty;
    if (facts.format === 1) {
      if (facts.stages.length !== 1 || facts.stages[0].plan_hash !== facts.row.plan_hash || facts.stages[0].level !== 1 || facts.stages[0].required_approvals !== 1 || facts.stages[0].state !== 'approved' || facts.decisions.length !== 1 || facts.decisions[0].plan_hash !== facts.row.plan_hash || facts.decisions[0].decision !== 'approve' || facts.decisions[0].level !== 1 || facts.decisions[0].approver_id !== facts.row.approved_by || facts.row.approved_by === facts.row.requester_user_id && !(facts.row.self_approved === true && facts.decisions[0].is_self_approval === true)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_INCOMPLETE' });
      const selfV1 = facts.row.self_approved === true && facts.decisions[0].is_self_approval === true;
      if (selfV1 && !await selfApprovalPermitted(tx, facts.row.approved_by)) throw new ConflictException({ code: 'WORKFLOW_SELF_APPROVAL_REVOKED' });
      await this.reviewer(plan, facts.row.approved_by, tx, input.checkpoint, false);
      return Object.freeze({ ...empty, reviewers: Object.freeze([Object.freeze({ approvalId: facts.decisions[0].id, userId: facts.row.approved_by, level: 1, candidateVersion: null, ...(selfV1 ? { selfApproval: true as const } : {}) })]) });
    }
    if (mode !== 'full' && !this.policies.has(plan.kind)) throw new ConflictException({ code: 'WORKFLOW_REVIEWER_POLICY_UNAVAILABLE' });
    if (mode === 'namespace-configuration-sql' && !this.scheduledConfigurationSql) throw new ConflictException({ code: 'WORKFLOW_SCHEDULE_CONFIGURATION_SQL_POLICY_UNAVAILABLE' });
    await this.validateDecisions(plan, facts, tx, input.checkpoint, true, mode === 'namespace-configuration-sql' ? mode : mode === 'full');
    if (facts.decisions.some(vote => vote.decision !== 'approve') || facts.stages.some(stage => stage.state !== 'approved' || facts.decisions.filter(vote => vote.level === stage.level).length !== stage.required_approvals)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_INCOMPLETE' });
    const set = await tx.one<any>('SELECT * FROM workflow_approval_sets WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6', [facts.row.approval_set_id, plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision, facts.row.plan_hash]);
    const reviewers = facts.decisions.map(vote => Object.freeze({ approvalId: vote.id, userId: vote.approver_id, level: vote.level, candidateVersion: vote.candidate_version, ...(vote.is_self_approval === true ? { selfApproval: true as const } : {}) }));
    const material = { version: 1, clusterId: plan.clusterId, workspaceId: plan.workspaceId, workflowId: plan.workflowId, planRevision: plan.planRevision, planHash: facts.row.plan_hash, policyHash: plan.definition.policyHash, candidateVersion: facts.row.candidate_version, candidateManifestHmac: facts.row.candidate_manifest_hmac, reviewers };
    if (!set || set.set_hmac !== facts.row.approval_set_hmac || this.secrets.fingerprint(set.manifest) !== set.set_hmac || this.secrets.fingerprint(material) !== set.set_hmac
      || !reviewers.some(reviewer => reviewer.userId === facts.row.approved_by && reviewer.level === facts.stages.length)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_INVALID' });
    const members = await tx.query<any>('SELECT * FROM workflow_approval_set_members WHERE set_id=$1 ORDER BY level,user_id,approval_id', [set.id]);
    if (members.length !== reviewers.length || members.some((member, index) => member.cluster_id !== plan.clusterId || member.workspace_id !== plan.workspaceId || member.workflow_id !== plan.workflowId || member.plan_revision !== plan.planRevision || member.plan_hash !== facts.row.plan_hash || member.set_hmac !== set.set_hmac || member.approval_id !== reviewers[index].approvalId || member.user_id !== reviewers[index].userId || member.level !== reviewers[index].level || member.candidate_version !== facts.row.candidate_version || member.candidate_manifest_hmac !== facts.row.candidate_manifest_hmac)) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SET_INVALID' });
    if (input.executionId) {
      const execution = await tx.one<any>('SELECT * FROM workflow_executions WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5 AND plan_hash=$6', [input.executionId, plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision, facts.row.plan_hash]);
      if (!execution || execution.approval_format !== 2 || execution.approval_set_id !== set.id || execution.approval_set_hmac !== set.set_hmac) throw new ConflictException({ code: 'WORKFLOW_EXECUTION_APPROVAL_SET_INVALID' });
    }
    const invalidation = await tx.one<any>('SELECT id FROM workflow_approval_invalidations WHERE set_id=$1 LIMIT 1', [set.id]);
    if (invalidation) throw new ForbiddenException({ code: 'WORKFLOW_APPROVAL_SET_INVALIDATED' });
    const epochAfter = await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
    if (!epochBefore || !epochAfter || String(epochBefore.version) !== String(epochAfter.version)) throw new ForbiddenException({ code: 'WORKFLOW_APPROVAL_PERMISSIONS_CHANGED' });
    return Object.freeze({ format: 2, policyHash: plan.definition.policyHash, setId: set.id, setHmac: set.set_hmac, reviewers: Object.freeze(reviewers) });
  }
  async projection(plan: WorkflowPlanV1, tx: DbService = this.db): Promise<Record<string, unknown>> {
    const facts = await this.facts(plan, tx);
    return { format: facts.format, policyHash: plan.definition.policyHash, candidateVersion: facts.row.candidate_version, distinctAcrossStages: facts.policy?.distinctAcrossStages ?? true, stages: facts.stages.map(stage => ({ level: stage.level, name: facts.policy?.stages.find(definition => definition.level === stage.level)?.name ?? '管理员审批', mode: stage.stage_mode, threshold: stage.required_approvals, state: stage.state, revision: stage.revision, candidateCount: facts.manifest?.stages.find(frozen => frozen.level === stage.level)?.candidates.length ?? null, votes: facts.decisions.filter(vote => vote.level === stage.level && vote.decision === 'approve').length })), approvalSetId: facts.row.approval_set_id };
  }
}
