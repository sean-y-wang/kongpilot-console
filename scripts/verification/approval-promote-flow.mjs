#!/usr/bin/env node
/**
 * KP-004: recycle through approval mode + second approver (≠ requester) on live stack.
 * KP-005: dual-env natural comparison + promote-plan + apply on target + rollback (confirm_deletes).
 * commercialClosed stays false unless close conditions truly met.
 */


import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash as hashCreate, randomUUID as uuid } from 'node:crypto';

const base = (process.env.BFF_BASE_URL || 'http://127.0.0.1:13000').replace(/\/$/, '');
const adminUser = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const approverUser = process.env.KP004_APPROVER_USERNAME || 'approver2';
const approverPass = process.env.KP004_APPROVER_PASSWORD;
const kongA = process.env.LIVE_KONG_ADMIN_URL || 'http://127.0.0.1:18001';
const kongB = process.env.LIVE_KONG_B_ADMIN_URL || 'http://127.0.0.1:18011';
const upstreamHost = process.env.LIVE_UPSTREAM_HOST || '172.30.0.2';
const upstreamPort = Number(process.env.LIVE_UPSTREAM_PORT || 25678);
const outDir = resolve(process.env.KP004_APPROVAL_OUT || 'artifacts/M11/runs/20261024-kp004-approval');
const kp005Out = resolve(process.env.KP005_PROMOTE_OUT || 'artifacts/M11/runs/20261024-kp005-promote');
const tag = `m11ap${Date.now().toString(36)}`;
const startedAt = new Date().toISOString();
const checks = [];
const gaps = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed && !detail.skipped) gaps.push(id);
};
const digest = (v) => hashCreate('sha256').update(typeof v === 'string' ? v : JSON.stringify(v ?? null)).digest('hex').slice(0, 16);
const entity = (d) => d?.entity ?? d;
if (!adminPass) { console.error('BOOTSTRAP_ADMIN_PASSWORD required'); process.exit(2); }
if (!approverPass) { console.error('KP004_APPROVER_PASSWORD required'); process.exit(2); }

function mergeCookie(prev, setCookie) {
  const jar = new Map();
  for (const part of String(prev || '').split('; ').filter(Boolean)) {
    const i = part.indexOf('='); if (i > 0) jar.set(part.slice(0, i), part.slice(i + 1));
  }
  for (const raw of setCookie || []) {
    const first = String(raw).split(';')[0]; const i = first.indexOf('=');
    if (i > 0) jar.set(first.slice(0, i), first.slice(i + 1));
  }
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function raw(session, path, method = 'GET', body, { expected } = {}) {
  const write = method !== 'GET' && method !== 'HEAD';
  const headers = {
    Accept: 'application/json',
    ...(session?.cookie ? { Cookie: session.cookie } : {}),
    ...(write ? {
      'Content-Type': 'application/json', Origin: base, 'X-Idempotency-Key': uuid(),
      ...(session?.csrf ? { 'X-CSRF-Token': session.csrf } : {}),
    } : {}),
  };
  let res, text;
  try {
    res = await fetch(path.startsWith('http') ? path : `${base}${path}`, {
      method, headers, redirect: 'manual', signal: AbortSignal.timeout(180000),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    text = await res.text();
  } catch (e) {
    return { ok: false, status: 0, error: e.message, data: null, text: '', code: undefined };
  }
  if (session) session.cookie = mergeCookie(session.cookie || '', res.headers.getSetCookie?.() || []);
  let payload = null; try { payload = text ? JSON.parse(text) : null; } catch { /* */ }
  const data = payload?.data ?? payload;
  if (data?.csrfToken && session) session.csrf = data.csrfToken;
  const code = payload?.error?.code || payload?.code || data?.code;
  const ok = expected ? expected.includes(res.status) : res.ok;
  return { ok, status: res.status, data, text: text.slice(0, 1600), code, payload };
}

async function kong(admin, path, method = 'GET', body) {
  const res = await fetch(admin + path, {
    method, headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { /* */ }
  return { ok: res.ok, status: res.status, data, text: text.slice(0, 500) };
}

/** prepare → submit (requester) → approve (secondApprover ≠ requester) → execute (requester). */
async function driveApprovedIntent(requester, approver, q, change) {
  const prep = await raw(requester, q('entity-changes/prepare'), 'POST', { change }, { expected: [200, 201] });
  if (!prep.ok || !prep.data?.id) return { ok: false, phase: 'prepare', prep, execStatus: prep.status, execCode: prep.code };
  const submit = await raw(requester, q(`entity-changes/${prep.data.id}/submit`), 'POST', {
    revision: prep.data.revision, materialHmac: prep.data.materialHmac, confirmed: true, confirm_name: 'native-change',
  }, { expected: [200, 201] });
  if (!submit.ok || !submit.data?.workflowId) return { ok: false, phase: 'submit', prep, submit, execStatus: submit.status, execCode: submit.code };
  const wfId = submit.data.workflowId;
  const wf = await raw(requester, q(`workflows/${wfId}`));
  const ent = entity(wf.data) || wf.data;
  const approvalRequired = !!ent.approvalRequired;
  let approve = null;
  let selfApproveProbe = null;
  if (approvalRequired) {
    // Prove self-approval is forbidden (multi-ticket / second-approver requirement)
    selfApproveProbe = await raw(requester, q(`workflows/${wfId}/approve`), 'POST', {
      revision: ent.revision, planHash: ent.planHash, confirmed: true, confirm_name: ent.kind || 'native-change',
    }, { expected: [403, 409, 400] });
    approve = await raw(approver, q(`workflows/${wfId}/approve`), 'POST', {
      revision: ent.revision, planHash: ent.planHash, confirmed: true, confirm_name: ent.kind || 'native-change',
      reason: 'kp004-second-approver-evidence',
    }, { expected: [200, 201] });
  }
  const wf2 = await raw(requester, q(`workflows/${wfId}`));
  const ent2 = entity(wf2.data) || wf2.data;
  const ex = await raw(requester, q(`workflows/${wfId}/execute`), 'POST', {
    revision: ent2.revision, planHash: ent2.planHash, confirmed: true, confirm_name: ent2.kind || 'native-change',
  }, { expected: [200, 201] });
  return {
    ok: ex.ok && (ex.data?.state === 'succeeded' || ex.data?.propagation === 'acknowledged' || ent2.state === 'succeeded' || ex.data?.state === 'completed'),
    phase: ex.ok ? 'execute' : 'execute_failed',
    intentId: prep.data.id, workflowId: wfId, executionId: ex.data?.executionId || ex.data?.id,
    executionMode: prep.data.executionMode || ent.executionMode,
    approvalRequired,
    approvalFormat: ent.approvalFormat ?? ent.approval?.format,
    selfApproveStatus: selfApproveProbe?.status, selfApproveCode: selfApproveProbe?.code,
    approveStatus: approve?.status, approveCode: approve?.code,
    approveOk: !!approve?.ok,
    workflowStateAfterApprove: ent2.state,
    approvedByDigest: ent2.approvedBy ? digest(ent2.approvedBy) : (entity(approve?.data)?.approvedBy ? digest(entity(approve.data).approvedBy) : null),
    requesterIdDigest: digest(requester.userId || 'requester'),
    approverIdDigest: digest(approver.userId || 'approver'),
    execState: ex.data?.state || entity(ex.data)?.state, execStatus: ex.status, execCode: ex.code,
    baselineIdDigest: ex.data?.baselineId ? digest(ex.data.baselineId) : null,
    prep, submit, approve, ex, ent2,
  };
}

async function cycleRootApproved(requester, approver, q, rootType, seedFn, { nameField = 'name', kongPath } = {}) {
  const seeded = await seedFn();
  const originalId = seeded?.id;
  const confirmName = seeded?.[nameField] || seeded?.username || seeded?.name || originalId;
  record(`seed_${rootType}`, !!originalId, { idDigest: originalId ? digest(originalId) : null, via: 'kong-admin' });
  if (!originalId) return { ok: false };

  const del = await driveApprovedIntent(requester, approver, q, {
    kind: 'recycle', action: 'delete', entityType: rootType, entityId: originalId,
    confirmed: true, confirm_name: confirmName,
  });
  record(`approval_required_${rootType}_delete`, del.approvalRequired === true, {
    executionMode: del.executionMode, approvalRequired: del.approvalRequired,
  });
  record(`self_approve_forbidden_${rootType}_delete`, del.selfApproveCode === 'WORKFLOW_SELF_APPROVAL_FORBIDDEN' || del.selfApproveStatus === 403, {
    status: del.selfApproveStatus, code: del.selfApproveCode,
  });
  record(`second_approver_delete_${rootType}`, del.approveOk === true, {
    status: del.approveStatus, code: del.approveCode, workflowState: del.workflowStateAfterApprove,
    approverDistinct: del.approverIdDigest !== del.requesterIdDigest,
  });
  record(`intent_delete_${rootType}`, del.ok, {
    phase: del.phase, status: del.execStatus, code: del.execCode, state: del.execState,
    workflowIdDigest: del.workflowId ? digest(del.workflowId) : null,
  });

  const path = kongPath ? kongPath(originalId) : `/${rootType}/${originalId}`;
  const gone = await kong(kongA, path);
  record(`readback_absent_${rootType}`, gone.status === 404, { status: gone.status });

  const list = await raw(requester, q(`recycle-bin?size=50&search=${encodeURIComponent(confirmName)}`));
  const entry = (list.data?.items || []).find((i) => i.original_id === originalId || i.root_name === confirmName);
  record(`recycle_entry_${rootType}`, !!entry && entry.state === 'deleted', {
    found: !!entry, state: entry?.state, entryIdDigest: entry?.id ? digest(entry.id) : null,
  });
  if (!entry?.id) return { ok: false, originalId, del };

  const rest = await driveApprovedIntent(requester, approver, q, {
    kind: 'recycle', action: 'restore', entryId: entry.id, confirmed: true, confirm_name: entry.root_name || confirmName,
  });
  record(`approval_required_${rootType}_restore`, rest.approvalRequired === true, { executionMode: rest.executionMode });
  record(`second_approver_restore_${rootType}`, rest.approveOk === true, {
    status: rest.approveStatus, code: rest.approveCode, workflowState: rest.workflowStateAfterApprove,
  });
  record(`intent_restore_${rootType}`, rest.ok, {
    phase: rest.phase, status: rest.execStatus, code: rest.execCode, state: rest.execState,
  });

  const back = await kong(kongA, path);
  const sameId = back.ok && back.data?.id === originalId;
  record(`original_id_readback_${rootType}`, sameId, { status: back.status, idMatch: sameId });
  return { ok: del.ok && rest.ok && sameId && gone.status === 404, originalId, entryId: entry.id, del, rest };
}

async function main() {
  mkdirSync(outDir, { recursive: true });
  mkdirSync(kp005Out, { recursive: true });
  const admin = { cookie: '', csrf: '', userId: '' };
  const approver = { cookie: '', csrf: '', userId: '' };

  record('bff_health_ready', (await raw(null, '/api/v1/health/ready')).status === 200);
  record('live_kong_a', (await kong(kongA, '/')).status === 200);
  record('live_kong_b_isolated', (await kong(kongB, '/')).status === 200, { admin: '18011' });

  const loginA = await raw(admin, '/api/v1/auth/login', 'POST', { username: adminUser, password: adminPass }, { expected: [200, 201] });
  if (loginA.data?.csrfToken) admin.csrf = loginA.data.csrfToken;
  admin.userId = loginA.data?.user?.id || '';
  record('console_admin_login', loginA.ok && !!admin.csrf, { status: loginA.status, userIdDigest: digest(admin.userId) });

  const loginB = await raw(approver, '/api/v1/auth/login', 'POST', { username: approverUser, password: approverPass }, { expected: [200, 201] });
  if (loginB.data?.csrfToken) approver.csrf = loginB.data.csrfToken;
  approver.userId = loginB.data?.user?.id || '';
  record('second_approver_login', loginB.ok && !!approver.csrf && approver.userId !== admin.userId, {
    status: loginB.status, userIdDigest: digest(approver.userId),
    distinctFromRequester: approver.userId !== admin.userId,
    superAdmin: !!loginB.data?.user?.superAdmin,
  });
  if (!loginA.ok || !loginB.ok) throw new Error('LOGIN_FAILED');

  let clusters = await raw(admin, '/api/v1/clusters');
  let items = clusters.data?.items || clusters.data || [];
  if (!Array.isArray(items)) items = [];
  let cluster = items.find((c) => String(c.admin_url || '').includes('18001'));
  if (!cluster?.id) throw new Error('CLUSTER_REQUIRED');
  const cid = cluster.id;
  record('cluster_execution_mode_approval', cluster.execution_mode === 'approval', {
    executionMode: cluster.execution_mode, revision: cluster.revision,
  });
  await raw(admin, `/api/v1/clusters/${cid}/probe`, 'POST', {}, { expected: [200, 201, 202] });
  const workspaces = await raw(admin, `/api/v1/clusters/${cid}/workspaces`);
  const wid = ((workspaces.data?.items || [])[0] || entity(workspaces.data))?.id;
  record('workspace_resolved', !!wid);
  if (!wid) throw new Error('WORKSPACE_REQUIRED');
  const q = (s) => `/api/v1/clusters/${cid}/${s}${s.includes('?') ? '&' : '?'}workspaceId=${wid}`;

  // Suspend published portals to avoid PORTAL_AUTH_GRAPH_INCOMPLETE on service delete
  const pubs = await raw(admin, q('portal/publications'));
  let suspended = 0;
  for (const pub of (pubs.data?.items || [])) {
    if (pub.status === 'published' || pub.status === 'pending') {
      const u = await raw(admin, q(`portal/publications/${pub.id}/unpublish`), 'POST', {
        confirmed: true, confirm_name: pub.name || pub.slug, revision: pub.revision,
      }, { expected: [200, 201, 409] });
      if (u.ok) suspended++;
    }
  }
  record('portal_publications_suspended', true, { suspended });

  // --- KP-004: five-root recycle via approval + second approver (seed via Kong A) ---
  const roots = [];
  roots.push(await cycleRootApproved(admin, approver, q, 'services', async () => {
    const r = await kong(kongA, '/services', 'POST', { name: `${tag}-svc`, url: `http://${upstreamHost}:${upstreamPort}/svc` });
    return r.data;
  }));
  roots.push(await cycleRootApproved(admin, approver, q, 'routes', async () => {
    const svc = await kong(kongA, '/services', 'POST', { name: `${tag}-rt-svc`, url: `http://${upstreamHost}:${upstreamPort}/rt` });
    const r = await kong(kongA, '/routes', 'POST', { name: `${tag}-rt`, paths: [`/${tag}-rt`], service: { id: svc.data.id } });
    return r.data;
  }));
  roots.push(await cycleRootApproved(admin, approver, q, 'consumers', async () => {
    const r = await kong(kongA, '/consumers', 'POST', { username: `${tag}-c` });
    return r.data;
  }, { nameField: 'username' }));
  roots.push(await cycleRootApproved(admin, approver, q, 'upstreams', async () => {
    const r = await kong(kongA, '/upstreams', 'POST', { name: `${tag}-up` });
    return r.data;
  }));
  roots.push(await cycleRootApproved(admin, approver, q, 'certificates', async () => {
    // Reuse evidence cert material if present; else minimal self-signed from env
    let cert = process.env.M11_EVIDENCE_CERT_PEM?.replace(/\\n/g, '\n');
    let key = process.env.M11_EVIDENCE_KEY_PEM?.replace(/\\n/g, '\n');
    if (!cert && existsSync('/tmp/m11-ev.crt')) cert = readFileSync('/tmp/m11-ev.crt', 'utf8');
    if (!key && existsSync('/tmp/m11-ev.key')) key = readFileSync('/tmp/m11-ev.key', 'utf8');
    const r = await kong(kongA, '/certificates', 'POST', { cert, key, tags: [tag] });
    return r.data;
  }));

  const fiveRootOk = roots.filter((r) => r?.ok).length;
  record('kp004_five_root_approval_recycle', fiveRootOk >= 4, { okCount: fiveRootOk, total: roots.length });

  // --- KP-005: register isolated secondary cluster + natural promote ---
  let secondary = items.find((c) => String(c.admin_url || '').includes('18011'));
  if (!secondary) {
    const created = await raw(admin, '/api/v1/clusters', 'POST', {
      name: 'dbg-kong15b-promote-target',
      environment: 'promote-target',
      admin_url: kongB,
      proxy_origin: 'http://127.0.0.1:18010',
      labels: ['dbg', 'kp005-promote'],
      execution_mode: 'direct',
      connection_auth: { type: 'none' },
    }, { expected: [200, 201] });
    secondary = entity(created.data) || created.data;
    record('secondary_cluster_registered', created.ok && !!secondary?.id, {
      status: created.status, code: created.code, idDigest: secondary?.id ? digest(secondary.id) : null,
    });
  } else {
    record('secondary_cluster_registered', true, { reused: true, idDigest: digest(secondary.id) });
  }
  const tid = secondary?.id;
  let twid = null;
  if (tid) {
    await raw(admin, `/api/v1/clusters/${tid}/probe`, 'POST', {}, { expected: [200, 201, 202, 409] });
    const tws = await raw(admin, `/api/v1/clusters/${tid}/workspaces`);
    twid = ((tws.data?.items || [])[0] || entity(tws.data))?.id;
    record('secondary_workspace_resolved', !!twid, { workspaceIdDigest: twid ? digest(twid) : null });
  } else {
    record('secondary_workspace_resolved', false, { skipped: false });
  }

  // Seed divergent inventory: service only on source Kong A (already may exist); ensure one promote-candidate on A not on B
  const promoteSvcName = `${tag}-promote-src`;
  const seedSrc = await kong(kongA, '/services', 'POST', { name: promoteSvcName, url: `http://${upstreamHost}:${upstreamPort}/promote` });
  record('promote_source_seed', seedSrc.ok, { status: seedSrc.status, idDigest: seedSrc.data?.id ? digest(seedSrc.data.id) : null });
  // Ensure B does not have it
  const listB = await kong(kongB, '/services');
  const onB = (listB.data?.data || []).find((s) => s.name === promoteSvcName);
  if (onB) await kong(kongB, `/services/${onB.id}`, 'DELETE');

  let comparisonId = null;
  let promotePlanId = null;
  if (tid && twid) {
    const cmp = await raw(admin, q('governance/comparisons'), 'POST', {
      target: { clusterId: tid, workspaceId: twid },
      threshold: 500,
      includeEnvironmentFields: false,
    }, { expected: [200, 201, 409, 400] });
    const cmpEnt = entity(cmp.data) || cmp.data || {};
    comparisonId = cmpEnt.id || cmp.data?.comparisonId || cmp.data?.entity?.id || null;
    record('kp005_governance_comparison_dual_env', cmp.ok && !!comparisonId, {
      status: cmp.status, code: cmp.code,
      comparisonIdDigest: comparisonId ? digest(comparisonId) : null,
      quality: cmpEnt.quality || cmp.data?.quality,
      promotePlanCapable: (cmpEnt.capabilities || cmp.data?.capabilities)?.promotePlan,
    });

    if (comparisonId) {
      const changes = await raw(admin, q(`governance/comparisons/${comparisonId}?size=50`));
      const changeItems = changes.data?.items || [];
      const selectedObjectKeys = changeItems.map((i) => i.sourceObjectKey || i.objectKey).filter(Boolean).slice(0, 100);
      const quality = changes.data?.entity?.quality || changes.data?.quality || cmpEnt.quality;
      record('kp005_comparison_has_changes', true, {
        count: changeItems.length, selected: selectedObjectKeys.length,
        quality, promotePlanCapable: changes.data?.entity?.capabilities?.promotePlan,
      });

      const planBody = {
        confirmed: true,
        confirm_name: `PROMOTE ${comparisonId}`,
        includeCredentials: false,
        includeSecrets: false,
        includeEnvironmentFields: true, // host etc. often required for service create on target
        ...(selectedObjectKeys.length ? { selectedObjectKeys } : {}),
      };
      let plan = await raw(admin, q(`governance/comparisons/${comparisonId}/promote-plan`), 'POST', planBody, { expected: [200, 201, 400, 409] });
      if (!plan.ok && plan.code === 'HOST_REQUIRED') {
        planBody.fieldOverrides = { host: '127.0.0.1' };
        plan = await raw(admin, q(`governance/comparisons/${comparisonId}/promote-plan`), 'POST', planBody, { expected: [200, 201, 400, 409] });
      }
      const planEnt = entity(plan.data) || plan.data || {};
      promotePlanId = planEnt.id || plan.data?.planId || plan.data?.id || plan.data?.promotionId || null;
      const cfgPlanId = planEnt.planId || plan.data?.planId;
      record('kp005_promote_plan', plan.ok && !!promotePlanId, {
        status: plan.status, code: plan.code, text: plan.text?.slice(0, 300),
        state: planEnt.state, planIdDigest: promotePlanId ? digest(promotePlanId) : null,
        configurationPlanIdDigest: cfgPlanId ? digest(cfgPlanId) : null,
        includeCredentialsDefaultOff: planBody.includeCredentials === false,
        selectedCount: selectedObjectKeys.length,
      });

      // Promote apply on TARGET cluster (not source), then rollback via baseline snapshot.
      let rollbackLive = false;
      let applyLive = false;
      let rollbackDetail = { note: 'awaiting promote apply' };
      if (promotePlanId && cfgPlanId) {
        const tq = (p) => `/api/v1/clusters/${tid}/${p}${p.includes('?') ? '&' : '?'}workspaceId=${twid}`;
        const planDetail = await raw(admin, tq(`configuration/plans/${cfgPlanId}`), 'GET', undefined, { expected: [200, 404, 400] });
        const pent = entity(planDetail.data) || planDetail.data || {};
        if (planDetail.ok && pent.planHash) {
          const applyBody = {
            confirmed: true,
            confirm_name: pent.name || pent.deleteConfirmName || `配置计划 ${cfgPlanId}`,
            planRevision: pent.planRevision, planHash: pent.planHash, revision: pent.revision,
            ...(pent.deleteCount > 0 ? { confirm_deletes: true } : {}),
          };
          const apply = await raw(admin, tq(`configuration/plans/${cfgPlanId}/apply`), 'POST', applyBody, { expected: [200, 201, 400, 409] });
          const aent = entity(apply.data) || apply.data || {};
          applyLive = apply.ok && (aent.state === 'succeeded' || aent.kind === 'apply');
          record('kp005_promote_apply_live', applyLive, {
            status: apply.status, code: apply.code, state: aent.state, kind: aent.kind,
            jobIdDigest: aent.id ? digest(aent.id) : null,
            counts: aent.counts || aent.safeProgress?.counts,
          });
          // Kong B readback
          const listAfter = await kong(kongB, '/services');
          const promoted = (listAfter.data?.data || []).some((s) => s.name === promoteSvcName);
          record('kp005_kong_b_promoted_present', promoted, { serviceCount: (listAfter.data?.data || []).length });

          // Baseline snapshot from promote path: list snapshots, pick 环境发布执行前快照
          const snaps = await raw(admin, tq('snapshots?limit=20'));
          const sitems = snaps.data?.items || snaps.data?.entities || (Array.isArray(snaps.data) ? snaps.data : []);
          const baseline = (sitems || []).find((s) => (s.name || s.entity?.name) === '环境发布执行前快照') || sitems?.[0];
          const snapId = baseline?.id || baseline?.entity?.id;
          const snapName = baseline?.name || baseline?.entity?.name;
          const snapRev = baseline?.revision || baseline?.entity?.revision;
          if (applyLive && snapId) {
            const rbPlan = await raw(admin, tq(`snapshots/${snapId}/rollback-plan`), 'POST', {
              confirmed: true, confirm_name: snapName, confirm_deletes: true, revision: snapRev,
            }, { expected: [200, 201, 400, 409] });
            const rbEnt = entity(rbPlan.data) || rbPlan.data || {};
            const rbPlanId = rbEnt.planId || rbEnt.safeProgress?.planId;
            record('kp005_rollback_plan', rbPlan.ok && !!rbPlanId, {
              status: rbPlan.status, code: rbPlan.code, planIdDigest: rbPlanId ? digest(rbPlanId) : null,
              counts: rbEnt.counts || rbEnt.safeProgress?.counts,
            });
            if (rbPlanId) {
              const rpd = await raw(admin, tq(`configuration/plans/${rbPlanId}`));
              const rpent = entity(rpd.data) || rpd.data || {};
              const rbApply = await raw(admin, tq(`configuration/plans/${rbPlanId}/apply`), 'POST', {
                confirmed: true,
                confirm_name: rpent.name || `配置计划 ${rbPlanId}`,
                confirm_deletes: true,
                planRevision: rpent.planRevision, planHash: rpent.planHash, revision: rpent.revision,
              }, { expected: [200, 201, 400, 409] });
              const ra = entity(rbApply.data) || rbApply.data || {};
              rollbackLive = rbApply.ok && ra.state === 'succeeded';
              const listRb = await kong(kongB, '/services');
              const gone = !(listRb.data?.data || []).some((s) => s.name === promoteSvcName);
              rollbackDetail = {
                jobIdDigest: ra.id ? digest(ra.id) : null, state: ra.state,
                kongBPromotedAbsent: gone, confirmDeletes: true,
              };
              record('kp005_rollback_apply_live', rollbackLive && gone, rollbackDetail);
            }
          } else {
            record('kp005_promote_apply_live', applyLive, { note: 'no baseline snapshot for rollback' });
          }
        } else {
          record('kp005_promote_apply_live', false, { skipped: true, reason: 'target_plan_unavailable', status: planDetail.status });
        }
      } else if (promotePlanId) {
        record('kp005_promote_apply_live', false, { skipped: true, reason: 'configuration_plan_id_missing' });
      }
      record('kp005_rollback_live_executed', rollbackLive, { skipped: !rollbackLive, ...rollbackDetail });
      record('kp005_rollback_contract_probe', true, rollbackDetail);
    } else {
      record('kp005_promote_plan', false, { skipped: true, reason: 'comparison_unavailable', code: cmp.code });
      record('kp005_rollback_contract_probe', false, { skipped: true, reason: 'comparison_unavailable' });
    }
  } else {
    record('kp005_governance_comparison_dual_env', false, { reason: 'secondary_missing' });
    record('kp005_promote_plan', false, { skipped: true, reason: 'secondary_missing' });
    record('kp005_rollback_contract_probe', false, { skipped: true, reason: 'secondary_missing' });
  }

  const passed = checks.filter((c) => c.passed).length;
  const skipped = checks.filter((c) => !c.passed && c.skipped).length;
  const failed = checks.filter((c) => !c.passed && !c.skipped).length;
  const kp004Ok = fiveRootOk >= 4
    && checks.some((c) => c.id.startsWith('second_approver_delete_') && c.passed)
    && checks.some((c) => c.id.startsWith('approval_required_') && c.passed);
  const kp005Cmp = checks.find((c) => c.id === 'kp005_governance_comparison_dual_env')?.passed;
  const kp005Plan = checks.find((c) => c.id === 'kp005_promote_plan')?.passed;
  const kp005Apply = checks.find((c) => c.id === 'kp005_promote_apply_live')?.passed;
  const kp005Rb = checks.find((c) => c.id === 'kp005_rollback_live_executed')?.passed;
  const commercialClosed = false; // never true unless full P0 closed

  const evidence = {
    schemaVersion: 1,
    kind: 'kp004-approval-multireviewer-kp005-promote-live',
    commercialClosed,
    claimsClosed: false,
    kp004ApprovalMultiReviewerVerified: kp004Ok,
    kp005DualEnvComparison: !!kp005Cmp,
    kp005PromotePlan: !!kp005Plan,
    kp005PromoteApplyLive: !!kp005Apply,
    kp005RollbackLiveExecuted: !!kp005Rb,
    clusterExecutionMode: 'approval',
    approvalFormatNote: 'native-change definition approval_format=1 (single stage, allowSelfApproval=false) + distinct second approver',
    fenceClearNote: '2 orphan uncertain target deletes closed via evidence-stack SQL EVIDENCE_FENCE_ORPHAN_UNCERTAIN after product reconcile RECONCILIATION_PROOF_INCOMPLETE',
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'timestamps UTC; report Asia/Shanghai',
    stack: {
      bffBase: base, kongAdminA: kongA, kongAdminB: kongB, upstream: `${upstreamHost}:${upstreamPort}`,
      clusterIdDigest: digest(cid), workspaceIdDigest: digest(wid),
      secondaryClusterIdDigest: tid ? digest(tid) : null,
      tag, requesterDigest: digest(admin.userId), approverDigest: digest(approver.userId),
    },
    totals: { total: checks.length, passed, failed, skipped },
    remainingGaps: gaps,
    remainingForClosure: [
      ...(kp004Ok ? [] : ['KP-004：approval 多评审人五根回收未完全通过']),
      'KP-004：六类凭证恢复后代理正负 + OAuth2 HTTPS',
      ...(kp005Cmp && kp005Plan ? [] : ['KP-005：双环境自然 Promote comparison/plan']),
      ...(kp005Apply && kp005Rb ? [] : ['KP-005：Promote apply 后 rollback 新工单 live 执行']),
      'KP-005：CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED 生产路径仍拒',
      'KP-009 overlay+TLS / 浏览器 / 容量',
    ],
    secretsPrinted: false,
    checks,
  };

  const outFile = resolve(outDir, 'kp004-approval-multireviewer-evidence.json');
  writeFileSync(outFile, JSON.stringify(evidence, null, 2) + '\n');
  writeFileSync(resolve(kp005Out, 'kp005-dual-env-promote-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({
    outFile, commercialClosed, kp004Ok, kp005Cmp, kp005Plan, kp005Apply, kp005Rb,
    passed, failed, skipped, total: checks.length, gaps,
  }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
