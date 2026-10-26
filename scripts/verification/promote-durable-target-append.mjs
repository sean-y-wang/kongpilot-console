#!/usr/bin/env node
/**
 * KP-005: prove configuration durable admission no longer blanket-rejects
 * well-formed Target weight append (POST + allocatedNativeId). Schedule path
 * remains separately fenced. commercialClosed stays false.
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID as uuid, createHash } from 'node:crypto';

const base = (process.env.BFF_BASE_URL || 'http://127.0.0.1:13000').replace(/\/$/, '');
const adminUser = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const approverUser = process.env.KP004_APPROVER_USERNAME || 'approver2';
const approverPass = process.env.KP004_APPROVER_PASSWORD;
const kongA = process.env.LIVE_KONG_ADMIN_URL || 'http://127.0.0.1:18001';
const upstreamHost = process.env.LIVE_UPSTREAM_HOST || '172.30.0.2';
const upstreamPort = Number(process.env.LIVE_UPSTREAM_PORT || 25678);
const clusterId = process.env.KP005_APPEND_CLUSTER_ID || '3b148022-2251-47f5-b79d-faa7e1202e6d';
const outDir = resolve(process.env.KP005_APPEND_OUT || 'artifacts/M11/runs/20261024-kp005-durable-append');
const tag = `m11da${Date.now().toString(36)}`;
const startedAt = new Date().toISOString();
const checks = [];
const gaps = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed && !detail.skipped) gaps.push(id);
};
if (!adminPass) { console.error('BOOTSTRAP_ADMIN_PASSWORD required'); process.exit(2); }
if (!approverPass) { console.error('KP004_APPROVER_PASSWORD required for approve→execute'); process.exit(2); }

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
  return { ok, status: res.status, data, text: text.slice(0, 2400), code, payload };
}

async function kong(path, method = 'GET', body) {
  const res = await fetch(kongA + path, {
    method, headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { /* */ }
  return { ok: res.ok, status: res.status, data, text: text.slice(0, 800) };
}

const entity = (d) => d?.entity ?? d;

async function main() {
  mkdirSync(outDir, { recursive: true });
  const session = { cookie: '', csrf: '' };
  const login = await raw(session, '/api/v1/auth/login', 'POST', { username: adminUser, password: adminPass }, { expected: [200, 201] });
  record('login', login.ok && !!session.csrf, { status: login.status });
  if (!login.ok) throw new Error('login failed');

  const wsRes = await raw(session, `/api/v1/clusters/${clusterId}/workspaces`);
  const workspaces = wsRes.data?.items || wsRes.data || [];
  const wid = Array.isArray(workspaces) ? workspaces[0]?.id : null;
  record('workspace', !!wid, { status: wsRes.status, wid });
  const q = (p) => `/api/v1/clusters/${clusterId}${p}${p.includes('?') ? '&' : '?'}workspaceId=${wid}`;

  const cluster = await raw(session, `/api/v1/clusters/${clusterId}`);
  const mode = entity(cluster.data)?.executionMode || entity(cluster.data)?.execution_mode;
  record('cluster_approval_mode', mode === 'approval', { mode, status: cluster.status });

  const upName = `${tag}-up`;
  const targetAddr = `${upstreamHost}:${upstreamPort}`;
  const upCreate = await kong('/upstreams', 'POST', { name: upName, tags: [tag, 'kp005-durable-append', 'kos-ws-default'] });
  const upstreamId = upCreate.data?.id;
  record('kong_create_upstream', upCreate.ok && !!upstreamId, { status: upCreate.status, upstreamId });
  const tCreate = upstreamId
    ? await kong(`/upstreams/${upstreamId}/targets`, 'POST', { target: targetAddr, weight: 100, tags: [tag, 'kos-ws-default'] })
    : { ok: false, status: 0, data: null };
  const oldTargetId = tCreate.data?.id;
  record('kong_create_target_weight_100', tCreate.ok && !!oldTargetId, { status: tCreate.status, oldTargetId, weight: tCreate.data?.weight });

  // Import must pin existing Kong IDs so merge matches baseline objectKeys;
  // weight change on an existing Target compiles as append (POST + allocatedNativeId).
  const yaml = [
    '_format_version: "1.1"',
    'upstreams:',
    `- id: ${upstreamId}`,
    `  name: ${upName}`,
    '  targets:',
    `  - id: ${oldTargetId}`,
    `    target: ${JSON.stringify(targetAddr)}`,
    '    weight: 55',
    '',
  ].join('\n');

  const imp = await raw(session, q('/configuration/imports'), 'POST', {
    scope: 'workspace', serviceIds: [], yaml, mode: 'merge', confirm_deletes: false,
  }, { expected: [200, 201, 202] });
  let job = entity(imp.data) || imp.data;
  // Import may return early; poll job until terminal or planId appears
  for (let i = 0; i < 40 && job?.id && !['ready','failed','succeeded','partial','uncertain'].includes(job.state); i++) {
    await new Promise((r) => setTimeout(r, 500));
    const jr = await raw(session, q(`/configuration/jobs/${job.id}`));
    job = entity(jr.data) || jr.data || job;
  }
  const planId = job?.safeProgress?.planId || job?.planId || null;
  record('configuration_import', !!planId && job?.state !== 'failed', {
    status: imp.status, code: imp.code, planId, jobId: job?.id, jobState: job?.state,
    blockers: job?.blockerCodes || job?.safeProgress?.blockerCodes || null,
    changeActions: (job?.safeProgress?.changes?.changes || []).map((c) => `${c.action}:${c.entityType}`),
    text: planId ? undefined : (imp.text || '').slice(0, 600),
  });

  let plan = null, caps = null, steps = null;
  if (planId) {
    for (let i = 0; i < 30; i++) {
      const pr = await raw(session, q(`/configuration/plans/${planId}`));
      plan = entity(pr.data) || pr.data;
      if (plan && (plan.state === 'ready' || plan.capabilities || plan.planHash)) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    caps = plan?.capabilities || {};
    const updateCount = job?.safeProgress?.counts?.update ?? null;
    const stepCount = plan?.stepCount ?? job?.safeProgress?.stepCount ?? 0;
    // Plan detail API does not embed sealed steps; job counts + stepCount prove a Target weight update compiled.
    record('plan_ready_with_target_append', !!plan && plan.state === 'ready' && stepCount >= 1 && updateCount >= 1, {
      planState: plan?.state, stepCount, updateCount, planRevision: plan?.planRevision ?? 1, hasPlanHash: !!plan?.planHash,
    });
    const blocker = caps.durableSubmitBlockerCode || null;
    record('durable_blocker_not_blanket_append', blocker !== 'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED', { blocker });

    const planRevision = plan?.planRevision ?? 1;
    const planHash = plan?.planHash;
    let sub = null, subEnt = null;
    if (planHash) {
      sub = await raw(session, q(`/configuration/plans/${planId}/durable-submissions`), 'POST', {
        planRevision, planHash, confirmed: true, confirm_name: `配置计划 ${planId}`,
      }, { expected: [200, 201, 202, 403, 409] });
      subEnt = entity(sub.data) || sub.data;
    }
    const appendStillBlocked = sub?.code === 'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED' || blocker === 'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED';
    const admittedPastAppendFence = !appendStillBlocked && (caps.durableSubmit === true || (sub && sub.code !== 'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED'));
    record('durable_submit_capability_admits_append', admittedPastAppendFence, {
      durableSubmit: caps.durableSubmit, blocker, reason: caps.durableSubmitReason || null,
      submitStatus: sub?.status, submitCode: sub?.code, apply: caps.apply,
    });
    const subOk = !!(sub?.ok && subEnt && (subEnt.authorityDomain === 'durable-configuration-v1' || subEnt.durableIssueId || subEnt.workflowId || subEnt.kind === 'configuration_v2' || subEnt.state));
    record('durable_submission_live', subOk, {
      status: sub?.status, code: sub?.code,
      jobId: subEnt?.id, workflowId: subEnt?.workflowId, durableIssueId: subEnt?.durableIssueId,
      authorityDomain: subEnt?.authorityDomain, state: subEnt?.state,
      text: subOk ? undefined : (sub?.text || '').slice(0, 800),
      labNote: 'configuration_v2 definition upgraded to approval_format=2 on evidence DB before this run',
    });

    const wfId = subEnt?.workflowId || null;
    const durableJobId = subEnt?.id || null;
    if (subOk && wfId) {
      const approver = { cookie: '', csrf: '', userId: '' };
      const loginB = await raw(approver, '/api/v1/auth/login', 'POST', { username: approverUser, password: approverPass }, { expected: [200, 201] });
      if (loginB.data?.csrfToken) approver.csrf = loginB.data.csrfToken;
      approver.userId = loginB.data?.user?.id || '';
      const requesterId = login.data?.user?.id || '';
      record('second_approver_login', loginB.ok && !!approver.csrf && !!approver.userId && approver.userId !== requesterId, {
        status: loginB.status, distinctFromRequester: approver.userId !== requesterId,
      });

      const wf0 = await raw(session, q('/workflows/' + wfId));
      const ent0 = entity(wf0.data) || wf0.data;
      const stage0 = (ent0?.approval?.stages || []).find((s) => s.state === 'active') || (ent0?.approval?.stages || [])[0];
      const stageFields = stage0 ? {
        level: stage0.level,
        stageRevision: stage0.revision,
        candidateVersion: ent0?.approval?.candidateVersion,
      } : {};
      const selfProbe = await raw(session, q('/workflows/' + wfId + '/approve'), 'POST', {
        revision: ent0?.revision, planHash: ent0?.planHash, confirmed: true, confirm_name: ent0?.kind || 'configuration_v2',
        ...stageFields,
      }, { expected: [403, 409, 400] });
      record('self_approve_forbidden', selfProbe.code === 'WORKFLOW_SELF_APPROVAL_FORBIDDEN' || selfProbe.status === 403, {
        status: selfProbe.status, code: selfProbe.code,
      });

      const approve = await raw(approver, q('/workflows/' + wfId + '/approve'), 'POST', {
        revision: ent0?.revision, planHash: ent0?.planHash, confirmed: true, confirm_name: ent0?.kind || 'configuration_v2',
        reason: 'kp005-durable-target-append-second-approver',
        ...stageFields,
      }, { expected: [200, 201, 409] });
      const wf1 = await raw(session, q('/workflows/' + wfId));
      const ent1 = entity(wf1.data) || wf1.data;
      record('durable_second_approver_approve', !!(approve.ok && (ent1?.state === 'approved' || ent1?.state === 'ready')), {
        status: approve.status, code: approve.code, workflowState: ent1?.state,
        text: approve.ok ? undefined : (approve.text || '').slice(0, 600),
      });

      const ex = await raw(session, q('/workflows/' + wfId + '/execute'), 'POST', {
        revision: ent1?.revision ?? ent0?.revision, planHash: ent1?.planHash ?? ent0?.planHash,
        confirmed: true, confirm_name: ent1?.kind || ent0?.kind || 'configuration_v2',
      }, { expected: [200, 201, 202, 409] });
      const execEnt = entity(ex.data) || ex.data;
      let terminalJob = null, terminalWf = null;
      for (let i = 0; i < 90; i++) {
        if (durableJobId) {
          const jr = await raw(session, q('/configuration/jobs/' + durableJobId));
          terminalJob = entity(jr.data) || jr.data;
        }
        const wr = await raw(session, q('/workflows/' + wfId));
        terminalWf = entity(wr.data) || wr.data;
        const js = terminalJob?.state, ws = terminalWf?.state;
        if (['succeeded','failed','partial','uncertain','completed'].includes(js)
          || ['succeeded','failed','completed','cancelled'].includes(ws)) break;
        await new Promise((r) => setTimeout(r, 1000));
      }
      const execOk = !!(ex.ok && (terminalJob?.state === 'succeeded' || terminalWf?.state === 'succeeded' || execEnt?.state === 'succeeded'));
      record('durable_execute_live', execOk, {
        status: ex.status, code: ex.code,
        workflowState: terminalWf?.state, jobState: terminalJob?.state,
        executionId: execEnt?.executionId || execEnt?.id || null,
        text: execOk ? undefined : (ex.text || '').slice(0, 800),
      });

      let kongWeight = null, kongTargetId = null, kongTargets = [];
      if (upstreamId) {
        const list = await kong('/upstreams/' + upstreamId + '/targets');
        kongTargets = list.data?.data || list.data || [];
        if (!Array.isArray(kongTargets)) kongTargets = [];
        const match = kongTargets.find((t) => t.id === oldTargetId)
          || kongTargets.find((t) => String(t.target) === targetAddr && Number(t.weight) === 55)
          || kongTargets.find((t) => String(t.target) === targetAddr);
        kongWeight = match?.weight ?? null;
        kongTargetId = match?.id ?? null;
      }
      record('kong_target_weight_readback_55', Number(kongWeight) === 55, {
        expectedWeight: 55, actualWeight: kongWeight, targetId: kongTargetId, oldTargetId,
        targetCount: kongTargets.length,
        targets: kongTargets.map((t) => ({ id: t.id, target: t.target, weight: t.weight })),
      });
    } else {
      record('second_approver_login', false, { skipped: true });
      record('self_approve_forbidden', false, { skipped: true });
      record('durable_second_approver_approve', false, { skipped: true });
      record('durable_execute_live', false, { skipped: true });
      record('kong_target_weight_readback_55', false, { skipped: true });
    }
  } else {
    record('plan_ready_with_target_append', false, { skipped: true });
    record('durable_submit_capability_admits_append', false, { skipped: true });
    record('durable_blocker_not_blanket_append', false, { skipped: true });
    record('durable_submission_live', false, { skipped: true });
    record('second_approver_login', false, { skipped: true });
    record('self_approve_forbidden', false, { skipped: true });
    record('durable_second_approver_approve', false, { skipped: true });
    record('durable_execute_live', false, { skipped: true });
    record('kong_target_weight_readback_55', false, { skipped: true });
  }

  gaps.push('WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED (author/revision/activate/preclaim)');
  gaps.push('commercialClosed remains false');

  if (upstreamId) {
    const list = await kong('/upstreams/' + upstreamId + '/targets');
    const rows = list.data?.data || list.data || [];
    if (Array.isArray(rows)) {
      for (const t of rows) await kong('/upstreams/' + upstreamId + '/targets/' + t.id, 'DELETE');
    } else if (oldTargetId) {
      await kong('/upstreams/' + upstreamId + '/targets/' + oldTargetId, 'DELETE');
    }
    await kong('/upstreams/' + upstreamId, 'DELETE');
  }

  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.filter((c) => !c.passed && !c.skipped).length;
  const skipped = checks.filter((c) => c.skipped).length;
  const report = {
    schemaVersion: 1,
    kind: 'kp005-durable-target-append-evidence',
    commercialClosed: false,
    claimsClosed: false,
    kp005DurableTargetAppendAdmissionUnblocked: checks.some((c) => c.id === 'durable_submit_capability_admits_append' && c.passed),
    kp005DurableSubmissionLive: checks.some((c) => c.id === 'durable_submission_live' && c.passed),
    kp005DurableApproveExecuteKongReadbackLive: checks.some((c) => c.id === 'kong_target_weight_readback_55' && c.passed)
      && checks.some((c) => c.id === 'durable_execute_live' && c.passed)
      && checks.some((c) => c.id === 'durable_second_approver_approve' && c.passed),
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'Asia/Shanghai (box-local)',
    stack: { bffBase: base, kongAdmin: kongA, clusterId, workspaceId: wid, tag },
    checks,
    totals: { passed, failed, skipped, total: checks.length },
    remainingGaps: [...new Set(gaps)],
    remainingForClosure: [
      'Schedule of configuration_v2 Target append still fenced',
      'Full production compose + browser/capacity gates',
      'Never commercialClosed until all M11 close conditions met',
    ],
    secretsPrinted: false,
    focus: 'durable Target append admit -> approve -> execute -> Kong weight readback',
  };
  const out = resolve(outDir, 'kp005-durable-target-append-evidence.json');
  writeFileSync(out, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({
    out, totals: report.totals,
    admitted: report.kp005DurableTargetAppendAdmissionUnblocked,
    submitted: report.kp005DurableSubmissionLive,
    approveExecuteReadback: report.kp005DurableApproveExecuteKongReadbackLive,
    commercialClosed: false,
  }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
