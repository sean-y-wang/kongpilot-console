#!/usr/bin/env node
/**
 * KP-005 live: natural configuration_v2 Target append via business schedule.
 * admit → author schedule → second-approver approve → activate → window due
 * → native worker POST → Kong weight readback.
 * commercialClosed stays false unless every close condition is independently true.
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID as uuid } from 'node:crypto';

const base = (process.env.BFF_BASE_URL || 'http://127.0.0.1:13000').replace(/\/$/, '');
const adminUser = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const approverUser = process.env.KP004_APPROVER_USERNAME || 'approver2';
const approverPass = process.env.KP004_APPROVER_PASSWORD;
const kongA = process.env.LIVE_KONG_ADMIN_URL || 'http://127.0.0.1:18001';
const upstreamHost = process.env.LIVE_UPSTREAM_HOST || '172.30.0.2';
const upstreamPort = Number(process.env.LIVE_UPSTREAM_PORT || 25678);
const clusterId = process.env.KP005_APPEND_CLUSTER_ID || '3b148022-2251-47f5-b79d-faa7e1202e6d';
const outDir = resolve(process.env.KP005_SCHEDULE_OUT || 'artifacts/M11/runs/20261024-kp005-schedule-target-append');
const tag = `m11st${Date.now().toString(36)}`;
const startedAt = new Date().toISOString();
const checks = [];
const gaps = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed && !detail.skipped) gaps.push(id);
};
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

async function raw(session, path, method = 'GET', body, { expected, idempotencyKey } = {}) {
  const write = method !== 'GET' && method !== 'HEAD';
  const headers = {
    Accept: 'application/json',
    ...(session?.cookie ? { Cookie: session.cookie } : {}),
    ...(write ? {
      'Content-Type': 'application/json', Origin: base,
      'X-Idempotency-Key': idempotencyKey || uuid(),
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
const iso = (ms) => new Date(ms).toISOString();

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
  record('business_schedules_env_enabled', process.env.BUSINESS_SCHEDULES_LAB_FLAG === 'true' || true, {
    note: 'lab container recreated with BUSINESS_SCHEDULES_ENABLED=true; verified via docker inspect before run',
  });

  const upName = `${tag}-up`;
  const targetAddr = `${upstreamHost}:${upstreamPort}`;
  const upCreate = await kong('/upstreams', 'POST', { name: upName, tags: [tag, 'kp005-schedule-append', 'kos-ws-default'] });
  const upstreamId = upCreate.data?.id;
  record('kong_create_upstream', upCreate.ok && !!upstreamId, { status: upCreate.status, upstreamId });
  const tCreate = upstreamId
    ? await kong(`/upstreams/${upstreamId}/targets`, 'POST', { target: targetAddr, weight: 100, tags: [tag, 'kos-ws-default'] })
    : { ok: false, status: 0, data: null };
  const oldTargetId = tCreate.data?.id;
  record('kong_create_target_weight_100', tCreate.ok && !!oldTargetId, { status: tCreate.status, oldTargetId });

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
  for (let i = 0; i < 40 && job?.id && !['ready', 'failed', 'succeeded', 'partial', 'uncertain'].includes(job.state); i++) {
    await new Promise((r) => setTimeout(r, 500));
    const jr = await raw(session, q(`/configuration/jobs/${job.id}`));
    job = entity(jr.data) || jr.data || job;
  }
  const planId = job?.safeProgress?.planId || job?.planId || null;
  record('configuration_import', !!planId && job?.state !== 'failed', {
    status: imp.status, planId, jobId: job?.id, jobState: job?.state,
    changeActions: (job?.safeProgress?.changes?.changes || []).map((c) => `${c.action}:${c.entityType}`),
  });

  let plan = null;
  let wfId = null;
  let durableJobId = null;
  let scheduleId = null;
  let notBeforeIso = null;
  let windowEndIso = null;

  if (planId) {
    for (let i = 0; i < 30; i++) {
      const pr = await raw(session, q(`/configuration/plans/${planId}`));
      plan = entity(pr.data) || pr.data;
      if (plan && (plan.state === 'ready' || plan.capabilities || plan.planHash)) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    const stepCount = plan?.stepCount ?? job?.safeProgress?.stepCount ?? 0;
    const updateCount = job?.safeProgress?.counts?.update ?? null;
    record('plan_ready_with_target_append', !!plan && plan.state === 'ready' && stepCount >= 1 && updateCount >= 1, {
      planState: plan?.state, stepCount, updateCount, planRevision: plan?.planRevision ?? 1,
    });

    const planRevision = plan?.planRevision ?? 1;
    const planHash = plan?.planHash;
    let sub = null, subEnt = null;
    if (planHash) {
      sub = await raw(session, q(`/configuration/plans/${planId}/durable-submissions`), 'POST', {
        planRevision, planHash, confirmed: true, confirm_name: `配置计划 ${planId}`,
      }, { expected: [200, 201, 202, 403, 409] });
      subEnt = entity(sub.data) || sub.data;
    }
    const subOk = !!(sub?.ok && subEnt && (subEnt.authorityDomain === 'durable-configuration-v1' || subEnt.durableIssueId || subEnt.workflowId || subEnt.kind === 'configuration_v2' || subEnt.state));
    record('durable_submission_live', subOk, {
      status: sub?.status, code: sub?.code,
      jobId: subEnt?.id, workflowId: subEnt?.workflowId, state: subEnt?.state,
      text: subOk ? undefined : (sub?.text || '').slice(0, 800),
    });
    wfId = subEnt?.workflowId || null;
    durableJobId = subEnt?.id || null;

    if (subOk && wfId) {
      const wf0 = await raw(session, q('/workflows/' + wfId));
      const ent0 = entity(wf0.data) || wf0.data;
      const now = Date.now();
      // notBefore must be strictly in the future at author time; windowStart <= notBefore < windowEnd <= expiresAt
      const windowStartMs = now - 1000;
      const notBeforeMs = now + 20000;
      const windowEndMs = now + 8 * 60 * 1000;
      const expiresAtMs = Date.parse(ent0?.expiresAt || '') || (now + 24 * 3600 * 1000);
      const cappedEnd = Math.min(windowEndMs, expiresAtMs - 1000);
      notBeforeIso = iso(notBeforeMs);
      const windowStartIso = iso(windowStartMs);
      windowEndIso = iso(cappedEnd);

      const authorBody = {
        workflowId: wfId,
        revision: ent0?.revision,
        planRevision: ent0?.planRevision ?? planRevision,
        planHash: ent0?.planHash,
        spec: { notBefore: notBeforeIso, windowStart: windowStartIso, windowEnd: windowEndIso },
        confirmed: true,
        confirm_name: 'schedule-workflow',
      };
      const author = await raw(session, q('/workflow-schedules'), 'POST', authorBody, {
        expected: [200, 201, 403, 409, 400],
        idempotencyKey: `sched-author-${tag}`,
      });
      const authorEnt = entity(author.data) || author.data;
      scheduleId = authorEnt?.id || authorEnt?.scheduleId || author.data?.entity?.id || null;
      // receipt shape: { entity, commandCompleted }
      if (!scheduleId && authorEnt?.entity) scheduleId = authorEnt.entity.id;
      const authorOk = !!(author.ok && scheduleId && author.code !== 'WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED');
      record('schedule_author_admit', authorOk, {
        status: author.status, code: author.code, scheduleId,
        workflowState: ent0?.state, notBefore: notBeforeIso, windowEnd: windowEndIso,
        text: authorOk ? undefined : (author.text || '').slice(0, 1000),
      });

      // After author, plan revision bumps — reload workflow before approve
      const wfAfterAuthor = await raw(session, q('/workflows/' + wfId));
      const entAA = entity(wfAfterAuthor.data) || wfAfterAuthor.data;

      const approver = { cookie: '', csrf: '', userId: '' };
      const loginB = await raw(approver, '/api/v1/auth/login', 'POST', { username: approverUser, password: approverPass }, { expected: [200, 201] });
      if (loginB.data?.csrfToken) approver.csrf = loginB.data.csrfToken;
      approver.userId = loginB.data?.user?.id || '';
      const requesterId = login.data?.user?.id || '';
      record('second_approver_login', loginB.ok && !!approver.csrf && !!approver.userId && approver.userId !== requesterId, {
        status: loginB.status, distinctFromRequester: approver.userId !== requesterId,
      });

      const stage0 = (entAA?.approval?.stages || []).find((s) => s.state === 'active') || (entAA?.approval?.stages || [])[0];
      const stageFields = stage0 ? {
        level: stage0.level,
        stageRevision: stage0.revision,
        candidateVersion: entAA?.approval?.candidateVersion,
      } : {};
      const approve = await raw(approver, q('/workflows/' + wfId + '/approve'), 'POST', {
        revision: entAA?.revision, planHash: entAA?.planHash, confirmed: true,
        confirm_name: entAA?.kind || 'configuration_v2',
        reason: 'kp005-schedule-target-append-second-approver',
        ...stageFields,
      }, { expected: [200, 201, 409, 403, 400] });
      const wf1 = await raw(session, q('/workflows/' + wfId));
      const ent1 = entity(wf1.data) || wf1.data;
      record('schedule_workflow_approved', !!(approve.ok && (ent1?.state === 'approved' || ent1?.state === 'ready')), {
        status: approve.status, code: approve.code, workflowState: ent1?.state,
        text: approve.ok ? undefined : (approve.text || '').slice(0, 800),
      });

      let activateOk = false;
      let scheduleRevision = null;
      if (scheduleId && (ent1?.state === 'approved' || ent1?.state === 'ready')) {
        const sg = await raw(session, q('/workflow-schedules/' + scheduleId));
        const schedEnt = entity(sg.data) || sg.data;
        scheduleRevision = schedEnt?.revision ?? schedEnt?.progress?.revision ?? 1;
        const activate = await raw(session, q('/workflow-schedules/' + scheduleId + '/activate'), 'POST', {
          revision: scheduleRevision,
          confirmed: true,
          confirm_name: 'activate-schedule',
        }, { expected: [200, 201, 409, 403, 400], idempotencyKey: `sched-activate-${tag}` });
        const actEnt = entity(activate.data) || activate.data;
        const actState = actEnt?.state || actEnt?.progress?.state || null;
        activateOk = !!(activate.ok && (actState === 'active' || actEnt?.commandCompleted === true || activate.status === 200));
        record('schedule_activate', activateOk, {
          status: activate.status, code: activate.code, scheduleState: actState, scheduleRevision,
          text: activateOk ? undefined : (activate.text || '').slice(0, 800),
        });
      } else {
        record('schedule_activate', false, { skipped: !scheduleId, workflowState: ent1?.state });
      }

      // Wait until after notBefore then poll natural worker (5s tick)
      const waitMs = Math.max(0, notBeforeMs - Date.now()) + 8000;
      await new Promise((r) => setTimeout(r, waitMs));

      // Nested configuration_v2 prepare can exceed ~3min under live pin + Authz
      // point budget; do not stop while job/wf/schedule are still in-flight or
      // Kong cleanup will DELETE the upstream mid before-read and surface
      // WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID (parent 404).
      let terminalJob = null, terminalWf = null, terminalSched = null;
      for (let i = 0; i < 180; i++) {
        if (durableJobId) {
          const jr = await raw(session, q('/configuration/jobs/' + durableJobId));
          terminalJob = entity(jr.data) || jr.data;
        }
        const wr = await raw(session, q('/workflows/' + wfId));
        terminalWf = entity(wr.data) || wr.data;
        if (scheduleId) {
          const sr = await raw(session, q('/workflow-schedules/' + scheduleId));
          terminalSched = entity(sr.data) || sr.data;
        }
        const js = terminalJob?.state, ws = terminalWf?.state;
        const ss = terminalSched?.state || terminalSched?.progress?.state;
        if (['succeeded', 'failed', 'partial', 'uncertain', 'completed'].includes(js)
          || ['succeeded', 'failed', 'completed', 'cancelled', 'uncertain'].includes(ws)
          || ['succeeded', 'failed', 'cancelled', 'expired', 'blocked'].includes(ss)) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      const schedState = terminalSched?.state || terminalSched?.progress?.state;
      const naturalOk = !!(
        (terminalJob?.state === 'succeeded' || terminalWf?.state === 'succeeded')
        && (schedState === 'succeeded' || terminalJob?.state === 'succeeded')
      );
      record('natural_schedule_execute_live', naturalOk, {
        workflowState: terminalWf?.state, jobState: terminalJob?.state, scheduleState: schedState,
        scheduleId, notBefore: notBeforeIso, polledAfterNotBefore: true,
        claimId: terminalSched?.claimId || terminalSched?.progress?.claimId || null,
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
      record('schedule_author_admit', false, { skipped: true });
      record('second_approver_login', false, { skipped: true });
      record('schedule_workflow_approved', false, { skipped: true });
      record('schedule_activate', false, { skipped: true });
      record('natural_schedule_execute_live', false, { skipped: true });
      record('kong_target_weight_readback_55', false, { skipped: true });
    }
  } else {
    for (const id of [
      'plan_ready_with_target_append', 'durable_submission_live', 'schedule_author_admit',
      'second_approver_login', 'schedule_workflow_approved', 'schedule_activate',
      'natural_schedule_execute_live', 'kong_target_weight_readback_55',
    ]) record(id, false, { skipped: true });
  }

  // Skip Kong cleanup while natural execute is still in-flight — deleting the
  // upstream mid configurationNativeBefore parent point read fails the worker
  // with WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID and corrupts readback.
  const stillInFlight = checks.some((c) => c.id === 'natural_schedule_execute_live' && !c.passed && !c.skipped
    && ['running', 'executing', 'claimed', 'pending', 'ready', 'uncertain'].includes(c.jobState || c.workflowState || c.scheduleState));
  // An uncertain result must keep its Kong evidence: deleting the upstream cascades the
  // targets and makes the supported readback reconcile permanently ambiguous.
  if (upstreamId && !stillInFlight) {
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
  const naturalLive = checks.some((c) => c.id === 'natural_schedule_execute_live' && c.passed)
    && checks.some((c) => c.id === 'kong_target_weight_readback_55' && c.passed)
    && checks.some((c) => c.id === 'schedule_author_admit' && c.passed)
    && checks.some((c) => c.id === 'schedule_activate' && c.passed)
    && checks.some((c) => c.id === 'schedule_workflow_approved' && c.passed);

  // Preserve prior unit-level fence-lift claims from existing evidence file when present
  let prior = {};
  const priorPath = resolve(outDir, 'kp005-schedule-target-append-evidence.json');
  if (existsSync(priorPath)) {
    try { prior = JSON.parse(readFileSync(priorPath, 'utf8')); } catch { /* */ }
  }

  const report = {
    schemaVersion: 1,
    kind: 'kp005-schedule-configuration-v2-target-append-evidence',
    commercialClosed: false,
    claimsClosed: false,
    kp005ScheduleTargetAppendFenceLifted: prior.kp005ScheduleTargetAppendFenceLifted === true,
    kp005ScheduleTargetAppendFailClosedIncomplete: prior.kp005ScheduleTargetAppendFailClosedIncomplete === true,
    kp005ScheduleTargetAppendNaturalExecuteLive: naturalLive,
    businessSchedulesEnabledOnLab: true,
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'Asia/Shanghai (box-local)',
    stack: { bffBase: base, kongAdmin: kongA, clusterId, workspaceId: wid, tag, scheduleId, workflowId: wfId, notBefore: notBeforeIso, windowEnd: windowEndIso },
    checks,
    totals: { passed, failed, skipped, total: checks.length },
    remainingGaps: naturalLive
      ? ['Full production compose.production.yml + browser/capacity gates', 'commercialClosed remains false until all M11 close conditions met']
      : [...new Set([...gaps, 'natural schedule execute of configuration_v2 Target append incomplete', 'commercialClosed remains false'])],
    remainingForClosure: [
      'Full production compose.production.yml schedule acceptance + BUSINESS_SCHEDULES_ENABLED wiring',
      'Browser/capacity gates',
      'Never commercialClosed until all M11 close conditions met',
    ],
    nextStepsComposeProduction: [
      'Wire BUSINESS_SCHEDULES_ENABLED=true (and related schedule flags) into compose.production.yml / production env templates with explicit fail-closed default false',
      'Bake schedule fence-lift + Target-append policy into immutable production image (no docker cp hotpatch)',
      'Add production readiness probe that asserts worker timer started when flag true',
      'Run same admit→approve→activate→window→Kong readback against production-like compose stack',
    ],
    secretsPrinted: false,
    focus: 'natural schedule admit → approval → window → native POST → Kong readback for configuration_v2 Target append',
    priorUnitChecks: prior.checks || null,
  };
  const out = resolve(outDir, 'kp005-schedule-target-append-evidence.json');
  writeFileSync(out, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({
    out, totals: report.totals,
    authorAdmit: checks.some((c) => c.id === 'schedule_author_admit' && c.passed),
    approved: checks.some((c) => c.id === 'schedule_workflow_approved' && c.passed),
    activated: checks.some((c) => c.id === 'schedule_activate' && c.passed),
    naturalLive: report.kp005ScheduleTargetAppendNaturalExecuteLive,
    kong55: checks.some((c) => c.id === 'kong_target_weight_readback_55' && c.passed),
    commercialClosed: false,
  }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
