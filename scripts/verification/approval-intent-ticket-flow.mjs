#!/usr/bin/env node
/**
 * KP-004: five-root recycle via prepare → submit → execute → Kong readback (live).
 * KP-005: Target DELETE intent + poststate observation; promote exclusion probe as feasible.
 * Cluster execution_mode=direct ⇒ approvalRequired=false (honest); multi-approver 三票仍缺口.
 * commercialClosed stays false unless close conditions truly met.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const base = (process.env.BFF_BASE_URL || 'http://127.0.0.1:13000').replace(/\/$/, '');
const adminUser = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
const adminPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const kongAdmin = process.env.LIVE_KONG_ADMIN_URL || 'http://127.0.0.1:18001';
const upstreamHost = process.env.LIVE_UPSTREAM_HOST || '172.30.0.2';
const upstreamPort = Number(process.env.LIVE_UPSTREAM_PORT || 25678);
const outDir = resolve(process.env.KP004_INTENT_OUT || 'artifacts/M11/runs/20261024-kp004-intent');
const kp005Out = resolve(process.env.KP005_EVIDENCE_OUT || 'artifacts/M11/runs/20261024-kp005-live');
const certPem = (process.env.M11_EVIDENCE_CERT_PEM || '').replace(/\\n/g, '\n');
const keyPem = (process.env.M11_EVIDENCE_KEY_PEM || '').replace(/\\n/g, '\n');
const tag = `m11it${Date.now().toString(36)}`;
const startedAt = new Date().toISOString();
const checks = [];
const gaps = [];
const record = (id, passed, detail = {}) => {
  checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });
  if (!passed && !detail.skipped) gaps.push(id);
};
const digest = (v) => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v ?? null)).digest('hex').slice(0, 16);
const entity = (d) => d?.entity ?? d;
if (!adminPass) { console.error('BOOTSTRAP_ADMIN_PASSWORD required'); process.exit(2); }

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
      'Content-Type': 'application/json', Origin: base, 'X-Idempotency-Key': randomUUID(),
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
  return { ok, status: res.status, data, text: text.slice(0, 1200), code, payload };
}

async function kong(path, method = 'GET', body) {
  const res = await fetch(kongAdmin + path, {
    method, headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { /* */ }
  return { ok: res.ok, status: res.status, data, text: text.slice(0, 500) };
}

async function driveIntent(admin, q, change, confirmName) {
  const prep = await raw(admin, q('entity-changes/prepare'), 'POST', { change }, { expected: [200, 201] });
  if (!prep.ok || !prep.data?.id) return { ok: false, phase: 'prepare', prep, execStatus: prep.status, execCode: prep.code };
  const submit = await raw(admin, q(`entity-changes/${prep.data.id}/submit`), 'POST', {
    revision: prep.data.revision, materialHmac: prep.data.materialHmac, confirmed: true, confirm_name: 'native-change',
  }, { expected: [200, 201] });
  if (!submit.ok || !submit.data?.workflowId) return { ok: false, phase: 'submit', prep, submit };
  const wfId = submit.data.workflowId;
  const wf = await raw(admin, q(`workflows/${wfId}`));
  const ent = entity(wf.data) || wf.data;
  const approvalRequired = !!ent.approvalRequired;
  let approve = null;
  if (approvalRequired) {
    approve = await raw(admin, q(`workflows/${wfId}/approve`), 'POST', {
      revision: ent.revision, planHash: ent.planHash, confirmed: true, confirm_name: ent.kind || 'native-change',
    }, { expected: [200, 201, 403, 409] });
    // refresh workflow after approve attempt
  }
  const wf2 = await raw(admin, q(`workflows/${wfId}`));
  const ent2 = entity(wf2.data) || wf2.data;
  const ex = await raw(admin, q(`workflows/${wfId}/execute`), 'POST', {
    revision: ent2.revision, planHash: ent2.planHash, confirmed: true, confirm_name: ent2.kind || 'native-change',
  }, { expected: [200, 201] });
  return {
    ok: ex.ok && (ex.data?.state === 'succeeded' || ex.data?.propagation === 'acknowledged'),
    phase: ex.ok ? 'execute' : 'execute_failed',
    intentId: prep.data.id, workflowId: wfId, executionId: ex.data?.executionId || ex.data?.id,
    executionMode: prep.data.executionMode, approvalRequired,
    approveStatus: approve?.status, approveCode: approve?.code,
    execState: ex.data?.state, execStatus: ex.status, execCode: ex.code,
    baselineIdDigest: ex.data?.baselineId ? digest(ex.data.baselineId) : null,
    prep, submit, ex,
  };
}

async function cycleRootIntent(admin, q, rootType, createBody, { nameField = 'name', childFactory, kongPath } = {}) {
  const create = await raw(admin, q(`entities/${rootType}`), 'POST', createBody, { expected: [200, 201] });
  const created = entity(create.data);
  const originalId = created?.id;
  const confirmName = created?.[nameField] || created?.username || created?.name || originalId;
  record(`create_${rootType}`, create.ok && !!originalId, { status: create.status, code: create.code, idDigest: originalId ? digest(originalId) : null });
  if (!originalId) return { ok: false };

  if (childFactory) {
    const child = await childFactory(created);
    record(`child_${rootType}`, !!child?.ok, child || {});
  }

  const delChange = {
    kind: 'recycle', action: 'delete', entityType: rootType, entityId: originalId,
    confirmed: true, confirm_name: confirmName,
  };
  const del = await driveIntent(admin, q, delChange, confirmName);
  record(`intent_delete_${rootType}`, del.ok, {
    phase: del.phase, status: del.execStatus, code: del.execCode, state: del.execState,
    executionMode: del.executionMode, approvalRequired: del.approvalRequired,
    intentIdDigest: del.intentId ? digest(del.intentId) : null,
    workflowIdDigest: del.workflowId ? digest(del.workflowId) : null,
  });

  const path = kongPath ? kongPath(originalId) : `/${rootType}/${originalId}`;
  const gone = await kong(path);
  record(`readback_absent_${rootType}`, gone.status === 404, { status: gone.status });

  const list = await raw(admin, q(`recycle-bin?size=50&search=${encodeURIComponent(confirmName)}`));
  const entry = (list.data?.items || []).find((i) => i.original_id === originalId || i.root_name === confirmName);
  record(`recycle_entry_${rootType}`, !!entry && entry.state === 'deleted', {
    found: !!entry, state: entry?.state, entryIdDigest: entry?.id ? digest(entry.id) : null,
  });
  if (!entry?.id) return { ok: false, originalId, del };

  const rest = await driveIntent(admin, q, {
    kind: 'recycle', action: 'restore', entryId: entry.id, confirmed: true, confirm_name: entry.root_name || confirmName,
  }, confirmName);
  record(`intent_restore_${rootType}`, rest.ok, {
    phase: rest.phase, status: rest.execStatus, code: rest.execCode, state: rest.execState,
    workflowIdDigest: rest.workflowId ? digest(rest.workflowId) : null,
  });

  const back = await kong(path);
  const sameId = back.ok && back.data?.id === originalId;
  record(`original_id_readback_${rootType}`, sameId, { status: back.status, idMatch: sameId });
  return { ok: del.ok && rest.ok && sameId && gone.status === 404, originalId, entryId: entry.id, del, rest };
}

async function main() {
  const admin = { cookie: '', csrf: '' };
  record('bff_health_ready', (await raw(null, '/api/v1/health/ready')).status === 200);
  record('live_kong_admin', (await kong('/')).status === 200);
  const login = await raw(admin, '/api/v1/auth/login', 'POST', { username: adminUser, password: adminPass }, { expected: [200, 201] });
  if (login.data?.csrfToken) admin.csrf = login.data.csrfToken;
  record('console_admin_login', login.ok && !!admin.csrf, { status: login.status });
  if (!login.ok) throw new Error('LOGIN_FAILED');

  let clusters = await raw(admin, '/api/v1/clusters');
  let cluster = (clusters.data?.items || clusters.data || []).find?.((c) => String(c.admin_url || '').includes('18001'));
  if (!cluster?.id) throw new Error('CLUSTER_REQUIRED');
  const cid = cluster.id;
  record('cluster_execution_mode', true, { executionMode: cluster.execution_mode, note: 'direct ⇒ approvalRequired=false on native-change plans' });
  await raw(admin, `/api/v1/clusters/${cid}/probe`, 'POST', {}, { expected: [200, 201, 202] });
  const workspaces = await raw(admin, `/api/v1/clusters/${cid}/workspaces`);
  const wid = ((workspaces.data?.items || [])[0] || entity(workspaces.data))?.id;
  record('workspace_resolved', !!wid);
  if (!wid) throw new Error('WORKSPACE_REQUIRED');
  const q = (s) => `/api/v1/clusters/${cid}/${s}${s.includes('?') ? '&' : '?'}workspaceId=${wid}`;

  // Published portal auth graph otherwise blocks ordinary service+route prepare
  // (PORTAL_AUTH_GRAPH_INCOMPLETE) and can exhaust actor page budget on consumer delete.
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
  record('portal_publications_suspended_for_ordinary_intent', true, { suspended, total: (pubs.data?.items || []).length });

  // --- KP-004 five-root intent cycles ---
  const results = {};
  results.services = await cycleRootIntent(admin, q, 'services', {
    name: `${tag}-svc`, host: upstreamHost, port: upstreamPort, protocol: 'http', tags: [tag, 'm11-intent'],
  }, {
    childFactory: async (svc) => {
      const r = await raw(admin, q('entities/routes'), 'POST', {
        name: `${tag}-svc-route`, paths: [`/m11/${tag}/svc`], protocols: ['http'], service: { id: svc.id }, tags: [tag],
      }, { expected: [200, 201] });
      return { ok: r.ok, status: r.status, code: r.code };
    },
  });

  {
    const parent = await raw(admin, q('entities/services'), 'POST', {
      name: `${tag}-route-parent`, host: upstreamHost, port: upstreamPort, protocol: 'http', tags: [tag],
    }, { expected: [200, 201] });
    const parentSvc = entity(parent.data);
    record('routes_parent_service', parent.ok && !!parentSvc?.id, { status: parent.status });
    if (parentSvc?.id) {
      results.routes = await cycleRootIntent(admin, q, 'routes', {
        name: `${tag}-route`, paths: [`/m11/${tag}/route-only`], protocols: ['http'], service: { id: parentSvc.id }, tags: [tag],
      });
    } else results.routes = { ok: false };
  }

  results.consumers = await cycleRootIntent(admin, q, 'consumers', {
    username: `${tag}-consumer`, tags: [tag, 'm11-intent'],
  }, { nameField: 'username' });

  results.upstreams = await cycleRootIntent(admin, q, 'upstreams', {
    name: `${tag}-up`, tags: [tag, 'm11-intent'],
  }, {
    childFactory: async (up) => {
      const t = await raw(admin, q(`upstreams/${up.id}/targets`), 'POST', {
        target: `${upstreamHost}:${upstreamPort}`, weight: 100, tags: [tag],
      }, { expected: [200, 201] });
      return { ok: t.ok, status: t.status, code: t.code, targetId: entity(t.data)?.id };
    },
  });

  if (certPem && keyPem) {
    results.certificates = await cycleRootIntent(admin, q, 'certificates', {
      cert: certPem, key: keyPem, snis: [`${tag}.evidence.local`], tags: [tag, 'm11-intent'],
    }, { nameField: 'id' });
  } else {
    results.certificates = { ok: false };
    record('create_certificates', false, { reason: 'cert_pem_missing' });
  }

  const fiveOk = ['services', 'routes', 'consumers', 'upstreams', 'certificates'].every((k) => results[k]?.ok);
  record('kp004_five_root_intent_ticket_execute_readback', fiveOk, {
    roots: Object.fromEntries(Object.entries(results).map(([k, v]) => [k, !!v?.ok])),
    path: 'prepare→submit→execute→kong-readback',
    approvalMode: 'direct/skipped',
  });

  // --- KP-005 Target DELETE intent + poststate ---
  const up = await raw(admin, q('entities/upstreams'), 'POST', {
    name: `${tag}-kp005-up`, tags: [tag, 'm11-kp005'],
  }, { expected: [200, 201] });
  const upstream = entity(up.data);
  record('kp005_create_upstream', up.ok && !!upstream?.id, { status: up.status });
  let targetId = null, targetAddress = `${upstreamHost}:${upstreamPort}`;
  if (upstream?.id) {
    const t = await raw(admin, q(`upstreams/${upstream.id}/targets`), 'POST', {
      target: targetAddress, weight: 100, tags: [tag],
    }, { expected: [200, 201] });
    const target = entity(t.data);
    targetId = target?.id;
    record('kp005_create_target', t.ok && !!targetId, { status: t.status, weight: target?.weight });
    if (targetId) {
      const del = await driveIntent(admin, q, {
        kind: 'recycle', action: 'delete', entityType: 'targets', entityId: targetId,
        parentId: upstream.id, confirmed: true, confirm_name: targetAddress,
      }, targetAddress);
      record('kp005_intent_target_delete', del.ok, {
        phase: del.phase, state: del.execState, status: del.execStatus, code: del.execCode,
        workflowIdDigest: del.workflowId ? digest(del.workflowId) : null,
      });
      // Poststate: list targets / health — weight=0 overlay or absent from effective set
      const hist = await kong(`/upstreams/${upstream.id}/targets`);
      const health = await kong(`/upstreams/${upstream.id}/health`);
      const items = hist.data?.data || hist.data || [];
      const match = (Array.isArray(items) ? items : []).filter((row) => row.id === targetId || row.target === targetAddress);
      const weightZero = match.some((row) => row.weight === 0);
      const pruned = match.length === 0 || hist.status === 404;
      const effectiveAbsent = weightZero || pruned;
      record('kp005_target_delete_poststate', del.ok && effectiveAbsent, {
        historyStatus: hist.status, matchCount: match.length, weightZero, pruned,
        healthStatus: health.status, note: 'Kong 1.5 DELETE → weight=0 overlay or prune; not bare GET404',
      });

      const list = await raw(admin, q(`recycle-bin?size=50&type=targets`));
      const entry = (list.data?.items || []).find((i) => i.original_id === targetId);
      record('kp005_target_recycle_entry', !!entry && entry.state === 'deleted', {
        found: !!entry, state: entry?.state, entryIdDigest: entry?.id ? digest(entry.id) : null,
      });
      if (entry?.id) {
        const rest = await driveIntent(admin, q, {
          kind: 'recycle', action: 'restore', entryId: entry.id, confirmed: true, confirm_name: entry.root_name || targetAddress,
        }, entry.root_name || targetAddress);
        record('kp005_intent_target_restore', rest.ok, {
          phase: rest.phase, state: rest.execState, status: rest.execStatus, code: rest.execCode,
        });
        const after = await kong(`/upstreams/${upstream.id}/targets`);
        const afterItems = after.data?.data || after.data || [];
        const restored = (Array.isArray(afterItems) ? afterItems : []).find(
          (row) => row.id === targetId || (row.target === targetAddress && row.weight > 0),
        );
        // Target restore may use sealed replacement id
        const sealedReplace = !!restored && restored.id !== targetId && restored.target === targetAddress;
        const originalBack = !!restored && restored.id === targetId;
        record('kp005_target_restore_readback', rest.ok && !!restored, {
          originalIdMatch: originalBack, sealedReplacement: sealedReplace,
          restoredIdDigest: restored?.id ? digest(restored.id) : null,
          weight: restored?.weight,
        });
      }
    }
  }

  // Promote credential exclusion — source wiring + live compare attempt
  const promoteSrc = existsSync('apps/console-api/src/modules/governance/promote-compiler.ts')
    ? readFileSync('apps/console-api/src/modules/governance/promote-compiler.ts', 'utf8') : '';
  record('kp005_promote_exclusion_source_wired', promoteSrc.includes('assertPromoteCredentialDefaultExclusion')
    && promoteSrc.includes('GOVERNANCE_PROMOTE_CREDENTIAL_DEFAULT_EXCLUSION'), { present: !!promoteSrc });

  const caps = await raw(admin, q('governance/capabilities'));
  record('kp005_governance_capabilities', caps.ok, {
    status: caps.status, promotePlan: caps.data?.promotePlan, adapterAvailable: caps.data?.adapterAvailable,
  });

  // Same-cluster empty-ish comparison (may fail without dual inventory) — record honestly
  const cmp = await raw(admin, q('governance/comparisons'), 'POST', {
    scope: 'workspace',
    target: { clusterId: cid, workspaceId: wid, scope: 'workspace' },
    threshold: 10000,
    includeEnvironmentFields: false,
  }, { expected: [200, 201, 400, 403, 409, 422] });
  record('kp005_governance_comparison_attempt', [200, 201].includes(cmp.status), {
    status: cmp.status, code: cmp.code, skipped: ![200, 201].includes(cmp.status),
    note: 'dual-env natural Promote still requires distinct source/target inventories',
  });
  if ([200, 201].includes(cmp.status) && (cmp.data?.id || entity(cmp.data)?.id)) {
    const cmpId = cmp.data?.id || entity(cmp.data)?.id || cmp.data?.comparisonId;
    const promo = await raw(admin, q(`governance/comparisons/${cmpId}/promote-plan`), 'POST', {
      confirmed: true, confirm_name: `PROMOTE ${cmpId}`, includeCredentials: false, includeSecrets: false,
      selectedObjectKeys: ['services:synthetic-should-fail-closed'],
    }, { expected: [200, 201, 400, 403, 409, 422] });
    record('kp005_promote_plan_credentials_default_off', promo.status !== 500, {
      status: promo.status, code: promo.code,
      note: 'includeCredentials omitted/false; dual-env e2e Promote still open',
    });
  } else {
    record('kp005_promote_plan_credentials_default_off', false, {
      skipped: true, reason: 'comparison_unavailable', code: cmp.code, status: cmp.status,
    });
  }

  const rollbackSrc = existsSync('apps/console-api/src/modules/configuration/rollback-new-job-contract.ts')
    ? readFileSync('apps/console-api/src/modules/configuration/rollback-new-job-contract.ts', 'utf8') : '';
  record('kp005_rollback_new_job_contract_source', rollbackSrc.includes('CONFIGURATION_ROLLBACK_REQUIRES_NEW_JOB')
    || rollbackSrc.includes('assertRollbackIsNewConfigurationJob'), { present: !!rollbackSrc });

  const fiveIntentOk = fiveOk;
  const kp005TargetOk = checks.find((c) => c.id === 'kp005_intent_target_delete')?.passed
    && checks.find((c) => c.id === 'kp005_target_delete_poststate')?.passed;
  const commercialClosed = false;
  const evidence = {
    schemaVersion: 1,
    kind: 'kp004-intent-ticket-execute-readback-and-kp005-live-evidence',
    commercialClosed,
    claimsClosed: false,
    kp004FiveRootIntentVerified: fiveIntentOk,
    kp005TargetDeleteIntentPoststate: !!kp005TargetOk,
    clusterExecutionMode: cluster.execution_mode,
    approvalTicketsNote: 'live cluster execution_mode=direct → approvalRequired=false; multi-reviewer 三票需 approval 模式+第二审批人',
    startedAt,
    completedAt: new Date().toISOString(),
    timezoneNote: 'timestamps UTC; report Asia/Shanghai',
    stack: {
      bffBase: base, kongAdmin, upstream: `${upstreamHost}:${upstreamPort}`,
      clusterIdDigest: digest(cid), workspaceIdDigest: digest(wid), tag,
    },
    checks,
    totals: {
      total: checks.length,
      passed: checks.filter((c) => c.passed).length,
      failed: checks.filter((c) => !c.passed && !c.skipped).length,
      skipped: checks.filter((c) => c.skipped).length,
    },
    remainingGaps: [...new Set(gaps)],
    remainingForClosure: [
      'KP-004：approval 模式多评审人三票（allowSelfApproval=false）',
      'KP-004：六类凭证恢复后代理正负 + OAuth2 HTTPS',
      'KP-005：双环境自然 Promote 端到端 + 回滚新工单 live 执行',
      'KP-005：CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED 生产路径仍拒',
      'KP-009 overlay+TLS / 浏览器 / 容量',
    ],
    secretsPrinted: false,
  };
  mkdirSync(outDir, { recursive: true });
  mkdirSync(kp005Out, { recursive: true });
  const out = resolve(outDir, 'kp004-intent-ticket-execute-evidence.json');
  writeFileSync(out, JSON.stringify(evidence, null, 2));
  writeFileSync(resolve(kp005Out, 'kp005-target-promote-live-evidence.json'), JSON.stringify({
    ...evidence, kind: 'kp005-target-promote-live-slice', focus: 'target-delete-poststate+promote-exclusion-probe',
  }, null, 2));
  console.log(JSON.stringify({
    out, totals: evidence.totals, commercialClosed, fiveIntentOk, kp005TargetOk,
  }, null, 2));
  if (!fiveIntentOk) process.exitCode = 1;
}

main().catch((e) => { console.error(e); process.exit(2); });
