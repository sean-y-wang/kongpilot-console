// M11 formal-acceptance browser E2E matrix (headless Chromium, real lab Kong).
// Lab-only: requires KP_LAB_E2E=true and a private secrets file (mode 0600,
// outside the repo) providing {adminUser,adminPass,apprUser,apprPass,roUser,roPass,
// clusterId,workspaceId,otherWorkspaceId,kongAdmin,consoleOrigin,portalOrigin,dbUrl?,
// clusterB,workspaceB,clusterBLabel,kongProxyB,portalPublicationName,portalProxyPath}.
// Evidence (no cookies, passwords, keys) goes to KP_E2E_OUT.
import assert from 'node:assert/strict';
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';

if (process.env.KP_LAB_E2E !== 'true') throw Error('EXPLICIT_LAB_E2E_REQUIRED');
const secretsPath = process.env.KP_LAB_SECRETS; const st = lstatSync(secretsPath);
assert(st.isFile() && !st.isSymbolicLink() && (st.mode & 0o077) === 0, 'PRIVATE_SECRETS_FILE_REQUIRED');
const S = JSON.parse(readFileSync(secretsPath, 'utf8'));
const OUT = process.env.KP_E2E_OUT; mkdirSync(OUT + '/shots', { recursive: true });
const only = (process.env.KP_E2E_ONLY || '').split(',').filter(Boolean);
const secretValues = [S.adminPass, S.apprPass, S.roPass].filter(Boolean);
const results = [], writes = [];
const scrub = v => { let s = typeof v === 'string' ? v : JSON.stringify(v); for (const x of secretValues) s = s.split(x).join('***'); return s.replace(/(kongos_[a-z_]*=)[^;\s"]+/g, '$1***').replace(/("(?:key|apiKey|secret|password|token)"\s*:\s*")[^"]+/gi, '$1***'); };
const q = `clusters/${S.clusterId}`, wq = `workspaceId=${S.workspaceId}`;
const nav = (p, u) => p.evaluate(u => { history.pushState({}, '', u); dispatchEvent(new PopStateEvent('popstate')); }, u);
const kong = async (path) => { const r = await fetch(S.kongAdmin + path); return { status: r.status, body: r.status === 200 ? await r.json() : null }; };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function session(browser, who, origin = S.consoleOrigin) {
  const [user, pass] = { admin: [S.adminUser, S.adminPass], appr: [S.apprUser, S.apprPass], ro: [S.roUser, S.roPass] }[who];
  const c = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: process.env.KP_E2E_SELF_SIGNED === 'true' }); const p = await c.newPage(); p.setDefaultTimeout(20000);
  p.__errors = []; p.on('pageerror', e => p.__errors.push(e.message.slice(0, 200)));
  p.on('response', async r => { const req = r.request(), u = new URL(r.url()); if (!u.pathname.startsWith('/api/') || ['GET', 'HEAD', 'OPTIONS'].includes(req.method())) return;
    let rid; try { rid = (await r.json())?.meta?.requestId; } catch {} writes.push({ who, method: req.method(), path: u.pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, ':id'), status: r.status(), requestId: rid }); });
  await p.goto('/'); await p.getByLabel('账号', { exact: true }).fill(user); await p.getByLabel('密码', { exact: true }).fill(pass);
  await p.getByRole('button', { name: '登录控制台' }).click(); await p.locator('.user-button').waitFor(); return p;
}
async function confirm(p) { const m = p.locator('.ant-modal:visible').last(); await m.waitFor(); const t = await m.innerText(); const w = t.match(/输入\s*(\S+)\s*确认/); if (w) await m.getByRole('textbox').last().fill(w[1]); await m.locator('.ant-btn-primary, .ant-btn-dangerous').last().click(); return t.split('\n')[0]; }
async function api(p, method, path, body) { return p.evaluate(async ({ method, path, body }) => { let csrf; if (method !== 'GET') { const c = await fetch('/api/v1/auth/csrf', { credentials: 'include' }); try { const j = await c.json(); csrf = j?.data?.csrfToken ?? j?.data?.token; } catch {} } const r = await fetch(path, { method, credentials: 'include', headers: { 'content-type': 'application/json', 'x-idempotency-key': crypto.randomUUID(), ...(csrf ? { 'x-csrf-token': csrf } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) }); let j = null; try { j = await r.json(); } catch {} return { status: r.status, code: j?.error?.code ?? j?.code, data: j?.data }; }, { method, path, body }); }
async function shot(p, name) { await p.screenshot({ path: `${OUT}/shots/${name}.png`, fullPage: false }); return `shots/${name}.png`; }
async function wfState(p, wf) { const r = await api(p, 'GET', `/api/v1/${q}/workflows/${wf}?${wq}`); return { state: r.data?.entity?.state, caps: r.data?.entity?.capabilities, steps: (r.data?.steps || []).map(s => ({ state: s.state, errorCode: s.errorCode ?? null })) }; }
async function check(kp, id, fn) {
  if (only.length && !only.includes(kp)) return; const t0 = Date.now(); const row = { kp, id, startedAt: new Date().toISOString() };
  try { row.detail = await fn(); row.passed = true; } catch (e) { row.passed = false; row.error = scrub(String(e?.stack || e).slice(0, 1500)); }
  row.ms = Date.now() - t0; results.push(row); console.log(`${row.passed ? 'PASS' : 'FAIL'} ${kp} ${id} ${row.ms}ms ${row.passed ? '' : row.error.split('\n')[0]}`);
}
async function approveAndExecute(browser, admin, wf, label) {
  const ap = await session(browser, 'appr'); await nav(ap, '/workflows/' + wf); await ap.getByRole('button', { name: '批准变更', exact: true }).click(); await confirm(ap);
  await ap.waitForTimeout(2000); const afterApprove = await wfState(ap, wf); assert.equal(await ap.getByRole('button', { name: '执行已确认计划', exact: true }).count(), 0, 'APPROVER_MUST_NOT_EXECUTE');
  await ap.context().close();
  await nav(admin, '/'); await nav(admin, '/workflows/' + wf); await admin.getByRole('button', { name: '执行已确认计划', exact: true }).click(); await confirm(admin);
  let s; for (let i = 0; i < 30; i++) { await sleep(1000); s = await wfState(admin, wf); if (!['approved', 'running', 'queued', 'executing'].includes(s.state)) break; }
  await nav(admin, '/'); await nav(admin, '/workflows/' + wf); await admin.waitForTimeout(1500); const pic = await shot(admin, label);
  return { afterApprove: afterApprove.state, final: s, shot: pic };
}
async function submitFromPreview(p) { await p.getByRole('button', { name: '提交变更工单' }).click(); await confirm(p); await p.waitForURL(/\/workflows\/[0-9a-f-]{36}$/); return p.url().split('/').pop(); }

const browser = await chromium.launch();
const startedAt = new Date().toISOString();
const admin = await session(browser, 'admin');

// ---------- KP-007: authentication, read-only, IDOR, separation of duties ----------
await check('KP-007', 'bad-password-rejected-no-session', async () => {
  const c = await browser.newContext({ baseURL: S.consoleOrigin, ignoreHTTPSErrors: process.env.KP_E2E_SELF_SIGNED === 'true' }); const p = await c.newPage(); await p.goto('/');
  await p.getByLabel('账号', { exact: true }).fill(S.adminUser); await p.getByLabel('密码', { exact: true }).fill('wrong-' + Date.now());
  const r = p.waitForResponse(x => x.url().endsWith('/api/v1/auth/login')); await p.getByRole('button', { name: '登录控制台' }).click(); const st = (await r).status();
  const me = await p.evaluate(async () => (await fetch('/api/v1/auth/me', { credentials: 'include' })).status); await c.close();
  assert(st === 401 || st === 400, 'LOGIN_NOT_REJECTED'); assert.equal(me, 401); return { loginStatus: st, meStatus: me };
});
await check('KP-007', 'read-only-no-write-controls-and-backend-403', async () => {
  const ro = await session(browser, 'ro'); await nav(ro, '/entities/services'); await ro.locator('tbody tr.ant-table-row').first().waitFor();
  const del = await ro.locator('button:not([disabled])', { hasText: '提交删除工单' }).count(), create = await ro.locator('button:not([disabled])', { hasText: '提交创建工单' }).count(), disabledShown = await ro.locator('button[disabled]', { hasText: '提交删除工单' }).count(); const pic = await shot(ro, 'kp007-readonly-services');
  const forced = await api(ro, 'POST', `/api/v1/${q}/entity-changes/prepare?${wq}`, { change: { kind: 'recycle', action: 'delete', entityType: 'services', entityId: '0bb45280-2c42-469c-b3a2-3892bdebd81e', confirmed: true, confirm_name: 'fvmvml1u87-svc-8' } });
  const audit = await api(ro, 'POST', `/api/v1/${q}/recycle-bin/00000000-0000-4000-8000-000000000000/restore?${wq}`, { confirmed: true, confirm_name: 'x' });
  await ro.context().close(); assert.equal(del + create, 0, 'READONLY_SEES_WRITE_BUTTONS'); assert.equal(forced.status, 403); assert([403, 404].includes(audit.status));
  return { enabledWriteButtons: del + create, disabledWriteButtonsShown: disabledShown, forcedPrepare: [forced.status, forced.code], forcedRestore: [audit.status, audit.code], shot: pic };
});
await check('KP-007', 'idor-cross-workspace-and-cluster', async () => {
  const ro = await session(browser, 'ro'); const out = {};
  out.otherWorkspaceServices = await api(ro, 'GET', `/api/v1/${q}/workflows?size=5&workspaceId=${S.otherWorkspaceId}`);
  out.foreignCluster = await api(ro, 'GET', `/api/v1/clusters/00000000-0000-4000-8000-000000000000/workflows?size=5&${wq}`);
  out.globalUserDirectoryRead = await api(ro, 'GET', `/api/v1/iam/users?size=5`); // read-only role is a global auditor: read allowed by design
  const other = (out.globalUserDirectoryRead.data?.items ?? []).find(u => u.username === S.apprUser) ?? (await api(ro, 'GET', `/api/v1/iam/users?size=50&q=${encodeURIComponent(S.apprUser)}`)).data?.items?.find(u => u.username === S.apprUser);
  assert(other?.id, 'NO_TARGET_USER'); out.iamWriteResetOtherPassword = await api(ro, 'POST', `/api/v1/iam/users/${other.id}/reset-password`, { revision: 999999, new_password: 'x', confirmed: true }); // well-formed but unusable (stale revision, weak password) so only authorization can decide
  await ro.context().close(); const sts = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [v.status, v.code]]));
  for (const [k, v] of Object.entries(out)) if (k !== 'globalUserDirectoryRead') assert([403, 404].includes(v.status), 'IDOR_' + k + '_' + v.status); return sts;
});

// ---------- KP-004: approval-mode delete -> archive -> restore, real Kong readback ----------
const target = { name: S.kp004Service, id: null };
await check('KP-004', 'delete-via-two-person-approval-archives-and-removes-from-kong', async () => {
  const before = await kong('/services/' + target.name); assert.equal(before.status, 200, 'FIXTURE_SERVICE_MISSING'); target.id = before.body.id;
  const routesBefore = (await kong(`/services/${target.id}/routes`)).body.data.map(r => r.id);
  await nav(admin, '/'); await nav(admin, '/entities/services'); const row = admin.locator('tbody tr.ant-table-row').filter({ hasText: target.name }).first();
  await row.getByRole('button', { name: '提交删除工单' }).click(); await confirm(admin); const wf = await submitFromPreview(admin);
  const self = await wfState(admin, wf); assert.equal(self.caps?.approve, false, 'REQUESTER_CAN_SELF_APPROVE');
  const ex = await approveAndExecute(browser, admin, wf, 'kp004-delete-complete');
  const after = await kong('/services/' + target.id), routesAfter = await Promise.all(routesBefore.map(id => kong('/routes/' + id)));
  assert.equal(ex.final.state, 'succeeded', 'DELETE_NOT_SUCCEEDED ' + JSON.stringify(ex.final)); assert.equal(after.status, 404); assert(routesAfter.every(r => r.status === 404));
  target.routes = routesBefore; return { workflowId: wf, requesterSelfApprove: false, ...ex, kongServiceAfter: after.status, kongRoutesAfter: routesAfter.map(r => r.status) };
});
await check('KP-004', 'restore-original-ids-via-two-person-approval', async () => {
  assert(target.id, 'DELETE_STEP_REQUIRED');
  await nav(admin, '/'); await nav(admin, '/recycle-bin'); const row = admin.locator('tbody tr.ant-table-row').filter({ hasText: target.name }).first();
  await row.getByRole('button', { name: '提交恢复工单' }).click(); await confirm(admin); const wf = await submitFromPreview(admin);
  const ex = await approveAndExecute(browser, admin, wf, 'kp004-restore-complete');
  const svc = await kong('/services/' + target.id), routes = await Promise.all(target.routes.map(id => kong('/routes/' + id)));
  assert.equal(ex.final.state, 'succeeded', 'RESTORE_NOT_SUCCEEDED ' + JSON.stringify(ex.final)); assert.equal(svc.status, 200); assert.equal(svc.body.name, target.name); assert(routes.every(r => r.status === 200));
  return { workflowId: wf, ...ex, kongServiceId: target.id, kongServiceStatus: svc.status, routesRestoredSameIds: routes.map(r => r.status) };
});
await check('KP-004', 'legacy-origin-restore-refused-before-approval', async () => {
  const r = await api(admin, 'POST', `/api/v1/${q}/entity-changes/prepare?${wq}`, { change: { kind: 'recycle', action: 'restore', entryId: S.legacyEntryId, confirmed: true, confirm_name: S.legacyEntryName } });
  assert.equal(r.status, 409); assert.equal(r.code, 'ENTITY_RECYCLE_LEGACY_ORIGIN_RESTORE_UNSUPPORTED'); return [r.status, r.code];
});


// ---------- KP-002: scheduled entity change, two-person approval, explicit activation, natural worker claim ----------
const pad = n => String(n).padStart(2, '0'), local = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
async function scheduleCreateService(p, name, notBefore) {
  await nav(p, '/'); await nav(p, '/workflows'); await p.getByRole('tab', { name: '发起变更' }).click(); await p.getByRole('button', { name: '准备网关变更' }).click();
  const m = p.locator('.ant-modal:visible, .ant-drawer:visible').last(); await m.getByText('定时变更', { exact: true }).click();
  await m.getByLabel('窗口开始时间（上海）').fill(local(new Date(Date.now() - 60000))); await m.getByLabel('计划执行时间（上海）').fill(local(notBefore));
  await m.locator('input#name').fill(name); await m.locator('input#host').fill('172.30.0.2'); await m.locator('input#port').fill('80');
  const prep = p.waitForResponse(r => /entity-changes\/prepare-scheduled/.test(r.url())); await m.getByRole('button', { name: '生成变更预览' }).click(); await confirm(p);
  const pj = (await (await prep).json())?.data; const intentId = pj?.entity?.id ?? pj?.intent?.id ?? pj?.id ?? null; await p.getByText('定时变更预览 · Asia/Shanghai').waitFor();
  const wf = await submitFromPreview(p); let sched;
  for (let i = 0; i < 10 && !sched; i++) { const l = await api(p, 'GET', `/api/v1/${q}/entity-schedules?size=50&${wq}`); sched = (l.data?.items ?? l.data ?? []).find(x => x.intentId === intentId); if (!sched) await sleep(500); }
  assert(sched?.id, 'SCHEDULE_RECORD_NOT_FOUND'); return { wf, intentId, scheduleId: sched.id };
}
async function scheduleDetail(p, scheduleId) { await nav(p, '/'); await nav(p, '/workflows'); await p.getByRole('tab', { name: '定时变更' }).click();
  const l = await api(p, 'GET', `/api/v1/${q}/entity-schedules/${scheduleId}?${wq}`); const nb = new Date(l.data.entity.notBefore);
  const label = `${nb.getFullYear()}/${pad(nb.getMonth() + 1)}/${pad(nb.getDate())} ${pad(nb.getHours())}:${pad(nb.getMinutes())}:00`;
  await p.locator('tbody tr.ant-table-row').filter({ hasText: label }).first().getByRole('button', { name: '详情' }).click();
  const d = p.locator('.ant-modal:visible, .ant-drawer:visible').last(); await d.getByText(scheduleId).waitFor(); return d; }
const schedState = async (p, id) => (await api(p, 'GET', `/api/v1/${q}/entity-schedules/${id}?${wq}`)).data?.entity;
const k2 = { run: null, cancel: null }, stamp = Date.now();
await check('KP-002', 'scheduled-create-refuses-activation-before-approval-then-cancel', async () => {
  const name = `e2e-sched-cancel-${stamp}`; const r = await scheduleCreateService(admin, name, new Date(Date.now() + 150000)); k2.cancel = { ...r, name };
  const early = await api(admin, 'POST', `/api/v1/${q}/entity-schedules/${r.scheduleId}/activate?${wq}`, { revision: (await schedState(admin, r.scheduleId)).revision, confirmed: true, confirm_name: 'activate-schedule' });
  assert(early.status >= 400, 'ACTIVATED_BEFORE_APPROVAL'); const ro = await session(browser, 'ro');
  const roCancel = await api(ro, 'POST', `/api/v1/${q}/entity-schedules/${r.scheduleId}/cancel?${wq}`, { revision: (await schedState(admin, r.scheduleId)).revision, confirmed: true, confirm_name: 'cancel-schedule' }); await ro.context().close();
  assert([403, 404].includes(roCancel.status), 'READONLY_CANCEL_' + roCancel.status);
  const d = await scheduleDetail(admin, r.scheduleId); await d.getByRole('button', { name: '撤销定时变更' }).click(); await confirm(admin); await admin.waitForTimeout(2000);
  const after = await schedState(admin, r.scheduleId); const pic = await shot(admin, 'kp002-schedule-cancelled');
  assert(['cancelled', 'canceled'].includes(after.state), 'NOT_CANCELLED ' + after.state);
  return { ...r, activateBeforeApproval: [early.status, early.code], readOnlyCancel: [roCancel.status, roCancel.code], stateAfterCancel: after.state, shot: pic };
});
await check('KP-002', 'scheduled-create-approved-activated-natural-claim-executes-on-kong', async () => {
  const name = `e2e-sched-run-${stamp}`, notBefore = new Date(Date.now() + 120000); const r = await scheduleCreateService(admin, name, notBefore); k2.run = { ...r, name };
  const ap = await session(browser, 'appr'); await nav(ap, '/workflows/' + r.wf); await ap.getByRole('button', { name: '批准变更', exact: true }).click(); await confirm(ap); await ap.waitForTimeout(1500); await ap.context().close();
  const d = await scheduleDetail(admin, r.scheduleId); await d.getByRole('button', { name: '激活定时变更' }).click(); await confirm(admin); await admin.waitForTimeout(1500);
  const activated = await schedState(admin, r.scheduleId); assert.equal(activated.state, 'active'); assert.equal(activated.workflowId, r.wf);
  const kongBefore = (await kong('/services/' + name)).status; assert.equal(kongBefore, 404, 'EXECUTED_BEFORE_NOT_BEFORE');
  let st; for (let i = 0; i < 80; i++) { await sleep(5000); st = await schedState(admin, r.scheduleId); if (!['active', 'claimed', 'running'].includes(st.state)) break; }
  const kongAfter = await kong('/services/' + name), wf = await wfState(admin, r.wf); await scheduleDetail(admin, r.scheduleId); const pic = await shot(admin, 'kp002-schedule-succeeded');
  assert.equal(st.state, 'succeeded', 'SCHEDULE_NOT_SUCCEEDED ' + JSON.stringify(st)); assert.equal(kongAfter.status, 200); const serverNotBefore = Date.parse(activated.notBefore); assert(kongAfter.body.created_at * 1000 >= serverNotBefore - 1000, 'KONG_CREATED_BEFORE_NOT_BEFORE');
  const cancelled = k2.cancel && (await kong('/services/' + k2.cancel.name)).status;
  return { ...r, notBefore: activated.notBefore, kongCreatedAt: new Date(kongAfter.body.created_at * 1000).toISOString(), activatedState: activated.state, kongBeforeNotBefore: kongBefore, finalState: st.state, claimId: st.claimId, workflowState: wf.state, kongServiceId: kongAfter.body?.id, cancelledScheduleKongStatus: cancelled, shot: pic };
});

// ---------- KP-003: unknown execute result; mismatching receipt must not close it; original key verified without replay ----------
async function prepareCreateService(p, name) {
  await nav(p, '/'); await nav(p, '/workflows'); await p.getByRole('tab', { name: '发起变更' }).click(); await p.getByRole('button', { name: '准备网关变更' }).click();
  const m = p.locator('.ant-modal:visible, .ant-drawer:visible').last(); await m.locator('input#name').fill(name); await m.locator('input#host').fill('172.30.0.2'); await m.locator('input#port').fill('80');
  const prep = p.waitForResponse(r => /entity-changes\/prepare/.test(r.url()) && r.request().method() === 'POST'); await m.getByRole('button', { name: '生成变更预览' }).click(); await prep; await p.waitForTimeout(800);
  return submitFromPreview(p);
}
await check('KP-003', 'unknown-execute-result-mismatching-receipt-rejected-original-verified-no-replay', async () => {
  const name = `e2e-unknown-${Date.now()}`; const wf = await prepareCreateService(admin, name);
  const ap = await session(browser, 'appr'); await nav(ap, '/workflows/' + wf); await ap.getByRole('button', { name: '批准变更', exact: true }).click(); await confirm(ap); await ap.waitForTimeout(1500); await ap.context().close();
  let executePosts = 0, serverExecuteStatus = null; const exRe = new RegExp(`/workflows/${wf}/execute`);
  admin.on('request', r => { if (r.method() === 'POST' && exRe.test(r.url())) executePosts++; });
  const exMatch = u => exRe.test(u.href); await admin.route(exMatch, async route => { const resp = await route.fetch(); serverExecuteStatus = resp.status(); await route.abort('connectionreset'); });
  await nav(admin, '/'); await nav(admin, '/workflows/' + wf); await admin.getByRole('button', { name: '执行已确认计划', exact: true }).click(); await confirm(admin);
  const banner = admin.getByText('原操作需要核验，禁止重新提交'); await banner.waitFor(); await admin.waitForTimeout(800);
  for (let i = 0; i < 3 && await admin.locator('.ant-modal-wrap:visible').count(); i++) { await admin.keyboard.press('Escape'); await admin.waitForTimeout(500); } await admin.unroute(exMatch);
  const key = (await admin.locator('.ant-alert-warning .mono').first().innerText()).trim(); assert.match(key, /^[0-9a-f-]{36}$/, 'NO_ORIGINAL_KEY');
  const unknownShot = await shot(admin, 'kp003-unknown-banner');
  // (a) server: a key that was never used proves nothing
  const foreign = await api(admin, 'GET', `/api/v1/${q}/workflows/receipts/by-key/${crypto.randomUUID()}?${wq}`); assert(foreign.status >= 400 && foreign.status !== 500, 'FOREIGN_KEY_RECEIPT_' + foreign.status);
  // (b) UI: a receipt that does not match the original reference (workspace/key altered in transit) must be rejected; journal kept
  const rcRe = new RegExp(`/workflows/receipts/by-key/${key}`);
  const rcMatch = u => rcRe.test(u.href); await admin.route(rcMatch, async route => { const resp = await route.fetch(); const j = await resp.json(); if (j?.data) { j.data.idempotencyKey = crypto.randomUUID(); j.data.workspaceId = S.otherWorkspaceId; } await route.fulfill({ response: resp, json: j }); });
  await admin.getByRole('button', { name: '只读核验原请求' }).click(); await admin.getByText('原回执尚未证明此请求已完成').first().waitFor();
  assert.equal(await banner.count(), 1, 'MISMATCH_CLEARED_UNKNOWN_JOURNAL'); const rejectShot = await shot(admin, 'kp003-mismatch-rejected'); await admin.unroute(rcMatch);
  assert.equal(await admin.getByRole('button', { name: '执行已确认计划', exact: true }).count(), 0, 'REEXECUTE_OFFERED_WHILE_UNKNOWN');
  // (c) genuine original-key receipt closes it; still exactly one execute POST
  let verifyClicks = 0, lastReceipt = null; for (; verifyClicks < 10 && await banner.count(); verifyClicks++) { await sleep(2000); const rr = admin.waitForResponse(r => rcRe.test(r.url()));
    await admin.getByRole('button', { name: '只读核验原请求' }).click(); try { const j = await (await rr).json(); const x = j?.data ?? {}; lastReceipt = { http: (await rr).status(), action: x.action, state: x.state, submissionCompleted: x.submissionCompleted, executionCompleted: x.executionCompleted, decisionCompleted: x.decisionCompleted, keys: Object.keys(x), steps: (x.steps || []).map(s => [s.name, s.state, s.remoteCompleted]) }; } catch {} await admin.waitForTimeout(1500); }
  assert.equal(await banner.count(), 0, 'ORIGINAL_RECEIPT_NEVER_CLOSED ' + JSON.stringify({ uiError: await admin.locator('.ant-alert-error').allInnerTexts(), journal: await admin.evaluate(() => Object.fromEntries(Object.entries({ ...localStorage, ...sessionStorage }).filter(([k]) => /workflow|attempt/i.test(k)))), serverExecuteStatus, lastReceipt, wf: await wfState(admin, wf) })); await admin.waitForTimeout(1000);
  const st = await wfState(admin, wf), svc = await kong('/services/' + name); const okShot = await shot(admin, 'kp003-original-verified');
  assert.equal(executePosts, 1, 'EXECUTE_REPLAYED ' + executePosts); assert.equal(st.state, 'succeeded'); assert.equal(svc.status, 200);
  return { workflowId: wf, serverExecuteStatus, clientSawTransportFailure: true, foreignKeyReceipt: [foreign.status, foreign.code], mismatchRejected: true, journalKeptAfterMismatch: true, genuineVerifyClicks: verifyClicks, executePosts, finalState: st.state, kongService: svc.status, shots: [unknownShot, rejectShot, okShot] };
});

// ---------- KP-006: portal full flow in two browsers (developer portal + console), real Kong proxy ----------
const toB = async p => { await nav(p, '/'); await p.locator('.ant-select').first().click(); await p.getByText(S.clusterBLabel).last().click(); await p.waitForTimeout(1500); return p; };
async function approveExecuteB(wf, label) {
  const ap = await toB(await session(browser, 'appr')); await nav(ap, '/workflows/' + wf); await ap.getByRole('button', { name: '批准变更', exact: true }).click(); await confirm(ap); await ap.waitForTimeout(1500);
  // Observation (not asserted): portal workflows grant execute by cluster 'write' permission; there is no approver!=executor hard rule.
  const approverSeesExecute = await ap.getByRole('button', { name: '执行已确认计划', exact: true }).count() > 0; await ap.context().close();
  const ad = await toB(await session(browser, 'admin')); await nav(ad, '/workflows/' + wf); await ad.getByRole('button', { name: '执行已确认计划', exact: true }).click(); await confirm(ad);
  const qb = `clusters/${S.clusterB}`; let s; for (let i = 0; i < 30; i++) { await sleep(1000); s = (await api(ad, 'GET', `/api/v1/${qb}/workflows/${wf}?workspaceId=${S.workspaceB}`)).data?.entity?.state; if (!['approved', 'running', 'queued', 'executing'].includes(s)) break; }
  await nav(ad, '/'); await nav(ad, '/workflows/' + wf); await ad.waitForTimeout(1500); const pic = await shot(ad, label); await ad.context().close(); return { state: s, approverSeesExecute, executedBy: 'admin', shot: pic };
}
const proxy = async key => (await fetch(S.kongProxyB + S.portalProxyPath, { headers: key ? { apikey: key } : {} })).status;
const k6 = {};
async function portalConfirm(d) { const m = d.locator('.ant-modal:visible').last(); await m.waitFor(); const t = (await m.innerText()).replace(/\s+/g, ' '); const w = t.match(/请输入名称\s*(.+?)\s*二次确认/); if (w) await m.getByRole('textbox').last().fill(w[1]); await m.getByRole('button', { name: '确认执行' }).click(); return t.slice(0, 40); }
await check('KP-006', 'portal-register-approve-app-key-request-execute-masked-reveal-proxy-rotate-revoke', async () => {
  const u = 'e2edev' + Date.now().toString(36), pw = 'Pw-' + crypto.randomUUID(); secretValues.push(pw); k6.user = u;
  const c = await browser.newContext({ baseURL: S.portalOrigin, viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: process.env.KP_E2E_SELF_SIGNED === 'true' }); const d = await c.newPage(); d.setDefaultTimeout(20000); const posts = [];
  d.on('response', async r => { const x = new URL(r.url()); if (!x.pathname.startsWith('/api/') || r.request().method() === 'GET') return; let j; try { j = await r.json(); } catch {} posts.push({ path: x.pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, ':id'), status: r.status(), workflowId: j?.data?.workflowId ?? j?.data?.workflow?.id ?? null }); });
  const dnav = u2 => nav(d, u2); let portalLoaded = false; const toPortal = async () => { if (portalLoaded) { await nav(d, '/apis'); await d.waitForTimeout(1200); return; } portalLoaded = true; await d.goto('/'); await d.waitForTimeout(1500); const enter = d.getByText('进入门户 →'); if (await enter.count()) { await enter.click(); await d.waitForTimeout(800); } };
  const toLogin = async () => { await toPortal(); const l = d.getByText('开发者登录'); if (await l.count()) await l.first().click(); await d.locator('#username').waitFor(); };
  await toLogin(); await d.getByText('申请开发者账号').click();
  await d.locator('#username').fill(u); await d.locator('#email').fill(u + '@example.test'); await d.locator('#displayName').fill('E2E ' + u); await d.locator('#password').fill(pw);
  await d.getByRole('button', { name: '提交注册申请' }).click(); await d.getByText('注册申请已提交').waitFor(); const regShot = await shot(d, 'kp006-01-registered');
  // pending developer cannot log in yet
  await toLogin(); await d.locator('#username').fill(u); await d.locator('#password').fill(pw); await d.getByRole('button', { name: '登录开发者门户' }).click(); await d.waitForTimeout(2000);
  const pendingLoginBlocked = !/\/applications/.test(d.url()); assert(pendingLoginBlocked, 'PENDING_DEVELOPER_LOGGED_IN');
  // console admin approves the developer
  const ad = await toB(await session(browser, 'admin')); await nav(ad, '/portal'); await ad.waitForTimeout(1500); await ad.getByRole('tab', { name: '开发者审核' }).click();
  const row = ad.locator('tbody tr.ant-table-row').filter({ hasText: u }).first(); await row.waitFor();
  const reviewResp = ad.waitForResponse(r => r.request().method() === 'POST' && /\/portal\/developers\/[^/]+\/review/.test(r.url())); await row.getByRole('button', { name: '审核通过' }).click();
  if (await ad.locator('.ant-modal:visible').count()) await confirm(ad); const rv = await (await reviewResp).json().catch(() => null); await ad.waitForTimeout(1500); const devApproveShot = await shot(ad, 'kp006-02-developer-approved'); await ad.context().close();
  // Approval-mode cluster: developer review is itself a two-person workflow; approve (approver) + execute (admin) and require success.
  const reviewWf = rv?.data?.workflowId ?? rv?.data?.workflow?.id ?? null; let reviewExec = null;
  if (reviewWf) { reviewExec = await approveExecuteB(reviewWf, 'kp006-02b-developer-review-executed'); assert.equal(reviewExec.state, 'succeeded', 'DEV_REVIEW_' + reviewExec.state); } k6.developerReview = { workflow: !!reviewWf, state: reviewExec?.state ?? 'direct' };
  // developer: login, app, request key
  await toLogin(); await d.locator('#username').fill(u); await d.locator('#password').fill(pw); await d.getByRole('button', { name: '登录开发者门户' }).click(); await d.waitForURL(/\/applications/);
  await d.getByRole('button', { name: '创建应用' }).click(); await d.locator('#name').fill('e2eapp-' + u); await d.getByRole('button', { name: '保存应用' }).click(); await d.getByText('e2eapp-' + u).first().waitFor();
  await d.getByText('API 目录').first().click(); await d.getByText(S.portalPublicationName).first().click(); await d.getByRole('button', { name: '申请 API Key' }).click();
  await d.locator('.ant-select').last().click(); await d.locator('.ant-select-item-option').filter({ hasText: 'e2eapp-' + u }).first().click(); await d.locator('#reason').fill('KP-006 browser matrix');
  const reqResp = d.waitForResponse(r => r.request().method() === 'POST' && /\/portal\/requests/.test(r.url())); await d.getByRole('button', { name: '提交凭证申请' }).click();
  const rq = await (await reqResp).json(); const issueWf = rq?.data?.workflowId; assert(issueWf, 'NO_ISSUE_WORKFLOW'); await d.getByText('待审核').first().waitFor(); const pendShot = await shot(d, 'kp006-03-request-pending');
  const before = await proxy(null); assert.equal(before, 401);
  const issue = await approveExecuteB(issueWf, 'kp006-04-issue-executed'); assert.equal(issue.state, 'succeeded', 'ISSUE_' + issue.state);
  // masked key, then reveal
  const openApp = async () => { await d.getByText('我的应用').first().click(); await d.getByText('e2eapp-' + u).first().click(); await d.getByText('API 授权与凭证').waitFor(); await d.getByRole('button', { name: '刷新授权状态' }).click(); await d.waitForTimeout(1500); };
  await openApp(); await d.getByText('••••••••').first().waitFor(); const maskedShot = await shot(d, 'kp006-05-masked');
  const reveal = async (name = 'kp006-06-reveal-panel') => { await d.getByRole('button', { name: '查看 API Key' }).first().click(); const inp = d.locator('input[type=password]:visible').last(); await inp.waitFor(); const v = await inp.inputValue(); assert(v && v.length >= 16, 'NO_KEY'); secretValues.push(v); const pic = await shot(d, name); await d.getByRole('button', { name: '关闭并清除' }).click(); return { v, pic }; };
  const k1 = await reveal(); const p1 = await proxy(k1.v), pWrong = await proxy('wrong-' + crypto.randomUUID()); assert.equal(p1, 200, 'KEY1_PROXY_' + p1); assert.equal(pWrong, 401);
  // rotate
  const nPosts = posts.length; await d.getByRole('button', { name: '轮 换' }).first().click(); await portalConfirm(d); await d.waitForTimeout(2500);
  const rotWf = posts.slice(nPosts).map(x => x.workflowId).find(Boolean); let rotate = null; if (rotWf) rotate = await approveExecuteB(rotWf, 'kp006-07-rotate-executed');
  await openApp(); const k2 = await reveal('kp006-07b-reveal-rotated'); assert.notEqual(k2.v, k1.v, 'ROTATE_SAME_KEY'); const p2 = await proxy(k2.v), p1after = await proxy(k1.v);
  assert.equal(p2, 200, 'KEY2_PROXY_' + p2); assert([401, 403].includes(p1after), 'OLD_KEY_STILL_' + p1after);
  // revoke
  const nPosts2 = posts.length; await d.getByRole('button', { name: '停用 / 吊销' }).first().click(); await portalConfirm(d); await d.waitForTimeout(2500);
  const revWf = posts.slice(nPosts2).map(x => x.workflowId).find(Boolean); let revoke = null; if (revWf) revoke = await approveExecuteB(revWf, 'kp006-08-revoke-executed');
  let p2after; for (let i = 0; i < 10; i++) { p2after = await proxy(k2.v); if (p2after !== 200) break; await sleep(1000); }
  await openApp(); const revokedShot = await shot(d, 'kp006-09-revoked'); assert([401, 403].includes(p2after), 'REVOKED_KEY_STILL_' + p2after);
  // unauthenticated portal reveal is refused
  const anon = await (await fetch(S.portalOrigin + '/api/v1/portal/applications')).status; assert([401, 403].includes(anon), 'ANON_PORTAL_' + anon);
  await c.close();
  return { developer: u, pendingLoginBlocked, issueWorkflow: issueWf, issue, rotateWorkflow: rotWf ?? null, rotate, revokeWorkflow: revWf ?? null, revoke,
    proxy: { noKey: before, wrongKey: pWrong, key1: p1, key2AfterRotate: p2, key1AfterRotate: p1after, key2AfterRevoke: p2after }, anonymousPortalApi: anon, keysDistinct: true, portalWrites: posts.map(({ path, status }) => ({ path, status })),
    shots: [regShot, devApproveShot, pendShot, maskedShot, k1.pic, k2.pic, revokedShot] };
});

// ---------- KP-008: every product write in this run has an audit record ----------
await check('KP-008', 'all-successful-writes-audited', async () => {
  await sleep(1500); const ids = [...new Set(writes.filter(w => w.status >= 200 && w.status < 300 && w.requestId && !w.path.endsWith('/auth/login') && !w.path.endsWith('/authorization/entity-capabilities')).map(w => w.requestId))];
  assert(ids.length > 0, 'NO_WRITES');
  const sql = `SELECT DISTINCT request_id FROM audit_events WHERE request_id = ANY(ARRAY[${ids.map(i => `'${i.replace(/[^0-9a-f-]/g, '')}'`).join(',')}]::text[])`;
  const outp = execFileSync('docker', ['run', '--rm', '--network', 'host', '-e', 'DB', 'postgres:16-alpine', 'sh', '-c', `psql "$DB" -v ON_ERROR_STOP=1 -Atc "BEGIN READ ONLY; ${sql}; COMMIT;"`], { env: { ...process.env, DB: S.dbUrl }, encoding: 'utf8' });
  const got = new Set(outp.split('\n').filter(l => /^[0-9a-f-]{36}$/.test(l))); const missing = ids.filter(i => !got.has(i));
  assert.equal(missing.length, 0, 'UNAUDITED_WRITES ' + missing.join(',')); return { successfulWrites: ids.length, audited: got.size, missing };
});

const pageErrors = admin.__errors; await browser.close();
const summary = { version: 1, title: 'M11 browser E2E matrix (headless Chromium, lab real Kong)', startedAt, completedAt: new Date().toISOString(), headSha: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  origins: { console: S.consoleOrigin, portal: S.portalOrigin, kongAdmin: S.kongAdmin.replace(/\/\/[^@]*@/, '//') }, passed: results.filter(r => r.passed).length, failed: results.filter(r => !r.passed).length, pageErrors, results, writes, commercialClosed: false };
writeFileSync(`${OUT}/browser-e2e-matrix.json`, scrub(JSON.stringify(summary, null, 1)) + '\n');
console.log(`TOTAL pass=${summary.passed} fail=${summary.failed}`); process.exitCode = summary.failed ? 1 : 0;
