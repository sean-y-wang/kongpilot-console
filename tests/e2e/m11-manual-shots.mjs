// KP-011 manual screenshot re-shoot (lab only). Captures docs/manuals/shots/* slots from the live bridge stack.
// Requires KP_LAB_E2E=true and private secrets (0600). Writes raw 1440x835 PNGs to KP_SHOTS_OUT; no secrets are written.
// U-unknown-verify uses Playwright network fault injection on the browser side only (server receives and commits the
// real schedule request; the browser connection is reset and receipt lookups get 503 during a hold window).
import assert from 'node:assert/strict';
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { chromium } from '@playwright/test';
if (process.env.KP_LAB_E2E !== 'true') throw Error('EXPLICIT_LAB_E2E_REQUIRED');
const st = lstatSync(process.env.KP_LAB_SECRETS); assert(st.isFile() && (st.mode & 0o077) === 0, 'PRIVATE_SECRETS_FILE_REQUIRED');
const S = JSON.parse(readFileSync(process.env.KP_LAB_SECRETS, 'utf8')); const OUT = process.env.KP_SHOTS_OUT; mkdirSync(OUT, { recursive: true });
const only = (process.env.KP_SHOTS_ONLY || '').split(',').filter(Boolean); const log = [];
const q = `clusters/${S.clusterId}`, wq = `workspaceId=${S.workspaceId}`; const VP = { width: 1440, height: 835 };
const nav = (p, u) => p.evaluate(u => { history.pushState({}, '', u); dispatchEvent(new PopStateEvent('popstate')); }, u);
const ctx = (b, origin = S.consoleOrigin) => b.newContext({ baseURL: origin, viewport: VP, ignoreHTTPSErrors: true });
async function session(b, who) { const [u, pw] = { admin: [S.adminUser, S.adminPass], appr: [S.apprUser, S.apprPass] }[who];
  const p = await (await ctx(b)).newPage(); p.setDefaultTimeout(20000); await p.goto('/'); await p.getByLabel('账号', { exact: true }).fill(u); await p.getByLabel('密码', { exact: true }).fill(pw);
  await p.getByRole('button', { name: '登录控制台' }).click(); await p.locator('.user-button').waitFor(); await p.waitForTimeout(1500); return p; }
async function confirm(p, click = true) { const m = p.locator('.ant-modal:visible').last(); await m.waitFor(); const t = await m.innerText(); const w = t.match(/输入\s*(\S+)\s*确认/); if (w) await m.getByRole('textbox').last().fill(w[1]); if (click) await m.locator('.ant-btn-primary, .ant-btn-dangerous').last().click(); return t.split('\n')[0]; }
const menu = async (p, text) => { await p.locator('.ant-layout-sider, aside, nav').getByText(text, { exact: true }).first().click(); await p.waitForTimeout(2000); };
async function shot(p, name) { await p.waitForTimeout(600); await p.screenshot({ path: `${OUT}/${name}.png` }); const t = await p.evaluate(() => document.body.innerText); const hit = t.includes('AI \u4e91'); log.push({ name, legacyBrandInDom: hit, url: new URL(p.url()).pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, ':id') }); assert(!hit, 'LEGACY_BRAND_IN_DOM ' + name); }
const want = n => !only.length || only.includes(n);
const b = await chromium.launch();
try {
  if (want('login')) { const p = await (await ctx(b)).newPage(); await p.goto('/'); await p.getByText('登录控制台').first().waitFor(); await shot(p, 'U-login-light');
    await p.locator('.login-appearance-control button').first().click(); await p.waitForTimeout(800); await shot(p, 'U-login-dark'); await p.context().close(); }
  const admin = await session(b, 'admin');
  if (want('nav')) { await nav(admin, '/'); await admin.waitForTimeout(2500); await shot(admin, 'U-sidebar-nav');
    await menu(admin, 'Vitals 监控'); await admin.waitForTimeout(4000); await shot(admin, 'U-vitals-overview');
    await admin.locator('.user-button').click(); await admin.getByText('用户使用手册').first().waitFor(); await shot(admin, 'R-brand-manual-link'); await admin.keyboard.press('Escape');
    const r = await admin.context().newPage(); await r.goto('/api/v1/health/ready'); await shot(r, 'O-ready-probe'); await r.close(); }
  if (want('entity')) { await menu(admin, 'Services'); const row = admin.locator('tbody tr.ant-table-row').first(); await row.waitFor(); await row.locator('button.table-name').first().click(); await admin.waitForTimeout(1500);
    const d = admin.locator('.ant-drawer-content:visible, .ant-modal:visible').last(); await d.waitFor(); const tab = d.getByRole('tab', { name: 'Plugins' }); if (await tab.count()) { await tab.click(); await admin.waitForTimeout(1500); } await shot(admin, 'U-entity-service-detail'); await admin.keyboard.press('Escape'); }
  if (want('recycle')) { await menu(admin, '回收站'); const btn = admin.locator('button:not([disabled])', { hasText: '提交恢复工单' }).first(); await btn.waitFor(); await btn.click(); await confirm(admin, false); await shot(admin, 'U-recycle-restore'); await admin.keyboard.press('Escape'); await admin.waitForTimeout(600); }
  let wf = process.env.KP_SHOTS_WF || null;
  if (want('workflow')) {
    await menu(admin, '变更审批'); await admin.getByRole('tab', { name: '发起变更' }).click(); await admin.getByRole('button', { name: '准备网关变更' }).click();
    let m = admin.locator('.ant-drawer:visible, .ant-modal:visible').last(); await m.getByText('定时变更', { exact: true }).click(); await admin.waitForTimeout(800); await shot(admin, 'U-schedule-register');
    await m.getByText('定时变更', { exact: true }).click(); const name = 'manual-shot-' + Date.now().toString(36);
    await m.locator('input#name').fill(name); await m.locator('input#host').fill('172.30.0.2'); await m.locator('input#port').fill('80');
    const prep = admin.waitForResponse(r => /entity-changes\/prepare/.test(r.url()) && r.request().method() === 'POST'); await m.getByRole('button', { name: '生成变更预览' }).click(); await prep; await admin.waitForTimeout(1500);
    await admin.getByRole('button', { name: '提交变更工单' }).click(); await confirm(admin); await admin.waitForURL(/\/workflows\/[0-9a-f-]{36}$/); wf = admin.url().split('/').pop(); log.push({ workflowCreated: true, serviceName: name });
    const ap = await session(b, 'appr'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(ap); await nav(ap, '/workflows/' + wf); await ap.getByRole('button', { name: '批准变更', exact: true }).waitFor(); await ap.getByRole('button', { name: '批准变更', exact: true }).scrollIntoViewIfNeeded(); await shot(ap, 'U-approval-vote'); await ap.context().close(); }
  if (want('reject')) { const ap = await session(b, 'appr'); for (const id of (process.env.KP_SHOTS_REJECT || '').split(',').filter(Boolean)) { await nav(ap, '/'); await nav(ap, '/workflows/' + id);
      await ap.getByRole('button', { name: '驳回变更', exact: true }).waitFor(); const ta = ap.getByPlaceholder(/驳回原因|审批/).first(); if (await ta.count()) await ta.fill('KP-011 manual shot cleanup');
      await ap.getByRole('button', { name: '驳回变更', exact: true }).click(); await confirm(ap); await ap.waitForTimeout(1500); log.push({ rejected: true }); } await ap.context().close(); }
  const toB = async p => { await nav(p, '/'); await p.locator('.ant-select').first().click(); await p.getByText(S.clusterBLabel).last().click(); await p.waitForTimeout(1500); return p; };
  if (want('config')) { if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); const sid = process.env.KP_SHOTS_SVC, rt = Number(process.env.KP_SHOTS_RETRIES); assert(process.env.KP_SHOTS_PLAN || (sid && Number.isInteger(rt)), 'SVC_REQUIRED');
    if (process.env.KP_SHOTS_PLAN) { await nav(admin, '/configuration/plans/' + process.env.KP_SHOTS_PLAN); } else {
    await menu(admin, '导入导出 / Diff'); await admin.getByRole('tab', { name: '导入与 Diff' }).click(); await admin.getByLabel('临时导入 YAML').fill(`_format_version: '1.1'\nservices:\n- id: ${sid}\n  retries: ${rt}\n`);
    await admin.getByRole('button', { name: '上传并生成预检 Diff' }).click(); await admin.waitForURL(/\/configuration\/(plans|jobs)\/[0-9a-f-]{36}/, { timeout: 60000 }); log.push({ uploaded: true }); throw Error('UPLOADED_RERUN_WITH_KP_SHOTS_PLAN'); }
    await admin.getByText('配置变更计划').first().waitFor(); await admin.waitForTimeout(2500);
    await admin.getByRole('button', { name: '脱敏字段差异' }).first().click(); await admin.getByText('脱敏 JSON Patch 与真实关系').waitFor(); await shot(admin, 'U-diff-review'); await admin.keyboard.press('Escape'); await admin.waitForTimeout(800);
    await admin.getByRole('button', { name: /审阅并提交审批|创建配置工单/ }).first().click(); await admin.waitForTimeout(1200); const dr = admin.locator('.ant-drawer-content:visible, .ant-modal:visible').last();
    const t = await dr.innerText(); const w = t.match(/输入计划名称[：:]\s*(.+)/); assert(w, 'NO_PLAN_NAME'); await dr.getByRole('textbox').last().fill(w[1].trim());
    const go = dr.getByRole('button', { name: '提交工单' }).last(); await go.click(); await admin.waitForTimeout(1500); if (await admin.locator('.ant-modal:visible').count()) await confirm(admin);
    await admin.waitForURL(/\/workflows\/[0-9a-f-]{36}$/, { timeout: 60000 }).catch(() => {}); await shot(admin, 'debug-config-after'); if (/\/workflows\/[0-9a-f-]{36}$/.test(admin.url())) wf = admin.url().split('/').pop(); log.push({ configWorkflow: !!wf }); }
  if (want('policy')) { if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); await menu(admin, '变更审批'); await admin.getByRole('tab', { name: '审批政策' }).click(); await admin.waitForTimeout(1500); await admin.screenshot({ path: OUT + '/debug-policy-tab.png', fullPage: true });
    await admin.locator('tbody tr').filter({ hasText: /^configuration_v2/ }).first().getByRole('button', { name: '编辑政策' }).click(); const dr = admin.locator('.ant-drawer-content:visible').last(); await dr.waitFor(); await admin.waitForTimeout(800); await admin.screenshot({ path: OUT + '/debug-policy-drawer.png' });
    if (!(await dr.getByLabel('阶段名称').count())) await dr.getByRole('button', { name: '添加审批阶段' }).click();
    await dr.getByLabel('阶段名称').first().fill('管理员审批'); const users = dr.locator('.ant-select').nth(2); await users.click(); await admin.keyboard.type(S.apprUser); await admin.waitForTimeout(1500);
    await admin.locator('.ant-select-item-option').filter({ hasText: S.apprUser }).first().click(); await admin.keyboard.press('Escape').catch(() => {}); await admin.screenshot({ path: OUT + '/debug-policy.png' });
    await dr.getByRole('button', { name: '发布新版本' }).click(); await admin.waitForTimeout(1000); if (await admin.locator('.ant-modal:visible').count()) await confirm(admin); await admin.waitForTimeout(2500); await admin.screenshot({ path: OUT + '/debug-policy-after.png' }); log.push({ policyPublished: true }); }
  if (want('approve')) { assert(wf, 'NO_WF'); const ap = await session(b, 'appr'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(ap); await nav(ap, '/workflows/' + wf);
    const btn = ap.getByRole('button', { name: '批准变更', exact: true }); await btn.waitFor(); await btn.scrollIntoViewIfNeeded(); await shot(ap, 'U-approval-vote'); await btn.click(); await confirm(ap); await ap.waitForTimeout(2000); log.push({ approved: true }); await ap.context().close(); }
  if (want('execute')) { assert(wf, 'NO_WF'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); await nav(admin, '/workflows/' + wf); const x = admin.getByRole('button', { name: '执行已确认计划', exact: true }); await x.waitFor(); await x.click(); await confirm(admin); await admin.waitForTimeout(6000); log.push({ executed: true }); }
  if (want('cancelsched')) { assert(wf, 'NO_WF'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); await nav(admin, '/workflows/' + wf); const c = admin.getByRole('button', { name: '撤销', exact: true }).first(); await c.waitFor(); await c.click(); await confirm(admin); await admin.waitForTimeout(2500); log.push({ businessScheduleCancelled: true }); }
  if (want('board')) { assert(wf, 'NO_WF'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); await nav(admin, '/workflows/' + wf); await admin.getByText('业务排程', { exact: true }).first().waitFor(); await admin.waitForTimeout(1500);
    const c = admin.getByRole('button', { name: '撤销', exact: true }).first(); if (await c.isEnabled().catch(() => false)) { await c.click(); await confirm(admin); await admin.waitForTimeout(2500); log.push({ businessScheduleCancelled: true }); }
    await admin.getByText('业务排程', { exact: true }).first().scrollIntoViewIfNeeded(); await admin.evaluate(() => window.scrollBy(0, -80)); await shot(admin, 'U-schedule-board'); }
  if (want('revoke')) { assert(wf, 'NO_WF'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); await nav(admin, '/workflows/' + wf); const x = admin.getByRole('button', { name: '撤销工单', exact: true }); await x.waitFor(); await x.click(); await confirm(admin); await admin.waitForTimeout(2500); log.push({ revoked: true }); }
  if (want('unknown')) { assert(wf, 'NO_WF'); if (process.env.KP_SHOTS_CLUSTER_B === 'true') await toB(admin); await nav(admin, '/'); await nav(admin, '/workflows/' + wf); await admin.getByRole('button', { name: '登记排程' }).waitFor().catch(async e => { await admin.screenshot({ path: OUT + '/debug-wf.png', fullPage: true }); throw e; });
    let hold = true, serverStatus = null, key = null; const post = u => /\/workflow-schedules(\?|$)/.test(u.pathname);
    await admin.route(u => post(u), async route => { if (route.request().method() !== 'POST') return route.continue(); const h = route.request().headers()['x-idempotency-key'];
      if (!key) { key = h; const resp = await route.fetch(); serverStatus = resp.status(); return route.abort('connectionreset'); } if (hold) return route.abort('connectionreset'); return route.continue(); });
    await admin.route(u => /\/workflow-schedules\/receipts\/by-key\//.test(u.pathname), async route => hold ? route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":{"code":"LAB_RECEIPT_UNAVAILABLE","message":"lab hold"}}' }) : route.continue());
    const pad = n => String(n).padStart(2, '0'), loc = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`, T = Date.now();
    const dts = admin.locator('input[type=datetime-local]:visible'); await dts.nth(0).fill(loc(new Date(T + 4 * 60000))); await dts.nth(1).fill(loc(new Date(T + 3 * 60000))); await dts.nth(2).fill(loc(new Date(T + 8 * 60000)));
    await admin.getByRole('button', { name: '登记排程' }).scrollIntoViewIfNeeded(); await admin.getByRole('button', { name: '登记排程' }).click(); await admin.waitForTimeout(1000); await confirm(admin).catch(async e => { await admin.screenshot({ path: OUT + '/debug-reg.png' }); throw e; });
    await admin.getByText('原排程请求尚未核验').first().waitFor({ timeout: 60000 }); await admin.waitForTimeout(1500); await shot(admin, 'U-unknown-verify');
    for (let i = 0; i < 3 && await admin.locator('.ant-modal:visible').count(); i++) { await admin.locator('.ant-modal:visible .ant-modal-footer button').first().click({ force: true }).catch(() => {}); await admin.waitForTimeout(700); }
    hold = false; await admin.unrouteAll({ behavior: 'wait' }); await admin.waitForTimeout(1000); if (await admin.locator('.ant-modal:visible').count()) await admin.keyboard.press('Escape'); await admin.getByRole('button', { name: '核验原回执' }).dispatchEvent('click'); await admin.getByText('原排程请求已确认').first().waitFor({ timeout: 30000 }); await shot(admin, 'U-unknown-verify-resolved');
    log.push({ unknownServerStatus: serverStatus });
  }

} catch (e) { for (const pg of b.contexts().flatMap(c => c.pages())) await pg.screenshot({ path: `${OUT}/debug-fail-${Math.random().toString(36).slice(2, 6)}.png` }).catch(() => {}); throw e; } finally { writeFileSync(`${OUT}/shots-log.json`, JSON.stringify(log, null, 2)); await b.close(); }
console.log(JSON.stringify(log));
