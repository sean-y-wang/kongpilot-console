import { chromium, expect } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { M8_REFERENCE, readM8Reference, durableJson, sha256, entity } from './lib/m8-harness.mjs';
import { M8_UI_ACTIONS, M8_UI_NOOP_YAML, createM8UiJournal, m8UiCookies, m8UiUuid, m8UiRemember, beforeM8UiPacket, m8UiAttemptFor, observeM8UiAck, confirmM8UiReceipt, m8UiReceiptPath, proveM8UiActor, bindM8UiEntity, interruptM8Ui, stopM8Ui } from './lib/m8-manual-journal.mjs';
import { isM8ProvenConsumedUnknownDownload } from './lib/m8-consumed-review-download.mjs';

if(process.env.M8_MANUAL_UNUSED_TWO_READY!=='true')throw Error('M8_MANUAL_UNUSED_TWO_RELEASE_REQUIRED');
const reference=readM8Reference(),handoff=reference.manualUiHandoff,journal=reference.manualUiJournal;
const originalPrefixSha256='c3f28268c46f554b6c8c480edd853dc45384ed25ce676f44a77dd6b03dbd1749';
if(reference.phase!=='manual-known-ten-sessions-ready'||reference.requests.length!==197||sha256(JSON.stringify(reference.requests))!==originalPrefixSha256||journal.phase!=='ready'||journal.nextIndex!==10||journal.attempts.length!==10||journal.attempts.some(a=>a.state!=='succeeded')||reference.inFlight!==null)throw Error('M8_EXACT197_KNOWN_TEN_ACTIONS_REQUIRED');
const sessions=journal.currentSessions,M8_UI_OUTPUT='artifacts/M8/manual-ui-unused-tail.json',old=JSON.parse(readFileSync('artifacts/M8/manual-ui-independent.json'));
if(existsSync(M8_UI_OUTPUT))throw Error('M8_ORIGINAL_UNUSED_TAIL_REPORT_EXISTS');
const checks=old.checks.filter(c=>c.passed),screenshots=[...old.screenshots],reads=[...old.reads],errors=[],report={milestone:'M8',stage:'actual-manual-ui-known-unused-tail',testTag:journal.testTag,allPassed:false,checks,screenshots,reads,plannedActions:[...M8_UI_ACTIONS],originalFirstTenReplayed:false,inheritedManualPath:'artifacts/M8/manual-ui-independent.json',inheritedRestoreProofPath:'artifacts/M8/manual-original-restore-confirmed.json',normalSameSidEpochsRetained:true};
let browser,phase='unused-tail-preflight',chain=Promise.resolve(),lateHeld=true,lateRelease;
function persistReport() { Object.assign(report, { allPassed: report.allPassed === true && journal.phase === 'complete' && errors.length === 0 && checks.every(row => row.passed), performedAt: new Date().toISOString(), passed: checks.filter(row => row.passed).length, failed: checks.filter(row => !row.passed).length, successfulUiWrites: journal.attempts.filter(row => row.state === 'succeeded').length, unknownUiWrites: journal.attempts.filter(row => row.state === 'response_unknown').length, blockedBeforePacketAttempts: journal.attempts.filter(row => row.state === 'blocked-before-packet').length, stopped: journal.phase === 'stopped-without-replay', currentPhase: phase }); durableJson(M8_UI_OUTPUT, report, 0o644); }
function check(name, passed, facts = {}) { phase = name; checks.push({ name, passed: !!passed, ...facts }); persistReport(); if (!passed) throw Error('M8_UI_ASSERTION_FAILED'); }
function retain() {
 const latest=readM8Reference();
 if(sha256(JSON.stringify(latest.requests.slice(0,197)))!==originalPrefixSha256)throw Error('M8_ORIGINAL197_PREFIX_CHANGED');
 const packets=[...latest.requests];
 for(const attempt of journal.attempts){
  if(attempt.index<10)continue;
  if(attempt.globalPacketIndex===undefined)attempt.globalPacketIndex=packets.length;
  const p={index:attempt.globalPacketIndex,source:'manual-ui',manualIndex:attempt.index,action:attempt.action,key:attempt.key,method:attempt.method,path:attempt.path??new URL(attempt.url).pathname,query:attempt.query??new URL(attempt.url).search,body:attempt.body,bodySha256:attempt.bodySha256,actorId:attempt.actorId,sessionId:attempt.sessionId,clusterId:attempt.clusterId,workspaceId:attempt.workspaceId,headers:attempt.headers,state:attempt.state==='prepared'?'prepared':attempt.state==='response_unknown'?'response_unknown':attempt.state==='blocked-before-packet'?'blocked-before-packet':'response_observed',startedAt:attempt.startedAt,expected:[200,201,202],status:attempt.status,requestId:attempt.requestId,responseData:attempt.responseData??null,receiptRequestId:attempt.receiptRequestId,binary:attempt.binary};
  if(p.index===packets.length)packets.push(p);else if(p.index>=197&&packets[p.index]?.key===p.key)packets[p.index]=p;else throw Error('M8_UNUSED_TAIL_PACKET_INDEX_CONFLICT');
 }
 durableJson(M8_REFERENCE,{...latest,manualUiJournal:journal,requests:packets,secrets:[...new Set([...latest.secrets,...m8UiRemember(journal)])],phase:journal.phase==='complete'?'ui-complete':journal.phase==='stopped-without-replay'?'stopped-ui-no-replay':'ui-active',inFlight:journal.inFlight===null?null:(journal.attempts[journal.inFlight].globalPacketIndex??184+journal.inFlight)});
}

function packet(request, headers = request.headers()) { return { method: request.method(), url: request.url(), rawBody: request.postData(), headers }; }
function safeRead(role, urlText, status, data, requestId) {
  const url = new URL(urlText); reads.push({ role, actorId: sessions[role].user.id, method: 'GET', path: url.pathname, query: url.search, status, requestId });
  if (status !== 200 || !m8UiUuid(requestId)) return;
  if (url.pathname === '/api/v1/auth/me') proveM8UiActor(journal, role, data, retain);
  const pending = journal.attempts[journal.inFlight]; if (role === 'admin' && pending?.state === 'acknowledged' && url.pathname + url.search === m8UiReceiptPath(journal, pending)) confirmM8UiReceipt(journal, role, { method: 'GET', url: urlText }, data, requestId, retain);
  if (role === 'admin' && url.pathname === `/api/v1/clusters/${journal.scope.cid}/snapshots/${journal.bindings.captureId}` && url.searchParams.get('workspaceId') === journal.scope.wid) bindM8UiEntity(journal, 'snapshot', entity(data), retain);
  if (role === 'admin' && url.pathname === `/api/v1/clusters/${journal.scope.cid}/configuration/plans/${journal.seed.planId}` && url.searchParams.get('workspaceId') === journal.scope.wid) bindM8UiEntity(journal, 'plan', entity(data), retain);
}
async function boundary(context, role) {
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (/^https?:$/.test(url.protocol) && url.origin !== 'http://127.0.0.1:8080') { try { stopM8Ui(journal, 'browser-origin-outside-console-bff', retain); } catch {} await route.abort('blockedbyclient'); return; }
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
      const current = journal.attempts[journal.inFlight];
      if (current?.action === 'snapshot.restore' && url.pathname + url.search === m8UiReceiptPath(journal, current) && !lateHeld) { lateHeld = true; await new Promise(resolve => { lateRelease = resolve; }); }
      await route.continue(); return;
    }
    try { beforeM8UiPacket(journal, role, packet(request, await request.allHeaders()), await context.cookies(), retain); await route.continue(); } catch { await route.abort('blockedbyclient'); }
  });
  context.on('response', response => {
    if (!response.url().startsWith('http://127.0.0.1:8080/api/v1/')) return;
    chain = chain.then(async () => {
      const request = response.request(), write = !['GET', 'HEAD', 'OPTIONS'].includes(request.method()), attempt = write ? m8UiAttemptFor(journal, packet(request)) : null;
      if (write && attempt?.binary) {
        const headers = response.headers();
        // Preserve genuine header evidence before asking Chromium for bytes.
        // Binary downloads never pass through the JSON-envelope parser.
        attempt.observedResponse = { status: response.status(), requestId: headers['x-request-id'], contentType: headers['content-type'], contentDisposition: headers['content-disposition'], cacheControl: headers['cache-control'], nosniff: headers['x-content-type-options'], bodyConfirmed: false }; retain();
        const bytes = await response.body(), expected = journal.bindings.export.exportId;
        observeM8UiAck(journal, attempt, { status: response.status(), requestId: headers['x-request-id'], binary: { bytes: bytes.length, sha256: sha256(bytes), yaml: /^application\/yaml\b/.test(headers['content-type'] ?? ''), noStore: headers['cache-control'] === 'no-store', nosniff: headers['x-content-type-options'] === 'nosniff', exportId: /^attachment; filename="configuration-([a-f\d-]{36})\.yaml"$/.exec(headers['content-disposition'] ?? '')?.[1] === expected ? expected : null } }, retain); bytes.fill(0); return;
      }
      let payload; try { payload = await response.json(); } catch {
        if (!write) return;
        if (!attempt?.binary) { interruptM8Ui(journal, attempt, retain); return; }
        const bytes = await response.body(), headers = response.headers(), expected = journal.bindings.export.exportId;
        observeM8UiAck(journal, attempt, { status: response.status(), requestId: headers['x-request-id'], binary: { bytes: bytes.length, sha256: sha256(bytes), yaml: /^application\/yaml\b/.test(headers['content-type'] ?? ''), noStore: headers['cache-control'] === 'no-store', nosniff: headers['x-content-type-options'] === 'nosniff', exportId: /^attachment; filename="configuration-([a-f\d-]{36})\.yaml"$/.exec(headers['content-disposition'] ?? '')?.[1] === expected ? expected : null } }, retain); bytes.fill(0); return;
      }
      const requestId = payload?.meta?.requestId ?? response.headers()['x-request-id'];
      if (write) observeM8UiAck(journal, attempt, { status: response.status(), requestId, data: payload.data }, retain); else safeRead(role, response.url(), response.status(), payload.data, requestId);
      persistReport();
    }).catch(() => { errors.push({ phase, code: 'M8_UI_RESPONSE_NOT_PROVEN' }); try { stopM8Ui(journal, 'response-not-proven', retain); } catch {} });
  });
  context.on('requestfailed', request => { if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) { try { interruptM8Ui(journal, m8UiAttemptFor(journal, packet(request)), retain); } catch {} } });
}
async function settle() { await chain; if (errors.length || journal.phase === 'stopped-without-replay') throw Error('M8_UI_ORIGINAL_RESULT_STOPPED'); }
async function choose(page, label, text) { const input = page.getByLabel(label, { exact: true }).and(page.locator('input[role="combobox"]')); await expect(input).toHaveCount(1); if (await input.getAttribute('aria-expanded') !== 'true') await input.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-select ")][1]').locator('.ant-select-selector').click(); const option = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ has: page.getByText(text, { exact: true }) }); await expect(option).toHaveCount(1); await option.click(); }
async function scopePage(page, path, clusterLabel = handoff.directClusterLabel, workspaceName = handoff.directWorkspaceName) { await page.goto(`http://127.0.0.1:8080${path}`); await expect(page.getByLabel('选择集群', { exact: true }).and(page.locator('input[role="combobox"]'))).toBeVisible(); await choose(page, '选择集群', clusterLabel); await choose(page, '选择工作区', workspaceName); await settle(); }
async function stable(page) { await expect(page.locator('.ant-spin-spinning:visible')).toHaveCount(0); await settle(); }
async function shot(page, name) { await stable(page); await expect(page.locator('input[type="password"]:visible')).toHaveCount(0); const material = page.getByLabel('临时导入 YAML', { exact: true }); if (await material.count()) await expect(material).toHaveValue(''); await page.evaluate(() => window.scrollTo(0, 0)); await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0); await page.mouse.move(320, 60); await page.waitForTimeout(200); const path = `artifacts/M8/manual-${'unused-tail-'}${name}.png`; if (existsSync(path)) throw Error('M8_UI_SCREENSHOT_ORIGINAL_NO_OVERWRITE'); await page.screenshot({ path, fullPage: true, animations: 'disabled' }); screenshots.push({ path, sha256: sha256(readFileSync(path)) }); persistReport(); }
async function read(context, role, suffix) { const response = await context.request.get(`http://127.0.0.1:8080/api/v1${suffix}`), payload = await response.json(); check('protected read uses current original actor and exact BFF route', response.status() === 200 && m8UiUuid(payload.meta?.requestId)); safeRead(role, response.url(), response.status(), payload.data, payload.meta.requestId); return payload.data; }
async function waitStep(context, index) { await expect.poll(async () => { await settle(); const pending = journal.attempts[journal.inFlight]; if (pending?.state === 'acknowledged' && journal.nextIndex < index) await read(context, 'admin', m8UiReceiptPath(journal, pending).slice('/api/v1'.length)); return journal.nextIndex; }, { timeout: 60000 }).toBe(index); check(`exact unused ${M8_UI_ACTIONS[index - 1]} has original protected terminal receipt`, true, { requestId: journal.attempts[index - 1].requestId, receiptRequestId: journal.attempts[index - 1].receiptRequestId }); }
async function confirm(page, title, name, execute = true) { const dialog = page.getByRole('dialog').filter({ has: page.getByText(title, { exact: true }) }); await expect(dialog).toHaveCount(1); const input = dialog.getByLabel('确认名称', { exact: true }), button = dialog.getByRole('button', { name: '确认执行', exact: true }); await expect(button).toBeDisabled(); await input.fill(`${name}-wrong`); await expect(button).toBeDisabled(); await input.fill(name); await expect(button).toBeEnabled(); if (execute) await button.click(); else await dialog.getByRole('button', { name: /取\s*消/ }).click(); }
async function knownRow(page, id) { for (let pages = 0; pages < 5; pages++) { await expect.poll(() => page.locator('tr[data-row-key]').count(), { timeout: 20000 }).toBeGreaterThan(0); await stable(page); const row = page.locator(`tr[data-row-key="${id}"]`); if (await row.count() === 1) return row; const next = page.getByRole('button', { name: '下一页', exact: true }).last(); if (!await next.isEnabled()) break; const before = await page.locator('tr[data-row-key]').evaluateAll(rows => rows.map(row => row.getAttribute('data-row-key')).join('|')); await next.click(); await expect.poll(() => page.locator('tr[data-row-key]').evaluateAll(rows => rows.map(row => row.getAttribute('data-row-key')).join('|'))).not.toBe(before); } throw Error('M8_UI_KNOWN_ROW_NOT_IN_BOUNDED_SERVER_PAGES'); }
try {
 retain();persistReport();browser=await chromium.launch({headless:true,executablePath:'/usr/bin/chromium'});
 const contexts={},pages={};
 for(const role of ['admin','owner','readonly']){contexts[role]=await browser.newContext({baseURL:'http://127.0.0.1:8080',viewport:{width:1440,height:1050},acceptDownloads:true});await contexts[role].addCookies(m8UiCookies(sessions[role]));await boundary(contexts[role],role);pages[role]=await contexts[role].newPage();}
 const page=pages.admin,context=contexts.admin,area=journal.scope,q=`?workspaceId=${area.wid}`;
  await scopePage(page, '/configuration'); await page.getByRole('tab', { name: '导入与 Diff', exact: true }).click(); await page.getByLabel('临时导入 YAML', { exact: true }).fill(M8_UI_NOOP_YAML); await page.getByRole('button', { name: '上传并生成预检 Diff', exact: true }).click(); await waitStep(context, 11); await expect(page.getByRole('heading', { name: '配置作业详情', exact: true })).toBeVisible(); await page.getByRole('link', { name: '审阅不可变 Diff', exact: true }).click(); await expect(page.getByRole('heading', { name: '配置变更计划', exact: true })).toBeVisible(); check('safe empty merge generates no native mutations', journal.attempts[10].receipt.stepCount === 0 && journal.attempts[10].receipt.deleteCount === 0); await shot(page, 'noop-import-immutable-plan');
  await scopePage(page, `/configuration/plans/${handoff.planId}`); await read(context, 'admin', `/clusters/${area.cid}/configuration/plans/${handoff.planId}${q}`); await page.getByRole('button', { name: '只读核验实际结果', exact: true }).click(); await waitStep(context, 12); await expect(page.getByRole('dialog').filter({ has: page.getByText('逐对象只读核验', { exact: true }) })).toBeVisible(); await shot(page, 'plan-readonly-causal-unproven'); await page.getByRole('dialog').filter({ has: page.getByText('逐对象只读核验', { exact: true }) }).locator('.ant-drawer-close').click();
  await scopePage(pages.readonly, '/snapshots'); await expect(pages.readonly.getByRole('button', { name: '手动创建快照', exact: true })).toBeDisabled(); await shot(pages.readonly, 'readonly-snapshots'); await scopePage(pages.admin, `/workflows/${handoff.approvalWorkflowId}`, handoff.approvalClusterLabel, handoff.approvalWorkspaceName); await expect(page.getByTestId('workflow-state')).toContainText('已完成'); await expect(page.getByRole('button', { name: '执行已确认计划', exact: true })).toHaveCount(0); await expect(page.getByRole('button', { name: '批准变更', exact: true })).toHaveCount(0); await shot(page, 'completed-approval-readonly');
  await pages.owner.setViewportSize({ width: 390, height: 844 }); await scopePage(pages.owner, '/snapshots'); await shot(pages.owner, 'snapshots-mobile'); report.mobileDimensions = await pages.owner.evaluate(() => ({ innerWidth: window.innerWidth, documentScrollWidth: document.documentElement.scrollWidth, tableScrollers: Array.from(document.querySelectorAll('.ant-table-content,.ant-table-body')).map(el => ({ clientWidth: el.clientWidth, scrollWidth: el.scrollWidth })) })); check('mobile overflow is contained inside the table scroller', report.mobileDimensions.documentScrollWidth <= report.mobileDimensions.innerWidth && report.mobileDimensions.tableScrollers.some(row => row.scrollWidth >= row.clientWidth));
  check('all twelve unique UI requests have protected original terminal receipts', journal.nextIndex === 12 && journal.attempts.length === 12 && journal.attempts.every(row => row.state === 'succeeded' && m8UiUuid(row.requestId) && m8UiUuid(row.receiptRequestId))); report.allPassed = true;
} catch { if (!checks.some(row => row.passed === false)) checks.push({ name: `manual stopped after ${phase}`, passed: false, reason: 'M8_UI_ASSERTION_OR_ORIGINAL_RESULT_STOP' }); try { stopM8Ui(journal, 'manual-assertion-or-original-unknown-stop', retain); } catch {} }
finally { lateRelease?.(); await browser?.close(); await chain; try { retain(); } catch { report.allPassed = false; checks.push({ name: 'final original journal preservation', passed: false }); } persistReport(); }
console.log(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, successfulUiWrites: report.successfulUiWrites, unknownUiWrites: report.unknownUiWrites, screenshots: screenshots.length })); process.exitCode = report.allPassed ? 0 : 1;
