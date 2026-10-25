import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';

assert.equal(process.env.RELEASE_LAB_READY, 'true');
const state = JSON.parse(readFileSync('/dev/shm/kongpilot-release-lab/m11-harness.json'));
const user = state.sessions.admin;
assert(process.argv.length <= 3 && [undefined, '--after-scroll-layout', '--after-compact-height'].includes(process.argv[2]));
const directory = `artifacts/M11/workflow-board-browser-readonly-${process.argv[2]?.slice(2) ?? 'original'}`;
const output = `${directory}/verification.json`;
assert(!existsSync(output));
mkdirSync(directory, { recursive: true });
const checks = [], responses = [], screenshots = [];
let browser, context, failure, writes = 0, adminRequests = 0, pageErrors = 0;
const check = (name, value) => { assert(value, name); checks.push({ name, passed: true }); };
try {
  browser = await chromium.launch({ headless: true, executablePath: '/usr/bin/chromium' });
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });
  await context.addCookies(user.cookie.split('; ').map(pair => {
    const separator = pair.indexOf('=');
    return { name: pair.slice(0, separator), value: pair.slice(separator + 1), domain: '127.0.0.1', path: '/', httpOnly: !pair.startsWith('kongos_csrf='), secure: false, sameSite: 'Lax' };
  }));
  await context.addInitScript(({ cid, wid }) => {
    sessionStorage.setItem('kongos.clusterId', cid);
    sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid);
  }, { cid: state.cid, wid: state.wid });
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (['8001', '8444'].includes(url.port)) { adminRequests++; return route.abort(); }
    if (url.pathname.startsWith('/api/v1/') && !['GET', 'HEAD'].includes(route.request().method())) { writes++; return route.abort(); }
    return route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', () => pageErrors++);
  page.on('response', response => {
    const url = new URL(response.url());
    if (url.pathname.startsWith('/api/v1/')) responses.push({ method: response.request().method(), path: url.pathname, status: response.status() });
  });
  const me = await context.request.get('http://127.0.0.1:5455/api/v1/auth/me');
  check('actual owner session accepted without a refresh', me.status() === 200 && (await me.json()).data.user.id === user.user.id);
  await page.goto('http://127.0.0.1:5455/workflows', { waitUntil: 'domcontentloaded' });
  const table = page.getByTestId('workflow-list');
  await table.locator('a[href^="/workflows/"]').first().waitFor({ timeout: 30000 });
  const loadedIds = await table.locator('a[href^="/workflows/"]').evaluateAll(links => links.map(link => link.getAttribute('href')).sort());
  check('actual BFF server page contains authorized workflow rows', loadedIds.length > 0);
  await page.getByText('看板', { exact: true }).click();
  const board = page.getByTestId('workflow-board');
  await board.waitFor();
  check('board shows exactly the same bounded server page', JSON.stringify(await board.locator('a[href^="/workflows/"]').evaluateAll(links => links.map(link => link.getAttribute('href')).sort())) === JSON.stringify(loadedIds));
  check('board labels page coverage without implying aggregate totals', (await board.innerText()).includes('第 1 页工单'));
  for (const label of ['待审批', '待执行', '执行中', '执行结果']) check(`board column ${label} is visible`, await board.getByText(label, { exact: true }).count() > 0);
  if (process.argv[2]) {
    check('desktop board retains pagination within viewport', await page.getByRole('button', { name: '下一页', exact: true }).evaluate(element => element.getBoundingClientRect().bottom <= innerHeight));
    check('long result column scrolls independently', await page.getByLabel('执行结果工单列表', { exact: true }).evaluate(element => element.scrollHeight > element.clientHeight));
    check('sidebar retains full viewport height', await page.locator('.console-sidebar').evaluate(element => element.getBoundingClientRect().height >= innerHeight - 30));
  }
  await page.screenshot({ path: `${directory}/workflow-board-desktop.png`, fullPage: !process.argv[2] });
  screenshots.push(`${directory}/workflow-board-desktop.png`);
  await page.setViewportSize({ width: 390, height: 844 });
  check('mobile board has no document width overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
  await page.screenshot({ path: `${directory}/workflow-board-mobile.png`, fullPage: true });
  screenshots.push(`${directory}/workflow-board-mobile.png`);
  check('no business write or direct Admin API request', writes === 0 && adminRequests === 0);
  check('no unhandled page errors', pageErrors === 0);
} catch (error) {
  failure = { kind: error.name, ...(typeof error.message === 'string' && error.message.length < 150 ? { check: error.message } : {}) };
} finally {
  await context?.close(); await browser?.close();
  const report = { passed: !failure, sourceOnly: false, actualBackend: true, productionDeployment: false, overallM11Accepted: false, checks, responses, screenshots, writes, adminRequests, pageErrors, ...(failure ? { failure } : {}) };
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify({ passed: report.passed, checks: checks.length, screenshots: screenshots.length, failure }));
  if (failure) process.exitCode = 1;
}
