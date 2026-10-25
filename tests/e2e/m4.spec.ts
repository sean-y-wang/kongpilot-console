import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';

if (existsSync('.env')) process.loadEnvFile('.env');
test.use({ trace: 'off', viewport: { width: 1440, height: 960 } });

test('M4 independent authenticated browser scopes, strict profile, IAM matrix and immediate role revocation', async ({ browser }) => {
  test.setTimeout(180_000);
  const live = JSON.parse(readFileSync('artifacts/M4/security-live.json', 'utf8'));
  expect(live.failed).toBe(0);
  const privatePath = '/tmp/kongos-m4-runtime-secrets.json';
  if (!existsSync(privatePath) || (statSync(privatePath).mode & 0o777) !== 0o600) throw new Error('private M4 runtime reference required');
  const privateReference = JSON.parse(readFileSync(privatePath, 'utf8'));
  const errors: string[] = [], adminRequests: string[] = [], missingScopes: string[] = [], screenshots: string[] = [];
  const contexts: BrowserContext[] = [];
  const successfulWrites: { method: string; path: string; requestId?: string }[] = [];
  const pendingWriteEvidence: Promise<void>[] = [];
  mkdirSync('artifacts/M4', { recursive: true });
  const service = live.fixtures.find((item: any) => item.clusterId === live.clusterId && item.type === 'services' && item.id === live.fixtureIds.service);
  const privateService = live.fixtures.find((item: any) => item.id === live.fixtureIds.privateService && item.type === 'services');
  if (!service || !privateService) throw new Error('owned real M4 Service fixtures required');
  async function open(label: string) {
    const account = privateReference.users.find((item: any) => item.label === label);
    const credentials = label === 'bootstrap' ? { username: process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password: process.env.BOOTSTRAP_ADMIN_PASSWORD } : account;
    if (!credentials?.password) throw new Error('fixture account missing');
    const context = await browser.newContext({ baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080', viewport: { width: 1440, height: 960 } });
    contexts.push(context);
    await context.addInitScript(({ cid, wid }) => { sessionStorage.setItem('kongos.clusterId', cid); sessionStorage.setItem(`kongos.workspaceId.${cid}`, wid); }, { cid: live.clusterId, wid: live.payWorkspace.id });
    const page = await context.newPage(); page.setDefaultTimeout(15_000);
    page.on('pageerror', error => errors.push(error.name));
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.port === '8001') adminRequests.push(url.pathname);
      if (/\/api\/v1\/clusters\/[^/]+\/(entities|entity-annotations|upstreams|consumers|recycle-bin|plugin-center|plugin-schemas|schemas|inventory|mutations|workspace-migrations|authorization)(\/|$)/.test(url.pathname) && !url.searchParams.has('workspaceId')) missingScopes.push(`${request.method()} ${url.pathname}`);
    });
    page.on('response', response => {
      const request = response.request(), url = new URL(response.url());
      // Authorization projections are read-only reviews despite POST transport.
      if (!url.pathname.startsWith('/api/v1/') || ['GET', 'HEAD'].includes(request.method()) || response.status() < 200 || response.status() >= 300 || url.pathname.endsWith('/authorization/entity-capabilities')) return;
      pendingWriteEvidence.push((async () => {
        const payload = await response.json();
        successfulWrites.push({ method: request.method(), path: url.pathname, requestId: payload?.meta?.requestId });
      })());
    });
    await page.goto('/');
    await page.getByLabel('账号', { exact: true }).fill(credentials.username);
    await page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, value);
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, credentials.password);
    await page.getByRole('button', { name: '登录控制台', exact: true }).click();
    await expect(page.getByRole('heading', { name: label === 'ordinary' ? '我的账号' : '网关总览', exact: true })).toBeVisible();
    const cookies = await context.cookies();
    privateReference.secrets.push(...cookies.filter(cookie => /^kongos_(access|refresh|csrf)$/.test(cookie.name)).map(cookie => cookie.value));
    const csrf = cookies.find(cookie => cookie.name === 'kongos_csrf')?.value;
    if (!csrf) throw new Error('validated browser CSRF cookie required');
    return { context, page, csrf };
  }
  async function screenshot(page: Page, name: string) {
    await expect(page.locator('.ant-message-notice')).toHaveCount(0);
    await page.mouse.move(280, 100); await page.screenshot({ path: `artifacts/M4/${name}.png`, fullPage: true, animations: 'disabled' });
    screenshots.push(`${name}.png`);
  }
  const path = (type: string, id = service.id, cid = live.clusterId, wid = live.payWorkspace.id) => `/api/v1/clusters/${cid}/entities/${type}/${id}?workspaceId=${wid}`;
  try {
    const reader = await open('pay-reader');
    await reader.page.goto('/entities/services');
    await reader.page.getByLabel('搜索实体', { exact: true }).fill(service.name);
    await reader.page.getByLabel('搜索实体', { exact: true }).press('Enter');
    const serviceButton = reader.page.getByRole('button', { name: service.name, exact: true });
    await expect(serviceButton).toBeVisible();
    const row = serviceButton.locator('xpath=ancestor::tr[1]');
    await expect(reader.page.getByRole('button', { name: /创建 Services/ })).toBeDisabled();
    await expect(row.getByRole('button', { name: /编辑/ })).toBeDisabled();
    await expect(row.getByRole('button', { name: /删\s*除/ })).toBeDisabled();
    const before = await reader.context.request.get(path('services'));
    expect(before.status()).toBe(200);
    const oldRetries = (await before.json()).data.entity.retries;
    const forbidden = await reader.context.request.patch(path('services'), { headers: { 'X-CSRF-Token': reader.csrf, 'X-Idempotency-Key': randomUUID() }, data: { retries: 99 } });
    expect(forbidden.status()).toBe(403);
    expect((await (await reader.context.request.get(path('services'))).json()).data.entity.retries).toBe(oldRetries);
    expect((await reader.context.request.get(path('services', live.fixtureIds.secondaryService, live.secondaryClusterId, live.secondaryPayWorkspaceId))).status()).toBe(403);
    await screenshot(reader.page, 'read-only-actions');

    const tagReader = await open('tag-reader');
    await tagReader.page.goto('/entities/services');
    await tagReader.page.getByLabel('搜索实体', { exact: true }).fill(live.testTag);
    await tagReader.page.getByLabel('搜索实体', { exact: true }).press('Enter');
    await expect(tagReader.page.getByRole('button', { name: service.name, exact: true })).toBeVisible();
    await expect(tagReader.page.getByRole('button', { name: privateService.name, exact: true })).toHaveCount(0);
    expect((await tagReader.context.request.get(path('services', privateService.id))).status()).toBe(403);
    await screenshot(tagReader.page, 'tag-group-filter');

    const routeReader = await open('route-reader');
    await routeReader.page.goto(`/entities/services/${service.id}`);
    const inheritedDetail = routeReader.page.locator('.ant-drawer-content').filter({ hasText: `Services · ${service.name}` });
    await expect(inheritedDetail.getByRole('tab', { name: 'Configuration', exact: true })).toBeVisible();
    await expect(inheritedDetail.getByRole('button', { name: /编辑/ })).toBeDisabled();
    expect((await routeReader.context.request.patch(path('services'), { headers: { 'X-CSRF-Token': routeReader.csrf, 'X-Idempotency-Key': randomUUID() }, data: { retries: 98 } })).status()).toBe(403);
    await screenshot(routeReader.page, 'route-parent-read-only');

    const childReader = await open('credential-entity-reader');
    await childReader.page.goto('/authorized-children');
    await expect(childReader.page.getByRole('heading', { name: '授权子实体', exact: true })).toBeVisible();
    const childRow = childReader.page.locator('tbody tr').filter({ hasText: live.credentialIds['key-auth'] });
    await expect(childRow).toHaveCount(1);
    await expect(childRow.getByRole('button', { name: /编辑/ })).toBeDisabled();
    await expect(childRow.getByRole('button', { name: '查看秘密', exact: true })).toBeDisabled();
    const childList = await childReader.context.request.get(`/api/v1/clusters/${live.clusterId}/authorization/children?workspaceId=${live.payWorkspace.id}&type=key-auth&size=20`);
    expect(childList.status()).toBe(200);
    const childItems = (await childList.json()).data.items;
    expect(childItems.every((item: any) => item.id === live.credentialIds['key-auth'] && item.type === 'key-auth')).toBe(true);
    expect((await childReader.context.request.get(path('consumers', live.fixtureIds.consumer))).status()).toBe(403);
    await screenshot(childReader.page, 'typed-child-without-parent-configuration');

    const writer = await open('service-writer');
    await writer.page.goto(`/entities/services/${service.id}`);
    const writerDetail = writer.page.locator('.ant-drawer-content').filter({ hasText: `Services · ${service.name}` });
    await expect(writerDetail.getByRole('button', { name: /编辑/ })).toBeEnabled();
    await expect(writerDetail.getByRole('button', { name: /删\s*除/ })).toBeDisabled();
    await writerDetail.getByRole('button', { name: /编辑/ }).click();
    await writer.page.getByLabel('retries', { exact: true }).fill('3');
    const saved = writer.page.waitForResponse(response => response.request().method() === 'PATCH' && new URL(response.url()).pathname.endsWith(`/entities/services/${service.id}`));
    await writer.page.getByRole('button', { name: '保存配置', exact: true }).click();
    expect((await saved).status()).toBe(200);
    expect((await (await writer.context.request.get(path('services'))).json()).data.entity.retries).toBe(3);
    await screenshot(writer.page, 'entity-write-without-delete');

    const ordinary = await open('ordinary');
    await ordinary.page.goto('/profile');
    await expect(ordinary.page.getByRole('heading', { name: '我的账号', exact: true })).toBeVisible();
    const meBefore = (await (await ordinary.context.request.get('/api/v1/auth/me')).json()).data.user;
    const escalated = await ordinary.context.request.patch('/api/v1/auth/me/profile', { headers: { 'X-CSRF-Token': ordinary.csrf, 'X-Idempotency-Key': randomUUID() }, data: { revision: meBefore.revision, admin: 'true', superAdmin: true, roles: [live.accounts['workspace-admin'].role.id] } });
    expect([400, 403]).toContain(escalated.status());
    const meAfter = (await (await ordinary.context.request.get('/api/v1/auth/me')).json()).data.user;
    expect(meAfter.id).toBe(meBefore.id); expect(meAfter.superAdmin).toBe(false);
    await ordinary.page.getByLabel('显示名称', { exact: true }).fill('M4 普通账号已验证');
    const profileSaved = ordinary.page.waitForResponse(response => response.request().method() === 'PATCH' && new URL(response.url()).pathname.endsWith('/auth/me/profile'));
    await ordinary.page.getByRole('button', { name: '保存资料', exact: true }).click();
    expect((await profileSaved).status()).toBe(200);
    await screenshot(ordinary.page, 'ordinary-profile-strict-fields');
    // Exercise a real same-browser actor switch and real Set-Cookie handling.
    // The deferred late-refresh race is separately labelled in unit evidence.
    const priorAccess = (await ordinary.context.cookies()).find(cookie => cookie.name === 'kongos_access')?.value;
    if (!priorAccess) throw new Error('prior actor cookie required');
    await ordinary.page.locator('.user-button').click();
    await ordinary.page.getByRole('menuitem', { name: /退出登录/ }).click();
    await expect(ordinary.page.getByRole('button', { name: '登录控制台', exact: true })).toBeVisible();
    const nextActor = privateReference.users.find((item: any) => item.label === 'pay-reader');
    await ordinary.page.getByLabel('账号', { exact: true }).fill(nextActor.username);
    await ordinary.page.getByLabel('密码', { exact: true }).evaluate((element, value) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, value);
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, nextActor.password);
    await ordinary.page.getByRole('button', { name: '登录控制台', exact: true }).click();
    await expect(ordinary.page.getByRole('heading', { name: '我的账号', exact: true })).toBeVisible();
    await expect(ordinary.page.locator('.user-button')).toContainText('M4 pay-reader');
    const switched = (await (await ordinary.context.request.get('/api/v1/auth/me')).json()).data.user;
    expect(switched.id).toBe(live.accounts['pay-reader'].id);
    expect((await ordinary.context.request.get(path('services'))).status()).toBe(200);
    expect((await ordinary.context.request.get('/api/v1/auth/me', { headers: { Cookie: `kongos_access=${priorAccess}` } })).status()).toBe(401);
    await ordinary.page.goto('/');
    await expect(ordinary.page.getByRole('heading', { name: '网关总览', exact: true })).toBeVisible();
    await screenshot(ordinary.page, 'same-browser-verified-account-switch');

    const administrator = await open('bootstrap');
    await administrator.page.goto('/access?tab=matrix');
    await expect(administrator.page.getByRole('heading', { name: '身份与权限', exact: true })).toBeVisible();
    const picker = administrator.page.getByRole('combobox', { name: '矩阵角色', exact: true });
    await picker.click(); await picker.fill(live.accounts['pay-reader'].role.name);
    await administrator.page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({ hasText: live.accounts['pay-reader'].role.name }).click();
    await expect(administrator.page.getByText('固定继承规则', { exact: true })).toBeVisible();
    await expect(administrator.page.locator('.ant-tag').filter({ hasText: /工作区/ }).first()).toBeVisible();
    await screenshot(administrator.page, 'role-module-permission-matrix');
    const writerBinding = live.accounts['service-writer'];
    const revoked = await administrator.context.request.delete(`/api/v1/iam/users/${writerBinding.id}/role-bindings/${writerBinding.binding.id}`, { headers: { 'X-CSRF-Token': administrator.csrf, 'X-Idempotency-Key': randomUUID() }, data: { revision: writerBinding.binding.revision, confirmed: true, confirm_name: writerBinding.role.name } });
    expect(revoked.status()).toBe(200);
    successfulWrites.push({ method: 'DELETE', path: `/api/v1/iam/users/${writerBinding.id}/role-bindings/${writerBinding.binding.id}`, requestId: (await revoked.json()).meta?.requestId });
    expect((await writer.context.request.patch(path('services'), { headers: { 'X-CSRF-Token': writer.csrf, 'X-Idempotency-Key': randomUUID() }, data: { retries: 97 } })).status()).toBe(403);
    await writer.page.goto('/profile'); await writer.page.reload();
    await expect(writer.page.getByRole('heading', { name: '我的账号', exact: true })).toBeVisible();
    const refreshedWriter = (await (await writer.context.request.get('/api/v1/auth/me')).json()).data.user;
    expect(refreshedWriter.capabilities.grants.some((grant: any) => grant.role_id === writerBinding.role.id)).toBe(false);
    await screenshot(writer.page, 'revoked-role-current-session');
    await administrator.page.setViewportSize({ width: 390, height: 844 });
    await administrator.page.goto('/access?tab=matrix');
    await expect(administrator.page.getByRole('heading', { name: '身份与权限', exact: true })).toBeVisible();
    await screenshot(administrator.page, 'access-mobile');
    expect(errors).toEqual([]); expect(adminRequests).toEqual([]); expect(missingScopes).toEqual([]);
    await Promise.all(pendingWriteEvidence);
    expect(successfulWrites.every(item => !!item.requestId)).toBe(true);
    const requestIds = [...new Set(successfulWrites.map(item => item.requestId))];
    const auditCode = `import pg from 'pg';let input='';for await(const c of process.stdin)input+=c;const pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});try{const r=await pool.query('SELECT request_id FROM audit_events WHERE request_id=ANY($1::text[])',[JSON.parse(input)]);console.log(JSON.stringify(r.rows.map(v=>v.request_id)));}finally{await pool.end();}`;
    const auditedIds = new Set(JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', auditCode], { input: JSON.stringify(requestIds), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })));
    expect(requestIds.every(id => auditedIds.has(id))).toBe(true);
    writeFileSync('artifacts/M4/browser-verification.json', JSON.stringify({ performedAt: new Date().toISOString(), passed: 1, failed: 0, mechanisms: { readOnlyButtonsAndDirectHttp: true, tagGroupScope: true, parentReadInheritance: true, pureTypedChildWithoutParentConfig: true, entityWriteWithoutDelete: true, sameIdC2Denied: true, ordinaryProfileMassAssignmentDenied: true, realSetCookieActorSwitch: true, lateRefreshRace: 'separate explicitly simulated unit evidence', roleRevocationExistingCookie: true, explicitScopeAllGatewayRequests: true }, auditCoverage: { successfulProductWrites: successfulWrites.length, distinctRequestIds: requestIds.length, auditedRequestIds: auditedIds.size, allPassed: true, readOnlyAuthorizationReviewExcluded: true }, pageErrors: errors.length, browserAdminRequests: adminRequests.length, missingWorkspaceQueries: missingScopes.length, screenshots }, null, 2) + '\n');
  } finally {
    for (const context of contexts) {
      privateReference.secrets.push(...(await context.cookies()).filter(cookie => /^kongos_(access|refresh|csrf)$/.test(cookie.name)).map(cookie => cookie.value));
      await context.close();
    }
    writeFileSync(privatePath, JSON.stringify(privateReference), { mode: 0o600 });
  }
});
