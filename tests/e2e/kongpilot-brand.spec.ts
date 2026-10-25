import { expect, test, type Page, type Locator } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';

// Render real application components with synthetic BFF responses only.
// This is UI verification, not live Kong/business acceptance. No gateway writes.
test.use({ trace: 'off', video: 'off', screenshot: 'off', viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
const fixtureStates = new WeakMap<Page, { requests: Array<{ method: string; path: string; query?: string }>; unexpected: string[]; errors: string[] }>();
test.afterEach(async ({ page }, info) => { if (info.status !== info.expectedStatus) { const state=fixtureStates.get(page); if(state) console.log('Synthetic UI request diagnostics', JSON.stringify(state)); } });
const consoleOrigin = process.env.KONGPILOT_PREVIEW_ORIGIN || 'http://127.0.0.1:5175';
const portalOrigin = process.env.KONGPILOT_PORTAL_PREVIEW_ORIGIN || 'http://127.0.0.1:5176';
const cid = '10000000-0000-4000-8000-000000000001', wid = '20000000-0000-4000-8000-000000000001';
const sid = '30000000-0000-4000-8000-000000000001', actor = '40000000-0000-4000-8000-000000000001';
const at = '2026-10-12T10:00:00.000Z';
const plugins = ['key-auth','basic-auth','jwt','oauth2','acl','cors','ip-restriction','rate-limiting','request-transformer','response-transformer','prometheus','http-log'];
const service = { id: sid, name: 'payment-api', host: 'payment.internal.example.com', port: 443, protocol: 'https', path: '/api', tags: ['workspace:default', 'owner:platform'], created_at: 1791800000, updated_at: 1791800000, connect_timeout: 60000, read_timeout: 60000, write_timeout: 60000, retries: 3 };
const collection = (items: unknown[] = []) => ({ items, size: 20, nextCursor: null, total: null, observed_at: at });
const cluster = { id: cid, name: '生产集群', environment: 'prod', admin_url: 'http://kong.internal.example.com:8001', labels: ['region:cn'], execution_mode: 'direct', status: 'healthy', version: '1.5.1', enabled_plugins: plugins, last_probed_at: at, capabilities: {}, revision: 1 };
const workspace = { id: wid, cluster_id: cid, code: 'default', name: '默认工作区', status: 'active', is_default: true, revision: 1, created_at: at, updated_at: at };
const modules = ['overview','clusters','data-sources','services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','workspaces','monitoring','portal','developers','applications','workflows','audit','events','notifications','snapshots','gitops','users','teams','roles','permissions','recycle-bin'];

async function setup(page: Page, mode: 'admin' | 'readonly' | 'login' | 'metrics' = 'admin') {
  const requests: Array<{ method: string; path: string; query?: string }> = [], unexpected: string[] = [], errors: string[] = [], directAdmin: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).port === '8001') directAdmin.push(request.url()); });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/v1', '');
    requests.push({ method: request.method(), path, query: url.search });
    let data: unknown;
    const answer = (status = 200, value: unknown = data) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(status === 200 ? { data: value, meta: { requestId: 'synthetic-ui-only' } } : { error: { code: 'SYNTHETIC_UI_SESSION', message: '请使用个人账号登录。' } }) });
    if (path === '/auth/me') {
      if (mode === 'login') return answer(401);
      const readOnly = mode === 'readonly';
      data = { user: { id: actor, username: readOnly ? 'readonly' : 'platform-admin', displayName: readOnly ? '只读用户' : '管理员', superAdmin: !readOnly, permissionsVersion: 'preview-v1', capabilities: { platformAdmin: !readOnly, modules: Object.fromEntries(modules.map(module => [module, { read: true, write: !readOnly, delete: !readOnly, approve: !readOnly }])), grants: modules.flatMap(module => (readOnly ? ['read'] : ['read','write','delete','approve']).map(action => ({ module, action, cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] }))), clusters: [cid] } }, csrfToken: 'synthetic-ui-csrf' };
    } else if (path === '/auth/providers') data = { items: [] };
    else if (path === '/auth/csrf') data = { csrfToken: 'synthetic-ui-csrf' };
    else if (path === '/auth/refresh') return answer(401);
    else if (path === '/clusters') data = [cluster];
    else if (path === `/clusters/${cid}/workspaces`) data = collection([workspace]);
    else if (path === `/clusters/${cid}/workspaces/${wid}`) data = workspace;
    else if (path === `/clusters/${cid}/data-sources`) data = [
      { id: '50000000-0000-4000-8000-000000000001', cluster_id: cid, name: 'Prometheus', type: 'prometheus', base_url: 'http://prometheus.internal.example.com:9090', last_status: 'healthy', enabled: true, last_probed_at: at },
      { id: '50000000-0000-4000-8000-000000000002', cluster_id: cid, name: 'Loki', type: 'loki', base_url: 'http://loki.internal.example.com:3100', last_status: 'healthy', enabled: true, last_probed_at: at },
    ];
    else if (path === `/clusters/${cid}/inventory`) data = { counts: { services:24, routes:48, consumers:16, plugins:36, upstreams:8, certificates:4, ca_certificates:2, snis:6 }, observed_at:at, source:'synthetic-ui-index', quarantined_count:0, traffic:{available:true} };
    else if (path === '/notifications/unread-count') data = { unreadCount: 2, complete: true };
    else if (path === `/clusters/${cid}/entities/services`) data = collection([service, { ...service, id:'30000000-0000-4000-8000-000000000002', name:'order-api', host:'order.internal.example.com' }]);
    else if (path === `/clusters/${cid}/entities/certificates` || path === `/clusters/${cid}/entities/ca_certificates`) data = collection([]);
    else if (path === `/clusters/${cid}/entities/services/${sid}`) data = service;
    else if (path === `/clusters/${cid}/authorization/entity-capabilities`) data = { permissionsVersion:'preview-v1', items:(request.postDataJSON()?.entities ?? []).map((item: object) => ({ ...item, read:true, write:mode==='admin', delete:mode==='admin', approve:mode==='admin', reveal:false })) };
    else if (path === `/clusters/${cid}/schemas/services`) data = JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/schema-services.json','utf8'));
    else if (path === `/clusters/${cid}/plugin-center/catalog`) data = { items:plugins.map((name,index) => ({ name, category:index < 5 ? 'authentication' : index > 9 ? 'observability' : 'traffic', priority:1000-index*20, counts:{total:3,enabled:3,by_scope:{global:{total:1,enabled:1},service:{total:2,enabled:2}}} })), observed_at:at, counts_source:'synthetic-ui-index' };
    else if (path === `/clusters/${cid}/plugin-center/precedence`) data = { levels:['consumer-route-service','consumer-route','consumer-service','route-service','consumer','route','service','global'].map((scope,index) => ({scope,rank:index+1,label:scope})), execution_order:[], disabled_fallback:true };
    else if (path === `/clusters/${cid}/plugin-center/instances`) data = collection([]);
    else if (/\/vitals\/entities$/.test(path)) data = { ...collection([]), scan_budget_exhausted: false };
    else if (/\/vitals\/capabilities$/.test(path)) {
      const source=mode==='metrics'?{id:'50000000-0000-4000-8000-000000000001',name:'Prometheus',type:'prometheus',status:'healthy',availability:'available'}:null;
      data = { clusterId:cid,workspaceId:wid,scope:'workspace',source,sources:source?[source]:[],nativeVersion:'1.5.1',pluginVersion:'0.6.0',provider:source?'prometheus':null,configured:!!source,collectorEnabled:false,catalogRevision:1,credentialGeneration:1,permissions:{setup:false,nodeMetrics:false,clusterMetrics:false},capabilities:{qps:!!source,statusCodes:!!source,latency:!!source,bandwidth:!!source,serviceTopN:!!source,consumerTopN:false,nodes:false,routeDrilldown:!!source},limitations:[],setupModes:[],executionMode:'direct' };
    }
    else if (/\/vitals\/overview$/.test(path)) {
      const end=Math.floor(Date.now()/1000),points=Array.from({length:21},(_,i)=>({ts:end-600+i*30,value:120+Math.sin(i/3)*18}));
      const metric=(value:number)=>({value,availability:'available'});
      const names=['qps','status2xx','status4xx','status5xx','latencyRequestP50','latencyRequestP95','latencyRequestP99','latencyUpstreamP50','latencyUpstreamP95','latencyUpstreamP99','latencyKongP50','latencyKongP95','latencyKongP99','bandwidthIngress','bandwidthEgress'];
      data={clusterId:cid,workspaceId:wid,scope:'workspace',source:{id:'50000000-0000-4000-8000-000000000001',name:'Prometheus',type:'prometheus',status:'healthy',availability:'available'},evaluationAt:new Date().toISOString(),timeWindow:{start:new Date((end-600)*1000).toISOString(),end:new Date(end*1000).toISOString(),step:30,rateWindowSeconds:120},cards:{qps:metric(120),p50:metric(24),p95:metric(48),p99:metric(72),ingressBytesPerSecond:metric(18000),egressBytesPerSecond:metric(24000),onlineNodes:{value:null,availability:'unsupported'}},series:Object.fromEntries(names.map((name,i)=>[name,points.map(p=>({...p,value:i===0?p.value:i<4?p.value/(i===1?1.1:40):i>12?p.value*150:p.value/3}))])),topN:{services:[{id:sid,name:'payment-api',value:120}],consumers:[]},nodes:[],units:{throughput:'requests/second',latency:'milliseconds',bandwidth:'bytes/second'},availability:{qps:'available',latency:'available'},quality:{complete:true,reasonCodes:[],catalogRevision:1,historicalScope:'current_epoch',sourceMetricVersion:'synthetic-ui-only',gaps:[]}};
    }
    else if (/\/snapshots(?:\/schedules)?$/.test(path)) data = collection([]);
    else if (/\/entities\/services\/.+\/(?:routes|plugins)$/.test(path)) data = collection([]);
    else { unexpected.push(`${request.method()} ${path}`); return route.fulfill({status:404,contentType:'application/json',body:JSON.stringify({error:{code:'UI_FIXTURE_NOT_DEFINED',message:'未定义的视觉测试响应'}})}); }
    return answer();
  });
  fixtureStates.set(page, { requests, unexpected, errors });
  return { requests, unexpected, errors, directAdmin };
}

async function screenshot(page: Page, name: string) {
  await page.screenshot({ path: `artifacts/VisualRefinement/${name}.png`, fullPage: true, animations: 'disabled' });
}

async function expectFullyInside(container: Locator, entry: Locator) {
  await expect.poll(async () => {
    const bounds=await container.boundingBox(), item=await entry.boundingBox();
    return !!bounds && !!item && item.y >= bounds.y - 1 && item.y + item.height <= bounds.y + bounds.height + 1;
  }).toBe(true);
}

test('KongPilot login desktop and mobile render with readable brand and no page overflow', async ({ page }) => {
  const state = await setup(page,'login');
  await page.goto(consoleOrigin);
  await expect(page.getByRole('heading',{name:'登录控制台',exact:true})).toBeVisible();
  await expect(page.getByText('Kong 网关管理平台',{exact:true}).first()).toBeVisible();
  await expect(page).toHaveTitle('KongPilot | Kong 网关管理平台');
  await expect(page.getByLabel('密码',{exact:true})).toHaveAttribute('autocomplete','current-password');
  await screenshot(page,'login-desktop');
  await page.setViewportSize({width:390,height:844});
  await expect(page.getByRole('button',{name:'登录控制台',exact:true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await screenshot(page,'login-mobile');
  expect(state.errors).toEqual([]); expect(state.unexpected).toEqual([]); expect(state.directAdmin).toEqual([]);
});

test('overview uses real layout, scoped BFF fixtures, restrained theme and working quick navigation', async ({ page }) => {
  const state = await setup(page);
  await page.goto(consoleOrigin);
  await expect(page.getByRole('heading',{name:'网关总览',exact:true})).toBeVisible();
  await expect(page.locator('.inventory-item')).toHaveCount(8);
  await expect(page.getByText('按授权范围管理',{exact:true})).toHaveCount(0);
  await expect(page.locator('.console-footer, .header-stage, .page-heading .eyebrow')).toHaveCount(0);
  await expect(page.locator('.overview-shortcut')).toHaveCount(3);
  expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe('rgb(247, 248, 250)');
  expect(await page.locator('.console-sidebar').evaluate(element => getComputedStyle(element).backgroundImage)).toBe('none');
  await screenshot(page,'overview-desktop');
  await page.getByRole('link',{name:/登记集群$/}).click();
  await expect(page.getByRole('heading',{name:'集群管理',exact:true})).toBeVisible();
  await screenshot(page,'clusters-desktop');
  await page.goto(`${consoleOrigin}/plugin-center`);
  await expect(page.getByRole('heading',{name:'插件中心',exact:true})).toBeVisible();
  await screenshot(page,'plugins-desktop');
  expect(state.errors).toEqual([]); expect(state.unexpected).toEqual([]); expect(state.directAdmin).toEqual([]);
  expect(state.requests.some(r => !['GET','HEAD'].includes(r.method) && !r.path.endsWith('/entity-capabilities'))).toBe(false);
});

test('entity table, create drawer and destructive confirmation stay usable without sending a mutation', async ({ page }) => {
  const state = await setup(page);
  await page.goto(`${consoleOrigin}/entities/services`);
  await expect(page.getByRole('button',{name:'payment-api',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:/创建 Services$/})).toBeEnabled();
  await screenshot(page,'services-desktop');
  const inspected = await page.evaluate(() => {
    function read(selector:string|Element|null,pseudo?:string) {
      const element=typeof selector==='string'?document.querySelector(selector):selector;
      if(!element)return null;
      const style=getComputedStyle(element,pseudo);
      return Object.fromEntries(['backgroundColor','backgroundImage','backdropFilter','borderColor','borderRadius','boxShadow','color','fontFamily','fontWeight','width','height'].map(key=>[key,style[key as keyof CSSStyleDeclaration]]));
    }
    const rows=document.querySelectorAll('.ant-table-tbody tr.ant-table-row');
    return {canvas:read('body'),sidebar:read('.console-sidebar'),header:read('.console-header'),card:read('.table-card'),title:read('.page-heading h2'),auxiliaryText:read('.table-secondary'),bodyText:read('.ant-table-tbody .mono:not(.table-secondary)'),tableHeader:read('.ant-table-thead th:nth-child(2)'),rowOne:read(rows[0]?.querySelector('td:nth-child(3)')??null),rowTwo:read(rows[1]?.querySelector('td:nth-child(3)')??null),selectedMenu:read('.ant-menu-item-selected'),selectionMarker:read('.ant-menu-item-selected','::before'),primaryButton:read('.page-heading .ant-btn-primary'),tag:read('.entity-tags .ant-tag'),edit:read('.ant-table-cell-fix-right .ant-btn-link:not(.ant-btn-dangerous)'),remove:read('.ant-table-cell-fix-right .ant-btn-dangerous'),pagination:read('.cursor-pagination .ant-btn'),iconStroke:document.querySelector('.ant-menu-item-selected .pilot-icon svg')?.getAttribute('stroke-width')};
  });
  const visibleRow=page.getByRole('row').filter({has:page.getByRole('button',{name:'payment-api',exact:true})});
  await visibleRow.locator('td').nth(2).hover();
  await expect.poll(()=>visibleRow.locator('td').nth(2).evaluate(element=>getComputedStyle(element).backgroundColor)).not.toBe('rgba(0, 0, 0, 0)');
  await screenshot(page,'services-hover');
  const rowHover=await visibleRow.locator('td').nth(2).evaluate(element=>getComputedStyle(element).backgroundColor);
  writeFileSync('artifacts/VisualRefinement/computed-style-evidence.json',JSON.stringify({syntheticBffOnly:true,...inspected,rowHover},null,2)+'\n');
  await page.getByRole('heading',{name:'Services',exact:true}).hover();
  await page.getByRole('button',{name:/创建 Services$/}).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('button',{name:'保存配置',exact:true})).toBeVisible();
  await screenshot(page,'service-create-drawer');
  await page.locator('.ant-drawer-close').click();
  const row=page.getByRole('row').filter({has:page.getByRole('button',{name:'payment-api',exact:true})});
  await row.getByRole('button',{name:'删除',exact:true}).click();
  await expect(page.getByRole('dialog',{name:'移入回收站',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'确认执行',exact:true})).toBeDisabled();
  await page.getByLabel('确认名称',{exact:true}).fill('wrong-name');
  await expect(page.getByRole('button',{name:'确认执行',exact:true})).toBeDisabled();
  await page.getByLabel('确认名称',{exact:true}).fill('payment-api');
  await expect(page.getByRole('button',{name:'确认执行',exact:true})).toBeEnabled();
  await page.getByLabel('确认名称',{exact:true}).clear();
  await screenshot(page,'delete-confirmation');
  await page.getByRole('button',{name:/取\s*消/}).click();
  const search=page.getByRole('searchbox',{name:'搜索实体',exact:true});
  await search.fill('payment');
  await page.getByRole('button',{name:'执行实体搜索',exact:true}).click();
  await expect.poll(()=>state.requests.some(r=>r.path===`/clusters/${cid}/entities/services`&&new URLSearchParams(r.query).get('search')==='payment')).toBe(true);
  await search.clear();await search.press('Enter');
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await screenshot(page,'services-mobile');
  expect(state.errors).toEqual([]); expect(state.unexpected).toEqual([]);
  expect(state.requests.some(r => !['GET','HEAD'].includes(r.method) && !r.path.endsWith('/entity-capabilities'))).toBe(false);
});

test('read-only UI keeps writes disabled after the visual upgrade', async ({ page }) => {
  const state=await setup(page,'readonly');
  await page.goto(`${consoleOrigin}/entities/services`);
  await expect(page.getByRole('button',{name:'payment-api',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:/创建 Services$/})).toBeDisabled();
  await expect(page.getByRole('button',{name:/编辑$/}).first()).toBeDisabled();
  await expect(page.getByRole('button',{name:'删除',exact:true}).first()).toBeDisabled();
  await screenshot(page,'readonly-services');
  expect(state.errors).toEqual([]); expect(state.unexpected).toEqual([]);
});

test('mobile overview has no horizontal overflow and navigation opens/closes with keyboard support', async ({ page }) => {
  const state=await setup(page); await page.setViewportSize({width:390,height:844});
  await page.goto(consoleOrigin);
  await expect(page.getByRole('heading',{name:'网关总览',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'切换导航',exact:true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await screenshot(page,'overview-mobile');
  await page.getByRole('button',{name:'切换导航',exact:true}).click();
  await expect(page.getByRole('button',{name:'关闭导航',exact:true})).toBeVisible();
  const menu = page.getByRole('navigation',{name:'控制台功能导航',exact:true});
  await menu.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await expect(page.getByRole('menuitem',{name:/身份与权限$/})).toBeInViewport();
  await expectFullyInside(menu,page.getByRole('menuitem',{name:/身份与权限$/}));
  await screenshot(page,'navigation-mobile');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button',{name:'切换导航',exact:true})).toHaveAttribute('aria-expanded','false');
  expect(state.errors).toEqual([]); expect(state.unexpected).toEqual([]);
});

test('short desktop navigation keeps its brand and footer fixed and all authorized entries reachable', async ({ page }) => {
  const state=await setup(page); await page.setViewportSize({width:1280,height:720});
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.goto(`${consoleOrigin}/entities/services`);
  await expect(page.getByRole('button',{name:'payment-api',exact:true})).toBeVisible();
  const menu=page.getByRole('navigation',{name:'控制台功能导航',exact:true});
  const last=page.getByRole('menuitem',{name:/身份与权限$/});
  expect(await menu.evaluate(element=>element.scrollHeight>element.clientHeight)).toBe(true);
  await expect(page.locator('.console-sidebar .brand')).toBeInViewport();
  await expect(page.locator('.sidebar-footer')).toBeInViewport();
  await expect(page.getByRole('button',{name:'向下滚动查看更多菜单',exact:true})).toBeEnabled();
  for(let i=0;i<4;i++) {
    const down=page.getByRole('button',{name:'向下滚动查看更多菜单',exact:true});
    const before=await menu.evaluate(element=>element.scrollTop);
    if(await menu.evaluate(element=>element.scrollTop+element.clientHeight>=element.scrollHeight-1)) break;
    await down.click();
    await expect.poll(()=>menu.evaluate(element=>element.scrollTop)).toBeGreaterThan(before);
  }
  await expect(last).toBeInViewport();
  await expectFullyInside(menu,last);
  await expect(page.getByRole('button',{name:'向上滚动导航菜单',exact:true})).toBeEnabled();
  expect(await page.evaluate(()=>window.scrollY)).toBe(0);
  await screenshot(page,'navigation-desktop-bottom');
  await page.getByRole('button',{name:'收起网关实体菜单',exact:true}).click();
  await page.getByRole('button',{name:'收起控制台菜单',exact:true}).click();
  await page.setViewportSize({width:1280,height:900});
  await expect(page.getByRole('menuitem',{name:/Services$/,includeHidden:true})).toBeHidden();
  await expect(last).toBeInViewport();
  await expectFullyInside(menu,last);
  await screenshot(page,'navigation-platform-desktop');
  await page.getByRole('button',{name:'收起平台管理菜单',exact:true}).click();
  await expect(last).toBeHidden();
  await page.locator('.console-sidebar .brand').click();
  await expect(page.getByRole('heading',{name:'网关总览',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'展开平台管理菜单',exact:true})).toBeVisible();
  await page.getByRole('link',{name:/查看快照$/}).click();
  await expect(page.getByRole('heading',{name:'配置快照',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'收起平台管理菜单',exact:true})).toBeVisible();
  await expect(page.getByRole('menuitem',{name:/配置快照$/})).toBeInViewport();
  await expectFullyInside(menu,page.getByRole('menuitem',{name:/配置快照$/}));
  await expect(page.locator('.sidebar-footer')).toBeInViewport();
  expect(state.errors).toEqual([]);expect(state.unexpected).toEqual([]);expect(state.directAdmin).toEqual([]);
  expect(state.requests.some(r=>!['GET','HEAD'].includes(r.method)&&!r.path.endsWith('/entity-capabilities'))).toBe(false);
});

test('snapshots and Vitals empty states render consistently', async ({ page }) => {
  const state=await setup(page);
  await page.goto(`${consoleOrigin}/snapshots`);
  await expect(page.getByRole('heading',{name:'配置快照',exact:true})).toBeVisible();
  await screenshot(page,'snapshots-desktop');
  await page.goto(`${consoleOrigin}/vitals`);
  await expect(page.getByRole('heading',{name:'Vitals 监控',exact:true})).toBeVisible();
  await expect(page.getByText('监控数据通道尚未启用',{exact:true}).first()).toBeVisible();
  await screenshot(page,'vitals-unconfigured');
  expect(state.errors).toEqual([]);expect(state.unexpected).toEqual([]);
});

test('independent developer Portal shares the public brand without Console API access', async ({ page }) => {
  const errors:string[]=[],wrongBoundary:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{const url=new URL(request.url());if(url.port==='8001'||url.pathname.startsWith('/api/')&&!url.pathname.startsWith('/api/v1/portal/'))wrongBoundary.push(url.pathname);});
  await page.route('**/api/v1/portal/**',route=>{
    const path=new URL(route.request().url()).pathname.replace('/api/v1/portal','');
    const tenant={slug:'platform',name:'KongPilot API 空间',clusterId:cid,workspaceId:wid,branding:{welcomeText:'查看已发布 API 与接入文档'}};
    if (path==='/auth/me'||path==='/auth/refresh') return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'SYNTHETIC_UI_SESSION',message:'请登录开发者门户'}})});
    const data=path==='/tenants'?collection([tenant]):path==='/tenants/platform'?tenant:path==='/auth/csrf'?{csrfToken:'synthetic-portal-ui-csrf'}:path==='/publications'?collection([{id:'60000000-0000-4000-8000-000000000001',name:'支付服务 API',description:'查看支付业务接口规范与接入流程。',category:'业务服务',documentRevision:1}]):collection([]);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({data})});
  });
  await page.goto(portalOrigin);
  await expect(page.getByRole('heading',{name:'开发者门户',exact:true})).toBeVisible();
  await expect(page.getByText('KongPilot API 空间',{exact:true})).toBeVisible();
  await expect(page).toHaveTitle('KongPilot | 开发者门户');
  await screenshot(page,'portal-tenant-picker');
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
  await screenshot(page,'portal-tenant-picker-mobile');
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(`${portalOrigin}/apis?tenant=platform`);
  await expect(page.getByTestId('portal-catalog')).toBeVisible();
  await expect(page.getByRole('link',{name:'支付服务 API',exact:true})).toBeVisible();
  await screenshot(page,'portal-api-catalog');
  await page.getByRole('button',{name:'切换深色模式',exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','dark');
  await screenshot(page,'portal-api-catalog-dark');
  await page.goto(`${portalOrigin}/login?tenant=platform`);
  await expect(page.getByRole('heading',{name:'登录开发者门户',exact:true})).toBeVisible();
  await screenshot(page,'portal-login');
  expect(errors).toEqual([]);expect(wrongBoundary).toEqual([]);
});

test('Vitals charts render actual ECharts canvas with synthetic metric samples', async ({ page }) => {
  const state=await setup(page,'metrics');
  await page.goto(`${consoleOrigin}/vitals`);
  await expect(page.getByTestId('vitals-chart-qps')).toHaveAttribute('data-available','true');
  await expect(page.getByTestId('vitals-chart-qps').locator('canvas').first()).toBeVisible();
  await screenshot(page,'vitals-charts-desktop');
  await page.getByRole('button',{name:'切换深色模式',exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','dark');
  await expect(page.getByTestId('vitals-chart-qps').locator('canvas').first()).toBeVisible();
  await screenshot(page,'vitals-charts-dark');
  expect(state.errors).toEqual([]);expect(state.unexpected).toEqual([]);expect(state.directAdmin).toEqual([]);
});


test('light and dark appearance switches, persists across reload and keeps read-only controls disabled', async ({ page }) => {
  const state=await setup(page,'readonly');
  await page.goto(`${consoleOrigin}/entities/services`);
  await expect(page.getByRole('button',{name:'payment-api',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'切换深色模式',exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','dark');
  expect(await page.evaluate(()=>localStorage.getItem('kongpilot.appearance'))).toBe('dark');
  await expect(page.getByRole('button',{name:/创建 Services$/})).toBeDisabled();
  await expect(page.getByRole('button',{name:'删除',exact:true}).first()).toBeDisabled();
  await screenshot(page,'services-dark');
  await page.goto(consoleOrigin);
  await expect(page.getByRole('heading',{name:'网关总览',exact:true})).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','dark');
  await screenshot(page,'overview-dark');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','dark');
  await page.getByRole('button',{name:'切换浅色模式',exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','light');
  expect(await page.evaluate(()=>localStorage.getItem('kongpilot.appearance'))).toBe('light');
  expect(state.errors).toEqual([]);expect(state.unexpected).toEqual([]);expect(state.directAdmin).toEqual([]);
});

test('login follows the system initially and still switches when browser storage is unavailable', async ({ page }) => {
  const state=await setup(page,'login');await page.emulateMedia({colorScheme:'dark'});
  await page.addInitScript(()=>Object.defineProperty(window,'localStorage',{get(){throw new DOMException('Unavailable','SecurityError');}}));
  await page.goto(consoleOrigin);
  await expect(page.getByRole('heading',{name:'登录控制台',exact:true})).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','dark');
  await screenshot(page,'login-dark');
  await page.getByRole('button',{name:'切换浅色模式',exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-appearance','light');
  expect(state.errors).toEqual([]);expect(state.unexpected).toEqual([]);
});

test('用户菜单支持站内使用手册、目录搜索及 v1.0 版本展示', async ({ page }) => {
  const state = await setup(page);
  await page.goto(consoleOrigin);
  await page.getByRole('button', { name: '用户菜单', exact: true }).click();
  await expect(page.getByRole('menuitem', { name: 'KongPilot v1.0', exact: true })).toBeVisible();
  await page.getByRole('menuitem', { name: '用户使用手册', exact: true }).click();
  await expect(page).toHaveURL(/\/help\/user-guide$/);
  await expect(page.getByRole('heading', { name: '用户使用手册', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: '手册目录', exact: true })).toBeVisible();
  await expect(page.getByText('v1.0', { exact: true })).toBeVisible();
  await page.getByRole('searchbox', { name: '搜索手册', exact: true }).fill('不存在的手册搜索词12345');
  await page.getByRole('searchbox', { name: '搜索手册', exact: true }).press('Enter');
  await expect(page.getByText('未找到相关内容', { exact: true })).toBeVisible();
  await page.getByRole('searchbox', { name: '搜索手册', exact: true }).fill('');
  await page.getByRole('searchbox', { name: '搜索手册', exact: true }).press('Enter');
  await expect(page.getByRole('heading', { name: 'KongPilot 用户使用手册', exact: true })).toBeVisible();
  await page.screenshot({ path: 'artifacts/ReleaseV1_0/manual-desktop.png', fullPage: false });
  await page.getByRole('link', { name: '部署与运维手册', exact: true }).last().click();
  await expect(page).toHaveURL(/\/help\/operations-guide$/);
  await expect(page.getByRole('heading', { name: '部署与运维手册', exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await page.screenshot({ path: 'artifacts/ReleaseV1_0/manual-mobile.png', fullPage: false });
  expect(state.errors).toEqual([]); expect(state.unexpected).toEqual([]); expect(state.directAdmin).toEqual([]);
  expect(state.requests.some(request => !['GET','HEAD'].includes(request.method))).toBe(false);
});
