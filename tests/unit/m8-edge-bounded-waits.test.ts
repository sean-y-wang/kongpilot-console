import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const files = ['deploy/nginx/default.conf', 'deploy/nginx/console-production.conf'];
const cid = '12491546-24cc-4f35-be68-bbe6f25da3b1';
const id = '2ef83b70-5c1c-4536-9fd8-c7a5e8b6162f';
const other = '1daae605-57ef-4edc-82ae-9aab7522ad28';
const prefix = `/api/v1/clusters/${cid}`;
const postPaths = [
  `${prefix}/snapshots`, `${prefix}/snapshots/${id}/export`,
  `${prefix}/snapshots/${id}/rollback-plan`, `${prefix}/configuration/imports`,
  `${prefix}/configuration/exports`, `${prefix}/configuration/plans/${id}/apply`,
  `${prefix}/configuration/plans/${id}/reconcile`,
  `${prefix}/configuration/exports/${id}/download`, `${prefix}/workflows/${id}/execute`,
];
const compare = `${prefix}/snapshots/${id}/compare/${other}`;
function m8Block(source: string) {
  const block = source.match(/    # BEGIN M8 bounded operation waits:[\s\S]*?    # END M8 bounded operation waits\.\n/)?.[0];
  if (!block) throw new Error('M8_EDGE_BLOCK_MISSING');
  return block;
}
function locations(source: string) {
  return [...m8Block(source).matchAll(/location ~ "([^"]+)" \{\n([\s\S]*?)\n    \}/g)].map((match) => ({
    path: new RegExp(match[1]), body: match[2],
    method: match[2].match(/if \(\$request_method != (GET|POST)\) \{ return 405; \}/)?.[1],
  }));
}
function decision(source: string, path: string, method: string) {
  if (path.startsWith('/api/v1/portal/')) return { status: 404 };
  const matched = locations(source).find((location) => location.path.test(path));
  if (matched?.body.includes('error_page 418 = @m8_snapshot_capture;')) return method === 'POST' ? { timeout: 310 } : ['GET','HEAD'].includes(method) ? { timeout: 35 } : { status: 405 };
  if (matched) return matched.method === method ? { timeout: 310 } : { status: 405 };
  return { timeout: 35 };
}

describe.each(files)('bounded M8 waits in %s', (file) => {
  const source = readFileSync(file, 'utf8');
  it('covers the declared POST operations and GET comparison, including uppercase UUIDs', () => {
    expect(locations(source)).toHaveLength(3);
    for (const path of postPaths) expect(decision(source, path, 'POST')).toEqual({ timeout: 310 });
    expect(decision(source, compare, 'GET')).toEqual({ timeout: 310 });
    expect(decision(source, compare.replace(cid, cid.toUpperCase()), 'GET')).toEqual({ timeout: 310 });
  });
  it('rejects wrong methods without forwarding to the upstream', () => {
    for (const method of ['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      for (const path of postPaths) expect(decision(source, path, method)).toEqual(path===postPaths[0]&&['GET','HEAD'].includes(method)?{timeout:35}:{ status: 405 });
    }
    for (const method of ['POST', 'HEAD', 'DELETE', 'OPTIONS']) expect(decision(source, compare, method)).toEqual({ status: 405 });
    for (const location of locations(source)) expect(location.body.indexOf('return 405;')).toBeLessThan(location.body.indexOf('proxy_pass'));
  });
  it('keeps unrelated operations at the generic 35 seconds', () => {
    expect(decision(source,`${prefix}/snapshots`,'GET')).toEqual({timeout:35});
    expect(decision(source,`${prefix}/snapshots`,'HEAD')).toEqual({timeout:35});
    for (const path of [
      `${prefix}/snapshots/schedules`, `${prefix}/snapshots/${id}/restore`,
      `${prefix}/configuration/plans/${id}`, `${prefix}/configuration/plans/${id}/changes`,
      `${prefix}/configuration/jobs/${id}`, `${prefix}/configuration/gitops/runs`,
      `${prefix}/workflows/${id}/approve`, `${prefix}/workflows/${id}/reconcile-metadata`,
      `${prefix}/services/${id}`, '/api/v1/auth/login', '/api/docs-json',
    ]) expect(decision(source, path, 'POST')).toEqual({ timeout: 35 });
    const generic = source.match(/    location \/api\/ \{\n([\s\S]*?)\n    \}/)?.[1];
    expect(generic).toContain('proxy_read_timeout 35s;');
    expect(generic).toContain('proxy_send_timeout 35s;');
    expect(generic).not.toContain('310s');
  });
  it('requires whole UUID segments and the complete path', () => {
    for (const path of [
      postPaths[0].replace(cid, 'arbitrary'), postPaths[5].replace(id, id.slice(0, -1)),
      postPaths[5].replace(id, `${id}a`), postPaths[5].replace(id, id.replace('2', 'g')),
      `${postPaths[0]}/`, `${postPaths[5]}/extra`, `/prefix${postPaths[5]}`,
      compare.replace(other, 'not-a-uuid'), `${compare}/extra`,
      postPaths[5].replace('/api/v1/', '/api/v2/'),
      postPaths[5].replace('/configuration/', '/unknown/'),
    ]) expect(decision(source, path, 'POST')).toEqual({ timeout: 35 });
  });
  it('retains Portal priority and the existing proxy/header/rate boundaries', () => {
    expect(source).toContain('location ^~ /api/v1/portal/ { return 404; }');
    for (const method of ['GET', 'POST']) expect(decision(source, `/api/v1/portal${postPaths[0]}`, method)).toEqual({ status: 404 });
    expect(source).toContain('rate=20r/s;');
    expect(source.match(/add_header X-Content-Type-Options nosniff always;/g)).toHaveLength(1);
    expect(source.match(/add_header Content-Security-Policy /g)).toHaveLength(1);
    expect(source).not.toContain('$proxy_add_x_forwarded_for');
    for (const location of locations(source)) {
      for (const directive of [
        'limit_req zone=kongos_api burst=40 nodelay;', 'limit_req_status 429;',
        'proxy_pass http://console-api:3000;', 'proxy_hide_header X-Content-Type-Options;',
        'proxy_set_header Host $http_host;', 'proxy_set_header X-Forwarded-Host $http_host;',
        'proxy_set_header X-Forwarded-Proto $scheme;', 'proxy_set_header X-Forwarded-For $remote_addr;',
        'proxy_set_header X-Real-IP $remote_addr;', 'proxy_connect_timeout 5s;',
        `proxy_read_timeout ${location.body.includes('error_page 418')?35:310}s;`, `proxy_send_timeout ${location.body.includes('error_page 418')?35:310}s;`,
      ]) expect(location.body).toContain(directive);
      expect(location.body).not.toMatch(/add_header|proxy_intercept_errors|proxy_next_upstream|proxy_redirect/);
    }
  });
});

it('keeps both exact long-operation blocks identical and matches real controller declarations', () => {
  expect(m8Block(readFileSync(files[0], 'utf8'))).toBe(m8Block(readFileSync(files[1], 'utf8')));
  const controller = readFileSync('apps/console-api/src/modules/configuration/configuration.controller.ts', 'utf8');
  for (const route of ['snapshots', 'snapshots/:snapshotId/export', 'snapshots/:snapshotId/rollback-plan',
    'configuration/imports', 'configuration/exports', 'configuration/plans/:planId/apply',
    'configuration/plans/:planId/reconcile', 'configuration/exports/:exportId/download']) {
    expect(controller).toContain(`@Post('${route}')`);
  }
  expect(controller).toContain("@Get('snapshots/:snapshotId/compare/:otherId')");
  expect(controller).toContain("@Get('snapshots')");
  expect(readFileSync('apps/console-api/src/modules/workflows/workflow.controller.ts', 'utf8')).toContain("@Post(':id/execute')");
});
