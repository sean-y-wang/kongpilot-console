import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { PRODUCT_BRAND } from '../../packages/contracts/src/branding';

const LEGACY = /AI\s*\u4e91/;
const roots = ['apps/console-web/src', 'apps/portal-web/src', 'apps/console-api/src', 'packages/contracts/src', 'docs/manuals', 'docs/design'];
const files = ['README.md', 'apps/console-web/index.html', 'apps/portal-web/index.html', 'apps/console-web/Dockerfile', 'apps/portal-web/Dockerfile', 'apps/console-api/Dockerfile', 'deploy/deck-runner/Dockerfile', 'deploy/metrics-collector/Dockerfile'];
const walk = (d: string): string[] => readdirSync(d).flatMap(n => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : /\.(ts|tsx|json|html|md|css)$/.test(n) ? [p] : []; });

describe('§50 branding: KongPilot · Kong 网关管理平台, no legacy cloud brand', () => {
  it('brand constants', () => {
    expect(PRODUCT_BRAND.name).toBe('KongPilot');
    expect(PRODUCT_BRAND.chineseName).toBe('Kong 网关管理平台');
    expect(JSON.stringify(PRODUCT_BRAND)).not.toMatch(/Copilot|AI\s*\u4e91/);
  });
  it('zh-CN productName and console title', () => {
    expect(JSON.parse(readFileSync('apps/console-web/src/locales/zh-CN/common.json', 'utf8')).productName).toBe('Kong 网关管理平台');
    expect(readFileSync('apps/console-web/index.html', 'utf8')).toContain('<title>KongPilot | Kong 网关管理平台</title>');
  });
  it('no shipped source, image label or manual carries the legacy name', () => {
    const hits = [...roots.flatMap(walk), ...files.filter(f => { try { return statSync(f).isFile(); } catch { return false; } })].filter(f => LEGACY.test(readFileSync(f, 'utf8')));
    expect(hits).toEqual([]);
  });
});
