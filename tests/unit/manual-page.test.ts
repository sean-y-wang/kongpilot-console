import { describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { StaticRouter, Route, Routes } from 'react-router-dom';
import { ManualDocument, ManualPage, manualHeadingSlug, manualLink } from '../../apps/console-web/src/features/ManualPage';

// Actual Markdown/React SSR, with static source only. These tests do not run a
// browser, authenticate a user, call HTTP or prove runtime release acceptance.
function render(source: string, search = '') {
  return renderToStaticMarkup(createElement(StaticRouter, { location: '/help/user-guide' },
    createElement(ManualDocument, { source, search, onSearch: () => undefined, otherManual: 'operations-guide' })));
}
function hrefs(html: string) {
  return [...html.matchAll(/href="([^"]+)"/g)].map(match => { try { return decodeURIComponent(match[1]); } catch { return match[1]; } });
}

describe('KongPilot manual Markdown rendering and navigation', () => {
  it('renders GFM tables and readonly checked/unchecked task lists as semantic HTML', () => {
    const html = render('# 手册\n\n## 部署\n\n| 服务 | 状态 |\n| --- | --- |\n| BFF | 在线 |\n\n- [x] 备份已验证\n- [ ] 恢复待验证');
    expect(html).toContain('<table>'); expect(html).toContain('<thead>'); expect(html).toContain('<td>BFF</td>');
    expect(html).not.toContain('| --- | --- |');
    expect(html).toMatch(/<input(?=[^>]*type="checkbox")(?=[^>]*disabled="")(?=[^>]*checked="")[^>]*\/>/);
    expect(html).toMatch(/<input(?=[^>]*type="checkbox")(?=[^>]*disabled="")(?![^>]*checked=)[^>]*\/>/);
  });
  it('targets parsed formatted headings, ignores code-fence headings and preserves duplicate IDs during search', () => {
    const source = '# 手册\n\n## 1. **备份**与 `Key`\n\nfirst-only\n\n```md\n## 伪章节\n```\n\n### 重复\n\n## 2. 恢复\n\nsecond-only\n\n### 重复\n\n### 重复-1';
    const all = render(source), filtered = render(source, 'second-only');
    expect(all).toContain('id="1-备份与-key"'); expect(hrefs(all)).toContain('#1-备份与-key');
    expect(all).not.toContain('id="伪章节"'); expect(all).not.toContain('href="#伪章节"');
    expect(all).toContain('id="重复"'); expect(all).toContain('id="重复-1"'); expect(all).toContain('id="重复-1-1"');
    expect(filtered).toContain('id="重复-1"'); expect(filtered).not.toContain('id="重复"'); expect(filtered).not.toContain('first-only');
  });
  it('preserves exact safe chapter fragments when linking between the two manuals', () => {
    const source = '# 手册\n\n## 首页\n\n[部署章节](production-operations-guide.md#16-正式站点交付清单)\n\n[用户章节](./console-user-guide.md#23-m11变更工单独立审批与恢复基线)';
    const html = render(source);
    expect(hrefs(html)).toContain('/help/operations-guide#16-正式站点交付清单');
    expect(hrefs(html)).toContain('/help/user-guide#23-m11变更工单独立审批与恢复基线');
    const encoded = 'console-user-guide.md#23-m11%E5%8F%98%E6%9B%B4';
    expect(manualLink(encoded)?.href).toBe('/help/user-guide#23-m11%E5%8F%98%E6%9B%B4');
  });
  it('keeps repository evidence, API/private paths and deceptive document names non-actionable', () => {
    const html = render('# 手册\n\n[证据](../../artifacts/M11/example.json)\n\n[私有](/private/backup)\n\n[API](/api/v1/admin)\n\n[伪文档](production-operations-guide.md.old)\n\n[远端](https://example.com/production-operations-guide.md)');
    expect(html).not.toContain('href="../../artifacts'); expect(html).not.toContain('href="/private'); expect(html).not.toContain('href="/api');
    expect(html).toContain('<span>伪文档</span>');
    expect(hrefs(html).filter(href => href === '/help/operations-guide')).toHaveLength(1); // Only the product's other-manual link.
    expect(html).toContain('href="https://example.com/production-operations-guide.md"');
    expect(html).toContain('rel="noopener noreferrer"');
    for (const target of ['javascript:alert(1)', 'data:text/html,secret', '//example.com/file', 'https://user:password@example.com', 'production-operations-guide.md#%ZZ', 'console-user-guide.md#%3Cscript%3E']) expect(manualLink(target)).toBeUndefined();
  });
  it('keeps raw HTML and image fetches disabled even with GFM enabled', () => {
    const html = render('# 手册\n\n<script>alert("unsafe")</script>\n\n<img src="https://example.com/private" onerror="steal()">\n\n![说明](https://example.com/image)');
    expect(html).not.toContain('<script'); expect(html).not.toContain('<img'); expect(html).not.toContain('onerror');
    expect(html).not.toContain('src="https://example.com'); expect(html).toContain('<span>说明</span>');
    expect(manualHeadingSlug('"<部署>" & 恢复')).toBe('部署--恢复');
    expect(manualHeadingSlug('__proto__')).toBe('manual-__proto__');
  });
  it('gives an unheaded introduction an actual navigation target and handles no search matches', () => {
    const source = '产品介绍正文\n\n## 业务\n\n配置内容';
    const html = render(source);
    expect(html).toContain('href="#manual-introduction"'); expect(html).toContain('id="manual-introduction"');
    const missing = render(source, '不存在的词');
    expect(missing).toContain('未找到相关内容'); expect(missing).not.toContain('配置内容');
  });
  it('renders the real user manual and falls back safely for an unregistered manual name', () => {
    const html = renderToStaticMarkup(createElement(StaticRouter, { location: '/help/__proto__' },
      createElement(Routes, {}, createElement(Route, { path: '/help/:manual', element: createElement(ManualPage) }))));
    expect(html).toContain('用户使用手册'); expect(html).toContain('v1.0'); expect(html).toContain('href="/help/operations-guide"');
    expect(html).toContain('id="23-m11变更工单独立审批与恢复基线"'); expect(html).toContain('<table>');
  });
});
