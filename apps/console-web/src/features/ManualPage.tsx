import { createElement, useEffect, useState, type HTMLAttributes } from 'react';
import { Button, Card, Empty, Input, Space, Tag } from 'antd';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Link, useLocation, useParams } from 'react-router-dom';
import { PageHeading } from '../components/Shared';
import { PRODUCT_BRAND } from '../components/BrandIdentity';
import { PilotIcon } from '../../../../packages/contracts/src/PilotIcon';
import userGuide from '../../../../docs/manuals/console-user-guide.md?raw';
import operationsGuide from '../../../../docs/manuals/production-operations-guide.md?raw';

const manuals = {
  'user-guide': { title: '用户使用手册', source: userGuide },
  'operations-guide': { title: '部署与运维手册', source: operationsGuide },
};

type ManualName = keyof typeof manuals;
interface ManualNode {
  type: string; depth?: number; value?: string; alt?: string; children?: ManualNode[];
  position?: { start: { offset?: number }; end: { offset?: number } };
  data?: { hName?: string; hProperties?: Record<string, unknown> };
  url?: string;
}
function headingText(node: ManualNode): string {
  return node.type === 'text' || node.type === 'inlineCode' ? node.value ?? ''
    : node.type === 'image' ? node.alt ?? '' : (node.children ?? []).map(headingText).join('');
}
/** Local documentation IDs have no URL scheme, attributes or clobbering names. */
export function manualHeadingSlug(title: string): string {
  const slug = title.toLowerCase().trim().replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, '').replace(/\s/g, '-');
  return !slug ? 'manual-heading' : /^(?:__proto__|constructor|prototype|name|location|document|window)$/i.test(slug) ? `manual-${slug}` : slug;
}
function safeFragment(value: string): string | undefined {
  try {
    const decoded = decodeURIComponent(value);
    return decoded.length > 0 && decoded.length <= 256 && /^[\p{L}\p{N}\p{M}_-]+$/u.test(decoded) ? decoded : undefined;
  } catch { return undefined; }
}
/** Exact document names only; repository evidence and private paths stay text. */
export function manualLink(href: string | undefined): { kind: 'manual' | 'anchor' | 'external'; href: string } | undefined {
  if (!href) return undefined;
  const match = /^(?:\.\/)?(production-operations-guide|console-user-guide)\.md(?:#(.+))?$/.exec(href);
  if (match) {
    if (match[2] && !safeFragment(match[2])) return undefined;
    return { kind: 'manual', href: `/help/${match[1] === 'production-operations-guide' ? 'operations-guide' : 'user-guide'}${match[2] ? `#${match[2]}` : ''}` };
  }
  if (href.startsWith('#')) return safeFragment(href.slice(1)) ? { kind: 'anchor', href } : undefined;
  try {
    const url = new URL(href);
    if (url.protocol === 'https:' && !url.username && !url.password) return { kind: 'external', href };
  } catch { /* No relative URL becomes a product route or a data source. */ }
  return undefined;
}
function wrapper(hName: string, hProperties: Record<string, unknown>, children: ManualNode[]): ManualNode {
  return { type: 'manualContainer', data: { hName, hProperties }, children };
}
/** Assign IDs before filtering, using parsed headings instead of source regex.
 * Formatting, duplicates and code fences keep the same target across searches. */
function manualChapters(options: { source: string; search: string }) {
  return (tree: ManualNode) => {
    const used = new Set<string>();
    const assign = (node: ManualNode) => {
      if (node.type === 'heading') {
        const base = manualHeadingSlug(headingText(node)); let id = base, suffix = 0;
        while (used.has(id)) id = `${base}-${++suffix}`;
        used.add(id); node.data = { ...node.data, hProperties: { ...node.data?.hProperties, id, tabIndex: -1 } };
      }
      node.children?.forEach(assign);
    };
    assign(tree);
    const chapters: Array<{ id: string; title: string; nodes: ManualNode[] }> = [];
    for (const node of tree.children ?? []) {
      if (!chapters.length || node.type === 'heading' && node.depth === 2) {
        chapters.push({ id: String(node.type === 'heading' ? node.data!.hProperties!.id : 'manual-introduction'),
          title: node.type === 'heading' && node.depth === 2 ? headingText(node) : '产品介绍', nodes: [] });
      }
      chapters[chapters.length - 1].nodes.push(node);
    }
    const search = options.search.trim().toLocaleLowerCase();
    const visible = chapters.filter(chapter => !search || options.source.slice(chapter.nodes[0].position?.start.offset ?? 0,
      chapter.nodes[chapter.nodes.length - 1].position?.end.offset ?? options.source.length).toLocaleLowerCase().includes(search));
    tree.children = [wrapper('div', { className: ['manual-layout'] }, [
      wrapper('nav', { className: ['manual-toc'], 'aria-label': '手册目录' }, visible.map(chapter => ({ type: 'link', url: `#${chapter.id}`, children: [{ type: 'text', value: chapter.title }] }))),
      wrapper('div', { className: ['manual-document'] }, visible.map(chapter => wrapper('section',
        chapter.nodes.some(node => node.type === 'heading' && node.data?.hProperties?.id === chapter.id) ? {} : { id: chapter.id }, chapter.nodes))),
    ])];
  };
}
function manualHeading(tag: 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6') {
  return ({ node: _node, ...props }: HTMLAttributes<HTMLHeadingElement> & { node?: unknown }) => createElement(tag, { ...props, style: { ...props.style, scrollMarginTop: 96 } });
}

export function ManualDocument({ source, search, onSearch, otherManual }: { source: string; search: string; onSearch: (value: string) => void; otherManual: ManualName }) {
  return <Markdown skipHtml remarkPlugins={[remarkGfm, [manualChapters, { source, search }]]} components={{
    h1: manualHeading('h1'), h2: manualHeading('h2'), h3: manualHeading('h3'), h4: manualHeading('h4'), h5: manualHeading('h5'), h6: manualHeading('h6'),
    nav: ({ children }) => <Card className="manual-navigation"><Input.Search key={otherManual} aria-label="搜索手册" allowClear placeholder="搜索使用方法" onSearch={onSearch} />
      <nav aria-label="手册目录">{children}</nav><Link className="manual-other-guide" to={`/help/${otherManual}`}><PilotIcon name="audit" />{manuals[otherManual].title}</Link></Card>,
    div: ({ node, children, ...props }) => props.className === 'manual-document'
      ? <Card className="manual-document">{node?.children.length ? children : <Empty description="未找到相关内容" />}</Card> : <div {...props}>{children}</div>,
    a: ({ href, children }) => {
      const target = manualLink(href);
      return target?.kind === 'manual' ? <Link to={target.href}>{children}</Link>
        : target?.kind === 'anchor' ? <a href={target.href}>{children}</a>
          : target?.kind === 'external' ? <a href={target.href} target="_blank" rel="noopener noreferrer">{children}</a> : <span>{children}</span>;
    },
    img: ({ alt }) => <span>{alt}</span>,
  }}>{source}</Markdown>;
}

export function ManualPage() {
  const { manual = 'user-guide' } = useParams(), location = useLocation();
  const name: ManualName = Object.hasOwn(manuals, manual) ? manual as ManualName : 'user-guide';
  const [query, setQuery] = useState({ name, search: '' }), search = query.name === name ? query.search : '';
  const document = manuals[name];
  useEffect(() => {
    const id = safeFragment(location.hash.slice(1));
    if (!id) return;
    if (search && !window.document.getElementById(id)) { setQuery({ name, search: '' }); return; }
    const frame = requestAnimationFrame(() => { const target = window.document.getElementById(id); target?.scrollIntoView({ block: 'start' }); target?.focus({ preventScroll: true }); });
    return () => cancelAnimationFrame(frame);
  }, [name, search, location.hash]);
  return <><PageHeading title={document.title} extra={<Space><Tag>{PRODUCT_BRAND.versionLabel}</Tag><Button onClick={() => window.print()}>打印手册</Button></Space>} />
    <ManualDocument source={document.source} search={search} onSearch={value => setQuery({ name, search: value })} otherManual={name === 'operations-guide' ? 'user-guide' : 'operations-guide'} />
  </>;
}
