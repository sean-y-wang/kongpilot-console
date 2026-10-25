import { useEffect, useState } from 'react';
import { Button, Select, Space, Typography } from 'antd';
import { PilotIcon } from '../../../../packages/contracts/src/PilotIcon';

export function useCursorPages(resetKey: string) {
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [page, setPage] = useState(0);
  const [activeKey, setActiveKey] = useState(resetKey);
  useEffect(() => { setCursors([undefined]); setPage(0); setActiveKey(resetKey); }, [resetKey]);
  function next(cursor: string) { setCursors(values => [...values.slice(0, page + 1), cursor]); setPage(value => value + 1); }
  function previous() { setPage(value => Math.max(0, value - 1)); }
  return { cursor: activeKey === resetKey ? cursors[page] : undefined, page: activeKey === resetKey ? page : 0, visited: activeKey === resetKey ? cursors.length : 1, next, previous, select: setPage };
}

export function CursorPagination({ pages, nextCursor, loading, count, size, onSizeChange }: { pages: ReturnType<typeof useCursorPages>; nextCursor?: string | null; loading?: boolean; count: number; size: number; onSizeChange?: (size: number) => void }) {
  return <div className="cursor-pagination"><Typography.Text type="secondary">本页 {count} 条</Typography.Text><Space wrap>{onSizeChange && <Select size="small" aria-label="每页条数" value={size} onChange={onSizeChange} options={[10, 20, 50, 100].map(value => ({ value, label: `${value} 条 / 页` }))} />}<Button size="small" icon={<PilotIcon name="chevron-left" />} disabled={pages.page === 0 || loading} onClick={pages.previous}>上一页</Button><Select size="small" aria-label="已访问页" value={pages.page} onChange={pages.select} options={Array.from({ length: pages.visited }, (_, index) => ({ value: index, label: `第 ${index + 1} 页` }))} /><Button size="small" disabled={!nextCursor || loading} onClick={() => nextCursor && pages.next(nextCursor)}>下一页 <PilotIcon name="chevron-right" /></Button></Space></div>;
}
