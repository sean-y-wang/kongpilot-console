import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Select, Space, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { errorMessage } from '../api/client';
import { useCursorPages } from './CursorPagination';
import { vitalsPath, vitalsQueryKey, type VitalsScope } from '../features/vitals-model';
import { requestVitals } from '../features/vitals-response';
import type { VitalsIdentityPage } from '../features/vitals.types';

/** This lookup returns monitoring identities only, never native entity configuration. */
export function VitalsEntitySelect({ scope, type, value, onChange, label, disabled = false, allowClear = true }: { scope: VitalsScope; type: 'services' | 'routes' | 'consumers'; value?: string; onChange?: (id?: string) => void; label: string; disabled?: boolean; allowClear?: boolean }) {
  const [input, setInput] = useState(''), [term, setTerm] = useState('');
  const activeScope = useRef(scope); activeScope.current = scope;
  useEffect(() => { const timer = setTimeout(() => setTerm(input.trim()), 300); return () => clearTimeout(timer); }, [input]);
  const scopeKey = JSON.stringify(vitalsQueryKey('identity', scope, type));
  useEffect(() => { setInput(''); setTerm(''); }, [scopeKey]);
  const pages = useCursorPages(`${scopeKey}:${term}`);
  const query = useQuery({ queryKey: vitalsQueryKey('entities', scope, { type, search: term, cursor: pages.cursor }), queryFn: ({ signal }) => requestVitals<VitalsIdentityPage>(vitalsPath('entities', scope, { type, search: term, cursor: pages.cursor, size: 20 }), scope, () => activeScope.current, signal), enabled: !disabled && !!scope.clusterId && !!scope.workspaceId && !!scope.actorId, staleTime: 0, gcTime: 0, retry: false });
  const options = (query.isFetching || query.isError ? [] : query.data?.items ?? []).map(row => ({ value: row.id, label: row.parentName ? `${row.name} · ${row.parentName}` : row.name, title: row.id }));
  if (value && !options.some(row => row.value === value)) options.unshift({ value, label: value, title: value });
  return <div className="vitals-entity-lookup"><Select aria-label={label} value={value} onChange={onChange} disabled={disabled} allowClear={allowClear} showSearch filterOption={false} onSearch={setInput} loading={query.isFetching} options={options} placeholder="全部授权实体" popupRender={menu => <>{menu}<div className="vitals-lookup-pagination" onMouseDown={event => event.preventDefault()}><Space><Button size="small" disabled={pages.page === 0 || query.isFetching} onClick={pages.previous}>上一页</Button><Typography.Text type="secondary">第 {pages.page + 1} 页</Typography.Text><Button size="small" disabled={!query.data?.nextCursor || query.isFetching} onClick={() => query.data?.nextCursor && pages.next(query.data.nextCursor)}>下一页</Button></Space>{query.data?.scan_budget_exhausted && <Typography.Paragraph type="secondary">已达到本页扫描预算；可继续下一页或缩小搜索范围。</Typography.Paragraph>}{query.isError && <Alert type="warning" message={errorMessage(query.error)} />}</div></>} /></div>;
}
