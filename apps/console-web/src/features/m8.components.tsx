import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Descriptions, Form, Select, Space, Tag, Typography } from 'antd';
import { api } from '../api/client';
import { scopeQuery } from '../api/workspace-scope';
import { QueryError } from '../components/Shared';
import { currentCursor, nextCursorPage, type CursorState } from './m7.cursor';
import { configurationQueryIdentity, configurationSelection } from './m8.model';
import { useM8Scope } from './m8.hooks';
import { m8Labels, type ConfigurationQuality, type CredentialRecovery, type ConfigurationScopeKind, type ConfigurationSelection } from './m8.types';

export function M8State({ state }: { state?: string | null }) { return <Tag color={state === 'succeeded' || state === 'ready' ? 'green' : ['uncertain', 'partial', 'incomplete'].includes(state ?? '') ? 'orange' : state === 'failed' ? 'red' : undefined}>{state ? m8Labels[state] ?? state : '尚未提供'}</Tag>; }
export function M8Quality({ quality, recovery }: { quality?: ConfigurationQuality; recovery?: CredentialRecovery }) { return <><Alert style={{ marginBottom: 16 }} type={quality?.complete ? 'info' : 'warning'} showIcon message={quality?.complete ? '已完成有界捕获；Kong 不支持跨对象原子快照' : '尚未证明配置完整性，不能据此执行破坏性恢复或完整部署导出'} description={<>{quality?.consistency ? m8Labels[quality.consistency] ?? quality.consistency : '一致性尚未提供'}{quality?.warnings?.length ? <div>提示：{quality.warnings.join('、')}</div> : null}</>} />{recovery && <Descriptions size="small" column={1} items={[{ key: 'recovery', label: '对象与凭证恢复能力', children: recovery.complete ? `${recovery.recoverable} 个可恢复对象` : `${recovery.recoverable} 个可恢复 / ${recovery.unavailable} 个不可恢复` }, { key: 'reason', label: '恢复限制', children: recovery.reasons?.join('、') || '以服务端逐对象恢复能力为准；真实凭证可用性需单独验证。' }]} />}</>; }
export function ConfigurationScopeFields({ module = 'snapshots', disabled = false, compact = false }: { module?: 'snapshots' | 'gitops'; disabled?: boolean; compact?: boolean }) {
  const scope = useM8Scope(), form = Form.useFormInstance(), kind: ConfigurationScopeKind = Form.useWatch('scope', form) ?? 'workspace';
  return <><Form.Item name="scope" label="配置范围" rules={[{ required: true }]}><Select aria-label="配置范围" disabled={disabled} onChange={() => form.setFieldValue('serviceIds', [])} options={[{ value: 'workspace', label: '当前工作区' }, { value: 'services', label: '指定 Services 与依赖' }, { value: 'cluster', label: '完整集群（仍绑定当前工作区锚点）', disabled: !scope.whole(module, 'read', true) }]} /></Form.Item>{kind === 'services' && <Form.Item name="serviceIds" label="授权 Services（最多 100 个）" rules={[{ required: true, type: 'array', min: 1, max: 100 }]}><ConfigurationServiceSelect disabled={disabled} /></Form.Item>}{!compact && <Typography.Paragraph type="secondary">共享引用只核验，不自动纳入可写范围。完整部署与恢复继续校验每个原生对象及凭证权限。</Typography.Paragraph>}</>;
}
export function ConfigurationListScope({ value, onChange, module = 'snapshots' }: { value: ConfigurationSelection; onChange: (selection: ConfigurationSelection) => void; module?: 'snapshots' | 'gitops' }) {
  const [form] = Form.useForm(), scope = useM8Scope();
  return <Form key={configurationQueryIdentity(scope.identity, 'scope-selector')} clearOnDestroy form={form} layout="vertical" initialValues={value} preserve={false} onFinish={values => { try { onChange(configurationSelection(values)); } catch { form.setFields([{ name: 'serviceIds', errors: ['请选择实际授权的合法 Services。'] }]); } }} style={{ marginBottom: 20 }}>
    <ConfigurationScopeFields module={module} compact /><Button htmlType="submit" aria-label="应用列表范围">应用列表范围</Button>
  </Form>;
}
function ConfigurationServiceSelect({ value, onChange, disabled = false }: { value?: string[]; onChange?: (ids: string[]) => void; disabled?: boolean }) {
  const scope = useM8Scope(), [term, setTerm] = useState(''), key = configurationQueryIdentity(scope.identity, 'service-identities', { search: term }), [stored, setStored] = useState<CursorState>({ key, cursors: [undefined], page: 0 }), pages = currentCursor(stored, key), cursor = pages.cursors[pages.page];
  const query = useQuery({ queryKey: ['m8', key, cursor], queryFn: async ({ signal }) => { const captured = { ...scope.identity }, params = new URLSearchParams({ size: '20', ...(term ? { search: term } : {}), ...(cursor ? { cursor } : {}) }); const page = await api<{ items: Array<{ id: string; name?: string }>; nextCursor: string | null }>(scopeQuery(`/clusters/${captured.cid}/entities/services?${params}`, captured.cid, captured.wid), { signal }); scope.assertCurrent(captured); return { items: page.items.map(row => ({ id: row.id, name: row.name })), nextCursor: page.nextCursor }; }, enabled: scope.ready && scope.permission.has('services'), retry: false, staleTime: 0, gcTime: 0 });
  const options = (query.data?.items ?? []).map(row => ({ value: row.id, label: row.name ?? row.id })); for (const id of value ?? []) if (!options.some(row => row.value === id)) options.unshift({ value: id, label: id });
  return <Select aria-label="配置 Services" disabled={disabled} mode="multiple" showSearch filterOption={false} value={value} onChange={onChange} onSearch={setTerm} loading={query.isFetching} options={options} popupRender={menu => <>{menu}<div style={{ padding: 12 }}><Space><Button size="small" disabled={pages.page === 0 || query.isFetching} onClick={() => setStored({ ...pages, page: pages.page - 1 })}>上一页</Button><span>第 {pages.page + 1} 页</span><Button size="small" disabled={!query.data?.nextCursor || query.isFetching} onClick={() => query.data?.nextCursor && setStored(nextCursorPage(pages, query.data.nextCursor))}>下一页</Button></Space>{query.error && <QueryError error={query.error} />}</div></>} />;
}
