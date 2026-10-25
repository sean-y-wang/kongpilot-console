import { useEffect, useState } from 'react';
import { Alert, Button, Descriptions, Drawer, Space, Spin, Tabs, Tag, Typography } from 'antd';
import { DeleteOutlined, EditOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { scopeQuery } from '../api/workspace-scope';
import { api } from '../api/client';
import { redactForDisplay } from '../api/redaction';
import { EntityRelationList, relationUnavailableMessage } from '../components/EntityRelationList';
import { QueryError } from '../components/Shared';
import { entityLabels, entityName, entityTime } from './entities';
import { TargetManager } from './TargetManager';
import { CredentialManager } from './CredentialManager';
import { EntityAnnotations } from './EntityAnnotations';
import { usePermissions } from '../app/Permissions';
import { useEntityPermissions } from '../app/EntityPermissions';
import { useEntityChangePreparation } from './EntityEditor';

export function EntityDetails({ type, id, onClose, onEdit, onDelete }: { type: string; id?: string; onClose: () => void; onEdit: (entity: any) => void; onDelete: (entity: any) => void }) {
  const { clusterId, cluster } = useCluster();
  const { workspaceId, workspace, ready, writeBlocked, readonlyWorkspace } = useWorkspace();
  const permission = usePermissions();
  const preparation = useEntityChangePreparation({ clusterId, workspaceId, enabled: !!id && ready && !writeBlocked && !readonlyWorkspace && workspace?.status === 'active' && cluster?.execution_mode === 'approval' });
  const navigate = useNavigate();
  const [tab, setTab] = useState('configuration');
  useEffect(() => setTab('configuration'), [type, id]);
  const query = useQuery({ queryKey: ['entity', clusterId, workspaceId, type, id], queryFn: () => api<any>(scopeQuery(`/clusters/${clusterId}/entities/${type}/${id}`, clusterId, workspaceId)), enabled: !!id && ready });
  const entity = query.data?.entity;
  const abilities = useEntityPermissions(entity ? [{ type, id: entity.id }] : []);
  const certificate = query.data?.certificate;
  const relationTypes: Record<string, string> = { service: 'services', route: 'routes', consumer: 'consumers', certificate: 'certificates', client_certificate: 'certificates' };
  function renderValue(name: string, value: any): React.ReactNode {
    const unavailable = relationTypes[name] && relationUnavailableMessage(query.data?.relations?.[name]);
    if (unavailable) return <Typography.Text type="secondary">{unavailable}</Typography.Text>;
    value = redactForDisplay(value, name);
    if (value == null) return <Typography.Text type="secondary">—</Typography.Text>;
    if (name === 'created_at' || name === 'updated_at') return entityTime(value);
    if (name === 'tags') return <Space wrap>{value.map((tag: string) => <Tag key={tag}>{tag}</Tag>)}</Space>;
    if (relationTypes[name] && value.id) return <Button type="link" size="small" onClick={() => navigate(`/entities/${relationTypes[name]}/${value.id}`)}>{value.id}</Button>;
    if (typeof value === 'boolean') return <Tag color={value ? 'green' : 'default'}>{value ? 'true' : 'false'}</Tag>;
    if (typeof value === 'object') return <pre className="detail-value-json">{JSON.stringify(value, null, 2)}</pre>;
    return <Typography.Text className={['id', 'cert', 'key'].includes(name) ? 'mono' : undefined} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{String(value)}</Typography.Text>;
  }
  const tabs = [{ key: 'configuration', label: 'Configuration', children: entity && <>{certificate && <div className="certificate-metadata"><Alert showIcon type={certificate.expired ? 'error' : certificate.expiring_soon ? 'warning' : 'success'} message={certificate.expired ? '证书已过期' : `证书将在 ${certificate.days_remaining} 天后到期`} description={`到期时间：${certificate.expires_at} · 私钥匹配：${certificate.key_matches == null ? '未验证' : certificate.key_matches ? '匹配' : '不匹配'}`} /><Descriptions style={{ marginTop: 16 }} size="small" column={1} items={[{ key: 'subject', label: 'Subject', children: certificate.subject }, { key: 'issuer', label: 'Issuer', children: certificate.issuer }, { key: 'fingerprint', label: 'Fingerprint', children: <Typography.Text copyable className="mono">{certificate.fingerprint}</Typography.Text> }]} /></div>}{permission.can('annotations', 'read', entity, { entityType: type }) && <EntityAnnotations type={type} entity={entity} />}<Descriptions bordered size="small" column={1} items={Object.entries(entity).map(([name, value]) => ({ key: name, label: <span className="mono">{name}</span>, children: renderValue(name, value) }))} /></> }];
  for (const relation of ['routes', 'plugins', 'snis']) if (query.data?.relations?.[relation]) tabs.push({ key: relation, label: entityLabels[relation] ?? relation, children: <EntityRelationList parentType={type} parentId={id!} relation={relation} initial={query.data.relations[relation]} /> });
  if (type === 'upstreams' && id) tabs.push({ key: 'targets', label: 'Targets & Health', children: <TargetManager upstreamId={id} parentEntity={entity} /> });
  if (type === 'consumers' && id) tabs.push({ key: 'credentials', label: '认证凭证', children: <CredentialManager consumerId={id} parentEntity={entity} /> });
  return <Drawer width={980} title={`${entityLabels[type] ?? type} · ${entity ? entityName(entity) : id ?? ''}`} open={!!id} onClose={onClose} destroyOnClose extra={<Space><Button icon={<ReloadOutlined />} onClick={() => void query.refetch()}>刷新</Button><Button icon={<EditOutlined />} disabled={!entity || !abilities.can(type, entity?.id, 'write')} onClick={() => onEdit(entity)}>编辑</Button><Button danger icon={<DeleteOutlined />} disabled={!entity || !ready || writeBlocked || readonlyWorkspace || !abilities.can(type, entity?.id, 'delete') || cluster?.execution_mode === 'approval' && (!preparation.allowed || preparation.busy || !!preparation.attempt)} onClick={() => onDelete(entity)}>{cluster?.execution_mode === 'approval' ? '申请删除' : '删除'}</Button></Space>}>{query.isLoading && <Spin />}{abilities.query.isError && <QueryError error={abilities.query.error} retry={() => void abilities.query.refetch()} />}{query.isError && <QueryError error={query.error} retry={() => void query.refetch()} />}{entity && <><div className="entity-detail-summary"><Typography.Text copyable className="mono">{entity.id}</Typography.Text><Space wrap>{entity.tags?.map((tag: string) => <Tag key={tag}>{tag}</Tag>)}</Space></div><Tabs activeKey={tab} onChange={setTab} items={tabs} /></>}</Drawer>;
}
