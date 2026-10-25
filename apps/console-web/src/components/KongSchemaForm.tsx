import { useEffect, useState } from 'react';
import { Alert, Button, Collapse, Form, Input, InputNumber, Select, Space, Switch, Upload } from 'antd';
import type { FormInstance } from 'antd';
import { DeleteOutlined, PlusOutlined, UploadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { scopeQuery } from '../api/workspace-scope';
import { analyzeKongSchema, isSensitiveSchemaName, payloadPathToForm, rulePathKey, schemaFieldEntries } from './kong-schema-rules';
import type { FieldHint, SchemaAnalysis } from './kong-schema-rules';

export interface KongField {
  type?: string; required?: boolean; default?: any; fields?: Record<string, KongField>[] | Record<string, KongField>;
  elements?: KongField; keys?: KongField; values?: KongField; one_of?: any[];
  between?: number[]; gt?: number; gte?: number; lt?: number; lte?: number;
  auto?: boolean; read_only?: boolean; reference?: string; description?: string;
  len_min?: number; len_max?: number; nullable?: boolean; [key: string]: any;
}
export interface KongSchema extends KongField { name?: string; }
type FieldPath = (string | number)[];
const generated = new Set(['id', 'created_at', 'updated_at']);
const labels: Record<string, string> = { name: '名称', host: '上游主机', port: '端口', protocol: '协议', protocols: '协议', path: '路径', paths: '匹配路径', methods: '请求方法', hosts: '匹配域名', tags: '标签', retries: '重试次数', username: '用户名', custom_id: '业务标识', service: '绑定 Service', route: '绑定 Route', consumer: '绑定 Consumer', certificate: '绑定证书', client_certificate: '客户端证书', algorithm: '算法', slots: '槽位数', enabled: '启用', healthchecks: '健康检查', active: '主动检查', passive: '被动检查', strip_path: '剥离路径', preserve_host: '保留 Host', regex_priority: '正则优先级', cert: 'PEM 证书', key: '密钥', snis: 'SNI', weight: '权重', target: '目标地址', config: '插件配置', connect_timeout: '连接超时（毫秒）', read_timeout: '读取超时（毫秒）', write_timeout: '写入超时（毫秒）', hash_on: '哈希来源', hash_fallback: '哈希回退', headers: '匹配请求头' };

export function schemaFields(schema: KongSchema, root = false): [string, KongField][] {
  return schemaFieldEntries(schema).filter(([name, field]) => !field.read_only && !(root && generated.has(name)));
}
export function sensitiveField(name: string, field?: KongField) { return isSensitiveSchemaName(name, field?.type); }
export function redactedValue(value: unknown) { return typeof value === 'string' && /^(\[REDACTED(?::[^\]]+)?\]|<redacted>|__REDACTED__|\*{3,}|<hidden>)$/i.test(value); }

function fieldDefault(field: KongField): any {
  if (field.default != null) return structuredClone(field.default);
  if (field.type === 'record') return Object.fromEntries(schemaFields(field).map(([key, def]) => [key, fieldDefault(def)]).filter(([, value]) => value !== undefined));
  if (['array', 'set', 'map'].includes(field.type ?? '')) return [];
  return undefined;
}
export function prepareFormValues(schema: KongSchema, input: Record<string, any> = {}, editing = false, root = true): Record<string, any> {
  function visit(field: KongField, value: any, name = ''): any {
    if (sensitiveField(name, field)) return undefined;
    if (redactedValue(value)) return undefined;
    const current = value ?? fieldDefault(field);
    if (field.type === 'record') return schemaFields(field).length ? Object.fromEntries(schemaFields(field).map(([key, def]) => [key, visit(def, current?.[key], key)]).filter(([, val]) => val !== undefined)) : stripRedacted(current ?? {});
    if (field.type === 'map') return Array.isArray(current) ? current : Object.entries(current ?? {}).map(([key, val]) => ({ key, value: visit(field.values ?? { type: 'string' }, val) }));
    if (field.type === 'array' || field.type === 'set') return (Array.isArray(current) ? current : []).map(val => visit(field.elements ?? { type: 'string' }, val));
    return current;
  }
  return Object.fromEntries(schemaFields(schema, root).map(([name, field]) => [name, visit(field, input[name], name)]).filter(([, value]) => value !== undefined));
}

function stripRedacted(value: any): any {
  if (Array.isArray(value)) return value.map(stripRedacted);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key, val]) => !isSensitiveSchemaName(key, typeof val) && !redactedValue(val)).map(([key, val]) => [key, stripRedacted(val)]));
  return value;
}

export function formPayload(schema: KongSchema, input: Record<string, any>, editing = false): Record<string, any> {
  function visit(field: KongField, value: any, name = ''): any {
    if (redactedValue(value) || value === undefined || (sensitiveField(name, field) && (value === '' || value === null))) return undefined;
    if (value === '' && !field.required) return editing && !sensitiveField(name, field) ? null : undefined;
    // 1.5 omits nullable defaults from its schema response. Empty UI lists must
    // not turn an unset optional Route source/destination into an explicit [].
    // PATCH clearing is handled separately against the original object.
    if (!editing && ['array', 'set', 'map'].includes(field.type ?? '') && !field.required && !(field.len_min && field.len_min > 0)
      && (!Object.hasOwn(field, 'default') || field.default === null)
      && (Array.isArray(value) ? value.length === 0 : value !== null && typeof value === 'object' && Object.keys(value).length === 0)) return undefined;
    if (field.type === 'record') return value && typeof value === 'object' && !Array.isArray(value) && schemaFields(field).length ? Object.fromEntries(schemaFields(field).map(([key, def]) => [key, visit(def, value?.[key], key)]).filter(([, val]) => val !== undefined)) : value;
    if (field.type === 'map') return Array.isArray(value) ? Object.fromEntries(value.filter(row => typeof row?.key === 'string' && row.key !== '').map(row => [row.key, visit(field.values ?? { type: 'string' }, row.value)])) : value;
    if (field.type === 'array' || field.type === 'set') return Array.isArray(value) ? value.map((val: any) => visit(field.elements ?? { type: 'string' }, val)) : value;
    if (['integer', 'number'].includes(field.type ?? '') && typeof value === 'string' && value.trim()) return Number(value);
    if (field.type === 'boolean' && typeof value === 'string' && ['true', 'false'].includes(value)) return value === 'true';
    return value;
  }
  return Object.fromEntries(schemaFields(schema, true).map(([name, field]) => [name, visit(field, input[name], name)]).filter(([, value]) => value !== undefined));
}

export function ForeignLookup({ reference, value, onChange, label, id }: { reference: string; value?: any; onChange?: (value: any) => void; label: string; id?: string }) {
  const { clusterId } = useCluster();
  const { workspaceId, ready } = useWorkspace();
  const type = reference.split('.')[0];
  const scope = `${clusterId}:${workspaceId}:${type}`;
  const [state, setState] = useState<{ scope: string; search: string; cursor?: string; items: any[] }>({ scope, search: '', items: [] });
  const active = state.scope === scope ? state : { scope, search: '', cursor: undefined, items: [] };
  const { search, cursor, items } = active;
  const query = useQuery({ queryKey: ['foreign', clusterId, workspaceId, type, search, cursor], queryFn: () => api<any>(scopeQuery(`/clusters/${clusterId}/entities/${type}?size=20${search ? `&search=${encodeURIComponent(search)}` : ''}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, clusterId, workspaceId)), enabled: ready });
  useEffect(() => { if (query.data) setState(prev => ({ scope, search, cursor, items: cursor && prev.scope === scope ? [...new Map([...prev.items, ...(query.data.items ?? [])].map(item => [item.id, item])).values()] : query.data.items ?? [] })); }, [query.data, scope, search, cursor]);
  const selectedId = typeof value === 'string' ? value : value?.id;
  const options = items.map(item => ({ value: item.id, label: `${item.name ?? item.username ?? item.id} · ${item.id.slice(0, 8)}` }));
  if (selectedId && !options.some(option => option.value === selectedId)) options.unshift({ value: selectedId, label: selectedId });
  return <Select id={id} aria-label={label} showSearch allowClear value={selectedId} options={options} loading={query.isFetching} filterOption={false} placeholder="选择实体，或输入完整名称 / ID 搜索" onSearch={term => setState({ scope, search: term, cursor: undefined, items: [] })} onChange={selected => onChange?.(selected ? { id: selected } : null)} notFoundContent={query.isError ? '查询失败，请检查权限与连接' : query.isFetching ? '正在查询…' : '没有匹配实体'} popupRender={menu => <>{menu}{query.data?.nextCursor && <Button block type="text" size="small" onMouseDown={event => event.preventDefault()} onClick={() => setState({ ...active, cursor: query.data.nextCursor })}>加载下一页</Button>}</>} />;
}

function PemInput({ value, onChange, secret, label, id }: { value?: string; onChange?: (value: string) => void; secret?: boolean; label: string; id?: string }) {
  return <div><Input.TextArea id={id} aria-label={label} value={value} onChange={event => onChange?.(event.target.value)} rows={secret ? 4 : 6} spellCheck={false} placeholder={secret ? '粘贴 PEM 私钥；留空保持原密钥' : label === 'rsa_public_key' ? '-----BEGIN PUBLIC KEY-----' : '-----BEGIN CERTIFICATE-----'} className="mono" /><Upload accept=".pem,.crt,.cer,.key,.pub" showUploadList={false} beforeUpload={file => { void file.text().then(text => onChange?.(text)); return false; }}><Button size="small" icon={<UploadOutlined />} style={{ marginTop: 8 }}>从本地文件读取</Button></Upload></div>;
}

interface FormRuleContext {
  hints: Record<string, FieldHint>;
  submittedErrors: Record<string, string[]>;
  validate: (path: FieldPath) => Promise<void>;
}
function SchemaField({ name, field, path, basePath = [], editing, depth = 0, entityType, validation }: {
  name: string; field: KongField; path: FieldPath; basePath?: FieldPath; editing: boolean;
  depth?: number; entityType?: string; validation: FormRuleContext;
}) {
  const actualPath = [...basePath, ...path];
  const key = rulePathKey(actualPath);
  const hint = validation.hints[key];
  const required = (!!field.required || !!hint?.required) && !field.auto && !(editing && sensitiveField(name, field));
  const label = <span>{labels[name] ?? name}{labels[name] && <code className="field-code">{name}</code>}{required && <span className="schema-required" aria-label="必填" style={{ color: '#ff7875', marginLeft: 6 }}>*</span>}</span>;
  const secret = sensitiveField(name, field);
  const rules: any[] = [{ validator: () => validation.validate(actualPath) }];
  const marker = { 'data-testid': `schema-field-${actualPath.join('-')}`, 'data-field-path': actualPath.join('.') };
  const groupErrors = <Form.ErrorList errors={validation.submittedErrors[key] ?? []} />;
  const hintText = hint?.messages.join('；');
  if (field.type === 'record' && schemaFields(field).length) return <div {...marker}><Collapse className="schema-record" defaultActiveKey={depth === 0 ? ['record'] : undefined} items={[{ key: 'record', label, forceRender: true, children: <><div className="schema-field-grid">{schemaFields(field).map(([childName, def]) => <SchemaField key={childName} name={childName} field={def} path={[...path, childName]} basePath={basePath} editing={editing} depth={depth + 1} entityType={entityType} validation={validation} />)}</div>{groupErrors}</> }]} /></div>;
  if (field.type === 'map') return <div {...marker} className="schema-list"><div className="schema-list-title">{label}</div>{hintText && <div className="schema-condition-hint">{hintText}</div>}<Form.List name={path} rules={[{ validator: async (_, rows) => {
    const keys = (rows ?? []).map((row: any) => row?.key).filter(Boolean);
    if (new Set(keys).size !== keys.length) throw new Error('键名不能重复');
    await validation.validate(actualPath);
  } }]}>{(rows, { add, remove }, meta) => <>{rows.map(row => <div key={row.key} className="schema-map-row"><Form.Item name={[row.name, 'key']} rules={[{ required: true, message: '填写键名' }]}><Input aria-label={`${name} key`} placeholder="键名" /></Form.Item><div className="schema-map-value"><SchemaField name="value" field={field.values ?? { type: 'string' }} path={[row.name, 'value']} basePath={actualPath} editing={editing} depth={depth + 1} entityType={entityType} validation={validation} /></div><Button type="text" danger icon={<DeleteOutlined />} onClick={() => remove(row.name)} aria-label={`删除 ${name} 项`} /></div>)}<Button type="dashed" icon={<PlusOutlined />} onClick={() => add({ key: '', value: prepareNested(field.values ?? {}) })}>添加键值项</Button><Form.ErrorList errors={meta.errors} /></>}</Form.List>{groupErrors}</div>;
  if ((field.type === 'array' || field.type === 'set') && (['record', 'map', 'array', 'set', 'foreign', 'boolean'].includes(field.elements?.type ?? '') || (field.type === 'array' && field.elements?.type === 'string' && !field.elements.one_of && !field.elements.enum))) return <div {...marker} className="schema-list"><div className="schema-list-title">{label}</div>{hintText && <div className="schema-condition-hint">{hintText}</div>}<Form.List name={path} rules={rules}>{(rows, { add, remove }, meta) => <>{rows.map(row => <div key={row.key} className="schema-array-row" data-testid={`schema-record-${[...actualPath, row.name].join('-')}`}><div className="schema-array-row-heading"><strong>第 {row.name + 1} 项</strong><Button type="text" danger size="small" icon={<DeleteOutlined />} onClick={() => remove(row.name)}>移除</Button></div>{field.elements?.type === 'record' ? <><div className="schema-field-grid">{schemaFields(field.elements).map(([childName, def]) => <SchemaField key={childName} name={childName} field={def} path={[row.name, childName]} basePath={actualPath} editing={editing} depth={depth + 1} entityType={entityType} validation={validation} />)}</div><Form.ErrorList errors={validation.submittedErrors[rulePathKey([...actualPath, row.name])] ?? []} /></> : <SchemaField name="item" field={{ ...(field.elements ?? { type: 'string' }), multiline: ['functions', 'script', 'lua'].includes(name) }} path={[row.name]} basePath={actualPath} editing={editing} depth={depth + 1} entityType={entityType} validation={validation} />}</div>)}<Button type="dashed" icon={<PlusOutlined />} onClick={() => add(prepareNested(field.elements ?? {}))}>添加一项</Button><Form.ErrorList errors={meta.errors} /></>}</Form.List>{groupErrors}</div>;
  let control: React.ReactNode;
  const choices = field.one_of ?? field.enum;
  if (field.type === 'record') { control = <Input.TextArea aria-label={name} rows={7} className="mono" />; rules.push({ validator: (_: unknown, value: any) => { try { if (typeof value === 'string') JSON.parse(value); return Promise.resolve(); } catch { return Promise.reject(new Error('请输入有效的 JSON 对象')); } } }); }
  else if (field.type === 'foreign' || field.reference) control = <ForeignLookup reference={field.reference ?? name} label={name} />;
  else if (name === 'cert' || name === 'rsa_public_key' || name === 'rsa_private_key' || ((name === 'key') && ['certificates', 'ca_certificates'].includes(entityType ?? ''))) control = <PemInput secret={secret} label={name} />;
  else if (field.type === 'boolean') control = <Switch aria-label={name} checkedChildren="启用" unCheckedChildren="关闭" />;
  else if (choices) control = <Select aria-label={name} allowClear={!required} options={choices.map((value: any) => ({ value, label: String(value) }))} />;
  else if (field.type === 'integer' || field.type === 'number') control = <InputNumber aria-label={name} style={{ width: '100%' }} precision={field.type === 'integer' ? 0 : undefined} min={field.between?.[0] ?? field.gte ?? (field.gt != null ? field.gt + (field.type === 'integer' ? 1 : 0.000001) : undefined)} max={field.between?.[1] ?? field.lte ?? (field.lt != null ? field.lt - (field.type === 'integer' ? 1 : 0.000001) : undefined)} />;
  else if (field.type === 'array' || field.type === 'set') { const options = field.elements?.one_of ?? field.elements?.enum; control = <Select aria-label={name} mode={options ? 'multiple' : 'tags'} tokenSeparators={[',']} options={(options ?? []).map((value: any) => ({ value, label: String(value) }))} placeholder="输入一项，回车确认" />; }
  else if (secret) control = <Input.Password aria-label={name} autoComplete="new-password" placeholder={editing ? '留空保持原秘密；填写后替换' : '秘密在服务端加密记录，默认脱敏'} />;
  else if (field.multiline) control = <Input.TextArea aria-label={name} rows={5} spellCheck={false} className="mono" />;
  else control = <Input aria-label={name} placeholder={field.default != null ? `默认值：${String(field.default)}` : undefined} />;
  const extra = [secret && editing ? '原秘密不回显，留空不会覆盖。' : field.auto ? '留空时由 Kong 自动生成。' : '', hintText].filter(Boolean).join('；');
  return <div {...marker} className={field.type === 'record' || (['cert', 'key'].includes(name) && entityType?.includes('certificate')) ? 'schema-wide-field' : undefined}><Form.Item name={path} label={label} rules={rules} valuePropName={field.type === 'boolean' ? 'checked' : 'value'} getValueProps={field.type === 'record' ? value => ({ value: typeof value === 'string' ? value : JSON.stringify(value ?? {}, null, 2) }) : undefined} getValueFromEvent={field.type === 'record' ? event => { try { return JSON.parse(event.target.value); } catch { return event.target.value; } } : undefined} tooltip={field.description} extra={extra || undefined}>{control}</Form.Item></div>;
}

function prepareNested(field: KongField) {
  if (field.type === 'record') return prepareFormValues(field, {}, false, false);
  return fieldDefault(field);
}

export function KongSchemaForm({ schema, form, onFinish, editing = false, entityType, children }: { schema: KongSchema; form: FormInstance; onFinish: (values: Record<string, any>) => void; editing?: boolean; entityType?: string; children?: React.ReactNode }) {
  const watchedValues = Form.useWatch([], { form, preserve: true });
  const values = watchedValues ?? form.getFieldsValue(true);
  const editableSchema: KongSchema = { ...schema, fields: schemaFields(schema, true).map(([name, field]) => ({ [name]: field })) };
  const analysis = analyzeKongSchema(editableSchema, formPayload(editableSchema, values ?? {}, editing), { editing });
  const [submittedErrors, setSubmittedErrors] = useState<Record<string, string[]>>({});
  const hints: Record<string, FieldHint> = Object.create(null);
  for (const [logicalPath, hint] of Object.entries(analysis.hints)) hints[rulePathKey(payloadPathToForm(editableSchema, values, JSON.parse(logicalPath)))] = hint;
  const latestAnalysis = (): SchemaAnalysis => analyzeKongSchema(editableSchema, formPayload(editableSchema, form.getFieldsValue(true), editing), { editing });
  const validation: FormRuleContext = { hints, submittedErrors, validate: async path => {
    const currentValues = form.getFieldsValue(true);
    const errors = latestAnalysis().issues.filter(issue => rulePathKey(payloadPathToForm(editableSchema, currentValues, issue.path)) === rulePathKey(path));
    if (errors.length) throw new Error(errors.map(error => error.message).join('；'));
  } };
  const submit = (input: Record<string, any>) => {
    const payload = formPayload(editableSchema, input, editing);
    const result = analyzeKongSchema(editableSchema, payload, { editing });
    const errors: Record<string, string[]> = Object.create(null);
    for (const issue of result.issues) (errors[rulePathKey(payloadPathToForm(editableSchema, input, issue.path))] ??= []).push(issue.message);
    setSubmittedErrors(errors);
    if (result.issues.length) {
      form.setFields(Object.entries(errors).filter(([path]) => JSON.parse(path).length).map(([path, messages]) => ({ name: JSON.parse(path), errors: messages })));
      const first = payloadPathToForm(editableSchema, input, result.issues[0].path);
      if (first.length) form.scrollToField(first);
      return;
    }
    onFinish(payload);
  };
  return <Form form={form} layout="vertical" requiredMark={false} onValuesChange={() => setSubmittedErrors({})} onFinish={submit}><div className="schema-field-grid">{schemaFields(editableSchema, true).map(([name, field]) => <SchemaField key={name} name={name} field={field} path={[name]} editing={editing} entityType={entityType} validation={validation} />)}</div><Form.ErrorList errors={submittedErrors[rulePathKey([])] ?? []} /><Alert type="info" showIcon className="schema-authority-note" data-remote-authoritative="true" message="字段来自当前 Kong schema" description={<>{analysis.unsupportedValidators.length ? `部分 Lua / 自定义规则由 Kong 最终校验：${analysis.unsupportedValidators.slice(0, 8).join('；')}${analysis.unsupportedValidators.length > 8 ? '…' : ''}。` : '必填、取值范围与条件字段在提交前校验。'} 引用、Lua 验证器及配置冲突始终以 Kong 返回的字段错误为准。</>} />{children}</Form>;
}
